#include "pch.h"

#include "Emulation.h"

#include <cstring>
#include <memory>
#include <vector>

extern "C" {
#include <bdshemu.h>
}

// Adapted from cursey/kananlib @ 8c27b65 (utility::emulate) with the BDShemu
// setup from bitdefender/bddisasm @ 70db095 disasmtool.c. Analysis only:
// external stores are discarded and RIP is confined to a bounded window.

namespace memory
{
namespace detail
{
uint64_t ShemuGpr(const _SHEMU_GPR_REGS& r, int ndrReg) noexcept
{
    switch (ndrReg)
    {
    case NDR_RAX: return r.RegRax;
    case NDR_RCX: return r.RegRcx;
    case NDR_RDX: return r.RegRdx;
    case NDR_RBX: return r.RegRbx;
    case NDR_RSP: return r.RegRsp;
    case NDR_RBP: return r.RegRbp;
    case NDR_RSI: return r.RegRsi;
    case NDR_RDI: return r.RegRdi;
    case NDR_R8: return r.RegR8;
    case NDR_R9: return r.RegR9;
    case NDR_R10: return r.RegR10;
    case NDR_R11: return r.RegR11;
    case NDR_R12: return r.RegR12;
    case NDR_R13: return r.RegR13;
    case NDR_R14: return r.RegR14;
    case NDR_R15: return r.RegR15;
    default: return 0;
    }
}
} // namespace detail

namespace
{
// NDR_RAX .. NDR_R15 in canonical order (do not assume the enum values).
constexpr int kNdrGpr[16] = {NDR_RAX, NDR_RCX, NDR_RDX, NDR_RBX, NDR_RSP, NDR_RBP, NDR_RSI, NDR_RDI,
                             NDR_R8,  NDR_R9,  NDR_R10, NDR_R11, NDR_R12, NDR_R13, NDR_R14, NDR_R15};

ND_BOOL ShemuAccessMemory(void* /*ctx*/, ND_UINT64 gla, ND_SIZET size, ND_UINT8* buffer, ND_BOOL store) noexcept
{
    if (store)
    {
        // Analysis only: never write real game memory. Pretend it worked.
        return ND_TRUE;
    }
    if (buffer != nullptr && size != 0)
    {
        std::memset(buffer, 0, size);
        if (memory::IsReadable(static_cast<uintptr_t>(gla), size))
        {
            __try
            {
                std::memcpy(buffer, reinterpret_cast<const void*>(gla), size);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                std::memset(buffer, 0, size);
            }
        }
    }
    return ND_TRUE;
}

// ~32 KiB window rounded around `start`, clamped to the module image.
constexpr size_t kWindowSize = 0x8000;
constexpr size_t kStackSize = 0x2000;
} // namespace

std::optional<ImageBaseRegisterResult> FindRegisterHoldingValue(const ModuleRange& game, uintptr_t start,
                                                                uintptr_t wantedValue,
                                                                size_t maxInstructions) noexcept
{
    if (!game || wantedValue == 0 || start < game.base || start >= game.end())
    {
        return std::nullopt;
    }

    uintptr_t winBase = start & ~static_cast<uintptr_t>(0xFFF);
    winBase = winBase > game.base + 0x1000 ? winBase - 0x1000 : game.base;
    uintptr_t winEnd = winBase + kWindowSize;
    if (winEnd > game.end())
    {
        winEnd = game.end();
    }
    const size_t winSize = winEnd - winBase;
    if (winSize < 0x40 || start + 16 > winEnd)
    {
        return std::nullopt;
    }

    auto ctx = std::make_unique<SHEMU_CONTEXT>();
    std::memset(ctx.get(), 0, sizeof(SHEMU_CONTEXT));

    std::vector<uint8_t> stack(kStackSize, 0);
    std::vector<uint8_t> intbuf(winSize + kStackSize, 0);

    ctx->Stack = stack.data();
    ctx->Intbuf = intbuf.data();
    ctx->Shellcode = reinterpret_cast<ND_UINT8*>(winBase);
    ctx->ShellcodeBase = winBase;
    ctx->ShellcodeSize = static_cast<ND_UINT32>(winSize);
    ctx->StackBase = 0x100000;
    ctx->StackSize = static_cast<ND_UINT32>(kStackSize);
    ctx->IntbufSize = static_cast<ND_UINT32>(intbuf.size());
    ctx->Registers.RegRsp = 0x101000;
    ctx->Registers.RegFlags = NDR_RFLAG_IF | 2;
    ctx->Registers.RegCr0 = 0x0000000080050031ull;
    ctx->Registers.RegCr4 = 0x0000000000170678ull;

    ctx->Segments.Cs.Selector = 0x10;
    ctx->Segments.Ds.Selector = 0x28;
    ctx->Segments.Es.Selector = 0x28;
    ctx->Segments.Ss.Selector = 0x28;
    ctx->Segments.Fs.Selector = 0x30;
    ctx->Segments.Gs.Selector = 0x30;
    ctx->Segments.Fs.Base = 0x7FFF0000;
    ctx->Segments.Gs.Base = 0x7FFF0000;
    ctx->TibBase = 0x7FFF0000;

    ctx->Mode = ND_CODE_64;
    ctx->Ring = 3;
    ctx->NopThreshold = SHEMU_DEFAULT_NOP_THRESHOLD;
    ctx->StrThreshold = SHEMU_DEFAULT_STR_THRESHOLD;
    ctx->MemThreshold = 100;
    ctx->AccessMemory = &ShemuAccessMemory;

    ctx->Registers.RegRip = start;

    size_t consumed = 0;
    for (size_t i = 0; i <= maxInstructions; ++i)
    {
        for (int idx = 0; idx < 16; ++idx)
        {
            if (detail::ShemuGpr(ctx->Registers, kNdrGpr[idx]) == wantedValue)
            {
                return ImageBaseRegisterResult{kNdrGpr[idx], consumed};
            }
        }
        if (i == maxInstructions)
        {
            break;
        }

        const uintptr_t rip = static_cast<uintptr_t>(ctx->Registers.RegRip);
        if (rip < winBase || rip + 16 > winEnd)
        {
            break; // execution left the bounded window - fail closed
        }

        const auto decoded = memory::DecodeOne(rip);
        if (!decoded)
        {
            break;
        }
        const INSTRUX& ix = decoded->instrux;
        const bool writesMem = (ix.MemoryAccess & ND_ACCESS_ANY_WRITE) != 0 && !ix.BranchInfo.IsBranch;
        const bool isCall = ix.Category == ND_CAT_CALL;

        if (writesMem || isCall)
        {
            ctx->Registers.RegRip = rip + decoded->length;
            ctx->Instruction = ix;
            ctx->InstructionsCount += 1;
            consumed += decoded->length;
            continue;
        }

        ctx->MaxInstructionsCount = ctx->InstructionsCount + 1;
        const SHEMU_STATUS status = ShemuEmulate(ctx.get());
        if (status != SHEMU_SUCCESS)
        {
            const auto again = memory::DecodeOne(static_cast<uintptr_t>(ctx->Registers.RegRip));
            if (!again)
            {
                break;
            }
            ctx->Registers.RegRip += again->length;
            ctx->Instruction = again->instrux;
            ctx->InstructionsCount += 1;
            consumed += again->length;
            continue;
        }
        consumed += decoded->length;
    }

    return std::nullopt;
}
} // namespace memory
