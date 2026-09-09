#include "pch.h"

#include "PeHeaderIntegrityBypass.h"

#include "../memory/Emulation.h"
#include "../memory/MemoryPatch.h"
#include "../memory/MemoryScan.h"
#include "../memory/ThreadSuspension.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

// Behavioral source: praydog/REFramework @ b6baf6b
// (src/mods/IntegrityCheckBypass.cpp: immediate_patch_re9, PE-header section).
// REFramework: Copyright (c) 2019 praydog, MIT License. See THIRD_PARTY_NOTICES.md.

namespace antitamper::pe_header
{
namespace
{
constexpr size_t kAnchorLen = 10;       // "4C 89 ? 24 40 00 00 00 41 ?"
constexpr size_t kHeaderCopySize = 0x1000;
constexpr auto kAnchorSig = "4C 89 ? 24 40 00 00 00 41 ?";

void Log(const char* format, ...)
{
    char buffer[512]{};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
}

const char* GprName(int ndrReg) noexcept
{
    static const char* kNames[16] = {"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
                                     "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15"};
    const auto idx = detail::ToX64GprIndex(ndrReg);
    return idx ? kNames[*idx] : "?";
}

bool RangeIsCommittedExecutable(uintptr_t address, size_t size) noexcept
{
    if (size == 0 || address + size < address)
    {
        return false;
    }
    uintptr_t cursor = address;
    const uintptr_t end = address + size;
    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi))
        {
            return false;
        }
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
        {
            return false;
        }
        const DWORD prot = mbi.Protect & 0xFFu;
        if (prot != PAGE_EXECUTE && prot != PAGE_EXECUTE_READ && prot != PAGE_EXECUTE_READWRITE &&
            prot != PAGE_EXECUTE_WRITECOPY)
        {
            return false;
        }
        const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        cursor = regionEnd > cursor ? regionEnd : end;
    }
    return true;
}

struct Discovery
{
    uintptr_t anchor{};
    uintptr_t patchAddress{};
    int reg{};
    size_t span{};
    std::vector<uint8_t> expected;
};

bool BoundariesProven(uintptr_t anchor) noexcept
{
    auto start = memory::FindFunctionStartUnwind(anchor);
    if (!start)
    {
        start = memory::FindFunctionStart(anchor);
    }
    if (!start)
    {
        return false;
    }
    return detail::DecodeReachesBoundary(*start, anchor) &&
           detail::DecodeReachesBoundary(*start, anchor + kAnchorLen);
}

// Full read-only completion for an anchor that already passed the boundary +
// structural checks. nullopt here means fail-closed (caller must not fall
// through to a later look-alike anchor).
std::optional<Discovery> CompleteCandidate(const memory::ModuleRange& game, uintptr_t anchor) noexcept
{
    const uintptr_t patchAddr = anchor + kAnchorLen;

    const auto emu = memory::FindRegisterHoldingValue(game, patchAddr, game.base, 15);
    if (!emu)
    {
        Log("[CapcomPatcher][PEHeader] emulation did not resolve image-base register; no patch");
        return std::nullopt;
    }
    if (emu->consumedBytes < kAnchorLen)
    {
        Log("[CapcomPatcher][PEHeader] patch span %zu shorter than movabs; no patch", emu->consumedBytes);
        return std::nullopt;
    }
    if (patchAddr + emu->consumedBytes > game.end() || !RangeIsCommittedExecutable(patchAddr, emu->consumedBytes))
    {
        Log("[CapcomPatcher][PEHeader] patch span not inside committed executable image; no patch");
        return std::nullopt;
    }
    if (!detail::ToX64GprIndex(emu->reg))
    {
        return std::nullopt;
    }

    std::vector<uint8_t> expected(emu->consumedBytes);
    if (!memory::TryReadBytes(patchAddr, expected.data(), expected.size()))
    {
        return std::nullopt;
    }

    return Discovery{anchor, patchAddr, emu->reg, emu->consumedBytes, std::move(expected)};
}

std::optional<Discovery> Discover(const memory::ModuleRange& game) noexcept
{
    if (game.size <= kHeaderCopySize)
    {
        return std::nullopt;
    }
    // REF scans up to game_end - 0x1000 for this anchor.
    const uintptr_t scanEnd = game.end() - kHeaderCopySize;
    uintptr_t cursor = game.base;

    while (cursor < scanEnd)
    {
        const auto hit = memory::Scan(cursor, scanEnd - cursor, kAnchorSig);
        if (!hit)
        {
            return std::nullopt;
        }
        cursor = *hit + 1;

        if (!BoundariesProven(*hit))
        {
            continue; // not a proven instruction boundary pair - try a later anchor
        }
        if (!detail::StructuralDiscriminatorMatches(*hit))
        {
            continue; // structural discriminator not established - try a later anchor
        }

        Log("[CapcomPatcher][PEHeader] structural candidate accepted @ +0x%zx",
            static_cast<size_t>(*hit - game.base));
        // Fully recognized PE-integrity candidate: succeed or fail closed here.
        return CompleteCandidate(game, *hit);
    }
    return std::nullopt;
}

void* CreateHeaderCopy(const memory::ModuleRange& game) noexcept
{
    if (game.size < kHeaderCopySize || !memory::IsReadable(game.base, kHeaderCopySize))
    {
        return nullptr;
    }
    void* copy = VirtualAlloc(nullptr, kHeaderCopySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (copy == nullptr)
    {
        return nullptr;
    }
    bool ok = false;
    __try
    {
        std::memcpy(copy, reinterpret_cast<const void*>(game.base), kHeaderCopySize);
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = false;
    }
    if (!ok)
    {
        VirtualFree(copy, 0, MEM_RELEASE);
        return nullptr;
    }
    return copy;
}

enum class State
{
    Uninitialized,
    Patched,
    NotFound,
    Failed,
};

std::mutex g_mutex;
State g_state = State::Uninitialized;
void* g_headerCopy = nullptr; // process-lifetime; never freed after success
} // namespace

bool SupportsPeHeaderIntegrity(game_profile::GameId id) noexcept
{
    using game_profile::GameId;
    switch (id)
    {
    case GameId::DragonsDogma2:
    case GameId::ResidentEvilRequiem:
    case GameId::Pragmata:
    case GameId::OnimushaWots:
    case GameId::MonsterHunterStories3:
        return true;
    default:
        return false;
    }
}

void Initialize(const game_profile::GameProfile& profile) noexcept
{
    if (!profile.re9Family || !SupportsPeHeaderIntegrity(profile.id))
    {
        return;
    }

    std::lock_guard lock(g_mutex);
    if (g_state != State::Uninitialized)
    {
        return; // Patched / NotFound / Failed are all terminal for this process
    }

    const auto game = memory::MainModule();
    if (!game)
    {
        g_state = State::Failed;
        return;
    }

    Log("[CapcomPatcher][PEHeader] scan started");
    auto candidate = Discover(game);
    if (!candidate)
    {
        g_state = State::NotFound;
        Log("[CapcomPatcher][PEHeader] integrity path not found; no patch applied");
        return;
    }

    void* cleanHeader = CreateHeaderCopy(game);
    if (cleanHeader == nullptr)
    {
        g_state = State::Failed;
        Log("[CapcomPatcher][PEHeader] header copy allocation failed; no patch");
        return;
    }

    const auto mov = detail::EncodeMovAbs(candidate->reg, reinterpret_cast<uint64_t>(cleanHeader));
    if (!mov)
    {
        g_state = State::Failed;
        return;
    }
    auto replacementOpt = detail::BuildReplacement(candidate->span, *mov);
    if (!replacementOpt)
    {
        g_state = State::Failed;
        return;
    }
    std::vector<uint8_t> replacement = std::move(*replacementOpt);

    memory::ThreadSuspensionScope suspension;
    if (!suspension.Ok())
    {
        g_state = State::Failed;
        Log("[CapcomPatcher][PEHeader] safe suspension window unavailable; no patch");
        return;
    }

    // Revalidate the dynamic meaning (register + span + bytes) under suspension.
    const auto stillGame = memory::MainModule();
    if (!stillGame || stillGame.base != game.base || stillGame.size != game.size ||
        !BoundariesProven(candidate->anchor) || !detail::StructuralDiscriminatorMatches(candidate->anchor))
    {
        g_state = State::Failed;
        Log("[CapcomPatcher][PEHeader] final revalidation changed; skipped");
        return;
    }
    const auto revalidated = CompleteCandidate(game, candidate->anchor);
    if (!revalidated || revalidated->reg != candidate->reg || revalidated->span != candidate->span ||
        revalidated->expected != candidate->expected)
    {
        g_state = State::Failed;
        Log("[CapcomPatcher][PEHeader] final revalidation changed; skipped");
        return;
    }

    memory::BytePatchCandidate patch{};
    patch.address = candidate->patchAddress;
    patch.expected = candidate->expected;
    patch.writeOffset = 0;
    patch.replacement = std::move(replacement);
    patch.name = "RE9-family PE-header image-base redirection";
    patch.requireExecutable = true;
    patch.requireUnwindFunctionStart = false;

    const auto outcome = memory::CommitPatch(patch);
    switch (outcome)
    {
    case memory::PatchOutcome::Patched:
    case memory::PatchOutcome::AlreadyPatched:
        g_state = State::Patched;
        g_headerCopy = cleanHeader;
        Log("[CapcomPatcher][PEHeader] patched @ +0x%zx (reg=%s span=%zu -> 0x%p)",
            static_cast<size_t>(candidate->patchAddress - game.base), GprName(candidate->reg), candidate->span,
            cleanHeader);
        break;
    case memory::PatchOutcome::Skipped:
        g_state = State::Failed;
        Log("[CapcomPatcher][PEHeader] commit skipped (validation changed); no write");
        break;
    case memory::PatchOutcome::Failed:
        g_state = State::Failed;
        Log("[CapcomPatcher][PEHeader] commit failed (write/verify); no retry");
        break;
    }
}

namespace detail
{
std::optional<unsigned> ToX64GprIndex(int ndrReg) noexcept
{
    switch (ndrReg)
    {
    case NDR_RAX: return 0u;
    case NDR_RCX: return 1u;
    case NDR_RDX: return 2u;
    case NDR_RBX: return 3u;
    case NDR_RSP: return 4u;
    case NDR_RBP: return 5u;
    case NDR_RSI: return 6u;
    case NDR_RDI: return 7u;
    case NDR_R8: return 8u;
    case NDR_R9: return 9u;
    case NDR_R10: return 10u;
    case NDR_R11: return 11u;
    case NDR_R12: return 12u;
    case NDR_R13: return 13u;
    case NDR_R14: return 14u;
    case NDR_R15: return 15u;
    default: return std::nullopt;
    }
}

std::optional<std::array<uint8_t, 10>> EncodeMovAbs(int ndrReg, uint64_t value) noexcept
{
    const auto index = ToX64GprIndex(ndrReg);
    if (!index)
    {
        return std::nullopt;
    }
    const unsigned r = *index;
    std::array<uint8_t, 10> out{};
    out[0] = static_cast<uint8_t>(0x48 | (r >= 8 ? 0x01 : 0x00)); // REX.W (+ REX.B for r8..r15)
    out[1] = static_cast<uint8_t>(0xB8 + (r & 7));
    std::memcpy(out.data() + 2, &value, sizeof(value));
    return out;
}

bool HasMemDisp(const INSTRUX& ix, uint64_t disp) noexcept
{
    for (uint8_t i = 0; i < ix.OperandsCount; ++i)
    {
        const auto& op = ix.Operands[i];
        if (op.Type == ND_OP_MEM && op.Info.Memory.HasBase && op.Info.Memory.HasDisp &&
            static_cast<uint64_t>(op.Info.Memory.Disp) == disp)
        {
            return true;
        }
    }
    return false;
}

bool HasRspMemDisp(const INSTRUX& ix, uint64_t disp) noexcept
{
    for (uint8_t i = 0; i < ix.OperandsCount; ++i)
    {
        const auto& op = ix.Operands[i];
        if (op.Type == ND_OP_MEM && op.Info.Memory.HasBase && op.Info.Memory.Base == NDR_RSP &&
            op.Info.Memory.HasDisp && static_cast<uint64_t>(op.Info.Memory.Disp) == disp)
        {
            return true;
        }
    }
    return false;
}

bool StructuralDiscriminatorMatches(uintptr_t start, size_t maxInstructions) noexcept
{
    bool found20 = false;
    bool found28 = false;
    bool found90 = false;

    memory::LinearDecode(start, maxInstructions, [&](memory::LinearDecodeStep& step) {
        const INSTRUX& ix = step.insn.instrux;

        if (!found20 && HasMemDisp(ix, 0x20))
        {
            found20 = true;
            return;
        }
        if (found20 && !found28 && HasMemDisp(ix, 0x28))
        {
            found28 = true;
            return;
        }
        if (found20 && found28 && HasRspMemDisp(ix, 0x90))
        {
            found90 = true;
            step.stop = true;
            return;
        }

        if (ix.Category == ND_CAT_RET || ix.Category == ND_CAT_INTERRUPT ||
            (ix.BranchInfo.IsBranch && !ix.BranchInfo.IsConditional && ix.Category != ND_CAT_CALL))
        {
            step.stop = true;
        }
    });

    return found90;
}

std::optional<std::vector<uint8_t>> BuildReplacement(size_t span, const std::array<uint8_t, 10>& movabs) noexcept
{
    if (span < movabs.size())
    {
        return std::nullopt;
    }
    std::vector<uint8_t> out(span, 0x90);
    std::memcpy(out.data(), movabs.data(), movabs.size());
    return out;
}

bool DecodeReachesBoundary(uintptr_t from, uintptr_t target, size_t maxInstructions) noexcept
{
    if (target < from)
    {
        return false;
    }
    uintptr_t ip = from;
    for (size_t i = 0; i < maxInstructions; ++i)
    {
        if (ip == target)
        {
            return true;
        }
        if (ip > target)
        {
            return false;
        }
        const auto decoded = memory::DecodeOne(ip);
        if (!decoded || decoded->length == 0)
        {
            return false;
        }
        ip += decoded->length;
    }
    return false;
}
} // namespace detail
} // namespace antitamper::pe_header
