#include "pch.h"

#include "StackDestroyerBypass.h"

#include "../memory/MemoryPatch.h"
#include "../memory/MemoryScan.h"
#include "../memory/ThreadSuspension.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>

// Behavioral source: praydog/REFramework @ b6baf6b
// (src/mods/IntegrityCheckBypass.cpp: remove_stack_destroyer).
// REFramework: Copyright (c) 2019 praydog, MIT License. See THIRD_PARTY_NOTICES.md.

namespace antitamper::stack_destroyer
{
namespace
{
constexpr size_t kSigLen = 18;
constexpr auto kSignatureText = "48 89 11 48 C7 04 24 00 00 00 00 48 81 C4 28 01 00 00";

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

enum class State
{
    Uninitialized,
    Patched,
    NotFound,
    Ambiguous,
    Failed,
};

std::mutex g_mutex;
State g_state = State::Uninitialized;
} // namespace

bool SupportsStackDestroyer(game_profile::GameId id) noexcept
{
    using game_profile::GameId;
    switch (id)
    {
    case GameId::MonsterHunterWilds:
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

namespace detail
{
namespace
{
bool IsMemOperand(const ND_OPERAND& op) noexcept
{
    return op.Type == ND_OP_MEM;
}

bool MemIsPlainBase(const ND_OPERAND& op, uint8_t base) noexcept
{
    return IsMemOperand(op) && op.Info.Memory.HasBase && op.Info.Memory.Base == base &&
           !op.Info.Memory.HasIndex && (!op.Info.Memory.HasDisp || op.Info.Memory.Disp == 0);
}

bool IsReg(const ND_OPERAND& op, uint8_t reg) noexcept
{
    return op.Type == ND_OP_REG && op.Info.Register.Reg == reg;
}

bool IsImm(const ND_OPERAND& op, uint64_t value) noexcept
{
    return op.Type == ND_OP_IMM && static_cast<uint64_t>(op.Info.Immediate.Imm) == value;
}

bool MnemonicIs(const INSTRUX& ix, const char* name) noexcept
{
    return std::strcmp(ix.Mnemonic, name) == 0;
}
} // namespace

bool ValidateSequence(uintptr_t address) noexcept
{
    // 1: mov qword ptr [rcx], rdx   (48 89 11)
    const auto i1 = memory::DecodeOne(address);
    if (!i1 || i1->length != 3)
    {
        return false;
    }
    {
        const INSTRUX& ix = i1->instrux;
        if (!MnemonicIs(ix, "MOV") || ix.OperandsCount < 2 || !MemIsPlainBase(ix.Operands[0], NDR_RCX) ||
            ix.Operands[0].Size != 8 || !IsReg(ix.Operands[1], NDR_RDX))
        {
            return false;
        }
    }

    // 2: mov qword ptr [rsp], 0     (48 C7 04 24 00 00 00 00)
    const auto i2 = memory::DecodeOne(address + 3);
    if (!i2 || i2->length != 8)
    {
        return false;
    }
    {
        const INSTRUX& ix = i2->instrux;
        if (!MnemonicIs(ix, "MOV") || ix.OperandsCount < 2 || !MemIsPlainBase(ix.Operands[0], NDR_RSP) ||
            ix.Operands[0].Size != 8 || !IsImm(ix.Operands[1], 0))
        {
            return false;
        }
    }

    // 3: add rsp, 0x128             (48 81 C4 28 01 00 00)
    const auto i3 = memory::DecodeOne(address + 11);
    if (!i3 || i3->length != 7)
    {
        return false;
    }
    {
        const INSTRUX& ix = i3->instrux;
        if (!MnemonicIs(ix, "ADD") || ix.OperandsCount < 2 || !IsReg(ix.Operands[0], NDR_RSP) ||
            ix.Operands[0].Size != 8 || !IsImm(ix.Operands[1], 0x128))
        {
            return false;
        }
    }

    return i1->length + i2->length + i3->length == kSigLen;
}

bool IsProvenFunctionEntry(uintptr_t address) noexcept
{
    auto start = memory::FindFunctionStartUnwind(address);
    if (!start)
    {
        start = memory::FindFunctionStart(address);
    }
    return start.has_value() && *start == address;
}

Selection SelectFrom(size_t validatedCount) noexcept
{
    if (validatedCount == 0)
    {
        return Selection::NotFound;
    }
    if (validatedCount == 1)
    {
        return Selection::Selected;
    }
    return Selection::Ambiguous;
}

std::vector<Candidate> DiscoverValidated(const memory::ModuleRange& game) noexcept
{
    std::vector<Candidate> out;
    if (!game || game.size < kSigLen)
    {
        return out;
    }

    size_t rawMatches = 0;
    uintptr_t cursor = game.base;
    const uintptr_t end = game.end();

    while (cursor + kSigLen <= end)
    {
        const auto hit = memory::Scan(cursor, end - cursor, kSignatureText);
        if (!hit)
        {
            break;
        }
        ++rawMatches;
        cursor = *hit + 1;

        if (*hit + kSigLen > end || !RangeIsCommittedExecutable(*hit, kSigLen))
        {
            continue;
        }
        if (!ValidateSequence(*hit) || !IsProvenFunctionEntry(*hit))
        {
            continue;
        }

        Candidate c{};
        c.address = *hit;
        if (!memory::TryReadBytes(*hit, c.expected.data(), c.expected.size()) ||
            std::memcmp(c.expected.data(), kSignatureBytes.data(), kSigLen) != 0)
        {
            continue;
        }
        out.push_back(c);
    }

    Log("[CapcomPatcher][StackDestroyer] raw matches=%zu validated=%zu", rawMatches, out.size());
    return out;
}

bool CandidateStillValid(const memory::ModuleRange& game, const Candidate& candidate) noexcept
{
    if (candidate.address == 0 || candidate.address + kSigLen < candidate.address ||
        candidate.address + kSigLen > game.end())
    {
        return false;
    }
    std::array<uint8_t, 18> now{};
    if (!memory::TryReadBytes(candidate.address, now.data(), now.size()) || now != candidate.expected ||
        std::memcmp(now.data(), kSignatureBytes.data(), kSigLen) != 0)
    {
        return false;
    }
    return RangeIsCommittedExecutable(candidate.address, kSigLen) && ValidateSequence(candidate.address) &&
           IsProvenFunctionEntry(candidate.address);
}

memory::BytePatchCandidate BuildPatch(const Candidate& candidate) noexcept
{
    memory::BytePatchCandidate patch{};
    patch.address = candidate.address;
    patch.expected.assign(candidate.expected.begin(), candidate.expected.end());
    patch.writeOffset = 0;
    patch.replacement = {0xC3};
    patch.name = "stack-destroyer immediate return";
    patch.requireExecutable = true;
    patch.requireUnwindFunctionStart = true;
    return patch;
}
} // namespace detail

void Initialize(const game_profile::GameProfile& profile) noexcept
{
    if (!profile.stackDestroyer || !SupportsStackDestroyer(profile.id))
    {
        return;
    }

    std::lock_guard lock(g_mutex);
    if (g_state != State::Uninitialized)
    {
        return; // Patched / NotFound / Ambiguous / Failed are all terminal
    }

    const auto game = memory::MainModule();
    if (!game)
    {
        g_state = State::Failed;
        return;
    }

    Log("[CapcomPatcher][StackDestroyer] scan started");
    const auto validated = detail::DiscoverValidated(game);
    const auto selection = detail::SelectFrom(validated.size());
    if (selection == detail::Selection::NotFound)
    {
        g_state = State::NotFound;
        Log("[CapcomPatcher][StackDestroyer] not found; no patch applied");
        return;
    }
    if (selection == detail::Selection::Ambiguous)
    {
        g_state = State::Ambiguous;
        Log("[CapcomPatcher][StackDestroyer] multiple validated candidates (%zu); no patch applied",
            validated.size());
        return;
    }

    const auto candidate = validated.front();
    Log("[CapcomPatcher][StackDestroyer] candidate @ +0x%zx validated",
        static_cast<size_t>(candidate.address - game.base));

    // Pre-suspension uniqueness re-check (runs before threads are held).
    const auto again = detail::DiscoverValidated(game);
    if (again.size() != 1 || again.front().address != candidate.address ||
        again.front().expected != candidate.expected)
    {
        g_state = State::Failed;
        Log("[CapcomPatcher][StackDestroyer] candidate changed before suspension; skipped");
        return;
    }

    memory::ThreadSuspensionScope suspension;
    if (!suspension.Ok())
    {
        g_state = State::Failed;
        Log("[CapcomPatcher][StackDestroyer] safe suspension window unavailable; no patch");
        return;
    }

    const auto stillGame = memory::MainModule();
    if (!stillGame || stillGame.base != game.base || stillGame.size != game.size ||
        !detail::CandidateStillValid(game, candidate))
    {
        g_state = State::Failed;
        Log("[CapcomPatcher][StackDestroyer] final revalidation changed; skipped");
        return;
    }

    const auto outcome = memory::CommitPatch(detail::BuildPatch(candidate));
    switch (outcome)
    {
    case memory::PatchOutcome::Patched:
    case memory::PatchOutcome::AlreadyPatched:
        g_state = State::Patched;
        Log("[CapcomPatcher][StackDestroyer] patched @ +0x%zx -> RET",
            static_cast<size_t>(candidate.address - game.base));
        break;
    case memory::PatchOutcome::Skipped:
        g_state = State::Failed;
        Log("[CapcomPatcher][StackDestroyer] commit skipped (validation changed); no write");
        break;
    case memory::PatchOutcome::Failed:
        g_state = State::Failed;
        Log("[CapcomPatcher][StackDestroyer] commit failed (write/verify); no retry");
        break;
    }
}
} // namespace antitamper::stack_destroyer
