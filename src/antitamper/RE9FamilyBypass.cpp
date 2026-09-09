// Compiled at /std:c++latest (SafetyHook needs std::expected / C++23) and
// without the PCH; see CapcomPatcher.vcxproj.

#include "../framework.h"

#include "RE9FamilyBypass.h"

#include "../memory/MemoryPatch.h"
#include "../memory/MemoryScan.h"
#include "../memory/ThreadSuspension.h"

#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace antitamper::re9_family
{
namespace
{
void Log(const char* message)
{
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

void Logf(const char* format, ...)
{
    char buffer[256]{};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    Log(buffer);
}

// ---- descriptor -> last legitimate job function cache -------------------

std::unordered_map<uintptr_t, uintptr_t>& JobFunctionCache()
{
    static std::unordered_map<uintptr_t, uintptr_t> cache;
    return cache;
}

std::shared_mutex& JobFunctionCacheMutex()
{
    static std::shared_mutex mutex;
    return mutex;
}

uintptr_t GetRememberedJobFunction(uintptr_t entry) noexcept
{
    if (entry == 0)
    {
        return 0;
    }
    try
    {
        std::shared_lock lock{JobFunctionCacheMutex()};
        const auto& cache = JobFunctionCache();
        const auto it = cache.find(entry);
        return it != cache.end() ? it->second : 0;
    }
    catch (...)
    {
        return 0;
    }
}

void RememberJobFunction(uintptr_t entry, uintptr_t func) noexcept
{
    if (entry == 0 || func == 0)
    {
        return;
    }
    try
    {
        if (GetRememberedJobFunction(entry) == func)
        {
            return; // shared-lock fast path: avoid exclusive-lock churn
        }
        std::unique_lock lock{JobFunctionCacheMutex()};
        JobFunctionCache()[entry] = func;
    }
    catch (...)
    {
    }
}

// ---- runtime counters (logged, not per-call) --------------------------

struct Counters
{
    std::atomic<uint64_t> ud2{0};
    std::atomic<uint64_t> restored{0};
    std::atomic<uint64_t> noop{0};
    std::atomic<uint64_t> faults{0};
};
Counters g_counters;
std::atomic<bool> g_restoreAnnounced{false};
std::atomic<bool> g_noopAnnounced{false};

// ---- harmless replacement job ----------------------------------------

void __fastcall noop_job(int64_t, int64_t)
{
}

// ---- SafetyHook context register access ------------------------------

uintptr_t GetContextRegister(const SafetyHookContext& ctx, int ndrReg) noexcept
{
    switch (ndrReg)
    {
    case NDR_RAX: return ctx.rax;
    case NDR_RCX: return ctx.rcx;
    case NDR_RDX: return ctx.rdx;
    case NDR_RBX: return ctx.rbx;
    case NDR_RSP: return ctx.rsp;
    case NDR_RBP: return ctx.rbp;
    case NDR_RSI: return ctx.rsi;
    case NDR_RDI: return ctx.rdi;
    case NDR_R8:  return ctx.r8;
    case NDR_R9:  return ctx.r9;
    case NDR_R10: return ctx.r10;
    case NDR_R11: return ctx.r11;
    case NDR_R12: return ctx.r12;
    case NDR_R13: return ctx.r13;
    case NDR_R14: return ctx.r14;
    case NDR_R15: return ctx.r15;
    default:      return 0;
    }
}

// Repair descriptor `entry + 8`, swapping ONLY the exact corrupt value for
// `value` (atomic CAS -- no compare/write TOCTOU). A newer legitimate pointer
// written by another scheduler thread is left untouched. SEH-guarded for a
// stale / unmapped entry; ctx.rax restoration still protects the current call.
void RepairJobEntry(uintptr_t entry, uintptr_t corrupt, uintptr_t value) noexcept
{
    if (entry == 0 || value == 0 || entry > UINTPTR_MAX - 8)
    {
        return;
    }
    __try
    {
        (void)detail::CompareExchangeSlot(entry + 8, corrupt, value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

// ---- mid-hook callback: one instantiation per descriptor register -----

template <int Reg>
void ValidateJobFunc(SafetyHookContext& ctx)
{
    const uintptr_t func = ctx.rax;
    if (func == 0)
    {
        return;
    }

    // One SEH-guarded 2-byte read (memory::TryReadBytes). An unreadable pending
    // call target fails closed to noop_job -- it is never left live for the
    // `call rax` right after this callsite.
    uint16_t head = 0;
    const bool probeOk = memory::TryReadBytes(func, &head, sizeof(head));
    if (!probeOk)
    {
        g_counters.faults.fetch_add(1);
    }

    const uintptr_t entry = GetContextRegister(ctx, Reg);
    const bool isUd2 = probeOk && head == 0x0B0F; // 0F 0B
    if (isUd2)
    {
        g_counters.ud2.fetch_add(1);
    }
    const uintptr_t cached = entry != 0 ? GetRememberedJobFunction(entry) : 0;
    const auto decision = detail::DecideJob(func, probeOk, isUd2, cached);

    switch (decision.action)
    {
    case detail::JobAction::LeaveUnchanged:
        break;
    case detail::JobAction::RememberOriginal:
        if (entry != 0)
        {
            RememberJobFunction(entry, decision.rememberValue);
        }
        break;
    case detail::JobAction::RestoreCached:
        ctx.rax = decision.restoreValue;
        RepairJobEntry(entry, func, decision.restoreValue);
        g_counters.restored.fetch_add(1);
        if (!g_restoreAnnounced.exchange(true))
        {
            Log("[CapcomPatcher][RE9Family][JobGuard] restored corrupted UD2 job pointer from cache");
        }
        break;
    case detail::JobAction::SubstituteNoop:
        ctx.rax = reinterpret_cast<uintptr_t>(&noop_job);
        g_counters.noop.fetch_add(1);
        if (!g_noopAnnounced.exchange(true))
        {
            Log("[CapcomPatcher][RE9Family][JobGuard] substituted noop_job for an untrusted job pointer");
        }
        break;
    }
}

template <int Reg>
constexpr safetyhook::MidHookFn ThunkFor() noexcept
{
    return &ValidateJobFunc<Reg>;
}

constexpr std::array<safetyhook::MidHookFn, 16> kThunks{
    ThunkFor<0>(), ThunkFor<1>(), ThunkFor<2>(), ThunkFor<3>(), ThunkFor<4>(), ThunkFor<5>(),
    ThunkFor<6>(), ThunkFor<7>(), ThunkFor<8>(), ThunkFor<9>(), ThunkFor<10>(), ThunkFor<11>(),
    ThunkFor<12>(), ThunkFor<13>(), ThunkFor<14>(), ThunkFor<15>()};

struct JobCallsiteHook
{
    uintptr_t address{};
    int descriptorReg{};
    safetyhook::MidHook hook;
};

std::vector<JobCallsiteHook>& JobCallsiteHooks()
{
    static std::vector<JobCallsiteHook> hooks;
    return hooks;
}

// ---- raw-patch commit (same fail-closed policy as PR2) ----------------

void CommitRawPatches(std::vector<memory::BytePatchCandidate>& candidates)
{
    if (candidates.empty())
    {
        return;
    }

    memory::ThreadSuspensionScope suspension;
    if (!suspension.Ok())
    {
        Log("[CapcomPatcher][RE9Family] no safe raw-patch window; raw byte writes skipped");
        return;
    }
    Logf("[CapcomPatcher][RE9Family] raw-patch window: %zu thread(s) suspended", suspension.SuspendedCount());

    for (const auto& candidate : candidates)
    {
        switch (memory::CommitPatch(candidate))
        {
        case memory::PatchOutcome::Patched:
            Logf("[CapcomPatcher][RE9Family] patched: %s", candidate.name);
            break;
        case memory::PatchOutcome::AlreadyPatched:
            Logf("[CapcomPatcher][RE9Family] already patched: %s", candidate.name);
            break;
        case memory::PatchOutcome::Skipped:
            Logf("[CapcomPatcher][RE9Family] skipped (validation mismatch): %s", candidate.name);
            break;
        case memory::PatchOutcome::Failed:
            Logf("[CapcomPatcher][RE9Family] FAILED: %s", candidate.name);
            break;
        }
    }
}

// ---- RE9+ / BushClover suspicious constants --------------------------

void DiscoverRe9Constants(const memory::ModuleRange& game, std::vector<memory::BytePatchCandidate>& out)
{
    Log("[CapcomPatcher][RE9Family][Constants] scan started");

    const uintptr_t end = game.end();
    size_t found = 0;
    for (auto ref = memory::Scan(game, "E1 53 BD 4C 75 ?"); ref.has_value();)
    {
        uint8_t local[6]{};
        if (memory::TryReadBytes(*ref, local, sizeof(local)) && local[0] == 0xE1 && local[1] == 0x53 &&
            local[2] == 0xBD && local[3] == 0x4C && local[4] == 0x75)
        {
            memory::BytePatchCandidate c{};
            c.address = *ref;
            c.expected.assign(local, local + sizeof(local));
            c.writeOffset = 0;
            c.replacement = {0xEF, 0xBE, 0x37, 0x13}; // 0x1337BEEF, little-endian
            c.name = "re9 sus_constant / BushClover";
            c.requireExecutable = true;
            out.push_back(std::move(c));
            ++found;
        }

        const uintptr_t next = *ref + 1;
        if (next + 0x1000 >= end)
        {
            break;
        }
        ref = memory::Scan(next, end - next - 0x1000, "E1 53 BD 4C 75 ?");
    }

    Logf("[CapcomPatcher][RE9Family][Constants] %zu candidate(s) located", found);
}

// ---- RE9-only slow-path discriminator -------------------------------

bool CategoryIsPathTerminator(const INSTRUX& ix) noexcept
{
    if (ix.Category == ND_CAT_RET || ix.Category == ND_CAT_INTERRUPT)
    {
        return true;
    }
    return ix.BranchInfo.IsBranch && ix.Category != ND_CAT_CALL;
}

void DiscoverRe9SlowPath(const memory::ModuleRange& game, std::vector<memory::BytePatchCandidate>& out)
{
    Log("[CapcomPatcher][RE9Family][SlowPath] scan started");

    // xor rcx,rsp ; call __security_check_cookie ; vmovaps xmm6,[rsp+0x1D0] ; ... ; add rsp,0x1E8
    // The *[5] tokens are kananlib segment globs (<=5 byte gap), NOT five wildcards.
    static constexpr const char* kEpilogueSig =
        "48 31 E1 E8 ? ? ? ? *[5] C5 F8 28 B4 24 D0 01 00 00 *[5] 48 81 C4 E8 01 00 00";

    const uintptr_t end = game.end();
    std::optional<uintptr_t> selector;
    size_t selectorLen = 0;

    for (auto ref = memory::Scan(game, kEpilogueSig); ref.has_value();)
    {
        const uintptr_t candidate = *ref;

        // Skip the un-obfuscated first candidate: it has a run of POPs after it.
        size_t popCount = 0;
        memory::LinearDecode(candidate, 100, [&](memory::LinearDecodeStep& step) {
            if (step.insn.instrux.Category == ND_CAT_POP)
            {
                ++popCount;
            }
            if (CategoryIsPathTerminator(step.insn.instrux))
            {
                step.stop = true;
            }
        });

        if (popCount <= 2)
        {
            std::optional<uintptr_t> condAddr;
            size_t condLen = 0;
            bool hasDispatchTable = false;
            bool alreadyInDispatchBlock = false;

            memory::LinearDecode(candidate, 0x150, [&](memory::LinearDecodeStep& step) {
                const INSTRUX& ix = step.insn.instrux;

                // Old / variant: the CMOVcc itself is the dispatch selector.
                if (ix.Instruction == ND_INS_CMOVcc)
                {
                    condAddr = step.insn.address;
                    condLen = step.insn.length;
                    hasDispatchTable = true;
                    step.stop = true;
                    return;
                }

                // New: SETcc sets an index, then MOV rXX, [base + index*8] loads
                // from the 2-entry dispatch table.
                if (ix.Instruction == ND_INS_SETcc)
                {
                    condAddr = step.insn.address;
                    condLen = step.insn.length;
                }
                if (condAddr.has_value() && ix.Instruction == ND_INS_MOV)
                {
                    for (uint8_t i = 0; i < ix.OperandsCount; ++i)
                    {
                        const auto& op = ix.Operands[i];
                        if (op.Type == ND_OP_MEM && op.Info.Memory.HasIndex && op.Info.Memory.HasBase &&
                            op.Info.Memory.Scale == 8)
                        {
                            hasDispatchTable = true;
                            step.stop = true;
                            return;
                        }
                    }
                }

                if (ix.Category == ND_CAT_RET)
                {
                    if (alreadyInDispatchBlock)
                    {
                        step.stop = true;
                        return;
                    }
                    alreadyInDispatchBlock = true;
                    step.next += 1; // skip the ret + garbage byte into the next block
                }
            });

            if (condAddr.has_value() && hasDispatchTable)
            {
                selector = condAddr;
                selectorLen = condLen;
                Logf("[CapcomPatcher][RE9Family][SlowPath] candidate @ +0x%llX (pop_count=%zu)",
                     static_cast<unsigned long long>(candidate - game.base), popCount);
                break;
            }
        }
        else
        {
            Logf("[CapcomPatcher][RE9Family][SlowPath] skipping candidate @ +0x%llX (pop_count=%zu)",
                 static_cast<unsigned long long>(candidate - game.base), popCount);
        }

        const uintptr_t nextFrom = candidate + 1;
        if (nextFrom + 0x1000 >= end)
        {
            break;
        }
        ref = memory::Scan(nextFrom, end - nextFrom - 0x1000, kEpilogueSig);
    }

    if (!selector || selectorLen == 0)
    {
        Log("[CapcomPatcher][RE9Family][SlowPath] not found; continuing (JobGuard still installs)");
        return;
    }

    uint8_t original[16]{};
    if (selectorLen > sizeof(original) || !memory::TryReadBytes(*selector, original, selectorLen))
    {
        Log("[CapcomPatcher][RE9Family][SlowPath] could not capture selector bytes; skipped");
        return;
    }

    memory::BytePatchCandidate c{};
    c.address = *selector;
    c.expected.assign(original, original + selectorLen);
    c.writeOffset = 0;
    c.replacement.assign(selectorLen, 0x90); // NOP the selector -> default (clean) path
    c.name = "re9 slow-path discriminator";
    c.requireExecutable = true;
    out.push_back(std::move(c));
}

// ---- JobQueue callsite mid-hooks -----------------------------------

void InstallJobCallsiteGuards(const memory::ModuleRange& game)
{
    Log("[CapcomPatcher][RE9Family][JobGuard] scan started");

    static constexpr std::array<const char*, 2> kCallsitePatterns{
        "? 8b ? 08 ? 8b ? 10 ? 8b ? 18 48 85 c9 0f 84 ? ? ? ? ff d0", // RE9 PC, MHS3
        "? 8b ? 08 ? 8b ? 10 ? 8b ? 18 48 85 c9 74 ? ff d0",          // rare path, both
    };

    auto& hooks = JobCallsiteHooks();
    size_t matched = 0;
    size_t accepted = 0;
    size_t installed = 0;

    for (const char* pattern : kCallsitePatterns)
    {
        uintptr_t from = game.base;
        while (from < game.end())
        {
            const auto ref = memory::Scan(from, game.end() - from, pattern);
            if (!ref)
            {
                break;
            }
            from = *ref + 1;
            ++matched;

            const auto decoded = memory::DecodeOne(*ref);
            if (!decoded || decoded->length != 4 || decoded->instrux.OperandsCount < 2 ||
                decoded->instrux.Operands[1].Type != ND_OP_MEM ||
                !decoded->instrux.Operands[1].Info.Memory.HasBase)
            {
                Logf("[CapcomPatcher][RE9Family][JobGuard] callsite @ +0x%llX failed semantic validation; skipped",
                     static_cast<unsigned long long>(*ref - game.base));
                continue;
            }

            const int reg = decoded->instrux.Operands[1].Info.Memory.Base;
            if (!detail::IsSupportedGpr(reg))
            {
                Logf("[CapcomPatcher][RE9Family][JobGuard] callsite @ +0x%llX unknown descriptor register; skipped",
                     static_cast<unsigned long long>(*ref - game.base));
                continue;
            }
            ++accepted;

            const uintptr_t hookAddr = *ref + 4;
            if (std::any_of(hooks.begin(), hooks.end(),
                            [&](const JobCallsiteHook& h) { return h.address == hookAddr; }))
            {
                continue; // idempotent: one live mid-hook per address
            }

            auto mid = safetyhook::create_mid(reinterpret_cast<void*>(hookAddr), kThunks[static_cast<size_t>(reg)]);
            if (!mid)
            {
                Logf("[CapcomPatcher][RE9Family][JobGuard] mid-hook creation failed @ +0x%llX; kept existing hooks",
                     static_cast<unsigned long long>(hookAddr - game.base));
                continue;
            }

            static constexpr const char* kRegNames[16] = {"RAX", "RCX", "RDX", "RBX", "RSP", "RBP",
                                                          "RSI", "RDI", "R8",  "R9",  "R10", "R11",
                                                          "R12", "R13", "R14", "R15"};
            Logf("[CapcomPatcher][RE9Family][JobGuard] callsite @ +0x%llX, entry-reg=%s",
                 static_cast<unsigned long long>(*ref - game.base), kRegNames[reg]);

            hooks.push_back({hookAddr, reg, std::move(mid)});
            ++installed;
        }
    }

    Logf("[CapcomPatcher][RE9Family][JobGuard] installed %zu callsite hook(s) (matched=%zu, accepted=%zu)",
         installed, matched, accepted);
}
} // namespace

void Initialize(const game_profile::GameProfile& profile) noexcept
{
    if (!profile.re9Family)
    {
        return;
    }

    const memory::ModuleRange game = memory::MainModule();
    if (!game)
    {
        Log("[CapcomPatcher][RE9Family] main module unavailable; layer skipped");
        return;
    }

    Log("[CapcomPatcher][RE9Family] scan started");

    std::vector<memory::BytePatchCandidate> rawPatches;
    DiscoverRe9Constants(game, rawPatches);

    if (profile.re9SlowPath)
    {
        DiscoverRe9SlowPath(game, rawPatches);
    }
    else
    {
        Log("[CapcomPatcher][RE9Family][SlowPath] skipped by profile");
    }

    CommitRawPatches(rawPatches);

    // Backup even when the slow-path patch succeeded (upstream: "hook anyways").
    InstallJobCallsiteGuards(game);

    Log("[CapcomPatcher][RE9Family] scan complete");
}
} // namespace antitamper::re9_family
