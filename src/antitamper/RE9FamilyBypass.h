#pragma once

#include <cstdint>
#include <intrin.h>

#include "../GameProfile.h"

// RE9-family scheduler/job corruption defense + RE9-only slow-path discriminator.
//
// Focused extraction of praydog/REFramework
// IntegrityCheckBypass::immediate_patch_re9() (@ b6baf6b):
//   - RE9+ / BushClover suspicious constant patch  E1 53 BD 4C 75 ?  ->  0x1337BEEF
//   - JobQueue callsite mid-hooks (SafetyHook) that validate the pending job
//     function pointer, restore a cached legitimate pointer on UD2 corruption,
//     or substitute a harmless noop_job
//   - RE9-only slow-path discriminator NOP
//
// Not in scope (deferred): PE-header integrity redirection, renderer heartbeat,
// stack destroyer, module-path spoofing.

namespace antitamper::re9_family
{
// Called from InitializeASI() for profiles with re9Family == true. The slow-path
// discriminator sub-layer additionally requires re9SlowPath == true (RE9 only).
// Idempotent: safe to call more than once.
void Initialize(const game_profile::GameProfile& profile) noexcept;

namespace detail
{
// Pure decision for the JobQueue mid-hook, given the facts the hook has already
// probed. Kept here so it is directly unit-testable.
enum class JobAction
{
    LeaveUnchanged,   // func == 0 (nothing to validate)
    RememberOriginal, // func is a normal readable pointer -> cache it
    RestoreCached,    // func is UD2 and a different cached original exists
    SubstituteNoop,   // func is UD2 without a usable cache, OR func is unreadable
};

struct JobDecision
{
    JobAction action{JobAction::LeaveUnchanged};
    uintptr_t rememberValue{0}; // for RememberOriginal
    uintptr_t restoreValue{0};  // for RestoreCached (written to ctx.rax and entry+8)
};

// funcPtr   : the pending job function pointer (ctx.rax)
// probeOk   : a readable probe of *funcPtr succeeded
// isUd2     : *(uint16_t*)funcPtr == 0x0B0F  (0F 0B) -- only meaningful if probeOk
// cachedOrig: GetRememberedJobFunction(entry), 0 if none
//
// Fail-closed: an unreadable pending call target (probeOk == false) is never left
// live -- the hooked site is immediately before `call rax`, so it is substituted
// with noop_job rather than executed.
inline JobDecision DecideJob(uintptr_t funcPtr, bool probeOk, bool isUd2, uintptr_t cachedOrig) noexcept
{
    if (funcPtr == 0)
    {
        return JobDecision{JobAction::LeaveUnchanged, 0, 0};
    }
    if (!probeOk)
    {
        return JobDecision{JobAction::SubstituteNoop, 0, 0};
    }
    if (isUd2)
    {
        if (cachedOrig != 0 && cachedOrig != funcPtr)
        {
            return JobDecision{JobAction::RestoreCached, 0, cachedOrig};
        }
        return JobDecision{JobAction::SubstituteNoop, 0, 0};
    }
    return JobDecision{JobAction::RememberOriginal, funcPtr, 0};
}

// Atomic "replace exactly the corrupt value" for the persistent descriptor slot
// at `slotAddress` (entry + 8). Returns true only if this call performed the
// swap; false if the slot was not naturally aligned or already changed. Closes
// the compare/write TOCTOU: a newer legitimate pointer written concurrently is
// left untouched.
inline bool CompareExchangeSlot(uintptr_t slotAddress, uintptr_t expected, uintptr_t desired) noexcept
{
    if (slotAddress == 0 || (slotAddress & (sizeof(void*) - 1)) != 0)
    {
        return false;
    }
    auto* slot = reinterpret_cast<volatile long long*>(slotAddress);
    const long long previous = _InterlockedCompareExchange64(
        slot, static_cast<long long>(desired), static_cast<long long>(expected));
    return static_cast<uintptr_t>(previous) == expected;
}

// bddisasm memory-operand base register id (NDR_RAX..NDR_R15) that maps to a
// 64-bit GPR the mid-hook can read from SafetyHookContext. Anything else must be
// rejected (no silent RDX fallback -- PR3 hardening over upstream).
inline bool IsSupportedGpr(int ndrReg) noexcept
{
    return ndrReg >= 0 /*NDR_RAX*/ && ndrReg <= 15 /*NDR_R15*/;
}
} // namespace detail
} // namespace antitamper::re9_family
