#pragma once

// DD2-family direct anti-tamper / stability core.
//
// Focused extraction of praydog/REFramework
// IntegrityCheckBypass::immediate_patch_dd2() and renderer_create_blas_hook()
// (@ b6baf6b406efc65e077b99cb4d9ad25b0a0a9095):
//   - MHW-only QueryPerformance* scanner/crasher suppression
//     (profile.dd2ScannerCrasher only)
//   - renderer createBLAS corruption guard (all dd2Family profiles)
//   - DD2-family suspicious constant patch  81 ? E1 53 BD 4C  ->  0x1337BEEF
//
// Excluded (PAK / natives / RE9-family / heartbeat / stack-destroyer / a second
// DbgUi watcher) per the PR2 work order. Every sub-layer fails independently.

#include <cstdint>

#include "../GameProfile.h"

namespace antitamper::dd2_family
{
// Called from InitializeASI() for profiles with dd2Family == true. Idempotent:
// safe to call more than once; already-applied patches/hooks are no-ops.
void Initialize(const game_profile::GameProfile& profile) noexcept;

namespace detail
{
// REFramework's documented default for corruption_when_zero (s_last_non_zero_
// corruption{8}). Used until a real non-zero value is observed.
constexpr uint32_t kDefaultCorruptionValue = 8;

// Pure decision for renderer_create_blas_hook(): given the value currently in
// *corruption_when_zero and the last known non-zero value, decide what to write
// back and the new last-known-non-zero. Memory access lives in the hook.
struct CorruptionAction
{
    bool restore{false};       // write `writeValue` back to *corruption_when_zero
    uint32_t writeValue{0};
    uint32_t newLastNonZero{0};
};

// REFramework renderer_create_blas_hook(): if the value was zeroed, write the
// last known non-zero value back; then last-known-non-zero tracks the current
// value. A restore while still zero would be a no-op without the {8} default.
inline CorruptionAction DecideCorruption(uint32_t observed, uint32_t lastNonZero) noexcept
{
    if (observed == 0)
    {
        return CorruptionAction{true, lastNonZero, lastNonZero};
    }
    return CorruptionAction{false, 0, observed};
}
} // namespace detail
} // namespace antitamper::dd2_family
