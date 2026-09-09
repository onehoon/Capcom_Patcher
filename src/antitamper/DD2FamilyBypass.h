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

#include "../GameProfile.h"

namespace antitamper::dd2_family
{
// Called from InitializeASI() for profiles with dd2Family == true. Idempotent:
// safe to call more than once; already-applied patches/hooks are no-ops.
void Initialize(const game_profile::GameProfile& profile) noexcept;
} // namespace antitamper::dd2_family
