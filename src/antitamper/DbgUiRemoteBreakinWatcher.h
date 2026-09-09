#pragma once

// Hardened DbgUiRemoteBreakin anti-debug watcher.
//
// Ported from onehoon/OptiPatcher @ b57408dc6efb7ae62229af028daef8f19caf2f66
// (OptiPatcher/CapcomAntiDebugWatcher.{cpp,h}). The low-level memory / hook /
// revalidation logic is intentionally preserved as-is; only the namespace,
// logging prefix and supported-game gating changed for this repository.
//
// Original behavioral reference: praydog/REFramework
// IntegrityCheckBypass::anti_debug_watcher(). See THIRD_PARTY_NOTICES.md.

namespace antitamper::dbg_ui
{
// Capture the DbgUiRemoteBreakin baseline, run one synchronous check, pin the
// module and start the 500 ms polling worker. Idempotent. The caller is
// responsible for verifying that the current game profile enables this layer.
bool Initialize();
} // namespace antitamper::dbg_ui
