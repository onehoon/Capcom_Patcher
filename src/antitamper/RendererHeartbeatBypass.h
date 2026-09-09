#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "../GameProfile.h"

// Standalone renderer heartbeat bypass.
//
// Focused extraction of praydog/REFramework @ b6baf6b
// IntegrityCheckBypass::re9_heartbeat_bypass() + on_frame() integration:
// discover the six renderer heartbeat/frame-like values with repeated structural
// confirmation, then continuously synchronize them to the engine's real
// via.render.Renderer.get_RenderFrame() value.
//
// Feature gate: GameProfile::heartbeat (DD2 / RE9 / PRAGMATA / Onimusha / MHS3 -
// never Monster Hunter Wilds). The renderer/frame source comes from the minimal
// standalone reengine::RendererBridge (TDB 82 / 83), not the REFramework SDK.
//
// Not in scope: DXGI / Present / swapchain hooks, PE-header redirection,
// stack-destroyer, module-path spoofing.

namespace antitamper::heartbeat
{
// Start the process-lifetime heartbeat worker for a profile with
// heartbeat == true. Returns quickly; the worker retries bridge resolution with
// bounded backoff. Idempotent: at most one worker per process.
void Initialize(const game_profile::GameProfile& profile) noexcept;

namespace detail
{
inline constexpr int kConfirmationsNeeded = 3;
inline constexpr uint32_t kMaxDistance = 1000;
inline constexpr size_t kHeartbeatCount = 6;
inline constexpr size_t kScanBegin = 0x2000;
inline constexpr size_t kScanEnd = 0x4000;

// A 4-byte-aligned candidate window inside the renderer:
//   before  = ints[-1]      (sentinel, must be 1)
//   values  = ints[0..5]    (the six heartbeats)
//   after   = ints[6]       (sentinel, must be 0)
struct ClusterSnapshot
{
    uint32_t before{};
    uint32_t values[kHeartbeatCount]{};
    uint32_t after{};
};

// REF semantics: reject unless the sentinels match and EITHER
//   normal: all six values are in range, OR
//   early:  values[0] == 0 and values[1..5] are in range
// where in-range == value > 0 && value <= frameCount &&
//                   (frameCount - value) < kMaxDistance.
bool AcceptCluster(const ClusterSnapshot& c, uint32_t frameCount) noexcept;

// True when the engine render-frame counter moved backwards - a renderer/device
// lifecycle reset. The worker fails closed (no write, reacquire) on this. A bare
// uint32 wrap is treated the same way (rare, and a reset is the safe choice).
inline bool FrameRegressed(bool haveObserved, uint32_t last, uint32_t current) noexcept
{
    return haveObserved && current < last;
}

// Candidate-intersection confirmation over renderer-relative offsets. A cluster
// is confirmed only when a single offset survives >= kConfirmationsNeeded scans.
class Confirmation
{
public:
    // Feed the accepted candidate offsets observed in one engine frame.
    void Observe(const uint32_t* offsets, size_t count) noexcept;
    // Full reset (renderer changed / confirmed sentinels lost).
    void Reset() noexcept;

    bool Confirmed() const noexcept { return m_confirmed.has_value(); }
    std::optional<uint32_t> ConfirmedOffset() const noexcept { return m_confirmed; }
    int Count() const noexcept { return m_count; }
    size_t CandidateCount() const noexcept { return m_candidateCount; }

private:
    // Every 4-byte-aligned start in the scan window can be a candidate; never
    // truncate the initial set (upstream keeps the full std::vector).
    static constexpr size_t kMaxCandidates = (kScanEnd - kScanBegin) / sizeof(uint32_t);
    uint32_t m_candidates[kMaxCandidates]{};
    size_t m_candidateCount{};
    int m_count{};
    bool m_seeded{};
    std::optional<uint32_t> m_confirmed{};
};
} // namespace detail
} // namespace antitamper::heartbeat
