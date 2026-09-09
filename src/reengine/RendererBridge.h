#pragma once

// Standalone minimal RE Engine renderer bridge for TDB 82 / 83.
//
// Supplies exactly what IntegrityCheckBypass::re9_heartbeat_bypass() reads from
// the full REFramework SDK:
//   - the `via.render.Renderer` native singleton instance pointer
//   - the native `via.render.Renderer.get_RenderFrame()` function
//   - the current uint32_t render-frame value
//
// Behavioral source: praydog/REFramework @ b6baf6b406efc65e077b99cb4d9ad25b0a0a9095
//   shared/sdk/REContext.cpp          (VM context + TDB discovery)
//   shared/sdk/RETypeDB.cpp / .hpp    (type / method / string resolution)
//   shared/sdk/RETypeDefinition.cpp   (get_name / get_namespace)
//   shared/sdk/REType.cpp             (native singleton via vtable[1])
//
// No REFramework runtime dependency, no DXGI / Present / swapchain hook.

#include <cstdint>
#include <optional>

#include "../GameProfile.h"

namespace reengine
{
enum class ResolveStatus
{
    Ready,             // frameSource fully populated
    NotReadyYet,       // engine not up yet - retry later, do not disable
    UnsupportedLayout, // TDB present but not the expected version - disable session
    Invalid,           // structural validation failed - retry later
};

using GetRenderFrameFn = uint32_t (*)();

struct RendererFrameSource
{
    void* renderer{};
    GetRenderFrameFn getRenderFrame{};
    uint32_t tdbVersion{};
};

struct RendererBridgeCounters
{
    uint32_t resolveAttempts{};
    uint32_t vmContextResolved{};
    uint32_t tdbValidated{};
    uint32_t rendererTypeResolved{};
    uint32_t getRenderFrameResolved{};
    uint32_t singletonResolved{};
    uint32_t faults{};
};

// Expected modern TDB version for a selected game. std::nullopt for games that
// must never run the heartbeat layer (Monster Hunter Wilds, Unsupported).
// This is an explicit per-GameId map - never a `tdbVersion >= 82` rule.
std::optional<uint32_t> ExpectedTdbVersion(game_profile::GameId id) noexcept;

class RendererBridge
{
public:
    explicit RendererBridge(uint32_t expectedTdbVersion) noexcept : m_expectedTdbVersion(expectedTdbVersion) {}

    // Re-resolves the renderer singleton on every call (it can change across a
    // device/renderer lifecycle). The TDB, renderer type and get_RenderFrame
    // native function are resolved once and cached. All memory access is
    // SEH-guarded / fail-soft.
    ResolveStatus Resolve(RendererFrameSource& out) noexcept;

    const RendererBridgeCounters& Counters() const noexcept { return m_counters; }
    uint32_t ExpectedTdbVersion() const noexcept { return m_expectedTdbVersion; }

private:
    uint32_t m_expectedTdbVersion{};

    void** m_globalContextSlot{};    // &global VM context pointer
    uintptr_t m_tdb{};               // validated TDB header
    uint32_t m_tdbVersion{};
    uintptr_t m_rendererType{};      // RETypeDefVersion84*
    void* m_rendererTypeClr{};       // its `type` field (REType*) - vtable owner
    GetRenderFrameFn m_getRenderFrame{};
    bool m_layoutUnsupported{false};

    RendererBridgeCounters m_counters{};

    bool ResolveVmContext() noexcept;
    bool ResolveTdb() noexcept;
    bool ResolveRendererType() noexcept;
    bool ResolveGetRenderFrame() noexcept;
    void* ResolveRendererSingleton() noexcept;
};
} // namespace reengine
