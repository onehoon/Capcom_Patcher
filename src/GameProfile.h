#pragma once

#include <string>
#include <string_view>

namespace game_profile
{
enum class GameId
{
    Unsupported,
    MonsterHunterWilds,
    DragonsDogma2,
    ResidentEvilRequiem,
    Pragmata,
    OnimushaWots,
    MonsterHunterStories3,
};

// Capability flags for the anti-tamper parity layers. PR0 consumes
// `dbgUiWatcher`; PR2 consumes `dd2Family` / `dd2ScannerCrasher`. The rest are
// declarative scaffolding for later PRs and must not trigger any patching yet.
struct GameProfile
{
    GameId id{GameId::Unsupported};
    const wchar_t* canonicalName{L"Unsupported"};

    bool dbgUiWatcher{false};
    bool dd2Family{false};
    // MHW-only in current REFramework: the QueryPerformance* scanner/crasher
    // sub-path of immediate_patch_dd2(). Never TDB-derived.
    bool dd2ScannerCrasher{false};
    bool re9Family{false};
    bool re9SlowPath{false};
    bool heartbeat{false};
};

// Resolve a profile from an executable file name (e.g. L"DD2.exe").
// Matching is an explicit, case-insensitive allowlist. Unknown names resolve to
// GameId::Unsupported. Intended for the runtime path and for unit checks.
GameProfile Resolve(std::wstring_view executableFileName);

// Loader-lock-safe resolution for use from DllMain: no std::filesystem, no heap
// allocation, ASCII case fold. Shares the one canonical table with Resolve().
GameId ResolveCurrentProcessEarly() noexcept;

// Profile for the current process, resolved once from the host executable name.
const GameProfile& Current();
} // namespace game_profile
