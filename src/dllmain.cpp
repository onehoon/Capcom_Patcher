// dllmain.cpp : DLL entry point and OptiScaler ASI exports for Capcom Patcher.

#include "pch.h"

#include "GameProfile.h"
#include "antitamper/DbgUiRemoteBreakinWatcher.h"

#include <cstdio>

namespace
{
void Log(const char* message)
{
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}
} // namespace

// OptiScaler treats a `true` PatchResult() as "game-side DLSS/vendor patching
// succeeded" and can change its spoofing behavior. Capcom Patcher only performs
// anti-tamper compatibility work, so this must always report false.
extern "C" __declspec(dllexport) bool PatchResult()
{
    return false;
}

// OptiScaler calls this after loading the .asi module. It is the PR0 activation
// point. Each anti-tamper component owns its own idempotency
// (antitamper::dbg_ui::Initialize() serializes on a mutex and no-ops once the
// watcher is running), so this entry point stays a thin dispatcher.
extern "C" __declspec(dllexport) void InitializeASI()
{
    const auto& profile = game_profile::Current();
    if (profile.id == game_profile::GameId::Unsupported)
    {
        Log("[CapcomPatcher] unsupported executable; no hooks installed");
        return;
    }

    char message[256]{};
    _snprintf_s(message, sizeof(message), _TRUNCATE,
                "[CapcomPatcher] detected %ls (dbgUiWatcher=%d dd2Family=%d re9Family=%d "
                "re9SlowPath=%d heartbeat=%d)",
                profile.canonicalName, profile.dbgUiWatcher, profile.dd2Family, profile.re9Family,
                profile.re9SlowPath, profile.heartbeat);
    Log(message);

    // PR0 only executes the DbgUiRemoteBreakin layer. The other capability flags
    // are declarative scaffolding for later PRs.
    if (profile.dbgUiWatcher)
    {
        if (antitamper::dbg_ui::Initialize())
        {
            Log("[CapcomPatcher][DbgUi] watcher active");
        }
        else
        {
            Log("[CapcomPatcher][DbgUi] watcher failed to initialize");
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
