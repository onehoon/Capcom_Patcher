// dllmain.cpp : DLL entry point and OptiScaler ASI exports for Capcom Patcher.

#include "pch.h"

#include "GameProfile.h"
#include "antitamper/DD2FamilyBypass.h"
#include "antitamper/DbgUiRemoteBreakinWatcher.h"
#include "antitamper/RE9FamilyBypass.h"
#include "antitamper/RendererHeartbeatBypass.h"
#include "antitamper/RuntimeGuards.h"

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

// OptiScaler calls this after loading the .asi module. It is the post-LoadLibrary
// dispatcher. Each anti-tamper component owns its own idempotency, so this entry
// point stays thin and safe to call more than once.
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
                "[CapcomPatcher] detected %ls (dbgUiWatcher=%d dd2Family=%d dd2ScannerCrasher=%d "
                "re9Family=%d re9SlowPath=%d heartbeat=%d)",
                profile.canonicalName, profile.dbgUiWatcher, profile.dd2Family, profile.dd2ScannerCrasher,
                profile.re9Family, profile.re9SlowPath, profile.heartbeat);
    Log(message);

    // Common runtime guard (VirtualProtect / NtProtectVirtualMemory integrity)
    // before the game-memory-touching layers, matching REFramework's order.
    antitamper::runtime_guards::PostLoadInitialize();

    // DD2-family direct anti-tamper core.
    if (profile.dd2Family)
    {
        antitamper::dd2_family::Initialize(profile);
    }

    // RE9-family scheduler/job corruption defense (+ RE9-only slow-path).
    if (profile.re9Family)
    {
        antitamper::re9_family::Initialize(profile);
    }

    // Standalone renderer heartbeat synchronization (TDB82/83 five-game set;
    // never MHW). Starts a single process-lifetime worker; no swapchain hook.
    if (profile.heartbeat)
    {
        antitamper::heartbeat::Initialize(profile);
    }

    // DbgUiRemoteBreakin watcher last.
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
        // Supported games only: install the early guards (pristine syscall
        // capture, VEH guard, RtlExitUserProcess guard) here to match
        // REFramework's relative timing. No persistent worker is started here.
        if (game_profile::ResolveCurrentProcessEarly() != game_profile::GameId::Unsupported)
        {
            antitamper::runtime_guards::EarlyInitialize(hModule);
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
