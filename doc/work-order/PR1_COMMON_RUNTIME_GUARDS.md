# PR1 Work Order — Port REFramework Common Runtime Anti-Tamper Guards

**Repository:** `onehoon/Capcom_Patcher`  
**Base:** current `main` after merged PR0 (`c0298310053d6268c4d7bcbbdc41a5438eb4a43b` at the time this work order was written)  
**Target branch:** new feature branch from latest `main`  
**PR type:** focused implementation / anti-tamper parity  
**Scope:** common early/runtime guards only  
**Do not merge automatically. Leave the PR open for review.**

---

## 1. Objective

PR0 established the standalone Capcom Patcher ASI, explicit six-game profiles, and the hardened `DbgUiRemoteBreakin` watcher.

PR1 adds the next REFramework parity layer: the **common runtime guards that REFramework installs before the game-specific DD2/RE9 anti-tamper patches run**.

Port these four behaviors from the pinned REFramework implementation:

1. pristine `NtProtectVirtualMemory` capture,
2. `VirtualProtect` guard / `NtProtectVirtualMemory` integrity restore,
3. `AddVectoredExceptionHandler` registration guard,
4. `RtlExitUserProcess` guard.

These guards apply to **all six explicitly supported Capcom Patcher games**:

- Monster Hunter Wilds
- Dragon's Dogma 2
- Resident Evil Requiem
- PRAGMATA
- Onimusha: Way of the Sword
- Monster Hunter Stories 3: Twisted Reflection

Do not add support for any other executable.

This PR is **not** the DD2-family patch PR and is **not** the RE9-family/heartbeat PR.

---

## 2. Why this is the next PR

Current REFramework installs several protection layers before its game-specific anti-tamper work.

In `Main.cpp`, after `GameIdentity::initialize()`, REFramework calls the following very early:

```cpp
IntegrityCheckBypass::setup_pristine_syscall();
IntegrityCheckBypass::hook_add_vectored_exception_handler();
IntegrityCheckBypass::hook_rtl_exit_user_process();
```

Then, once the framework object is being initialized outside the minimal DllMain bootstrap, it calls:

```cpp
IntegrityCheckBypass::fix_virtual_protect();
```

Reference:

- REFramework `Main.cpp` at pinned analysis commit:  
  `https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/Main.cpp`
- REFramework `IntegrityCheckBypass.cpp`:  
  `https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.cpp`

Capcom Patcher should preserve this **relative lifecycle** before adding DD2/RE9-family patches in later PRs.

---

## 3. Source reuse policy — port, do not reinvent

This project is intentionally reusing the years of REFramework anti-tamper work.

Do **not** clean-room rewrite the four mechanisms unless a REFramework-only dependency makes a direct port impossible.

Use the pinned REFramework source as the behavioral source of truth:

- Repository: `praydog/REFramework`
- Commit: `b6baf6b406efc65e077b99cb4d9ad25b0a0a9095`
- Main source:  
  `https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.cpp`
- Header:  
  `https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.hpp`

Relevant upstream functions:

```text
IntegrityCheckBypass::setup_pristine_syscall()
IntegrityCheckBypass::fix_virtual_protect()
IntegrityCheckBypass::virtual_protect_impl()
IntegrityCheckBypass::virtual_protect_hook()
IntegrityCheckBypass::hook_add_vectored_exception_handler()
IntegrityCheckBypass::add_vectored_exception_handler_hook()
IntegrityCheckBypass::hook_rtl_exit_user_process()
IntegrityCheckBypass::rtl_exit_user_process_hook()
```

The new code should be recognizable as a focused extraction/adaptation of these functions rather than a new anti-tamper design.

### Important

REFramework-specific infrastructure must be replaced, not dragged wholesale into this repository:

- no `sdk::GameIdentity`,
- no `g_framework`,
- no REFramework Mod base class,
- no spdlog dependency solely for this port,
- no general REFramework `utility` tree,
- no overlay/runtime/SDK dependencies.

Use existing Capcom Patcher `GameProfile` for support gating and the current `OutputDebugStringA` logging style.

---

## 4. Hook implementation — reuse REFramework's MinHook path

For these early guards, current REFramework does **not** use its SafetyHook-backed `FunctionHook` class. It uses `FunctionHookMinHook`.

Pinned sources:

- `shared/utility/FunctionHookMinHook.hpp`  
  `https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/shared/utility/FunctionHookMinHook.hpp`
- `shared/utility/FunctionHookMinHook.cpp`  
  `https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/shared/utility/FunctionHookMinHook.cpp`

REFramework uses the following MinHook submodule revision at the pinned source commit:

```text
TsudaKageyu/minhook
98b74f1fc12d00313d91f10450e5b3e0036175e3
```

Reference:

`https://github.com/TsudaKageyu/minhook/tree/98b74f1fc12d00313d91f10450e5b3e0036175e3`

### 4.1 Dependency integration

Prefer a pinned git submodule:

```text
third_party/minhook
```

pointing to exactly:

```text
https://github.com/TsudaKageyu/minhook.git
98b74f1fc12d00313d91f10450e5b3e0036175e3
```

Then compile the required x64 MinHook C sources directly as part of `CapcomPatcher.vcxproj`.

Do not add vcpkg/NuGet/Conan just for MinHook.

Do not implement a custom x64 trampoline/detour engine in this PR.

If a submodule causes a concrete repository/build problem, vendoring the exact pinned MinHook files is acceptable, but the PR body must explain the deviation and preserve the upstream license.

### 4.2 Minimal wrapper

Port/adapt the small behavior of `FunctionHookMinHook` rather than importing REFramework's `Address.hpp` and unrelated utility stack.

A Capcom Patcher-local wrapper is preferred, for example:

```text
src/hooking/MinHookInlineHook.h
src/hooking/MinHookInlineHook.cpp
```

It only needs to own:

```cpp
class MinHookInlineHook
{
public:
    MinHookInlineHook(void* target, void* destination);
    ~MinHookInlineHook();

    bool Enable();
    bool Remove();

    template <typename T>
    T Original() const
    {
        return reinterpret_cast<T>(m_original);
    }

    bool IsValid() const;

private:
    void* m_target{};
    void* m_destination{};
    void* m_original{};
};
```

Preserve the important upstream behavior:

- initialize MinHook once,
- create hook before enabling it,
- retain the trampoline/original function pointer,
- fail without enabling if `MH_CreateHook` fails,
- fail cleanly if `MH_EnableHook` fails,
- no silent partial success.

Do not introduce unhook/reload semantics merely because MinHook supports them. Capcom Patcher is expected to remain loaded for process lifetime once active.

---

## 5. Licensing changes required in PR1

The root project may remain MIT.

MinHook is not MIT; the pinned revision uses a BSD-style license. This does **not** prevent Capcom Patcher from remaining MIT, but its notice must be preserved.

Required:

- update `THIRD_PARTY_NOTICES.md`,
- identify `TsudaKageyu/MinHook`,
- identify pinned revision `98b74f1fc12d00313d91f10450e5b3e0036175e3`,
- reproduce/preserve MinHook's applicable license notice,
- if using a git submodule, keep its upstream `LICENSE.txt` intact.

Do not replace MinHook's license text with the Capcom Patcher MIT license.

---

## 6. Proposed PR1 module structure

Suggested new files:

```text
src/
├─ hooking/
│  ├─ MinHookInlineHook.h
│  └─ MinHookInlineHook.cpp
│
└─ antitamper/
   ├─ RuntimeGuards.h
   └─ RuntimeGuards.cpp
```

The exact names may differ, but keep the four common mechanisms together for this PR.

Do not create DD2/RE9/heartbeat source files yet.

Suggested public API:

```cpp
namespace antitamper::runtime_guards
{
    // Loader-lock phase. Called only for one of the six supported games.
    void EarlyInitialize(HMODULE selfModule) noexcept;

    // Called from InitializeASI() after LoadLibrary/DllMain has completed.
    void PostLoadInitialize() noexcept;
}
```

Individual internal functions may be:

```cpp
bool SetupPristineNtProtectVirtualMemory();
bool InstallVectoredExceptionHandlerGuard();
bool InstallRtlExitUserProcessGuard();
bool InstallVirtualProtectGuard();
```

Each operation should be idempotent or protected against duplicate installation.

---

## 7. Loader-lock-safe supported-game detection

PR0's normal `game_profile::Current()` uses `Util::ExePath()` / `std::filesystem`. PR1 introduces intentional early work in `DllMain`, so do not unnecessarily depend on filesystem/static heap machinery just to decide whether the host is supported.

Refactor the executable-name comparison so it can be used from a small stack-buffer path.

Recommended shape:

```cpp
namespace game_profile
{
    GameProfile Resolve(std::wstring_view executableFileName);

    // Must not use std::filesystem and should avoid heap allocation.
    GameId ResolveCurrentProcessEarly() noexcept;
}
```

Recommended implementation strategy:

```cpp
GameId ResolveCurrentProcessEarly() noexcept
{
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    if (length == 0 || length >= ARRAYSIZE(path))
        return GameId::Unsupported;

    const wchar_t* filename = path;
    for (const wchar_t* p = path; *p != L'\0'; ++p)
    {
        if (*p == L'\\' || *p == L'/')
            filename = p + 1;
    }

    return ResolveIdNoAlloc(filename);
}
```

Avoid maintaining a second independent six-game list. The early and normal resolution paths must share one canonical table/comparison function so they cannot drift.

ASCII executable names are sufficient for the current six-game list; an allocation-free ASCII case fold is acceptable.

### Reject condition

Do not install any early hook in an unsupported process.

---

## 8. DllMain lifecycle — match REFramework's relative timing

Current `dllmain.cpp` only calls `DisableThreadLibraryCalls`.

For supported processes only, PR1 should add the common early guards in `DLL_PROCESS_ATTACH`.

Conceptually:

```cpp
BOOL APIENTRY DllMain(HMODULE selfModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(selfModule);

        if (game_profile::ResolveCurrentProcessEarly() != game_profile::GameId::Unsupported)
        {
            antitamper::runtime_guards::EarlyInitialize(selfModule);
        }
    }

    return TRUE;
}
```

`EarlyInitialize()` should preserve REFramework's relative order:

```text
1. setup/capture pristine NtProtectVirtualMemory
2. install AddVectoredExceptionHandler guard
3. install RtlExitUserProcess guard
```

This matches current REFramework `Main.cpp`.

### Important

This project is an ASI loaded by OptiScaler, so its DllMain cannot run earlier than OptiScaler loads the ASI. That timing difference from REFramework's proxy-DLL startup is inherent to the selected architecture.

Do not pretend PR1 makes Capcom Patcher load as early as REFramework. Log initialization failures and preserve fail-closed behavior where applicable.

Do not start any new persistent worker thread from DllMain.

---

## 9. InitializeASI lifecycle

`InitializeASI()` remains the post-LoadLibrary dispatcher.

For a supported game, order the runtime guard before the existing DbgUi watcher:

```cpp
extern "C" __declspec(dllexport) void InitializeASI()
{
    const auto& profile = game_profile::Current();
    if (profile.id == game_profile::GameId::Unsupported)
        return;

    antitamper::runtime_guards::PostLoadInitialize();

    if (profile.dbgUiWatcher)
        antitamper::dbg_ui::Initialize();
}
```

`PostLoadInitialize()` installs the `VirtualProtect` guard.

Why this order:

- REFramework captures pristine `NtProtectVirtualMemory` before normal framework startup,
- REFramework later runs `fix_virtual_protect()` before its game-specific anti-tamper patches,
- Capcom Patcher should establish the same primitive before later DD2/RE9-family PRs start changing game memory.

Do not move the existing DbgUi persistent watcher into DllMain.

`PatchResult()` must remain `false`.

---

# 10. Guard A — pristine `NtProtectVirtualMemory` capture

Port `IntegrityCheckBypass::setup_pristine_syscall()` from pinned REFramework.

Upstream behavior to preserve:

1. locate `ntdll.dll`,
2. resolve `NtProtectVirtualMemory`,
3. if the entry begins with an `E9` redirect, resolve the rel32 target as REFramework does,
4. retain the selected live/original entry pointer as the callable `NtProtectVirtualMemory` target,
5. make the selected entry region writable/executable,
6. allocate a 256-byte private executable buffer,
7. copy 256 bytes from the selected `NtProtectVirtualMemory` entry into that private buffer,
8. keep the copy for later integrity comparison/restoration.

Pinned source is around `setup_pristine_syscall()` in:

`https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.cpp`

### Local types

Do not import the entire REFramework NT utility layer. Define the minimal function type locally, e.g.:

```cpp
using NtProtectVirtualMemoryFn = NTSTATUS (NTAPI*)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);
```

Provide an explicit local `NtSuccess` helper if needed instead of depending on an unrelated REFramework macro:

```cpp
constexpr bool NtSuccess(NTSTATUS status) noexcept
{
    return status >= 0;
}
```

### Safety / parity rule

Do not silently substitute the DbgUi watcher's 32-byte live-baseline policy here. This is a separate upstream mechanism with a separate 256-byte callable copy and a 32-byte integrity comparison/restore path.

Do not merge the two mechanisms just because both interact with ntdll.

### Failure behavior

If ntdll resolution, symbol resolution, allocation, or copy fails:

- log the failure,
- leave the guard inactive,
- do not crash the process,
- do not fabricate a baseline.

---

# 11. Guard B — `VirtualProtect` / `NtProtectVirtualMemory` integrity guard

Port these upstream functions together:

```text
fix_virtual_protect()
virtual_protect_impl()
virtual_protect_hook()
```

REFramework creates the `VirtualProtect` hook using `FunctionHookMinHook`.

### 11.1 `virtual_protect_impl()` behavior

Preserve the upstream intent: call the saved `NtProtectVirtualMemory` implementation directly rather than recursively calling hooked `VirtualProtect`.

The implementation must:

- operate on `GetCurrentProcess()`,
- pass the mutable base-address and size variables expected by `NtProtectVirtualMemory`,
- return `TRUE` for NT-success results,
- preserve the upstream `STATUS_INVALID_PAGE_PROTECTION (0xC0000045)` handling,
- attempt `RtlFlushSecureMemoryCache` then retry when that status occurs,
- log failure without recursively using the hooked path.

### 11.2 Integrity verification

On `VirtualProtect` entry, preserve the REFramework check:

```cpp
memcmp(originalNtProtectVirtualMemory,
       pristineNtProtectVirtualMemory,
       32) != 0
```

If modified, attempt to restore the first 32 bytes.

Preserve the upstream two-stage behavior:

1. try direct restoration first,
2. if direct restoration fails, use the direct `virtual_protect_impl()` path to make the surrounding region writable, restore the 32 bytes, then restore protection.

Do not call the hooked `VirtualProtect` recursively while trying to repair `NtProtectVirtualMemory`.

### 11.3 Instruction cache

REFramework's pinned implementation does not explicitly flush the instruction cache in this restore path.

Capcom Patcher may add:

```cpp
FlushInstructionCache(GetCurrentProcess(), originalNtProtectVirtualMemory, 32);
```

after a successful executable-code restore because this is a safety hardening that does not change the intended result.

If added, document it in the PR body as a deliberate hardening over upstream.

Do not make larger semantic changes in the same PR.

---

# 12. Guard C — `AddVectoredExceptionHandler`

Port REFramework's early VEH registration guard.

Upstream behavior:

1. hook `AddVectoredExceptionHandler` with MinHook,
2. track whether VEH registration has been called,
3. while the global `veh_allowed` state is false, inspect the caller return address,
4. allow selected known-safe module callers,
5. block the first unapproved registration,
6. after that blocked registration, transition to allowing subsequent VEH registrations,
7. return a non-null fake handle (`VectoredHandler`) to the blocked caller, matching upstream behavior.

The key pinned source is:

```text
hook_add_vectored_exception_handler()
add_vectored_exception_handler_hook()
```

in the pinned `IntegrityCheckBypass.cpp`.

### 12.1 Upstream allowed callers

Current REFramework allows early callers when the containing module path contains:

```text
vehdebug
coreclr
dinput8
```

or when the caller module is the REFramework module itself.

### 12.2 Capcom Patcher adaptation

There is no `REFramework::get_reframework_module()` in this repository.

Replace that exact self-module check with the HMODULE passed to `EarlyInitialize()`.

Equivalent policy:

```text
Allow if caller module path contains:
- vehdebug
- coreclr
- dinput8

OR caller module == CapcomPatcher's own module.
```

Do not broaden this into "allow every non-game DLL".

Do not add a generic allowlist for every OptiScaler proxy name (`dxgi.dll`, `winmm.dll`, etc.) unless runtime evidence proves it is required. Current OptiScaler source does not show its own `AddVectoredExceptionHandler` registration in the examined codebase.

### 12.3 Module resolution

Do not port all of REFramework `utility::Module` just to map a return address to an HMODULE/path.

Use Windows APIs, e.g.:

```cpp
HMODULE callerModule{};
GetModuleHandleExW(
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    reinterpret_cast<LPCWSTR>(_ReturnAddress()),
    &callerModule);
```

Then `GetModuleFileNameW(callerModule, ...)` for the optional path comparison.

Keep this helper small and local.

### 12.4 Fail behavior

If caller-module resolution fails while `veh_allowed == false`, follow the conservative/upstream behavior: treat it as unapproved rather than guessing it is safe.

The blocked call should still cause the state transition that allows later registrations, matching REFramework.

---

# 13. Guard D — `RtlExitUserProcess`

Port REFramework's `hook_rtl_exit_user_process()` and `rtl_exit_user_process_hook()` behavior.

Resolve:

```text
ntdll!RtlExitUserProcess
```

and hook it with the same MinHook wrapper.

Current REFramework intentionally does **not** call the original function from the hook.

Its active behavior is effectively:

```cpp
void* RtlExitUserProcessHook(uint32_t code)
{
    TerminateProcess(GetCurrentProcess(), code);
    return nullptr;
}
```

The upstream comment explains why: normal `RtlExitUserProcess` cleanup reaches `RtlpFlsDataCleanup` / TLS-like cleanup and can call heap-allocated code that no longer exists, causing a crash.

### Parity rule

Do not "improve" this into:

```text
try original first -> fallback only on exception
```

unless runtime evidence proves the current upstream behavior is inappropriate for Capcom Patcher.

For PR1, preserve current upstream semantics for the six supported games.

### Expected side effect

This makes supported-game process exit abrupt through `TerminateProcess` rather than the normal full user-process cleanup path. That is intentional parity with current REFramework.

Mention this explicitly in the PR body and runtime test notes.

---

## 14. Idempotency and state model

All four guards must tolerate duplicate entry points without double-hooking.

Suggested state:

```cpp
std::atomic<bool> g_earlyAttempted{};
std::atomic<bool> g_postLoadAttempted{};

HMODULE g_selfModule{};

NtProtectVirtualMemoryFn g_originalNtProtectVirtualMemory{};
void* g_pristineNtProtectVirtualMemory{};

std::unique_ptr<MinHookInlineHook> g_virtualProtectHook;
std::unique_ptr<MinHookInlineHook> g_vehHook;
std::unique_ptr<MinHookInlineHook> g_exitHook;

std::atomic<bool> g_vehAllowed{};
std::atomic<bool> g_vehCalled{};
```

Exact representation may differ.

### Important distinction from the removed PR0 outer latch

Do not recreate the PR0 bug where one failed top-level initialization permanently prevented a retry of every layer.

Prefer per-layer state:

```text
NotAttempted
Installed
FailedRetryable
```

or equivalent independent booleans/mutex-protected state.

A failure in the VEH guard must not prevent `RtlExitUserProcess`, `VirtualProtect`, or DbgUi initialization.

---

## 15. Interaction with the existing DbgUi watcher

Do not rewrite the PR0 watcher in PR1.

The existing watcher must retain:

- 32-byte baseline,
- E9/FF25 handling,
- safe FF25 slot reads,
- executable `MEM_PRIVATE` target requirement,
- destructive-write revalidation,
- race-aware restore,
- module pinning,
- 500 ms worker,
- `PatchResult() == false` semantics.

The only expected integration change should be ordering in `InitializeASI()`:

```text
PostLoad runtime guard
    -> DbgUi watcher
```

If the DbgUi file changes beyond include/logging/integration requirements, explain why in the PR body.

---

## 16. Do not implement module-path spoofing in PR1

REFramework also contains `spoof_module_paths_in_exe_dir()` behavior, but it is intertwined with its loader/storage-directory handling and `LdrRegisterDllNotification` path.

It is **not being declared unnecessary**.

It is intentionally deferred because this PR should isolate the four common `IntegrityCheckBypass` runtime guards and because Capcom Patcher is loaded through OptiScaler rather than REFramework's dinput8/storage loader.

A later focused review can determine whether module-path spoofing is needed for the selected six-game OptiScaler architecture and, if so, what paths should actually be spoofed.

Do not silently add it here.

---

## 17. Explicit non-goals for PR1

Do **not** implement:

- DD2 scanner/crasher patches,
- `createBLAS` corruption guard,
- DD2-family constants,
- RE9/BushClover constants,
- JobQueue hooks,
- PE-header integrity patch,
- RE9 slow-path discriminator,
- renderer heartbeat discovery/synchronization,
- stack-destroyer patch,
- module-path spoofing,
- PAK handling,
- `/natives/` handling,
- trial/demo executables,
- any seventh game,
- generic REFramework SDK/runtime,
- new persistent worker threads,
- GitHub Actions CI unless separately requested.

These belong to later focused PRs.

---

## 18. Logging requirements

Continue using the lightweight current logging style.

Suggested prefixes:

```text
[CapcomPatcher][RuntimeGuard]
[CapcomPatcher][NtProtect]
[CapcomPatcher][VEH]
[CapcomPatcher][Exit]
```

Log at minimum:

### Early init

```text
supported early runtime guard initialization started
NtProtectVirtualMemory resolved
pristine syscall copy captured
VEH hook installed / failed
RtlExitUserProcess hook installed / failed
```

### VirtualProtect

```text
VirtualProtect hook installed / failed
NtProtectVirtualMemory modification detected
restore succeeded / failed
```

Do not log every normal `VirtualProtect` call. The upstream one-time diagnostic is acceptable; high-frequency logging is not.

### VEH

On pre-allow calls:

```text
caller module/path
allowed early VEH
blocked first unapproved VEH
subsequent VEH state transitioned to allowed
```

Do not log every later allowed VEH call indefinitely if it becomes noisy.

### Exit

Log hook installation. Do not rely on a log immediately before `TerminateProcess` being flushed or visible.

---

## 19. Static / build validation

Required before opening the PR:

```text
Debug | x64   PASS
Release | x64 PASS
git diff --check PASS
```

Verify exports remain exactly compatible:

```text
InitializeASI
PatchResult
```

and:

```cpp
PatchResult() == false
```

### MinHook validation

Verify:

- MinHook is pinned to the intended revision,
- x64 sources compile as part of the project,
- no Win32 configuration is reintroduced,
- no missing submodule state is hidden in the PR instructions,
- `THIRD_PARTY_NOTICES.md` is updated.

If using a submodule, the PR body must state the required checkout/build command, e.g.:

```text
git submodule update --init --recursive
```

---

## 20. Focused functional validation without games

Where practical, add a small **test-only/debug harness** for deterministic parts. Do not add a large testing framework.

### 20.1 Game gating

Existing six mappings must still pass and unsupported executables must remain unsupported.

### 20.2 MinHook wrapper

A local test target/process may hook a harmless test function to verify:

```text
create -> enable -> trampoline/original call -> detour call
```

Do not hook actual `RtlExitUserProcess` in a unit test unless the test is an isolated disposable process.

### 20.3 VEH guard

If practical, use an isolated disposable test executable to verify:

- self-module registration is allowed,
- first unapproved caller path is blocked with non-null fake return,
- later calls transition to allowed.

If this cannot be safely automated, document as `NOT RUN` rather than fabricating a PASS.

### 20.4 NtProtect integrity path

At minimum validate by code review/static instrumentation that the restore path never recursively calls hooked `VirtualProtect`.

A deliberate synthetic corruption test is optional and should only be done in an isolated test process.

---

## 21. Runtime validation on the selected games

Preferred smoke-test order:

```text
1. MHW
2. DD2
3. RE9
4. PRAGMATA
5. Onimusha WotS
6. MHS3
```

Not every game must be available to the coding environment. Report unavailable tests as `NOT RUN`.

### 21.1 Minimum checks per available game

Confirm:

```text
CapcomPatcher detects the correct profile
pristine NtProtectVirtualMemory capture succeeds
VEH hook installation succeeds
RtlExitUserProcess hook installation succeeds
VirtualProtect guard installation succeeds
DbgUi watcher still initializes
normal game startup reaches rendering
no immediate crash/hang caused by early guards
```

### 21.2 MHW/DD2/RE9 regression check

These games already provided the strong DbgUi delayed-crash evidence.

Confirm the new runtime guards do not regress the PR0 watcher behavior.

When the Capcom DbgUi hook appears, expected watcher logs remain:

```text
DbgUiRemoteBreakin modification detected
hook type=FF25 (or E9 if observed)
validated executable MEM_PRIVATE target
neutralized executable private payload
restored DbgUiRemoteBreakin
```

### 21.3 Normal exit behavior

Because the `RtlExitUserProcess` guard intentionally redirects to `TerminateProcess`, specifically test one normal user-requested game exit if runtime access exists.

Expected:

- process terminates cleanly from the user's perspective,
- no exit-time crash dialog,
- no hang,
- no zombie process.

Do not require normal DLL detach/destructor execution; the upstream guard intentionally bypasses normal `RtlExitUserProcess` cleanup.

---

## 22. Failure policy

PR1 must be fail-soft at the layer level.

Example:

```text
NtProtect capture fails
  -> log
  -> VirtualProtect guard cannot safely activate
  -> VEH / Exit / DbgUi may still activate

VEH hook fails
  -> log
  -> do not abort whole patcher

Exit hook fails
  -> log
  -> do not abort whole patcher

VirtualProtect hook fails
  -> log
  -> DbgUi watcher still gets a chance to run
```

Do not treat one optional guard failure as a reason to unload or crash the game.

Never write guessed bytes or call through a null/invalid trampoline.

---

## 23. Review-sensitive invariants

Reviewers should request changes if any of the following occur:

1. A custom detour/trampoline implementation is written instead of reusing a mature hook library without a strong reason.
2. MinHook is unpinned or fetched from a floating branch.
3. Any early guard installs for unsupported games.
4. A second independent executable allowlist is introduced and can drift from `GameProfile`.
5. `VirtualProtect` restore recurses through hooked `VirtualProtect`.
6. `NtProtectVirtualMemory` restore writes through an unvalidated/null pointer.
7. `AddVectoredExceptionHandler` is broadened to allow arbitrary callers before the intended first-block transition.
8. The VEH guard returns `nullptr` for the blocked first registration instead of preserving the upstream non-null fake-return behavior.
9. `RtlExitUserProcess` silently calls the original path despite the current upstream implementation intentionally using `TerminateProcess`.
10. `PatchResult()` changes from false.
11. The PR rewrites or weakens the already-hardened DbgUi watcher.
12. DD2/RE9/heartbeat/stack-destroyer code leaks into this PR.
13. PAK or REFramework mod-loader behavior is imported.
14. MinHook's license/notice is missing.
15. Runtime tests are claimed as PASS when they were not run.

---

## 24. Expected diff shape

A good PR1 should look roughly like:

```text
+ .gitmodules / third_party/minhook pin
+ minimal MinHook wrapper
+ RuntimeGuards.h/.cpp
~ GameProfile.* (only if needed for loader-safe early resolution)
~ dllmain.cpp (early guards + post-load ordering)
~ CapcomPatcher.vcxproj(.filters)
~ THIRD_PARTY_NOTICES.md
~ README.md (briefly state PR1/runtime guards now implemented)
```

The core reverse-engineered logic should mostly be traceable to the pinned REFramework functions above.

This PR should **not** contain large game executable pattern tables.

---

## 25. Suggested implementation sequence

### Step 1 — add pinned MinHook

- add the exact REFramework-used MinHook revision,
- wire x64 build sources/include path,
- update third-party notices,
- verify blank project still builds.

### Step 2 — port minimal hook wrapper

- adapt `FunctionHookMinHook`,
- remove REFramework `Address`/spdlog dependencies,
- preserve create/enable/original semantics.

### Step 3 — make game detection usable from early DllMain

- share the existing six-game table,
- avoid filesystem/heap work in the early name lookup where practical,
- confirm unsupported host remains no-op.

### Step 4 — port pristine syscall capture

- extract `setup_pristine_syscall()` behavior,
- keep its state independent and diagnosable.

### Step 5 — port VEH guard

- port hook behavior,
- adapt REFramework self-module check to CapcomPatcher HMODULE,
- preserve first-unapproved-call behavior.

### Step 6 — port exit guard

- resolve/hook `RtlExitUserProcess`,
- preserve direct `TerminateProcess` semantics.

### Step 7 — port VirtualProtect guard

- port direct `NtProtectVirtualMemory` implementation,
- port 32-byte integrity verification/restore,
- install from `InitializeASI()` before DbgUi watcher.

### Step 8 — validation and PR body

- build Debug/Release x64,
- `git diff --check`,
- export check,
- dependency pin/license check,
- report runtime results honestly,
- open PR as Draft unless explicitly instructed otherwise,
- do not merge.

---

## 26. PR body checklist

The PR description should include:

- base commit/branch,
- pinned REFramework source commit,
- pinned MinHook revision,
- statement that the four guards were ported/adapted rather than redesigned,
- exact DllMain initialization order,
- exact InitializeASI ordering,
- any intentional hardening deviation from upstream (for example `FlushInstructionCache`),
- confirmation that only six games can activate early guards,
- confirmation that `PatchResult()` remains false,
- Debug x64 result,
- Release x64 result,
- `git diff --check` result,
- runtime result per available game or `NOT RUN`,
- normal-exit result if tested,
- explicit statement that DD2/RE9/heartbeat/module-path spoofing are not implemented in this PR.

**Do not merge as part of this work order.**
