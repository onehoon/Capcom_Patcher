# PR0 Work Order — Bootstrap Capcom Patcher and Port the Hardened DbgUiRemoteBreakin Watcher

**Repository:** `onehoon/Capcom_Patcher`  
**Target branch:** new feature branch from `main`  
**PR type:** implementation / bootstrap  
**Scope:** project skeleton + six-game profile table + hardened `DbgUiRemoteBreakin` watcher only  
**Do not merge automatically.**

---

## 1. Objective

Create the first functional version of **Capcom Patcher** as a standalone x64 ASI module for OptiScaler.

This PR must **not** reimplement the anti-debug watcher from scratch. The hardened implementation already exists and has been reviewed repeatedly in `onehoon/OptiPatcher` PR #1. Reuse that code directly, with only the minimum changes required to fit the new repository and explicit six-game profile architecture.

PR0 establishes a clean base for later PRs that will port the remaining REFramework anti-tamper layers.

At the end of this PR, `CapcomPatcher.asi` should:

1. build as an x64 C++20 ASI,
2. load through OptiScaler's normal ASI path,
3. recognize only the six selected Capcom games,
4. expose `InitializeASI()`,
5. keep `PatchResult()` semantically false so OptiScaler does not interpret anti-tamper initialization as a DLSS/vendor patch success,
6. start the already-hardened `DbgUiRemoteBreakin` watcher for supported games,
7. do nothing for all other executables,
8. contain no legacy generic OptiPatcher game catalog.

---

## 2. Primary design document

Read before making changes:

- [`doc/CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md`](../CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md)

PR0 implements only the first slice of that architecture. Do not pull later anti-tamper layers into this PR.

---

## 3. Source reuse policy — do not rewrite proven code unnecessarily

The purpose of this new repository is architectural separation, **not** a clean-room rewrite.

Reuse proven code where practical.

### 3.1 Hardened watcher — copy/adapt from OptiPatcher PR #1

Use this exact reviewed commit as the pinned source-of-truth for the initial port:

- Commit: `b57408dc6efb7ae62229af028daef8f19caf2f66`
- File: `OptiPatcher/CapcomAntiDebugWatcher.cpp`
- URL: `https://github.com/onehoon/OptiPatcher/blob/b57408dc6efb7ae62229af028daef8f19caf2f66/OptiPatcher/CapcomAntiDebugWatcher.cpp`
- Header: `OptiPatcher/CapcomAntiDebugWatcher.h`
- URL: `https://github.com/onehoon/OptiPatcher/blob/b57408dc6efb7ae62229af028daef8f19caf2f66/OptiPatcher/CapcomAntiDebugWatcher.h`

Do **not** downgrade or simplify the following hardening that is already present:

- 32-byte `DbgUiRemoteBreakin` baseline,
- explicit `E9 rel32` and `FF 25 rel32` resolution,
- safe FF25 pointer-slot validation/read,
- overflow-safe relative-target calculations,
- committed/readable range validation,
- executable `MEM_PRIVATE` target requirement,
- full observed-entry snapshot,
- hook re-resolution/revalidation before destructive work,
- target region identity revalidation immediately before neutralization,
- `MEM_PRIVATE + executable` revalidation,
- race-aware entry restore,
- full observed 32-byte identity check before restore,
- preservation/restoration of memory protection,
- `FlushInstructionCache()` after executable writes,
- baseline contamination guard that rejects an already-redirected `E9`/`FF25` live baseline,
- one synchronous watcher pass before relying on worker scheduling,
- module pinning before detached worker lifetime begins,
- 500 ms polling behavior,
- non-spamming observation/success diagnostics.

If the port materially changes any of these semantics, explain why in the PR body and treat the change as a review-sensitive deviation.

### 3.2 Minimal path utility — reuse from OptiPatcher

The existing utility is sufficient and may be copied/adapted:

- `https://github.com/onehoon/OptiPatcher/blob/b57408dc6efb7ae62229af028daef8f19caf2f66/OptiPatcher/Util.h`
- `https://github.com/onehoon/OptiPatcher/blob/b57408dc6efb7ae62229af028daef8f19caf2f66/OptiPatcher/Util.cpp`

Only keep functions actually required by this project. `ExePath()` is required. `DllPath()` may be kept if useful for future diagnostics, but do not import unrelated generic helpers.

### 3.3 Build skeleton — adapt, do not copy legacy game patching

The existing OptiPatcher Visual Studio project may be used as a bootstrap reference:

- `https://github.com/onehoon/OptiPatcher/blob/b57408dc6efb7ae62229af028daef8f19caf2f66/OptiPatcher/OptiPatcher.vcxproj`

Use it only for basic DynamicLibrary/ASI/C++20 settings.

Do **not** import the original generic OptiPatcher `CheckForPatch()` catalog, `Scanner.*`, or `Patcher.*` in PR0. They are unnecessary for the current watcher and would reintroduce the old product's unrelated scope.

### 3.4 REFramework reference — behavioral source, not a reason to downgrade the watcher

The watcher behavior originated from REFramework's `IntegrityCheckBypass`:

- Repository: `praydog/REFramework`
- Reference commit used during analysis: `b6baf6b406efc65e077b99cb4d9ad25b0a0a9095`
- File: `src/mods/IntegrityCheckBypass.cpp`
- URL: `https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.cpp`

Relevant upstream functions:

- `IntegrityCheckBypass::anti_debug_watcher()`
- `IntegrityCheckBypass::init_anti_debug_watcher()`
- `IntegrityCheckBypass::nuke_heap_allocated_code()`

The OptiPatcher watcher already contains additional safety hardening over the current REF implementation. Preserve the hardened OptiPatcher behavior rather than mechanically reverting to the older REF implementation.

### 3.5 OptiScaler ASI contract

OptiScaler loads ASI plugins and invokes `InitializeASI()` when exported.

Reference:

- `https://github.com/optiscaler/OptiScaler/blob/f78a26e979b2f81b1ce266fd372932c524b86342/OptiScaler/dllmain.cpp`

OptiScaler also checks an optional `PatchResult()` export and treats `true` as successful game patching. Therefore Capcom Patcher anti-tamper initialization must **not** return `true` through `PatchResult()`.

---

## 4. Explicit supported-game profile

Create a dedicated game-profile component rather than keeping executable checks inside the watcher.

Suggested files:

```text
src/GameProfile.h
src/GameProfile.cpp
```

Suggested model:

```cpp
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

struct GameProfile
{
    GameId id{GameId::Unsupported};
    const wchar_t* canonicalName{};

    // Future parity layers. PR0 only consumes dbgUiWatcher.
    bool dbgUiWatcher{};
    bool dd2Family{};
    bool re9Family{};
    bool re9SlowPath{};
    bool heartbeat{};
};
```

The exact representation may differ, but keep the capabilities centralized and explicit.

### 4.1 Required executable mapping

Case-insensitive executable mapping for release executables:

```text
MonsterHunterWilds.exe
DD2.exe
re9.exe
PRAGMATA.exe
OnimushaWotS.exe
MONSTER_HUNTER_STORIES_3_TWISTED_REFLECTION.exe
```

Do **not** automatically support arbitrary `tdb >= N` games.

Do **not** add Onimusha demo or MHS3 trial aliases in this PR unless explicitly requested later. The project scope for PR0 is the six release games above.

### 4.2 Initial capability matrix

Encode the planned profile now so later PRs do not need to scatter new game-name branches throughout the codebase:

| Game | Dbg watcher | DD2 family | RE9 family | RE9 slow path | Heartbeat |
|---|---:|---:|---:|---:|---:|
| MHW | true | true | false | false | false |
| DD2 | true | true | true | false | true |
| RE9 | true | true | true | true | true |
| PRAGMATA | true | true | true | false | true |
| Onimusha WotS | true | true | true | false | true |
| MHS3 | true | true | true | false | true |

**Important:** PR0 must only execute the `Dbg watcher` capability. The other flags are declarative scaffolding for later PRs and must not cause placeholder patching or empty worker threads.

---

## 5. Proposed repository structure after PR0

Keep the initial tree intentionally small:

```text
Capcom_Patcher/
├─ CapcomPatcher.sln
├─ LICENSE
├─ THIRD_PARTY_NOTICES.md
├─ README.md
├─ doc/
│  ├─ CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md
│  └─ work-order/
│     └─ PR0_BOOTSTRAP_AND_HARDENED_DBG_UI_WATCHER_PORT.md
└─ src/
   ├─ CapcomPatcher.vcxproj
   ├─ CapcomPatcher.vcxproj.filters
   ├─ pch.h
   ├─ pch.cpp
   ├─ dllmain.cpp
   ├─ GameProfile.h
   ├─ GameProfile.cpp
   ├─ Util.h
   ├─ Util.cpp
   └─ antitamper/
      ├─ DbgUiRemoteBreakinWatcher.h
      └─ DbgUiRemoteBreakinWatcher.cpp
```

Equivalent naming is acceptable if the same separation is preserved.

Do not create the full future directory tree with empty `.cpp` files. Add future modules only when their implementation PR begins.

---

## 6. Build configuration

This project is only intended for the selected modern x64 RE Engine games.

### Required

- MSVC / Visual Studio C++ project.
- C++20.
- `DynamicLibrary` configuration.
- x64 Debug.
- x64 Release.
- output extension: `.asi`.
- preferred target name: `CapcomPatcher.asi`.
- Windows 10/11 SDK compatible.

### Recommended simplification

Unlike the legacy OptiPatcher project, Win32 configurations are unnecessary. Remove/omit Win32 unless there is a concrete tooling reason to keep them.

Do not add package managers or third-party hooking libraries in PR0. The current watcher uses Win32 APIs only.

Do not add GitHub Actions CI in PR0. This repository is currently being developed/tested through local PR builds; CI can be added later if it becomes useful.

---

## 7. DLL / ASI lifecycle

### 7.1 `DllMain`

PR0 should keep `DllMain` minimal.

Suggested shape:

```cpp
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
    }

    return TRUE;
}
```

Do not start the persistent watcher thread from `DllMain`.

The architecture plan reserves very-early `DllMain` work for later runtime guards such as pristine syscall capture / VEH / exit protection. Those are intentionally out of scope for PR0 and will receive dedicated review.

### 7.2 `InitializeASI()`

Export `InitializeASI()` and use it as the PR0 activation point.

Suggested control flow:

```cpp
extern "C" __declspec(dllexport) void InitializeASI()
{
    const auto& profile = game_profile::Current();
    if (profile.id == GameId::Unsupported)
    {
        return;
    }

    if (profile.dbgUiWatcher)
    {
        antitamper::dbg_ui::Initialize();
    }
}
```

Avoid re-detecting executable names independently inside every module. `GameProfile` should be the single source of game identity.

### 7.3 `PatchResult()`

Keep the export for OptiScaler compatibility if desired, but it must remain false:

```cpp
extern "C" __declspec(dllexport) bool PatchResult()
{
    return false;
}
```

Do not use `PatchResult()` as an anti-tamper health/status channel.

The reason is semantic, not cosmetic: OptiScaler treats a true result as successful game patching and can change spoofing behavior based on that result.

---

## 8. Watcher port requirements

Move/rename the watcher into the new namespace/project without changing its safety properties.

Suggested namespace:

```cpp
namespace antitamper::dbg_ui
{
    bool Initialize();
}
```

The watcher should not own supported-game detection after this PR. That responsibility moves to `GameProfile`.

### 8.1 Preserve baseline behavior

The initial implementation may retain the reviewed OptiPatcher live-baseline strategy:

1. resolve `ntdll!DbgUiRemoteBreakin`,
2. read 32 bytes,
3. reject baseline if it already begins with supported redirect forms (`E9` or `FF 25`),
4. do not guess or overwrite an apparently contaminated baseline.

Do not replace this in PR0 with a new clean-mapped-ntdll implementation. That would be a separate behavior change and should receive its own review if needed.

### 8.2 Preserve redirect validation

Supported hook forms in PR0:

```text
E9 <rel32>
FF 25 <rel32-to-pointer-slot>
```

Unknown entry modifications must be logged and left untouched.

### 8.3 Preserve target eligibility

Never neutralize a redirect target unless it is currently verified as:

```text
State = MEM_COMMIT
Type  = MEM_PRIVATE
Protect = executable protection
```

Reject `PAGE_GUARD`, `PAGE_NOCACHE`, and `PAGE_WRITECOMBINE` combinations as in the reviewed implementation.

### 8.4 Preserve destructive-write revalidation

Before writing `0xC3` across the target region, revalidate:

- full 32-byte entry identity,
- redirect instruction form,
- FF25 pointer-slot-derived target,
- target address,
- target region base,
- allocation base,
- region size,
- `MEM_PRIVATE` state,
- executable protection.

If anything changed, abort the attempt and let the next polling cycle retry.

### 8.5 Preserve safe restore

Only restore the captured baseline if the current 32 bytes still match the exact observed hook snapshot that was neutralized.

If another writer changed the entry, log and leave it untouched.

### 8.6 Worker lifetime

Preserve the module pinning before detached worker creation. A detached thread executing code from an unloadable ASI is unsafe.

Preserve one synchronous `CheckDbgUiRemoteBreakin()` before the detached thread starts.

Polling cadence remains 500 ms for PR0.

Do not add a fake `Shutdown()` API that cannot safely stop/join the detached worker.

---

## 9. Logging

PR0 may retain `OutputDebugStringA` logging from the hardened watcher.

Use a consistent new prefix, for example:

```text
[CapcomPatcher]
[CapcomPatcher][DbgUi]
```

At minimum log:

- supported game/profile selected,
- watcher initialization success/failure,
- baseline captured,
- contaminated baseline refusal,
- hook form and target on new observation,
- target validation rejection,
- successful neutralization,
- successful entry restore,
- race/revalidation aborts,
- unsupported hook form.

Do not add high-frequency logs on every 500 ms clean poll.

A persistent file logger is not required in PR0. It can be added later when runtime diagnostics across all parity layers are designed together.

---

## 10. Attribution and licensing

Both reused sources are MIT-licensed, but attribution must remain explicit.

### Required repository files

- `LICENSE` — project license, MIT unless the repository owner chooses otherwise before implementation.
- `THIRD_PARTY_NOTICES.md`

`THIRD_PARTY_NOTICES.md` must identify at least:

1. `onehoon/OptiPatcher` — source of the hardened watcher/bootstrap utility code,
2. `praydog/REFramework` — original `IntegrityCheckBypass::anti_debug_watcher()` behavior/reference.

Keep an attribution comment near the watcher implementation, similar to the already-reviewed OptiPatcher comment.

Do not remove existing copyright/license notices from copied material when applicable.

---

## 11. README update

Replace the placeholder README with a concise project description.

It should state:

- Capcom Patcher is an OptiScaler-focused RE Engine anti-tamper compatibility ASI,
- only six games are currently in scope,
- the project is experimental / under active development,
- PR0 currently implements only the hardened `DbgUiRemoteBreakin` layer,
- additional REFramework-derived anti-tamper parity layers will be added in later PRs,
- no claim should be made that PR0 already provides full REFramework anti-tamper parity.

List the six release games explicitly.

---

## 12. Explicit non-goals for PR0

Do **not** implement any of the following in this PR:

- `setup_pristine_syscall()` port,
- `VirtualProtect` hook/guard,
- `AddVectoredExceptionHandler` interception,
- `RtlExitUserProcess` guard,
- module-path spoofing,
- DD2 scanner/crasher patches,
- `createBLAS` corruption guard,
- DD2-family constants,
- RE9-family constants,
- BushClover mitigation,
- JobQueue hooks,
- PE-header integrity protection,
- RE9 slow-path discriminator,
- heartbeat detection/synchronization,
- stack-destroyer scan,
- PAK handling,
- `/natives/` handling,
- loose-file/mod loader functionality,
- REFramework overlay/hooks/SDK/runtime,
- old generic OptiPatcher game patches,
- Onimusha demo support,
- MHS3 trial support,
- any game outside the explicit six-game list,
- GitHub Actions CI.

These exclusions are intentional PR boundaries, not a statement that the later anti-tamper layers are unnecessary.

---

## 13. Suggested implementation sequence

### Step 1 — Bootstrap project

- create x64 C++20 ASI solution/project,
- set target extension to `.asi`,
- add minimal `pch`,
- add `dllmain.cpp`,
- verify an empty ASI builds.

### Step 2 — Port minimal utility

Copy/adapt `Util::ExePath()` from pinned OptiPatcher source.

Do not import unused scanner/patcher files.

### Step 3 — Add GameProfile

- explicit six release executable names,
- case-insensitive matching,
- explicit capability matrix,
- unsupported fallback.

### Step 4 — Port hardened watcher

Copy/adapt the reviewed `CapcomAntiDebugWatcher.cpp/.h` from pinned commit.

Changes should primarily be:

- include paths,
- namespace/name cleanup,
- removal of internal executable allowlist,
- use of `GameProfile` as activation gate,
- logging prefix rename,
- new project structure.

Do not opportunistically rewrite the low-level memory logic.

### Step 5 — ASI exports

- add `InitializeASI()`,
- add `PatchResult() == false`,
- connect profile → watcher.

### Step 6 — Attribution/docs

- MIT `LICENSE`,
- `THIRD_PARTY_NOTICES.md`,
- README update.

### Step 7 — Local validation

Perform all available build/static checks and report unavailable runtime tests honestly.

---

## 14. Validation requirements

### 14.1 Build

Required before PR is considered ready for review:

```text
Debug | x64   PASS
Release | x64 PASS
```

No Win32 build is required.

### 14.2 Static repository checks

Required:

```text
git diff --check
```

Also inspect the built binary/export table or otherwise verify that the final ASI exports:

```text
InitializeASI
PatchResult
```

and that `PatchResult()` returns false.

### 14.3 Game-profile checks

Verify all six mappings resolve correctly and unrelated executables resolve as unsupported.

At minimum test these exact names case-insensitively:

```text
MonsterHunterWilds.exe                -> MHW
DD2.exe                               -> DD2
re9.exe                               -> RE9
PRAGMATA.exe                          -> PRAGMATA
OnimushaWotS.exe                      -> Onimusha
MONSTER_HUNTER_STORIES_3_TWISTED_REFLECTION.exe -> MHS3
notepad.exe                           -> Unsupported
```

If no unit-test project is added, a small debug-only test helper or direct logic inspection is acceptable for PR0. Do not introduce a large testing framework just for this bootstrap PR.

### 14.4 Runtime validation

If game runtime access is available, preferred smoke tests are:

```text
MHW + OptiScaler + CapcomPatcher.asi
DD2 + OptiScaler + CapcomPatcher.asi
RE9 + OptiScaler + CapcomPatcher.asi
```

Expected when the Capcom hook occurs:

```text
DbgUiRemoteBreakin modification detected
hook type=FF25 (or E9 if observed)
validated executable MEM_PRIVATE target
neutralized executable private payload
restored DbgUiRemoteBreakin
```

The known MHW/DD2/RE9 delayed-crash scenario should remain prevented by the ported watcher.

For PRAGMATA, Onimusha and MHS3, PR0 only validates that the watcher initializes safely. Full anti-tamper parity is explicitly deferred.

If runtime games are unavailable in the coding environment, state **NOT RUN**. Do not claim PASS based solely on compilation.

---

## 15. Review-sensitive invariants

Reviewers should reject PR0 if any of the following occur:

1. The generic old OptiPatcher game catalog is copied into the new repository.
2. The watcher is rewritten from scratch without a compelling technical reason.
3. The port removes any of the reviewed race/region/baseline hardening.
4. `PatchResult()` returns true because the anti-tamper watcher initialized.
5. Unsupported games can start the watcher through a broad TDB/version heuristic.
6. Persistent worker code starts from `DllMain`.
7. The detached watcher thread can outlive an unloadable module because pinning was removed.
8. Unknown `DbgUiRemoteBreakin` modifications are destructively patched.
9. MHS3/Onimusha trial/demo executables are silently enabled without an explicit scope decision.
10. Later DD2/RE9/heartbeat features are partially implemented in this PR without their own focused review.

---

## 16. Expected PR contents

A good PR0 diff should mostly contain:

```text
+ solution/project bootstrap
+ GameProfile
+ minimal Util
+ hardened watcher port
+ minimal dllmain / ASI exports
+ license / notices
+ README
```

It should **not** contain a large new reverse-engineering implementation.

The point of PR0 is to transfer already-proven work into the correct long-term repository and establish clean boundaries for the next anti-tamper parity PRs.

---

## 17. PR body checklist

The PR description should include:

- source branch/base,
- pinned OptiPatcher watcher source commit `b57408dc6efb7ae62229af028daef8f19caf2f66`,
- statement that watcher logic was ported rather than redesigned,
- list of the six executable profiles,
- statement that only the DbgUi layer is active in PR0,
- `PatchResult()` semantics unchanged/false,
- Debug x64 build result,
- Release x64 build result,
- `git diff --check` result,
- runtime test result per game or `NOT RUN`,
- any deliberate deviations from the pinned watcher implementation.

Do not merge the PR as part of the implementation task. Leave it open for review.
