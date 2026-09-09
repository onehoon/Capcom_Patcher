# PR7 Analysis — Module-Path Spoofing Review and Classification

**Deliverable for:** `doc/work-order/PR7_MODULE_PATH_SPOOFING_REVIEW_AND_CLASSIFICATION.md`
**Date:** 2026-09-09
**Production code changed:** **No** — documentation only.

---

## 1. Executive conclusion

**`INCONCLUSIVE`**, with a documented strong lean toward `NOT_APPLICABLE` for the
default OptiScaler + Capcom Patcher install topology.

Static source analysis shows that REFramework's `_storage_` + module-path spoof
responsibility is scoped to **DLLs whose loader path is the game executable
directory itself**, is backed by REF-owned file relocation into `_storage_`, and
that the current OptiScaler fork loads `CapcomPatcher.asi` **verbatim from its
configured plugin subdirectory** with all four path identities consistent and no
relocation. In the default topology the upstream trigger condition does not arise
for Capcom Patcher's own module.

It is not classified `NOT_APPLICABLE` because:

1. a **non-default but supported** OptiScaler configuration (`PluginPath` pointed
   at the game executable directory) recreates exactly the game-root DLL state
   REFramework spoofs — so the offending state is *not structurally impossible*,
   only *not the default*; and
2. there is **no game-side evidence**: the exact RE Engine anti-tamper check that
   REFramework's `_storage_` + spoof mechanism compensates for has not been
   located in any of the six selected titles, and no runtime PEB/loader identity
   observation was possible (no game runtime available to this work).

`REQUIRED` is not met: it needs positive evidence that a real path-identity
mismatch causes a delayed penalty removed by the spoof, and none exists.

**Follow-up action:** retain module-path spoofing as *deferred / unresolved*.
Section 13 names the exact evidence-collection tasks that would resolve it, to be
run in the six-game runtime validation phase.

---

## 2. Capcom Patcher base SHA

```
onehoon/Capcom_Patcher
main @ 54b82aa26314fd16097c2271d9b40b2fc883dd4f   (PR6 merged)
```

Branch cut from `main` at `07331e6` (`54b82aa` + this work-order commit).

PR0–PR6 source is not modified by this PR.

---

## 3. REFramework source pins

```
praydog/REFramework @ b6baf6b406efc65e077b99cb4d9ad25b0a0a9095
  src/REFramework.cpp        (call sites, _storage_ lifecycle, ldr notification)
  src/Main.cpp               (additional spoof call site)
```

`.gitmodules` at this pin declares only `imgui`, `minhook`, `spdlog`, `glm` as
submodules. REFramework's `utility::` namespace used by the spoof path is the
vendored **kananlib** tree.

---

## 4. Exact `spoof_module_paths_in_exe_dir()` definition

```
cursey/kananlib @ 8c27b656734355db0f2893581fd62e838fa130ad
  src/Module.cpp        void spoof_module_paths_in_exe_dir()   (line 479)
  include/utility/Module.hpp   (declaration)
```

This is the **same kananlib pin** Capcom Patcher already records for PR2/PR3/PR5
algorithmic adaptation (`THIRD_PARTY_NOTICES.md` → `cursey/kananlib`). No new
dependency and no new license family is involved in reviewing it. Kananlib is
Boost Software License 1.0.

### 4.1 What it actually mutates

Confirmed from the function body (not inferred from the name):

1. It walks the **PEB loader list** (`foreach_module`, iterating
   `PEB->Ldr->InMemoryOrderModuleList`, `CONTAINING_RECORD(... , _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)`).
2. For each `_LDR_DATA_TABLE_ENTRY`:
   - skip if the entry or `FullDllName.Buffer` is unreadable (`IsBadReadPtr`);
   - skip if `DllBase == current_exe`;
   - compute `path = FullDllName` (lower-cased);
   - **skip unless `path.parent_path() == <game executable directory>`** — i.e.
     it only processes DLLs whose loader-visible directory is the game root; a
     module in any subdirectory (e.g. `plugins\`) is explicitly logged
     `"Skipping ..."` and left untouched;
   - build `new_path = <gamedir>\_storage_\<stem><ext>`;
   - **copy the DLL file** from `<gamedir>\x.dll` to
     `<gamedir>\_storage_\x.dll` (`std::filesystem::copy_file`, overwrite); on
     failure, fall back to a system-directory path string;
   - allocate a fresh `wchar_t[]` for `new_path` and **overwrite the in-memory
     loader entry**:
     - `ldr_entry->FullDllName.Buffer   = <new heap wchar array>`
     - `ldr_entry->FullDllName.Length   = new_path.size() * 2`
     - `ldr_entry->FullDllName.MaximumLength = size * 2`
   - the previous `FullDllName.Buffer` is **leaked** (never freed).

**Fields mutated:** only `LDR_DATA_TABLE_ENTRY.FullDllName` (the
`UNICODE_STRING` `Buffer` / `Length` / `MaximumLength`). `BaseDllName` is **not**
touched. `DllBase`, load-order links, hash links, and every other loader field
are untouched. No PEB header field is written. No disk file is renamed or moved
(only *copied*).

**Serialization:** guarded by a `g_spoof_mutex` scoped lock; a
`g_skipped_paths` set de-dupes the skip log.

---

## 5. Current OptiScaler fork + loader source

```
onehoon/OptiScaler
master @ 3809b22150da2e5eb723f58d9e8eadb58705a553
  OptiScaler/dllmain.cpp              DllMain, LoadAsiPlugins(), config path resolution
  OptiScaler/proxies/Ntdll_Proxy.h    NtdllProxy::LoadLibraryExW_Ldr()
  OptiScaler/hooks/Ntdll_Hooks.h      hkLdrLoadDll / hkNtLoadDll
```

### 5.1 `LoadAsiPlugins()` — verified current behavior

`OptiScaler/dllmain.cpp:211`:

```cpp
std::filesystem::path pluginPath(Config::Instance()->PluginPath.value_or(L"plugins"));
...
for (const auto& entry : std::filesystem::directory_iterator(folderPath)) {
    ... if ext == ".asi" ...
    if (fileName.rfind(L"-loadlate") != npos)
        _lateLoadingEntries.push_back(entry);          // deferred (worker thread, 286)
    else
        hMod = NtdllProxy::LoadLibraryExW_Ldr(entry.path().c_str(), NULL, 0);
    ...
    auto init        = GetProcAddress_(hMod, "InitializeASI");
    auto patchResult = GetProcAddress_(hMod, "PatchResult");
    if (init != nullptr)        init();
    if (patchResult != nullptr) { auto pr = patchResult(); if (pr) { /* disable OptiScaler spoofing */ } }
}
```

- The path handed to the loader is `entry.path().c_str()` — the **absolute path
  produced by `directory_iterator` over the resolved `pluginPath`**. No string
  substitution, no `_storage_`, no copy/move/rename.
- `LoadAsiPlugins()` is called from **`DllMain(DLL_PROCESS_ATTACH)` directly**
  (`dllmain.cpp:2066`), under the Windows loader lock, as a **recursive
  `LdrLoadDll`**. `CapcomPatcher.asi`'s `InitializeASI()` and `PatchResult()`
  are then invoked **synchronously in that same loader-lock context**.
- Non-`-loadlate` plugins load during OptiScaler `DllMain`. `*-loadlate*.asi`
  plugins load later from a detached `std::thread` after a configurable delay
  (`dllmain.cpp:286`). `CapcomPatcher.asi` is not a `-loadlate` name, so it is
  the synchronous case.

### 5.2 `NtdllProxy::LoadLibraryExW_Ldr()` — verified

`OptiScaler/proxies/Ntdll_Proxy.h:23`. For a normal (non-`SYSTEM32`) load:

```cpp
UNICODE_STRING uName;
o_RtlInitUnicodeString(&uName, lpLibFileName);        // verbatim path
status = o_LdrLoadDll(nullptr, ldrFlags ? &ldrFlags : nullptr, &uName, &hModule);
```

The path is passed to `LdrLoadDll` **verbatim**. No rewriting, no `_storage_`,
no relocation. (`SYSTEM32` loads — not the ASI case — prepend the system dir.)

### 5.3 `hkLdrLoadDll` / `hkNtLoadDll` — verified not relevant

`OptiScaler/hooks/Ntdll_Hooks.h:44,98`. OptiScaler hooks `LdrLoadDll` /
`NtLoadDll`, but the hook only:

- passes through unchanged for api-set names, during shutdown, and when
  `State::SkipDllChecks()` matches;
- otherwise calls `LibraryLoadHooks::LoadLibraryCheckW(name, name)` which
  intercepts **specific known upscaler / vendor DLL *names*** (nvngx, streamline,
  XeSS/XeLL/XeFG, FSR, etc.) — substituting a handle or blocking the load;
- for any other name (including `...\plugins\CapcomPatcher.asi`) it falls through
  to `o_LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle)` **with the
  arguments unchanged**.

It never rewrites `FullDllName`, never relocates to `_storage_`, and does not
special-case `.asi` plugins.

### 5.4 `MainDllPath` / `PluginPath` resolution — verified

`OptiScaler/dllmain.cpp:1776–1806`:

```
MainDllPath:
  unset            -> "OptiScaler"
  relative         -> <exe dir> / MainDllPath
  missing / not dir -> <exe dir>
  final            -> std::filesystem::absolute(MainDllPath)

PluginPath:
  unset / missing / not dir -> <MainDllPath> / "plugins"
```

For the common install where OptiScaler is a **game-root proxy DLL**
(`dxgi.dll` / `winmm.dll` / `version.dll` / `dbghelp.dll` / … next to the game
`.exe`), `MainDllPath` resolves to the **game executable directory** and
`PluginPath` resolves to **`<gamedir>\plugins`**. Therefore the default physical
location of `CapcomPatcher.asi` is:

```
<game executable directory>\plugins\CapcomPatcher.asi
```

— a **subdirectory** of the game root, not the game root.

`PluginPath` is a user-configurable value. A user *can* set it to the game
executable directory itself, in which case `CapcomPatcher.asi` would be loaded
from `<gamedir>\CapcomPatcher.asi` — directly in the game root.

---

## 6. REFramework `_storage_` + call-site lifecycle

From `src/REFramework.cpp` (`REFramework::REFramework()` / `initialize()` path):

1. `g_current_game_path` = directory of `GetModuleHandle(0)` (the game exe).
2. **Gate:** `gi.is_dd2() || gi.is_mhrise() || gi.tdb_ver() >= 74` (modern RE
   Engine — the same family Capcom Patcher's PR2–PR6 target, minus the MHW
   TDB81 special-casing).
3. Create `<gamedir>\_storage_`.
4. Iterate `<gamedir>\*.dll`, `copy_file` each into `_storage_\` (overwrite).
5. If `<gamedir>\D3D12\D3D12Core.dll` exists, copy it to
   `_storage_\D3D12\D3D12Core.dll`.
6. `utility::spoof_module_paths_in_exe_dir()` (section 4).
7. `LdrRegisterDllNotification(0, ldr_notification_callback, ...)`.
8. `ldr_notification_callback` (`REFramework.cpp:214`): on
   `LDR_DLL_NOTIFICATION_REASON_LOADED`, if the loaded module's `FullDllName`
   `parent_path()` equals `g_current_game_path` **and** the gate matches, call
   `utility::spoof_module_paths_in_exe_dir()` again.
9. Fallback (`REFramework.cpp:486`): if `LdrRegisterDllNotification` was
   unavailable, REFramework calls `spoof_module_paths_in_exe_dir()` again after
   explicitly `LoadLibrary`-ing `dxgi.dll` / `d3d11.dll` / `openvr_api.dll` /
   `openxr_loader.dll` from the game directory.
10. Two more call sites in later runtime paths (`REFramework.cpp:2348,2424`).

**Why the pieces exist together:**

- The **file copy into `_storage_`** exists so that after the loader entry's
  `FullDllName` is rewritten to `<gamedir>\_storage_\x.dll`, that path names a
  **real file on disk** — any anti-tamper (or diagnostic) code that re-opens the
  reported module path with `CreateFile` still succeeds.
- The **`FullDllName` rewrite** moves the loader-visible identity of REF's own
  modules (and any DLL sitting in the game root) **out of the game executable
  directory**, so a check of the form "enumerate loaded modules; flag any whose
  directory is my own game directory and is not a known-good game module" no
  longer flags them.
- The **repeat on DLL-load notification** handles modules that land in the game
  root *after* the initial pass (game-loaded vendor DLLs, later plugins).
- REFramework is very often injected **as a game-root proxy DLL itself**
  (`dinput8.dll` / `dxgi.dll` / …), so its own primary module is squarely inside
  the trigger set. `_storage_` relocation is **REF-owned** behavior.

**Anti-tamper vs loader/proxy correctness:** the mechanism is primarily
anti-tamper motivated (it is gated on the RE Engine anti-tamper family and lives
in the same startup block as `IntegrityCheckBypass` immediate patches), but it
also intersects proxy-correctness (a spoofed path that pointed at a nonexistent
file would break code that opens it — hence the `_storage_` copy). Where the
upstream comments do not state intent, this is labelled **inference**: no comment
in `spoof_module_paths_in_exe_dir()` or its call sites names the exact game
function it defeats.

---

## 7. Metadata mutated by the upstream utility

| Structure | Field | Written by upstream? | Notes |
|---|---|---:|---|
| `LDR_DATA_TABLE_ENTRY` | `FullDllName.Buffer` | **yes** | replaced with a fresh heap `wchar_t[]` naming `<gamedir>\_storage_\<stem><ext>` |
| `LDR_DATA_TABLE_ENTRY` | `FullDllName.Length` | **yes** | set to `new_path.size() * 2` |
| `LDR_DATA_TABLE_ENTRY` | `FullDllName.MaximumLength` | **yes** | set to allocated size `* 2` |
| `LDR_DATA_TABLE_ENTRY` | `BaseDllName` | no | untouched |
| `LDR_DATA_TABLE_ENTRY` | `DllBase`, links, flags, `EntryPoint`, `SizeOfImage` | no | untouched |
| `PEB` / `PEB_LDR_DATA` | any field | no | not written |
| Disk | new `<gamedir>\_storage_\*.dll` files + `_storage_\D3D12\` | **yes** | `copy_file` overwrite; directory created |
| Disk | original DLLs | no | not renamed/moved/deleted |

`GetModuleFileNameW` reads from the same `FullDllName` in modern Windows, so a
rewrite is observable through Win32 too.

---

## 8. Current OptiScaler + Capcom Patcher load topology (ordered flow)

Default install (OptiScaler as a game-root proxy DLL):

```
game .exe starts
  loader maps a game-root proxy DLL   e.g. <gamedir>\dxgi.dll  (== OptiScaler)
  OptiScaler DllMain(DLL_PROCESS_ATTACH)  [loader lock held]
    resolve MainDllPath  -> <gamedir>            (dir of the proxy DLL)
    resolve PluginPath   -> <gamedir>\plugins
    AttachHooks(): install hkLdrLoadDll etc.
    ...
    LoadAsiPlugins():
      directory_iterator(<gamedir>\plugins)
      for CapcomPatcher.asi:
        NtdllProxy::LoadLibraryExW_Ldr("<gamedir>\plugins\CapcomPatcher.asi", NULL, 0)
          -> RtlInitUnicodeString(uName, "<gamedir>\plugins\CapcomPatcher.asi")   [verbatim]
          -> LdrLoadDll(nullptr, ..., &uName, &hMod)                              [recursive load]
             -> Capcom Patcher DllMain(DLL_PROCESS_ATTACH)
                  DisableThreadLibraryCalls
                  runtime_guards::EarlyInitialize   (pristine syscall / VEH / exit guard)
             loader records FullDllName = "<gamedir>\plugins\CapcomPatcher.asi"
        init        = GetProcAddress(hMod, "InitializeASI")
        patchResult = GetProcAddress(hMod, "PatchResult")
        init()        -> DD2/RE9/PE-header/stack-destroyer/heartbeat/DbgUi startup
        patchResult() -> returns false  (never disables OptiScaler spoofing)
```

Capcom Patcher performs **no** module copy, no directory creation, no
`FullDllName` write, no `LdrRegisterDllNotification`, no loader hook — for its
own module or any other. It is a passive ASI loaded from its real configured
path.

---

## 9. Four path identities for `CapcomPatcher.asi`

| Identity | Default topology value | Source of truth |
|---|---|---|
| **A. Physical file on disk** | `<gamedir>\plugins\CapcomPatcher.asi` | OptiScaler `PluginPath` = `<MainDllPath>\plugins`; nothing copies/moves it |
| **B. Path passed to the loader** | `<gamedir>\plugins\CapcomPatcher.asi` | `directory_iterator` absolute `entry.path()` → `RtlInitUnicodeString` verbatim → `LdrLoadDll` |
| **C. `GetModuleFileNameW`** | `<gamedir>\plugins\CapcomPatcher.asi` | loader records B; no `GetModuleFileName` hook in scope |
| **D. PEB `LDR_DATA_TABLE_ENTRY.FullDllName`** | `<gamedir>\plugins\CapcomPatcher.asi` (`BaseDllName` = `CapcomPatcher.asi`) | loader fills from B; nothing rewrites it |

**All four are the same string.** They are self-consistent, and the directory is
a **plugin subdirectory**, not the game executable directory.

Non-default `PluginPath = <gamedir>`: A/B/C/D all become
`<gamedir>\CapcomPatcher.asi` — still self-consistent, but now **directly in the
game executable directory**, which is the REFramework spoof trigger set.

---

## 10. Responsibility-equivalence table

| Responsibility / condition | REFramework | OptiScaler + Capcom Patcher | Equivalent? | Evidence |
|---|---|---|---:|---|
| A game-root proxy DLL is the injection vector | yes — REF is commonly `dxgi.dll`/`dinput8.dll` in the game root | yes — OptiScaler is commonly a game-root proxy DLL | **yes** (for OptiScaler's module, not Capcom Patcher's) | OptiScaler proxy headers; `dllmain.cpp` proxy handling |
| `_storage_` file copy / relocation exists | yes — REF copies `<gamedir>\*.dll` + `D3D12Core.dll` into `_storage_` | **no** — no `_storage_` or equivalent in the OptiScaler fork or Capcom Patcher | **no** | `git`-grep of both trees; `LoadLibraryExW_Ldr` / `hkLdrLoadDll` bodies |
| Loader path of *our* module differs from its physical/visible path | yes — REF rewrites `FullDllName` to `_storage_` | **no** — `CapcomPatcher.asi` loads verbatim; A=B=C=D | **no** | section 9 |
| `LDR_DATA_TABLE_ENTRY.FullDllName` is mutated | yes | **no** — Capcom Patcher never writes loader metadata | **no** | Capcom Patcher `src/` has no PEB/LDR write; `PatchResult()` == false |
| Spoof re-applied on later game-root DLL load | yes — `LdrRegisterDllNotification` + fallback | **no** — Capcom Patcher registers no notification | **no** | section 6 vs section 8 |
| Our module's loader directory is the game executable directory | yes (REF's own module) | **no** in the default topology (`plugins\` subdir); **yes** only under a non-default `PluginPath = <gamedir>` | **no (default) / yes (non-default config)** | section 5.4, 9; REF explicitly *skips* subdirectory modules (section 4.1) |
| A selected game's anti-tamper observes / penalizes a loader-path identity | REF gates `_storage_`+spoof on `is_dd2 \|\| is_mhrise \|\| tdb_ver >= 74`, implying *some* check exists in that family | **unproven** for the six selected titles at their current builds | **unknown** | no game-side check located; no runtime observation (no game available) |

The final classification derives from the last two rows: the mechanical
preconditions REFramework compensates for are **absent** in the default topology
(rows 2–6), but the game-side check that would make any of it *matter* is
**unverified** (row 7), and a non-default config reopens row 6.

---

## 11. Runtime evidence matrix

No game runtime was available to this work. Nothing was launched.

| Game | OptiScaler only | OptiScaler + Capcom Patcher | REF comparison | Result |
|---|---|---|---|---|
| MHW | — | — | — | **NOT RUN** |
| DD2 | — | — | — | **NOT RUN** |
| RE9 | — | — | — | **NOT RUN** |
| PRAGMATA | — | — | — | **NOT RUN** |
| Onimusha WotS | — | — | — | **NOT RUN** |
| MHS3 | — | — | — | **NOT RUN** |

No unrelated XeFG/FG/swapchain failure is presented as path-spoof evidence.

---

## 12. Final classification rationale

**`INCONCLUSIVE`.**

Against `NOT_APPLICABLE` (§8.1 threshold — "structurally impossible in the
current architecture"):

- The default-topology argument is strong: `CapcomPatcher.asi` loads verbatim
  from a plugin subdirectory, all four identities agree, nothing relocates it,
  and REFramework's own spoof routine *explicitly skips* modules that are not in
  the game executable directory. For the **default** install, the upstream
  trigger does not arise.
- But it is **not structurally impossible**: OptiScaler's `PluginPath` is
  user-configurable and may point at the game executable directory, which
  recreates the exact game-root-DLL state REFramework spoofs. `NOT_APPLICABLE`
  requires the state to be unreachable, not merely non-default.
- And the game-side half is unproven: REFramework gates `_storage_` + spoof on
  the modern RE Engine family, so a relevant loader-path or module-directory
  check plausibly exists — but it has **not been located** in any of the six
  selected titles, and **no runtime PEB/`GetModuleFileNameW`/disk comparison**
  was possible. A conclusion of `NOT_APPLICABLE` here would rest on "no evidence
  of a problem", which §8.1 and reject invariant 5 forbid.

Against `REQUIRED` (§8.2 threshold — positive evidence):

- No selected-game A/B evidence, no located anti-tamper loader-path check, no
  high-confidence REFramework evidence tying the condition to *our* topology.
  "REFramework calls it" and "the games use anti-tamper" are explicitly
  insufficient.

`INCONCLUSIVE` is the honest result: the mechanical preconditions are absent in
the default topology, but the evidence needed to *close* the item (game-side
check + runtime identity observation + non-default-config behavior) is missing.

No production spoof, `_storage_`, PEB/LDR write, loader hook, notification
callback, worker, or byte patch was added to reach this result.

---

## 13. Follow-up action

**Retain module-path spoofing as deferred / unresolved.** Do **not** implement
spoofing now.

The following bounded, read-only evidence-collection tasks resolve the
classification and belong in the six-game runtime validation phase:

1. **Loader-identity snapshot (read-only).** From `InitializeASI()` (post-load,
   off `DllMain`), a one-shot SEH-guarded walk of the PEB `InMemoryOrderModuleList`
   that records, for `CapcomPatcher.asi`, the OptiScaler proxy module, and the
   game `.exe` only: `BaseDllName`, a **path class**
   (`game_root | plugin_dir | game_subdir | system | other`) for each of
   (disk / `GetModuleFileNameW` / PEB `FullDllName`), and whether they agree.
   Output one normalized line per module — no raw user paths in normal output.
   No writes, no retained pointers, no callback, no polling. This is the
   `INCONCLUSIVE → resolved` instrument; add it with focused unit tests for the
   pure path-classification / normalization / case-insensitive comparison logic.
2. **Non-default `PluginPath` A/B.** With `PluginPath` set to the game
   executable directory (so `CapcomPatcher.asi` is game-root), launch each
   available selected game with and without `CapcomPatcher.asi` and record
   whether a delayed anti-tamper penalty (lag / crash / job corruption) appears
   that is absent in the default `plugins\` layout.
3. **Game-side check location.** In at least one selected title (DD2 or RE9 —
   the two REFramework special-cases by name), locate the anti-tamper code path
   that enumerates loaded modules / inspects a module directory, and determine
   whether a game-root non-game DLL (or a `plugins\` subdirectory DLL) is a
   penalty trigger.
4. **REFramework A/B on a shared build.** On a game/build where REFramework runs,
   capture a loaded-module `FullDllName` list before and after
   `spoof_module_paths_in_exe_dir()` and confirm which modules it actually
   rewrites in practice.

If (2)/(3)/(4) show a real penalty tied to a game-root or plugin-subdirectory
loader identity for one of the six games, raise a **separate focused
implementation work order** (not an amendment to PR7) defining: exact games,
exact modules, exact `FullDllName` old/new rule, whether the `_storage_` file
backing is required, initial timing, whether `LdrRegisterDllNotification` is
needed, lifetime/restore policy, loader-lock safety, and the fail-closed rule.

If (1) confirms consistent identities and (2)/(3) find no penalty for the
default `plugins\` layout, the classification moves to `NOT_APPLICABLE` and
module-path spoofing is closed as intentionally omitted.

---

## Appendix A — source references

| Item | Location |
|---|---|
| REFramework `_storage_` + call sites | `praydog/REFramework@b6baf6b` `src/REFramework.cpp` (`~355`, `431`, `434`, `486`, `2348`, `2424`), `src/Main.cpp` |
| REFramework ldr notification callback | `src/REFramework.cpp:214` (`ldr_notification_callback`) |
| `spoof_module_paths_in_exe_dir()` | `cursey/kananlib@8c27b65` `src/Module.cpp:479`; decl `include/utility/Module.hpp` |
| kananlib PEB walk | `cursey/kananlib@8c27b65` `src/Module.cpp:372` (`foreach_module`) |
| OptiScaler ASI loader | `onehoon/OptiScaler@3809b221` `OptiScaler/dllmain.cpp:211` (`LoadAsiPlugins`), call site `:2066` (in `DllMain`) |
| OptiScaler loader wrapper | `OptiScaler/proxies/Ntdll_Proxy.h:23` (`LoadLibraryExW_Ldr`) |
| OptiScaler loader hook | `OptiScaler/hooks/Ntdll_Hooks.h:44` (`hkLdrLoadDll`), `:98` (`hkNtLoadDll`) |
| OptiScaler `MainDllPath` / `PluginPath` resolution | `OptiScaler/dllmain.cpp:1776–1806` |
| Capcom Patcher ASI entry | `src/dllmain.cpp` (`DllMain`, `InitializeASI`, `PatchResult` → `false`) |
