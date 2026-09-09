# PR7 Analysis — Module-Path Spoofing Review and Classification

**Deliverable for:** `doc/work-order/PR7_MODULE_PATH_SPOOFING_REVIEW_AND_CLASSIFICATION.md`
**Date:** 2026-09-09
**Production code changed:** **No** — documentation only.

---

## 1. Executive conclusion

**`INCONCLUSIVE`.**

The upstream `spoof_module_paths_in_exe_dir()` eligibility test (§4.1) is:
*any loaded module, except the game `.exe`, whose loader-visible directory
(`FullDllName.parent_path()`) equals the game executable directory.* The
`_storage_` file copy and the `FullDllName` rewrite are that routine's **output
mechanism**, not a precondition. So the default OptiScaler + Capcom Patcher
topology must be split by module:

| Module | Loader directory (default install) | In the upstream spoof-eligible set? | Selected-game penalty for that identity |
|---|---|---:|---:|
| **OptiScaler proxy DLL** (`dxgi.dll` / `winmm.dll` / `version.dll` / …) | **game executable directory** (game-root proxy install) | **YES** | **UNKNOWN** — no game-side check located, not run |
| `CapcomPatcher.asi` | `<gamedir>\plugins\` (a subdirectory) | **NO** in the default layout (upstream explicitly *skips* subdirectory modules); **YES** only under a non-default `PluginPath = <gamedir>` | **UNKNOWN** |

So a game-root DLL that upstream would rewrite **does exist in the default
topology** — the OptiScaler proxy module, not `CapcomPatcher.asi`. The upstream
routine does **not** test for a pre-existing disk/Win32/PEB mismatch; its
eligibility condition is simply "non-exe loaded module whose `FullDllName`
directory is the game exe directory", and it rewrites even a fully
self-consistent such module. The OptiScaler proxy's identities being consistent
today therefore does not take it out of the upstream eligibility set.

The unresolved question is whether any of the six selected games **penalizes
that unspoofed game-root identity** at all. That is unverified — no anti-tamper
loader-path check located, no runtime observation (no game runtime available).

`NOT_APPLICABLE` is therefore **not** justified: an eligible game-root module is
present (the OptiScaler proxy), and the game-side half is unproven. A conclusion
of "not applicable" would rest on absence-of-evidence, which §8.1 / reject
invariant 5 forbid.

`REQUIRED` is **not** met either: it needs positive evidence that a game
penalizes the unspoofed game-root identity, and none exists — no A/B, no located
check, no high-confidence REFramework evidence tied to this topology.

`CapcomPatcher.asi` in the **default** `plugins\` layout is a subdirectory
module the upstream rule **skips** — but that is one module in one layout, not a
topology-wide `NOT_APPLICABLE`, and a non-default `PluginPath = <gamedir>` would
put it in the game-root eligible set too.

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
   - attempt `std::filesystem::create_directory(<gamedir>\_storage_)` then
     `std::filesystem::copy_file(<gamedir>\x.dll, new_path, overwrite_existing, ec)`.
     **Copy-failure handling — exact pinned behavior:**
     - an ordinary `copy_file` failure surfaces through the `std::error_code ec`
       (logged `"Failed to copy DLL file: {}"`), then `ec.clear()`. **`new_path`
       is not changed** — the routine proceeds with the `_storage_` path even
       though the `_storage_` file may not exist;
     - the system-directory fallback (`new_path = <system dir>\<stem><ext>`) runs
       **only** from the enclosing `catch (...)` handler, i.e. when a filesystem
       operation *throws* (e.g. `create_directory`), not on an `ec` return;
   - allocate a fresh `wchar_t[]` for the current `new_path` and **overwrite the
     in-memory loader entry**:
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

- The path handed to the loader is `entry.path().c_str()`. Its **string form
  follows the configured `PluginPath`**: absolute when `PluginPath` is absolute
  (including the default fallback `<MainDllPath>\plugins`), and **relative when a
  valid relative `PluginPath` was supplied** (e.g. `Path=plugins`) — see §5.4.
  OptiScaler performs no additional path substitution, `_storage_` relocation,
  copy, move, or rename.
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
`PluginPath` resolves to **`<gamedir>\plugins`**. So the default physical
location of `CapcomPatcher.asi` is `<gamedir>\plugins\CapcomPatcher.asi` — a
**subdirectory** of the game root, not the game root.

**`PluginPath` is not always absolutized.** `MainDllPath` is passed through
`std::filesystem::absolute(...)`, but a **configured, existing, is-directory
`PluginPath` is left exactly as supplied** — the fallback that joins it onto
`MainDllPath` only runs when it is unset / missing / not a directory. A valid
config such as `Path=plugins` therefore stays **relative**.
`std::filesystem::directory_iterator("plugins")` then yields **relative**
`entry.path()` values, and `LoadLibraryExW_Ldr` / `LdrLoadDll` receive a relative
`UNICODE_STRING`. The Windows loader resolves it against the process default
search order and records an **absolute** `FullDllName`. So in that config the
loader-input string (B) and the loader-metadata / `GetModuleFileNameW` string
(D / C) name the **same file and directory class** but are **not the same
string**, and the exact B/C/D representations are only knowable from a runtime
snapshot.

`PluginPath` is also user-configurable: a user *can* set it to the game
executable directory, in which case `CapcomPatcher.asi` loads from
`<gamedir>\CapcomPatcher.asi` — directly in the game root, i.e. inside the
upstream spoof-eligible set.

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

- The **file copy into `_storage_`** appears intended to give the rewritten
  `<gamedir>\_storage_\x.dll` identity a real file on disk, so code that re-opens
  the reported module path still succeeds. This is **inference** — no upstream
  comment states it — and the pinned implementation does **not** guarantee it: an
  `error_code` `copy_file` failure is logged and the routine still rewrites
  `FullDllName` to the `_storage_` path even if no `_storage_` file exists
  (§4.1). The reopen/consumer rationale therefore remains unproven.
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
| Disk | new `<gamedir>\_storage_\*.dll` files + `_storage_\D3D12\` | **attempted** | `create_directory` + `copy_file` overwrite; an `error_code` copy failure is only logged (no file created, `FullDllName` still rewritten to the `_storage_` path) |
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
        NtdllProxy::LoadLibraryExW_Ldr(entry.path(), NULL, 0)   // entry.path() from directory_iterator(PluginPath)
          -> RtlInitUnicodeString(uName, entry.path())          [verbatim - absolute or relative per config]
          -> LdrLoadDll(nullptr, ..., &uName, &hMod)             [recursive load]
             -> Capcom Patcher DllMain(DLL_PROCESS_ATTACH)
                  DisableThreadLibraryCalls
                  runtime_guards::EarlyInitialize   (pristine syscall / VEH / exit guard)
             loader records FullDllName = <absolute resolution of that path>   (same file, subdir class)
        init        = GetProcAddress(hMod, "InitializeASI")
        patchResult = GetProcAddress(hMod, "PatchResult")
        init()        -> DD2/RE9/PE-header/stack-destroyer/heartbeat/DbgUi startup
        patchResult() -> returns false  (never disables OptiScaler spoofing)
```

Capcom Patcher performs **no** module copy, no directory creation, no
`FullDllName` write, no `LdrRegisterDllNotification`, no loader hook — for its
own module or any other. It is a passive ASI loaded from its configured path.

The **OptiScaler proxy DLL** that started this whole chain is itself a
`<gamedir>\<name>.dll` module — i.e. a module the upstream
`spoof_module_paths_in_exe_dir()` walk **would process** (§4.1: eligible = any
loaded non-exe module whose `FullDllName` directory is the game exe directory).
It is not `CapcomPatcher.asi`, and Capcom Patcher does not own it, but it is the
concrete game-root DLL present in the default topology.

---

## 9. Path identities — per module

The work order requires the four identities (A disk / B loader-input /
C `GetModuleFileNameW` / D PEB `FullDllName`) to be kept separate. They must also
be kept separate **per module**.

### 9.1 `CapcomPatcher.asi`

| Identity | Default `plugins\` layout | Notes |
|---|---|---|
| A — physical file on disk | `<gamedir>\plugins\CapcomPatcher.asi` | nothing copies/moves it |
| B — path passed to the loader | `<configured PluginPath>\CapcomPatcher.asi` from `directory_iterator` `entry.path()`, passed **verbatim** to `LdrLoadDll` — **absolute if `PluginPath` is absolute, relative if `PluginPath` is a relative config value** (§5.4) | no rewrite in `LoadLibraryExW_Ldr` / `hkLdrLoadDll` |
| C — `GetModuleFileNameW` | absolute `<...>\plugins\CapcomPatcher.asi` | loader-recorded; no `GetModuleFileName` hook in scope |
| D — PEB `FullDllName` (`BaseDllName` = `CapcomPatcher.asi`) | absolute `<...>\plugins\CapcomPatcher.asi` | loader fills it; nothing rewrites it |

**What is statically established:** A, C and D all name the **same file** in the
**same directory class** (`plugin_dir`, a subdirectory of the game root). B names
the same file but its **string form may be relative** and is not provably equal
to C/D as a string. **Exact B/C/D string values require the read-only runtime
snapshot** (§13). Nothing relocates the file; there is no `FullDllName` rewrite.

Under a non-default `PluginPath = <gamedir>`, A/C/D become
`<gamedir>\CapcomPatcher.asi` — directory class `game_root`, i.e. inside the
upstream spoof-eligible set.

### 9.2 OptiScaler proxy DLL (the common `dxgi.dll` / `winmm.dll` / … install)

| Identity | Value | Notes |
|---|---|---|
| A — physical file on disk | `<gamedir>\<proxyname>.dll` | placed next to the game `.exe` by the user |
| B — path passed to the loader | not directly captured by this static audit — the OS loader resolves it from the game's import / known-DLL name (OptiScaler does not `LdrLoadDll` itself); it has an input identity, just not one OptiScaler chooses | |
| C — `GetModuleFileNameW` | `<gamedir>\<proxyname>.dll` | |
| D — PEB `FullDllName` (`BaseDllName` = `<proxyname>.dll`) | `<gamedir>\<proxyname>.dll` | loader-recorded |

**Directory class: `game_root`.** A/C/D are consistent. This does **not** take
the module out of the upstream spoof-eligible set: `spoof_module_paths_in_exe_dir()`
does not test for an identity mismatch — its condition is only
`FullDllName.parent_path() == <game exe dir>`, and it rewrites such a module's
`FullDllName` to `_storage_` regardless. Whether any selected game penalizes a
game-root non-game DLL with a graphics-DLL name (`dxgi.dll` is itself an expected
name) is **UNKNOWN**.

---

## 10. Responsibility-equivalence table

| Condition | REFramework behavior | Current OptiScaler + Capcom Patcher topology | Equivalent? | Evidence |
|---|---|---|---:|---|
| A non-exe loaded module has `FullDllName.parent_path() == game exe dir` | eligible — its `FullDllName` is rewritten out of the game root | **the OptiScaler proxy DLL satisfies this** in the common install | **yes** — an eligible game-root module is present | OptiScaler `proxies/*`; §5.4, §9.2 |
| An eligible module's `FullDllName` is rewritten out of the game root | rewritten to a `<gamedir>\_storage_\…` string (+ attempted backing copy) | **no equivalent mutation exists** — no component writes loader metadata | **no** | Capcom Patcher `src/` has no PEB/LDR write; tree grep; `LoadLibraryExW_Ldr` / `hkLdrLoadDll` bodies; `PatchResult()` == false |
| `_storage_` directory / file copy | REF-owned `create_directory` + `copy_file` | **absent** in both the OptiScaler fork and Capcom Patcher | **no** | tree grep |
| Re-apply on later game-root DLL load | `LdrRegisterDllNotification` + fallback | **no** notification/callback anywhere in Capcom Patcher | **no** | §6 vs §8 |
| Plugin-subdirectory ASI (`CapcomPatcher.asi`, default layout) | **not eligible** — skipped (not in game exe dir) | `CapcomPatcher.asi` is normally in `plugins\` | **yes: also skipped** | §4.1, §9.1 |
| Exact loader-input string proven equal to the visible / PEB string for our ASI | n/a (REF replaces it) | **not statically proven** — a relative configured `PluginPath` → relative loader-input, absolute recorded `FullDllName` (same file & class, different string) | **unknown (string) / yes (file + class)** | §5.4, §9.1 |
| A selected game penalizes an unspoofed game-root (or plugin-subdir) loader identity | REF gates `_storage_`+spoof on `is_dd2 \|\| is_mhrise \|\| tdb_ver >= 74`, implying *some* check in the family | **unproven** for the six selected titles; the exact check is not located | **unknown** | no game-side check located; no runtime observation |

**How the classification derives from this table:** an eligible game-root module
**is present** (row 1 — the OptiScaler proxy). The upstream routine does not
require or detect a pre-existing identity mismatch — it rewrites eligible
modules' `FullDllName` unconditionally — and **no equivalent rewrite exists in
the current topology** (rows 2–4). `CapcomPatcher.asi` in the default `plugins\`
layout is separately not eligible (row 5). What is unknown is whether any
selected game **penalizes the unspoofed game-root identity** at all (row 7), and
— for the ASI specifically — the exact loader-input string form (row 6).

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

Against `NOT_APPLICABLE` (§8.1 threshold — the offending state is "structurally
impossible in the current architecture"):

- A **game-root DLL that the upstream routine would rewrite does exist** in the
  default topology: the OptiScaler proxy module (`<gamedir>\dxgi.dll` etc.,
  §9.2). `spoof_module_paths_in_exe_dir()` does **not** require or detect a
  pre-existing disk/Win32/PEB mismatch — its eligibility condition is only
  `FullDllName.parent_path() == <game exe dir>`, and it rewrites such a module
  unconditionally. So the OptiScaler proxy's identities being consistent today
  does **not** remove it from the upstream eligibility set.
- What is absent in the current topology is the **rewrite itself**: no component
  changes any eligible module's `FullDllName` out of the game root, there is no
  `_storage_`, and no re-apply notification (§10 rows 2–4). `CapcomPatcher.asi`
  in the default `plugins\` layout is separately **not eligible** (subdirectory
  module, §4.1); a non-default `PluginPath = <gamedir>` would put it into the
  eligible set too.
- The **game-side half is unproven**: REFramework gates `_storage_` + spoof on
  the modern RE Engine family, so a loader-path / module-directory check
  plausibly exists — but it has **not been located** in any of the six selected
  titles, and **no runtime PEB / `GetModuleFileNameW` / disk comparison** was
  possible. A `NOT_APPLICABLE` conclusion here would rest on "no evidence of a
  problem", which §8.1 and reject invariant 5 forbid — and it cannot be
  supported while the OptiScaler proxy sits in the eligible set with no
  game-side penalty ruled out.

Against `REQUIRED` (§8.2 threshold — positive evidence):

- No selected-game A/B evidence, no located anti-tamper loader-path check, no
  high-confidence REFramework evidence tying the condition to *our* topology.
  "REFramework calls it" and "the games use anti-tamper" are explicitly
  insufficient.

`INCONCLUSIVE` is the honest result: an upstream-eligible game-root module is
present (the OptiScaler proxy), no equivalent `FullDllName` rewrite exists in the
current topology, `CapcomPatcher.asi` is normally not eligible, and the evidence
needed to *close* the item (whether any selected game penalizes the unspoofed
game-root identity + runtime identity observation + non-default-config behavior)
is missing.

No production spoof, `_storage_`, PEB/LDR write, loader hook, notification
callback, worker, or byte patch was added to reach this result.

---

## 13. Follow-up action

**Retain module-path spoofing as deferred / unresolved.** Do **not** implement
spoofing now.

The following bounded, read-only evidence-collection tasks resolve the
classification and belong in the six-game runtime validation phase:

1. **Loader-identity snapshot (read-only).** A one-shot SEH-guarded walk of the
   PEB `InMemoryOrderModuleList` recording, for `CapcomPatcher.asi`, **the
   OptiScaler proxy/main module**, and the game `.exe` only: `BaseDllName`, and a
   **path class** (`game_root | plugin_dir | game_subdir | system | other`) for
   each of (disk / `GetModuleFileNameW` / PEB `FullDllName`), plus whether they
   agree. For the OptiScaler proxy this confirms whether its game-root identity
   is truly consistent in practice; for the ASI it settles the
   relative-vs-absolute B/C/D question left open in §9.1. One normalized line per
   module — no raw user paths in normal output. No writes, no retained pointers,
   no callback, no polling.

   **Do not run this walk from `InitializeASI()` in the current default OptiScaler
   topology.** §5.1 / §8 establish that OptiScaler calls `CapcomPatcher.asi`'s
   `InitializeASI()` synchronously from `LoadAsiPlugins()`, which itself runs
   inside OptiScaler's `DllMain(DLL_PROCESS_ATTACH)` — so for a normal
   (non-`-loadlate`) plugin, `InitializeASI()` still executes **under the process
   loader lock**, and the PR7 work order (§14) requires a loader-list walk to run
   only outside `DllMain` / the loader lock. Run the one-shot audit only from a
   point proven to execute **after** the loader lock is released — e.g. a
   dedicated diagnostic/dev-build export invoked after normal startup returns, or
   an already-existing post-loader worker path whose timing is explicitly proven
   safe.

   Add it with focused unit tests for the pure path-classification / normalization
   / case-insensitive comparison logic.
2. **Non-default `PluginPath` A/B.** With `PluginPath` set to the game
   executable directory (so `CapcomPatcher.asi` is game-root), launch each
   available selected game with and without `CapcomPatcher.asi` and record
   whether a delayed anti-tamper penalty (lag / crash / job corruption) appears
   that is absent in the default `plugins\` layout.
3. **Game-side check location.** In at least one selected title (DD2 or RE9 —
   the two REFramework special-cases by name), locate the anti-tamper code path
   that enumerates loaded modules / inspects a module directory, and determine
   whether **a game-root non-game DLL (e.g. the OptiScaler proxy)** or a
   `plugins\` subdirectory DLL is a penalty trigger. This is the pivotal
   unknown: the OptiScaler proxy already sits in the game-root eligible set.
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

If (1) confirms consistent identities for the OptiScaler proxy and the ASI, and
(2)/(3) find no selected-game penalty for a game-root non-game DLL or the
`plugins\` layout, the classification moves to `NOT_APPLICABLE` and module-path
spoofing is closed as intentionally omitted.

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
