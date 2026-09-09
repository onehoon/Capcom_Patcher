# PR7 Work Order — Module-Path Spoofing Review and Classification

**Repository:** `onehoon/Capcom_Patcher`  
**Base:** latest `main` after merged PR6 (`54b82aa26314fd16097c2271d9b40b2fc883dd4f` at the time this work order was written)  
**Target branch:** new feature branch from latest `main`  
**PR type:** architecture/source audit + evidence-based classification; read-only diagnostics only if required  
**Scope:** decide whether REFramework-style module-path spoofing has a real responsibility in the current Capcom Patcher + OptiScaler loading topology  
**Open as Draft. Do not merge automatically.**

---

# 1. Objective

PR0 through PR6 now cover the anti-tamper mechanisms that were selected for direct implementation:

- PR0 — explicit six-game bootstrap + hardened `DbgUiRemoteBreakin` watcher,
- PR1 — common runtime guards,
- PR2 — DD2-family direct anti-tamper core,
- PR3 — RE9-family scheduler / JobQueue protection + RE9-only slow path,
- PR4 — renderer heartbeat bridge / synchronization,
- PR5 — RE9-family PE-header integrity redirection,
- PR6 — fail-closed stack-destroyer mitigation.

The remaining architecture item is **module-path spoofing review / classification**.

Current REFramework performs path-spoof work in a runtime architecture that also creates and uses a game-local `_storage_` directory. Capcom Patcher does **not** own that architecture. Therefore the next step is not to copy the upstream function blindly.

PR7 must answer this concrete question:

> Does the current OptiScaler + Capcom Patcher loading topology create the same loader-path identity problem that REFramework's `_storage_` + module-path spoofing code is designed to solve, and is there evidence that any of the six selected Capcom games penalizes that topology?

PR7 is primarily a **classification PR**.

It must end in exactly one of:

```text
NOT_APPLICABLE
    The upstream responsibility is specific to REFramework's own relocation/
    _storage_ topology and the equivalent mismatch cannot arise in the current
    OptiScaler + Capcom Patcher topology.

REQUIRED
    Concrete source/runtime evidence proves that the current topology can hit
    the same anti-tamper path. PR7 documents the evidence and defines the exact
    minimal scope for a separate implementation PR.

INCONCLUSIVE
    The available static/runtime evidence is insufficient. PR7 documents the
    exact missing evidence and leaves production spoofing deferred.
```

**PR7 must not add production module-path mutation merely to reach a result.**

If classification is `REQUIRED`, create the implementation as a **separate follow-up work order/PR**. Do not turn PR7 itself into an unreviewable PEB/loader-metadata mutation PR.

---

# 2. Current source state

Current Capcom Patcher `main` at work-order authoring time:

```text
onehoon/Capcom_Patcher
54b82aa26314fd16097c2271d9b40b2fc883dd4f
```

Relevant project files:

```text
src/dllmain.cpp
src/GameProfile.h
src/GameProfile.cpp
src/antitamper/*
src/memory/*
README.md
doc/CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md
```

PR7 must not redesign PR0-PR6 while performing this audit.

The current architecture plan already states the intended rule:

> REFramework relocates/proxies modules through its own `_storage_` architecture and therefore has reasons to spoof module paths. Capcom Patcher should not reproduce those semantics unless the actual OptiScaler loading arrangement is proven to trigger the same anti-tamper responsibility.

Treat this as the governing constraint.

---

# 3. Pinned source baselines

## 3.1 REFramework behavioral source

Use the same pinned REFramework baseline used by PR0-PR6:

```text
praydog/REFramework
b6baf6b406efc65e077b99cb4d9ad25b0a0a9095
```

Primary call-site source:

```text
src/REFramework.cpp
```

Important current behavior that must be explained in the PR7 analysis:

1. REFramework determines the game executable directory.
2. For its selected modern RE Engine paths, it creates a game-local `_storage_` directory.
3. It pre-emptively copies DLLs from the game directory into `_storage_`.
4. It also copies `D3D12/D3D12Core.dll` into `_storage_/D3D12/` when present.
5. It calls:

```cpp
utility::spoof_module_paths_in_exe_dir();
```

6. It registers an `LdrRegisterDllNotification` callback.
7. When a DLL is subsequently loaded from the game directory, it can call the spoof routine again.
8. If loader notifications are unavailable, REFramework has fallback re-application behavior after loading relevant modules.

This is materially more than a one-time string substitution. PR7 must understand **why these operations exist together** before deciding whether any part belongs in Capcom Patcher.

## 3.2 Exact upstream implementation must be pinned

Do not stop at the `REFramework.cpp` call sites.

Locate the exact definition of:

```cpp
utility::spoof_module_paths_in_exe_dir()
```

and record:

```text
repository
commit SHA
file path
function body / relevant helper chain
license/source attribution
```

The analysis must state exactly what Windows loader metadata or structures it mutates, for example as applicable:

```text
PEB loader list entries
LDR_DATA_TABLE_ENTRY fields
FullDllName
BaseDllName
other path-bearing loader state
```

Do not infer these details from the function name.

If the implementation lives in a utility dependency rather than the REFramework repository itself, pin that dependency's exact revision as well.

If the exact definition cannot be located and reviewed, final classification cannot be `NOT_APPLICABLE` or `REQUIRED`; use `INCONCLUSIVE` and document the missing source.

---

# 4. Current OptiScaler loading topology — audit the real fork, not an assumed loader

Use the current `onehoon/OptiScaler` source as the product-side reference.

Pinned reference at work-order authoring time:

```text
onehoon/OptiScaler
master
3809b22150da2e5eb723f58d9e8eadb58705a553
```

Primary source currently observed:

```text
OptiScaler/dllmain.cpp
LoadAsiPlugins()
```

At this pin, the loader behavior includes:

```cpp
std::filesystem::path pluginPath(
    Config::Instance()->PluginPath.value_or(L"plugins")
);

...
hMod = NtdllProxy::LoadLibraryExW_Ldr(entry.path().c_str(), NULL, 0);
...
auto init = ...GetProcAddress(hMod, "InitializeASI");
auto patchResult = ...GetProcAddress(hMod, "PatchResult");

if (init != nullptr)
    init();

if (patchResult != nullptr)
    patchResult();
```

This matters because Capcom Patcher is normally an ASI plugin loaded by OptiScaler from the configured plugin path; the default path is `plugins`.

PR7 must audit, not merely quote, the current topology:

```text
OptiScaler proxy/main DLL physical path
OptiScaler MainDllPath behavior
PluginPath resolution (relative vs absolute)
CapcomPatcher.asi physical path
path passed to LdrLoadDll/LoadLibrary-equivalent
whether any component is copied/relocated before load
whether any module is loaded from a path different from the path later reported by loader metadata
whether OptiScaler has an _storage_-like mechanism under another name
late-loaded ASI behavior
relevant support/vendor DLL loading paths
```

Search the current fork for at least:

```text
LoadAsiPlugins
PluginPath
MainDllPath
LoadLibrary / LoadLibraryEx / LdrLoadDll wrappers
GetModuleFileName
PEB / LDR_DATA_TABLE_ENTRY access
module-path rewriting
_storage_
copy/move/rename before load
```

Do not assume upstream OptiScaler behavior if the fork differs.

---

# 5. Separate four identities that are easy to conflate

PR7 must explicitly distinguish:

```text
A. Physical file location on disk
B. Path passed to the loader
C. Path reported by Win32 module APIs such as GetModuleFileNameW
D. Path stored in the loader's internal metadata / PEB entry
```

A path problem only exists if the anti-tamper mechanism observes an identity that differs in a meaningful way from the expected one.

Do not treat these statements as equivalent:

```text
"the file is in the plugins directory"
"the loader was passed plugins\\CapcomPatcher.asi"
"GetModuleFileNameW returns that same path"
"the PEB FullDllName matches that same path"
```

Prove the relationships for the current topology.

---

# 6. Required REFramework responsibility analysis

The analysis document must explain the upstream mechanism in responsibility terms, not only line-by-line code terms.

At minimum answer:

1. **What is REFramework trying to hide or redirect?**
2. **Why does `_storage_` exist before `spoof_module_paths_in_exe_dir()` is called?**
3. **Which loaded modules are eligible for spoofing?**
4. **What path is considered the original/expected identity?**
5. **What path becomes the spoofed identity?**
6. **What consumer is expected to read that identity?**
7. **Why is the operation repeated on DLL load notifications?**
8. **Is the behavior anti-tamper related, loader/proxy correctness related, or both?**
9. **Does the exact responsibility depend on REFramework-owned relocation that Capcom Patcher does not perform?**

Where comments do not prove intent, label conclusions as inference and separate them from confirmed code behavior.

---

# 7. Capcom Patcher / OptiScaler equivalence test

Build a responsibility comparison table in the final analysis document.

Required shape:

| Responsibility / condition | REFramework | OptiScaler + Capcom Patcher | Equivalent? | Evidence |
|---|---|---|---:|---|
| Game-root proxy DLL | ... | ... | yes/no | source/runtime |
| `_storage_` copy/relocation | ... | ... | yes/no | source |
| Loader path differs from desired visible path | ... | ... | yes/no/unknown | source/runtime |
| PEB path mutation | ... | ... | yes/no | source |
| Reapply on game-root DLL load | ... | ... | yes/no | source |
| Selected game anti-tamper observes path | ... | ... | proven/unproven | runtime/source |

The final classification must derive from this table.

---

# 8. Evidence threshold for each classification

## 8.1 `NOT_APPLICABLE`

This result is allowed only when the source audit proves that the upstream responsibility depends on a state that the current Capcom Patcher + OptiScaler architecture does not create.

Examples of sufficient reasoning:

```text
- upstream mutates loader metadata specifically to compensate for REF-owned
  game-root -> _storage_ relocation;
- current OptiScaler loads CapcomPatcher.asi directly from its actual configured
  plugin path with no equivalent relocation/identity substitution;
- all relevant loader-visible identities remain self-consistent;
- no separate selected-game evidence identifies that normal plugin-subdirectory
  path itself as a penalty trigger.
```

Do **not** classify `NOT_APPLICABLE` merely because no crash was observed in one short launch.

If static source proves the offending state is structurally impossible in the current architecture, runtime absence does not automatically block `NOT_APPLICABLE`; explain the proof explicitly.

## 8.2 `REQUIRED`

This result requires positive evidence.

At least one of the following must exist:

```text
- selected-game runtime A/B evidence ties a path identity mismatch to a delayed
  crash/penalty and the mismatch disappears with the upstream-equivalent spoof;
- direct game/anti-tamper analysis identifies the relevant loader-path check and
  shows that current OptiScaler/CapcomPatcher topology satisfies its trigger;
- equivalent high-confidence evidence from current REFramework behavior proves
  the same concrete path condition exists in our topology.
```

Do not classify `REQUIRED` because:

```text
"REFramework calls it"
"the game uses anti-tamper"
"CapcomPatcher.asi is not in the EXE root"
```

Those facts alone are insufficient.

If `REQUIRED`, PR7 still performs **no production spoof write**. Instead it must define the minimal implementation boundary for the next PR:

```text
exact games
exact modules
exact metadata fields
exact old/new identity rule
initial timing
whether loader notifications are needed
lifetime/ownership/restore policy
thread/loader-lock safety
fail-closed behavior
runtime validation matrix
```

## 8.3 `INCONCLUSIVE`

Use this when important evidence is missing.

The analysis must list exactly what would resolve it, for example:

```text
RE9 runtime module snapshot before delayed crash
DD2 A/B with REF path spoof isolated
PEB FullDllName vs GetModuleFileName comparison for CapcomPatcher.asi
proof of the exact upstream utility implementation
```

Do not turn uncertainty into speculative production code.

---

# 9. Read-only runtime diagnostics — allowed only if needed

PR7 may add **bounded read-only diagnostics** if static source analysis cannot establish the four path identities.

Prefer a small diagnostic helper that runs from `InitializeASI()` or a dedicated test harness, not a persistent production subsystem.

Allowed observations for explicitly relevant modules:

```text
main game EXE
OptiScaler's loaded module
CapcomPatcher.asi
known OptiScaler proxy/core modules relevant to the current load topology
selected support DLLs only when directly relevant to the upstream path-spoof rule
```

For each observed module, record only data needed for classification:

```text
module basename
module base address / RVA-style identifier if needed
physical/path class: game_root | plugin_dir | game_subdir | system | other
GetModuleFileNameW path class
PEB/LDR FullDllName path class
PEB/LDR BaseDllName
whether the identities agree
```

Avoid logging arbitrary full user paths in normal diagnostic output. Prefer normalized/path-class output such as:

```text
[PathAudit] module=CapcomPatcher.asi load_class=plugin_dir win32_class=plugin_dir ldr_class=plugin_dir consistent=1
```

If an absolute path is essential for a developer-only capture, make it opt-in and clearly mark it as diagnostic.

### Diagnostic prohibitions

PR7 diagnostics must not:

```text
write to PEB/LDR entries
change UNICODE_STRING buffers
copy modules into _storage_
rename/move DLLs
hook GetModuleFileName
hook loader APIs
register a persistent DLL notification callback merely for convenience
poll the loader/module list
change search paths
change ModuleFileName visibility
```

A short read-only loader-list walk is acceptable if implemented safely and only outside `DllMain`.

Do not perform heap-heavy or lock-heavy investigation under loader lock.

---

# 10. Runtime evidence matrix

If selected games are available, collect the smallest matrix that can answer the path question.

For each available game:

| Configuration | Required observation |
|---|---|
| OptiScaler only | relevant module identities / stability baseline |
| OptiScaler + Capcom Patcher | same identities + whether Capcom Patcher changes them |
| REFramework comparison, if available | path-spoof-related logs/identity before and after upstream behavior |

Selected games:

```text
MHW
DD2
RE9
PRAGMATA
Onimusha WotS
MHS3
```

Do not fabricate results for unavailable games. Mark them `NOT RUN`.

This is not yet the final full 30-minute six-game certification matrix. Runtime collection in PR7 exists to answer the **module-path responsibility question** only.

Useful observations include:

```text
cold launch
module identity after OptiScaler ASI loading
identity after one representative game-dir/support DLL is loaded
whether REF actually changes an identity in the same game/build
whether any path-related anti-tamper penalty is observable
```

Do not treat unrelated XeFG swapchain/FG crashes as path-spoof evidence without a causal link.

---

# 11. Required output document

PR7 must add:

```text
doc/analysis/PR7_MODULE_PATH_SPOOFING_CLASSIFICATION_2026-09-09.md
```

The document must include:

1. **Executive conclusion:** `NOT_APPLICABLE`, `REQUIRED`, or `INCONCLUSIVE`.
2. Capcom Patcher base SHA.
3. REFramework source pins.
4. Exact `spoof_module_paths_in_exe_dir()` definition pin/path.
5. Current OptiScaler fork SHA and loader source path.
6. REFramework `_storage_` + call-site lifecycle.
7. Exact metadata mutated by the upstream utility.
8. Current OptiScaler/CapcomPatcher load topology diagram or ordered flow.
9. Four-identity comparison: disk / loader input / Win32-visible / PEB-visible.
10. Responsibility-equivalence table.
11. Runtime evidence table, including `NOT RUN` entries.
12. Final classification rationale.
13. Follow-up action.

Follow-up action must be exactly one of:

```text
NOT_APPLICABLE -> close module-path spoofing as intentionally omitted and move to final runtime validation/cleanup.

REQUIRED -> add a new focused implementation work order; do not implement in PR7.

INCONCLUSIVE -> retain deferred status and name the exact evidence-collection task required next.
```

---

# 12. README / architecture-plan updates

Update documentation only after the classification is defensible.

## If `NOT_APPLICABLE`

Update README and architecture plan to state that module-path spoofing was reviewed and is intentionally omitted because the REFramework responsibility is not present in the current topology.

Do not say merely "not needed". Preserve the reasoning/reference to the PR7 analysis.

After that change, the only remaining project phase should be:

```text
six-game runtime validation / cleanup
```

## If `REQUIRED`

Keep full parity status open and link the follow-up implementation work order/task.

## If `INCONCLUSIVE`

Keep module-path spoofing listed as unresolved/deferred.

Do not claim full REFramework anti-tamper parity.

---

# 13. Production-code policy for PR7

Default expectation:

```text
analysis/documentation only
```

A small read-only diagnostic helper is permitted only if it materially resolves the classification and cannot be obtained from an external/debug harness more safely.

PR7 must not introduce:

```text
production PEB writes
production module-path spoofing
_storage_ directory creation/copying
DLL relocation
loader hooks
LdrRegisterDllNotification production callback
new worker thread
polling
new anti-tamper byte patches
new DD2/RE9 patterns
OptiScaler source changes
DXGI / Present / ResizeBuffers changes
Special K integration
```

`PatchResult()` must remain `false`.

If code is added only for diagnostics, ensure it is disabled/removed from normal production behavior before merge unless there is a strong reason to retain bounded read-only diagnostics.

---

# 14. Safety requirements if reading PEB/LDR state

If PR7 needs direct loader metadata observation:

- run outside `DllMain`,
- use current-process structures only,
- hold the appropriate loader lock or use a documented safe enumeration method where required,
- do not retain raw pointers after the protected enumeration window,
- validate `UNICODE_STRING.Length/MaximumLength/Buffer` before reading,
- use SEH/fail-soft handling around unsafe process-internal reads if necessary,
- bound every string read,
- never write to any loader structure,
- never free memory owned by the loader,
- fail closed on malformed or changing entries.

Prefer a test/debug utility over adding fragile PEB parsing to the main ASI when possible.

---

# 15. Deterministic/static checks

PR7 is not expected to create a new large unit-test suite if it remains documentation-only.

At minimum verify:

```text
Capcom Patcher main SHA is current
REFramework pins resolve
exact upstream spoof function definition is captured
OptiScaler loader pin resolves
LoadAsiPlugins current behavior is correctly represented
PluginPath default/current semantics are documented
no production path mutation has been introduced
PatchResult remains false
PR0-PR6 files have no unrelated modifications
```

If a read-only path classifier/helper is added, add focused tests for:

```text
same path normalization
case-insensitive Windows path comparison
game_root vs plugin_dir vs subdir classification
relative path normalization
malformed/empty loader string -> Unknown, never guessed
no write-capable API in the helper
```

Run existing build/regression checks if production C++ is touched.

---

# 16. Build / verification policy

### Documentation-only result

Required:

```text
git diff --check
source-link/pin verification
final diff audit
```

A rebuild is not required solely because Markdown changed, but state that explicitly in the PR body.

### If any production C++ is touched

Required:

```text
x64 Debug build
x64 Release build
git diff --check
existing PR0-PR6 regressions
exports remain InitializeASI + PatchResult
PatchResult() remains false
```

No CI addition is required solely for PR7.

---

# 17. Reject invariants

PR7 is incorrect if any of the following occurs:

1. REFramework's path-spoof code is copied into Capcom Patcher without first proving equivalent responsibility.
2. `_storage_` is introduced merely because REFramework has it.
3. A PEB/LDR path is modified as part of classification.
4. `REQUIRED` is concluded only because REFramework calls the function.
5. `NOT_APPLICABLE` is concluded only because a short runtime did not crash.
6. `INCONCLUSIVE` is hidden behind a speculative implementation.
7. The exact upstream spoof-function definition is not located/pinned but the PR still claims a definitive classification.
8. Current `onehoon/OptiScaler` loader behavior is replaced with assumptions from upstream or older versions.
9. Physical disk path, loader input path, Win32-visible path, and PEB-visible path are conflated.
10. Runtime evidence from an unrelated XeFG/FG/swapchain failure is presented as module-path evidence without causality.
11. Unsupported/future games are used to justify a generic path-spoof subsystem.
12. PR7 adds a persistent worker/poller/loader hook for observation.
13. PR7 changes `PatchResult()`.
14. PR7 redesigns or changes PR0-PR6 anti-tamper mechanisms.

---

# 18. Suggested analysis flow

```text
A. Pin latest Capcom Patcher main.
B. Pin exact REFramework call sites.
C. Locate and pin exact spoof_module_paths_in_exe_dir() implementation.
D. Explain _storage_ lifecycle and actual metadata mutation.
E. Pin current onehoon/OptiScaler master.
F. Trace OptiScaler main/proxy load + PluginPath + LoadAsiPlugins + late ASI path.
G. Draw current CapcomPatcher.asi path topology.
H. Compare disk / loader-input / Win32 / PEB identities.
I. Decide whether static evidence is sufficient.
J. If not, collect bounded read-only runtime observations.
K. Produce responsibility-equivalence table.
L. Select exactly one classification.
M. Update README/architecture status consistently.
N. Open Draft PR with no production spoof mutation.
```

---

# 19. Completion criteria

PR7 is complete only when:

- [ ] branch is based on latest `main` containing merged PR6 (`54b82aa2...` or newer)
- [ ] exact REFramework call sites are pinned
- [ ] exact `spoof_module_paths_in_exe_dir()` implementation is located and pinned
- [ ] the exact loader metadata mutated upstream is documented
- [ ] `_storage_` creation/copy/reapply lifecycle is documented
- [ ] current `onehoon/OptiScaler` loader source is pinned
- [ ] `LoadAsiPlugins()` and default/configured `PluginPath` semantics are audited
- [ ] CapcomPatcher.asi's actual current load topology is documented
- [ ] disk / loader-input / Win32-visible / PEB-visible identities are separately evaluated
- [ ] REFramework-vs-current-topology responsibility table is complete
- [ ] runtime evidence is included where available and unavailable games say `NOT RUN`
- [ ] final result is exactly `NOT_APPLICABLE`, `REQUIRED`, or `INCONCLUSIVE`
- [ ] classification satisfies the evidence threshold in this work order
- [ ] no production module-path mutation is added in PR7
- [ ] no `_storage_` implementation is added in PR7
- [ ] no new persistent loader callback/worker/polling is added
- [ ] `PatchResult()` remains false
- [ ] `doc/analysis/PR7_MODULE_PATH_SPOOFING_CLASSIFICATION_2026-09-09.md` is added
- [ ] README/architecture-plan status matches the final classification
- [ ] required static/build checks for the actual changed-file scope pass
- [ ] PR is opened as Draft

---

# 20. Expected PR body

The PR body should report:

```text
Capcom Patcher base SHA
REFramework pin + exact spoof implementation pin
OptiScaler fork pin
upstream _storage_ / module-path lifecycle summary
current OptiScaler + Capcom Patcher load topology
four path identities
responsibility-equivalence table summary
runtime evidence / NOT RUN matrix
final classification: NOT_APPLICABLE | REQUIRED | INCONCLUSIVE
why that evidence threshold is satisfied
production code changed: yes/no
build/static verification
follow-up action
```

Do not use language such as "full parity achieved" unless the classification is closed appropriately **and** the later six-game runtime validation/cleanup phase has also been completed.
