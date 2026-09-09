# Capcom Patcher Architecture and REFramework Anti-Tamper Parity Plan

**Date:** 2026-09-09  
**Repository:** `onehoon/Capcom_Patcher`  
**Primary reference:** `praydog/REFramework` `IntegrityCheckBypass` behavior  
**Secondary reference:** hardened `DbgUiRemoteBreakin` proof-of-concept from `onehoon/OptiPatcher` PR #1  
**Target integration:** OptiScaler ASI loading path

---

## 1. Purpose

Capcom Patcher is a new, dedicated x64 ASI compatibility module for a deliberately small set of modern Capcom RE Engine titles that use anti-tamper mechanisms which can interfere with OptiScaler and other injected/modded code.

This project is **not** a continuation of the original generic OptiPatcher game-patching catalog. It should be treated as a new product with a new scope.

The goal is:

> Reproduce, as faithfully as practical, the anti-tamper mitigation behavior that current REFramework applies to the six explicitly supported games, while removing REFramework features that are unrelated to anti-tamper or unnecessary for an OptiScaler-focused ASI.

The project is intentionally conservative about upstream behavior. REFramework's anti-tamper code represents years of reverse engineering and game-update adaptation. A mitigation must not be discarded merely because one observed crash was solved by a smaller subset of that code.

At the same time, Capcom Patcher must not blindly copy REFramework features that only exist to support REFramework's own loader, overlay, application hooks, PAK system, or scripting runtime. Every imported behavior must be classified by purpose.

---

## 2. Explicit supported-game scope

Only the following games are in scope.

| Game | Internal profile | Current REF TDB family | RE anti-tamper flag | Intended support |
|---|---|---:|---:|---:|
| Monster Hunter Wilds | `MHWILDS` | 81 | true | Yes |
| Dragon's Dogma 2 | `DD2` | 83 | true | Yes |
| Resident Evil Requiem | `RE9` | 83 | true | Yes |
| PRAGMATA | `PRAGMATA` | 83 | true | Yes |
| Onimusha: Way of the Sword | `ONIMUSHA_WOTS` | 82 | true | Yes |
| Monster Hunter Stories 3: Twisted Reflection | `MHSTORIES3` | 82 | true | Yes |

Known executable identities should be represented explicitly and case-insensitively. At minimum:

- `MonsterHunterWilds.exe`
- `DD2.exe`
- `re9.exe`
- `PRAGMATA.exe`
- `OnimushaWotS.exe`
- `MONSTER_HUNTER_STORIES_3_TWISTED_REFLECTION.exe`

Known trial/demo executable aliases may be added only when intentionally supported and tested. They must not be enabled merely because REFramework recognizes them.

### Hard scope rule

**Do not use TDB version as an automatic future-game opt-in.**

REFramework can reasonably use conditions such as `tdb_ver() >= 82` because it is a general RE Engine framework that continuously tracks new releases. Capcom Patcher has a different goal. It must use an explicit allowlist so a future TDB 84/85 Capcom game is never patched accidentally.

A future game requires a new profile, review, and test evidence before activation.

---

## 3. Why a new repository is preferable to extending OptiPatcher

The original OptiPatcher primarily exists to patch game-side DLSS/DLSSG/vendor checks for many unrelated titles. Its `CheckForPatch()` contains a broad catalog of per-game patterns and its `PatchResult()` is consumed by OptiScaler as a signal that game patching succeeded.

Capcom Patcher has a fundamentally different responsibility:

- Capcom RE Engine only.
- Six explicitly allowed games only.
- Anti-tamper stability, not DLSS exposure.
- Long-lived runtime guards and watchers.
- RE Engine-specific renderer heartbeat logic.
- Game-memory integrity/crash mitigation.
- No generic Unreal/UE game patch catalog.

Therefore the new repository should not import the old OptiPatcher `CheckForPatch()` game list.

The only OptiPatcher material that should be considered for reuse is:

1. minimal ASI/DLL build structure,
2. small generic utility code if still useful,
3. the already-hardened Capcom `DbgUiRemoteBreakin` watcher from PR #1,
4. attribution/license notices for reused code.

---

## 4. Investigation result: the current watcher is necessary but not sufficient for parity

The `DbgUiRemoteBreakin` proof-of-concept was successful and remains important. It demonstrated a common delayed-crash mechanism in multiple RE Engine titles:

```text
Capcom anti-tamper
    -> modifies ntdll!DbgUiRemoteBreakin
    -> E9 or FF 25 redirect
    -> executable private-memory payload
    -> payload eventually participates in the penalty/crash path

REFramework
    -> detects modified DbgUiRemoteBreakin
    -> resolves redirect target
    -> neutralizes private executable payload
    -> restores DbgUiRemoteBreakin
```

The hardened OptiPatcher implementation improved on the original REFramework watcher in several safety areas:

- full 32-byte observed-entry identity,
- safe FF25 pointer-slot reads,
- `MEM_COMMIT + MEM_PRIVATE + executable` validation,
- final hook/target/region revalidation before destructive write,
- race-aware restore,
- `FlushInstructionCache`,
- baseline contamination rejection,
- immediate synchronous first check before relying on the polling worker,
- non-spamming diagnostic state.

However, REFramework does much more than this watcher for the selected six games.

The selected-game parity effort therefore needs several independent layers.

---

## 5. REFramework anti-tamper layers relevant to this project

The current REFramework architecture contains the following major layers that are relevant to the selected games.

### Layer A - pristine `NtProtectVirtualMemory` / `VirtualProtect` protection

REFramework captures a pristine copy of `NtProtectVirtualMemory` very early and later checks whether the original syscall stub has been modified. Its `VirtualProtect` guard can restore the expected bytes when anti-tamper modifies them.

Purpose: prevent anti-tamper from corrupting or redirecting a critical memory-protection primitive used by the mod framework.

### Layer B - vectored exception handler registration protection

For modern TDB versions REFramework hooks `AddVectoredExceptionHandler` and prevents an early unapproved VEH registration while permitting known/allowed handlers.

Purpose: prevent a hostile/penalty exception path from registering before the framework's expected state is established.

### Layer C - `RtlExitUserProcess` protection

REFramework hooks `RtlExitUserProcess` and uses direct process termination instead of allowing the normal FLS/TLS cleanup sequence in the problematic path. The upstream comments explicitly state that the normal exit path can call heap-allocated code that no longer exists and crash.

This is particularly relevant to Capcom Patcher because the DbgUi watcher intentionally neutralizes an executable private-memory payload. Exit-time stale callback state therefore cannot be dismissed as an unrelated REFramework problem.

### Layer D - `DbgUiRemoteBreakin` watcher

This is the layer already proven in the OptiPatcher PoC and should be imported in its hardened form, not downgraded to the older REFramework implementation.

### Layer E - DD2-family anti-tamper bypass

REFramework's `immediate_patch_dd2()` contains several categories of logic. Some are anti-tamper and some are REFramework mod-loading conveniences. They must be separated rather than copied wholesale.

Anti-tamper-relevant behavior includes, depending on game build:

- scanner/crasher function suppression,
- renderer corruption mitigation around `createBLAS`,
- preservation of the `corruption_when_zero` value,
- DD2-family anti-tamper constants,
- anti-tamper penalty-path control-flow patches where purpose is confirmed.

Unrelated PAK/loose-file behavior inside the same function must not be imported merely because it shares the same upstream function.

### Layer F - RE9-family anti-tamper bypass

For TDB82+ games REFramework contains another anti-tamper family originally discovered while investigating RE9 and later confirmed in MHS3.

The current behavior includes:

- RE9-family anti-tamper constant replacement,
- BushClover/manual-map fake-UD2 mitigation,
- thread-scheduler corruption mitigation,
- JobQueue submission-site fallback protection,
- PE-header integrity-check protection when the pattern is found,
- RE9-only slow-path discriminator patch.

The source comments explicitly describe a penalty mechanism that finds UD2 gadgets and replaces legitimate scheduler job pointers with those gadgets.

### Layer G - renderer heartbeat bypass

This is one of the most important modern mechanisms.

The current REFramework implementation was developed after repeated obfuscation changes made direct RE9/MHS3 anti-tamper patterns fragile. Instead of continuously chasing the final penalty branch, it detects the state that causes the penalty branch.

Observed behavior:

- the renderer contains a cluster of six heartbeat/frame-like values,
- the values normally trail or match the renderer's frame counter,
- setting one to zero can activate a severe lag/crash penalty path,
- synchronizing all six values to the actual frame counter forces the clean state,
- REFramework identifies the cluster with sentinels and repeated confirmations before writing,
- after confirmation it synchronizes the six values every frame.

This is a preferred long-term mechanism because it targets a higher-level invariant instead of one obfuscated branch sequence.

### Layer H - stack destroyer mitigation

REFramework searches for a known stack-destroyer penalty path and patches the target to return immediately when a valid target is found.

This must remain fail-closed: no match or an ambiguous match means no patch.

---

## 6. Game-by-game evidence and required profiles

This section distinguishes three evidence levels:

- **Observed** - seen in the existing working REF + OptiScaler logs.
- **Upstream explicit** - REFramework source/history explicitly says the mechanism exists for the game/family.
- **Profile parity** - enabled because current REFramework intentionally applies the mechanism to that selected game, even though the current local log set has not yet shown a successful runtime hit.

### 6.1 Monster Hunter Wilds

Current REFramework family: TDB81.

Existing working logs show all of the following actually occurring:

- `Found crasher_fn_ref`
- `Found crasher fn (real)`
- `Found scanner_fn_middle`
- `Found scanner_fn`
- `Patched scanner_fn`
- `Patched crasher_fn`
- `Found createBLAS`
- `Found corruption_when_zero`
- `Hooked createBLAS`
- `Patched 5 sus_constants! (DD2+ variant)`
- later, `DbgUiRemoteBreakin` FF25/private-heap neutralization and restore

Therefore MHW must not be represented as "Dbg watcher only" in the final project.

Required profile:

```text
MHW
  Common runtime guards
  DbgUiRemoteBreakin watcher
  DD2-family anti-tamper core
  No RE9-family layer
  No heartbeat layer unless future upstream behavior changes
```

### 6.2 Dragon's Dogma 2

Current REFramework family: TDB83.

Existing logs show:

- `Found createBLAS`
- `Found corruption_when_zero`
- `Hooked createBLAS`
- DD2-family startup scanning
- RE9-family scan also runs
- `Patched 1 sus_constants! (RE9+)`
- direct thread-scheduler corruptor was not found in the sampled build
- REFramework therefore installed the `JobQueue::SubmitDescriptor` fallback at multiple call sites
- `DbgUiRemoteBreakin` private executable payload was observed and neutralized

Required profile:

```text
DD2
  Common runtime guards
  DbgUiRemoteBreakin watcher
  DD2-family anti-tamper core
  RE9-family common anti-tamper core
  JobQueue safety fallback
  Heartbeat support
  No RE9-only slow-path discriminator
```

Heartbeat is enabled because current REF executes the TDB82+ heartbeat path for DD2. A successful heartbeat-cluster hit has not yet been observed in the current DD2 log set, so diagnostics must distinguish "enabled" from "cluster confirmed".

### 6.3 Resident Evil Requiem

Current REFramework family: TDB83.

Existing logs show:

- DD2-family `createBLAS` corruption guard active,
- RE9+ anti-tamper constant patched,
- RE9 slow-path discriminator found and patched,
- JobQueue fallback hooks installed even as backup protection,
- `DbgUiRemoteBreakin` private executable payload observed and neutralized.

The RE9 slow-path implementation is explicitly guarded by `GameIdentity::is_re9()` in current REFramework and therefore must **not** automatically be shared with other TDB82+ profiles.

Required profile:

```text
RE9
  Common runtime guards
  DbgUiRemoteBreakin watcher
  DD2-family anti-tamper core
  RE9-family common anti-tamper core
  RE9-only slow-path discriminator
  JobQueue safety fallback
  PE-header integrity protection when validated
  Heartbeat support
```

### 6.4 PRAGMATA

Current REFramework family: TDB83.

PRAGMATA is a critical counterexample to the idea that the Dbg watcher alone represents the relevant anti-tamper logic.

Existing logs show:

- DD2-family `createBLAS` / corruption guard active,
- RE9-family path executed,
- multiple JobQueue integrity-check call sites hooked,
- no `DbgUiRemoteBreakin` hook event was observed in the sampled session,
- **heartbeat cluster was actually found at renderer + 0x32A0 after three confirmations and synchronized every frame.**

Thus the heartbeat bypass is demonstrated to be active even in a game where OptiScaler-only already appeared stable during the sampled test.

Required profile:

```text
PRAGMATA
  Common runtime guards
  DbgUiRemoteBreakin watcher
  DD2-family anti-tamper core
  RE9-family common anti-tamper core
  JobQueue safety fallback
  Heartbeat support
  No RE9-only slow-path discriminator
```

### 6.5 Onimusha: Way of the Sword

Current REFramework family: TDB82 and `reengine_at=true`.

The initial REFramework support addition mainly registered GameIdentity information; no large Onimusha-only anti-tamper function was added. That means it intentionally inherits the current TDB82 anti-tamper stack.

Current evidence does not yet show which individual patterns actually match at runtime in an Onimusha working log. Therefore the correct design is not to omit the family, but to enable the same selected-game profile with strict fail-closed pattern validation.

Required profile:

```text
Onimusha WotS
  Common runtime guards
  DbgUiRemoteBreakin watcher
  DD2-family anti-tamper core
  RE9-family common anti-tamper core
  JobQueue safety fallback where valid
  Heartbeat support
  No RE9-only slow-path discriminator
```

### 6.6 Monster Hunter Stories 3: Twisted Reflection

Current REFramework family: TDB82.

MHS3 has unusually strong upstream evidence.

REFramework history explicitly integrated the RE9 anti-tamper fixes into MHS3 after discovering the same class of mechanism there. Subsequent updates described the earlier MHS3-specific approach as fragile. The later robust fix introduced the renderer heartbeat strategy after analyzing the penalty path.

Important implementation rule:

> Do not port the old MHS3 UD2-writer-anchor fallback that is currently disabled with `#if 0` in REFramework.

It is historical/debugging material, not the current active solution.

Required profile:

```text
MHS3
  Common runtime guards
  DbgUiRemoteBreakin watcher
  DD2-family anti-tamper core
  RE9-family common anti-tamper core
  JobQueue safety fallback
  Heartbeat support
  No RE9-only slow-path discriminator
```

---

## 7. Feature/profile matrix

Legend:

- `ON` - feature is part of the explicit selected-game profile.
- `RE9 ONLY` - never inherited by TDB number.
- `FAIL-CLOSED` - scan/validation failure leaves the game untouched.

| Feature | MHW | DD2 | RE9 | PRAGMATA | Onimusha | MHS3 |
|---|---:|---:|---:|---:|---:|---:|
| Early runtime guards | ON | ON | ON | ON | ON | ON |
| DbgUi watcher | ON | ON | ON | ON | ON | ON |
| DD2-family anti-tamper core | ON | ON | ON | ON | ON | ON |
| RE9-family common core | Off | ON | ON | ON | ON | ON |
| RE9 slow-path discriminator | Off | Off | RE9 ONLY | Off | Off | Off |
| JobQueue integrity-job defense | Off/default | ON | ON | ON | ON | ON |
| PE-header integrity defense | Off/default | FAIL-CLOSED | FAIL-CLOSED | FAIL-CLOSED | FAIL-CLOSED | FAIL-CLOSED |
| Heartbeat service | Off | ON | ON | ON | ON | ON |
| Stack-destroyer scan | FAIL-CLOSED | FAIL-CLOSED | FAIL-CLOSED | FAIL-CLOSED | FAIL-CLOSED | FAIL-CLOSED |

The exact DD2-family sub-features must also be profile-aware because patterns may not exist in every build. A feature can be enabled while reporting `not found / no patch applied` without treating startup as a fatal error.

---

## 8. Architecture principles

### 8.1 Preserve upstream behavior before attempting clever simplification

The first production-quality implementation should favor behavior parity with current REFramework over local reinvention.

Where the REFramework algorithm is known and still active:

- preserve its control-flow intent,
- preserve its validation conditions,
- preserve its failure behavior,
- then add safety hardening where the existing OptiPatcher PoC has already demonstrated a safer implementation.

### 8.2 Separate mechanisms by purpose

Do not create one giant `IntegrityCheckBypass.cpp` clone.

The new project should split mechanisms so a future game update can disable or repair only the broken unit.

### 8.3 Fail closed for destructive patching

Any operation that changes executable game memory, function pointers, scheduler jobs, or executable private regions must require:

1. a uniquely identified candidate,
2. expected memory ownership/range,
3. expected instruction semantics,
4. a final revalidation immediately before write,
5. instruction-cache flush for executable-code changes,
6. one-time diagnostics describing what was changed.

An ambiguous or stale candidate is skipped.

### 8.4 Explicit game profiles, not version inheritance

No `if (tdb >= 82) enable everything` policy in the new project.

Each supported executable resolves to one immutable profile.

### 8.5 Do not mix anti-tamper success with OptiScaler game-patching success

OptiScaler's ASI loader may inspect an exported `PatchResult()`. In existing OptiPatcher, a true result means game-side patching succeeded and may change spoofing behavior.

Capcom Patcher must not return true simply because an anti-tamper guard is active.

Preferred compatibility behavior:

```cpp
extern "C" __declspec(dllexport) bool PatchResult()
{
    return false;
}
```

or omit the export if the currently targeted OptiScaler loader is confirmed to handle a missing `PatchResult()` without side effects.

`InitializeASI()` remains the normal post-load initialization entry point.

### 8.6 No runtime unload promise

The project should assume process-lifetime hooks/patches. Do not advertise hot unload. If module lifetime could become detached while hooks or workers remain active, pin the module or otherwise enforce process lifetime.

---

## 9. Proposed source layout

```text
Capcom_Patcher/
├─ CMakeLists.txt / project files
├─ LICENSE
├─ THIRD_PARTY_NOTICES.md
├─ README.md
│
├─ doc/
│  └─ CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md
│
├─ src/
│  ├─ dllmain.cpp
│  ├─ CapcomPatcher.cpp
│  ├─ CapcomPatcher.hpp
│  │
│  ├─ game/
│  │  ├─ GameId.hpp
│  │  ├─ GameDetector.cpp
│  │  ├─ GameDetector.hpp
│  │  ├─ GameProfile.cpp
│  │  └─ GameProfile.hpp
│  │
│  ├─ runtime/
│  │  ├─ PristineSyscall.cpp
│  │  ├─ PristineSyscall.hpp
│  │  ├─ VirtualProtectGuard.cpp
│  │  ├─ VirtualProtectGuard.hpp
│  │  ├─ VehGuard.cpp
│  │  ├─ VehGuard.hpp
│  │  ├─ ProcessExitGuard.cpp
│  │  └─ ProcessExitGuard.hpp
│  │
│  ├─ antitamper/
│  │  ├─ DbgUiRemoteBreakinWatcher.cpp
│  │  ├─ DbgUiRemoteBreakinWatcher.hpp
│  │  ├─ DD2FamilyBypass.cpp
│  │  ├─ DD2FamilyBypass.hpp
│  │  ├─ RE9FamilyBypass.cpp
│  │  ├─ RE9FamilyBypass.hpp
│  │  ├─ JobQueueGuard.cpp
│  │  ├─ JobQueueGuard.hpp
│  │  ├─ HeartbeatBypass.cpp
│  │  ├─ HeartbeatBypass.hpp
│  │  ├─ StackDestroyerBypass.cpp
│  │  └─ StackDestroyerBypass.hpp
│  │
│  ├─ reengine/
│  │  ├─ RendererLocator.cpp
│  │  ├─ RendererLocator.hpp
│  │  ├─ TypeDatabaseAdapter.cpp
│  │  └─ TypeDatabaseAdapter.hpp
│  │
│  ├─ hook/
│  │  ├─ HookBackend.hpp
│  │  └─ ... minimal hook wrappers ...
│  │
│  ├─ memory/
│  │  ├─ MemoryQuery.cpp
│  │  ├─ MemoryQuery.hpp
│  │  ├─ PatternScan.cpp
│  │  ├─ PatternScan.hpp
│  │  ├─ Patch.cpp
│  │  ├─ Patch.hpp
│  │  ├─ InstructionValidation.cpp
│  │  └─ InstructionValidation.hpp
│  │
│  ├─ threading/
│  │  ├─ ThreadSuspender.cpp
│  │  └─ ThreadSuspender.hpp
│  │
│  └─ log/
│     ├─ Log.cpp
│     └─ Log.hpp
│
└─ third_party/
   └─ pinned dependencies / notices
```

This is a logical architecture, not a requirement that every file exist in the first PR. Small modules may be combined if doing so does not blur responsibilities.

---

## 10. Game profile design

Use a compile-time or immutable runtime profile, for example:

```cpp
enum class GameId
{
    Unknown,
    MHWILDS,
    DD2,
    RE9,
    PRAGMATA,
    ONIMUSHA_WOTS,
    MHSTORIES3,
};

struct GameProfile
{
    GameId id{};
    const wchar_t* executable{};

    bool enable_common_runtime_guards{};
    bool enable_dbgui_watcher{};
    bool enable_dd2_family{};
    bool enable_re9_family{};
    bool enable_re9_slow_path{};
    bool enable_jobqueue_guard{};
    bool enable_pe_header_guard{};
    bool enable_heartbeat{};
    bool enable_stack_destroyer_scan{};
};
```

The table must be manually populated for the six supported games. No inferred inheritance from version numbers.

Development-only aliases for demos/trials should be separately visible so they cannot silently become production support.

---

## 11. Initialization and lifecycle

Timing is part of the anti-tamper behavior. REFramework deliberately installs some protection extremely early.

### 11.1 `DLL_PROCESS_ATTACH`

Keep DllMain limited, but preserve the behaviors that genuinely require an early baseline or early interception.

Recommended initial behavior:

```text
DLL_PROCESS_ATTACH
  -> DisableThreadLibraryCalls
  -> detect executable using loader-safe Win32 calls
  -> unsupported game: do nothing and return
  -> save module handle / pin policy state
  -> capture pristine/clean ntdll protection baseline
  -> install only the early guards whose timing is proven necessary
```

Do **not**:

- create the polling worker here,
- scan the whole game image here,
- perform heartbeat discovery here,
- suspend large thread sets here,
- initialize the RE Engine type system here.

REFramework currently performs more work under loader lock than ideal. Capcom Patcher should preserve required timing while avoiding unnecessary loader-lock work.

For the first parity implementation, if an early VEH/exit hook must remain in `DLL_PROCESS_ATTACH` to match upstream timing, isolate that decision and document it. It should be easy to A/B move the hook to the first line of `InitializeASI()` later if tests prove the timing window is irrelevant.

### 11.2 `InitializeASI()`

OptiScaler calls `InitializeASI()` after loading a normal `.asi` module. This should become the main initialization coordinator.

Recommended sequence:

```text
InitializeASI
  -> validate selected-game profile
  -> finish common runtime-guard installation
  -> install VirtualProtect / NtProtect protection
  -> create scoped thread-suspension window for startup scanning/patching
      -> DD2-family startup bypass
      -> RE9-family startup bypass when profile enables it
      -> RE9-only slow path when profile is RE9
      -> stack-destroyer scan
  -> resume threads
  -> initialize DbgUi watcher
      -> synchronous immediate check
      -> start polling worker
  -> initialize heartbeat service if profile enables it
  -> mark initialized
```

Initialization must be idempotent.

---

## 12. Common runtime guards

### 12.1 Pristine `NtProtectVirtualMemory`

Do not rely only on a late live-memory snapshot.

Requirements:

- acquire a known-clean reference for the relevant syscall bytes as early as practical,
- retain the original comparison span needed by the upstream algorithm,
- detect live modification,
- fail closed if a clean reference cannot be established with confidence,
- never treat an already redirected live entry as a trusted clean baseline.

The earlier OptiPatcher review identified exactly this class of contamination risk for `DbgUiRemoteBreakin`; the same principle applies here.

### 12.2 VirtualProtect guard

Port the anti-tamper behavior, not REFramework-specific logging/ownership assumptions.

The guard should:

- verify the pristine syscall state when relevant memory-protection operations occur,
- restore only when the expected original identity is established,
- avoid recursive guard behavior,
- serialize repair operations,
- emit a one-time warning when a repair was required.

### 12.3 VEH guard

This is high-risk code because legitimate software can use VEH.

Port requirements:

- preserve the upstream concept of allowing known-safe callers,
- identify Capcom/anti-tamper registration separately from the patcher and OptiScaler's legitimate handlers,
- never blanket-block every `AddVectoredExceptionHandler` call,
- log the caller module/path and decision in debug builds,
- keep the production log concise.

Before production enablement, test with:

- OptiScaler itself,
- Intel XeFG path,
- Steam overlay,
- NVIDIA/AMD overlays where applicable,
- crash handlers present in the game directory.

### 12.4 Process exit guard

Preserve upstream motivation: avoid an unsafe normal exit cleanup path after anti-tamper heap code has been invalidated.

A useful Capcom Patcher refinement is to track whether the process has actually entered a destructive anti-tamper-neutralization state and allow the fast exit policy to be conditionally armed.

Example state:

```cpp
std::atomic<bool> g_antiTamperPayloadNeutralized{false};
```

However, do not weaken parity merely to make this conditional unless runtime testing proves the condition is sufficient. Start from upstream behavior, then narrow only with evidence.

---

## 13. Hardened `DbgUiRemoteBreakin` watcher

Use the hardened PR #1 implementation as the starting point.

Required behavior:

1. resolve `ntdll!DbgUiRemoteBreakin`,
2. establish a trustworthy baseline,
3. detect full-entry change,
4. support current `E9 rel32` and `FF 25 rel32` forms,
5. safely read FF25 slot,
6. resolve current target,
7. require executable `MEM_PRIVATE` target,
8. snapshot target region identity,
9. re-read entry and FF25 target immediately before neutralization,
10. re-query target region immediately before neutralization,
11. fill validated region with `RET` only after final validation,
12. restore original protection,
13. flush instruction cache,
14. revalidate observed DbgUi entry before restoring baseline,
15. restore and flush,
16. poll at a low frequency consistent with upstream behavior,
17. perform one synchronous initial check before relying on worker scheduling.

Do not regress to REFramework's older `IsBadReadPtr` / first-8-byte-only implementation.

The project should log unsupported future hook forms without attempting to guess.

---

## 14. DD2-family bypass extraction

`immediate_patch_dd2()` cannot be copied as one unit because it mixes multiple responsibilities.

### 14.1 Import: scanner/crasher mitigation

MHW logs prove the scanner/crasher path is active in a currently supported target.

Port the current active upstream algorithm and associated semantic checks.

Requirements:

- locate expected scanner/crasher references,
- validate function boundaries where upstream does so,
- patch only when the candidate is unique/valid,
- preserve original bytes for diagnostics,
- do not fail the whole patcher if a game update removes one pattern.

### 14.2 Import: `createBLAS` renderer-corruption mitigation

Current upstream behavior:

- find `createBLAS`,
- identify the renderer corruption state (`corruption_when_zero`),
- hook the `createBLAS` function,
- if the value was forced to zero, restore the last non-zero value,
- update the saved non-zero value.

This mechanism is confirmed by existing MHW, DD2, RE9, and PRAGMATA logs.

This should be a first-class module rather than buried inside a generic scan function.

### 14.3 Import: DD2-family anti-tamper constants

Port only constants/patterns whose purpose is anti-tamper penalty/crash avoidance.

Pattern match rules:

- match count must be logged,
- unexpected match counts are diagnostic warnings,
- code/data range must be verified,
- final bytes must be revalidated before patching.

### 14.4 Exclude: PAK and loose-file features

Do not import the following merely because they are located in `immediate_patch_dd2()`:

- restoring unencrypted PAK behavior,
- patch-file count support,
- `/natives/` string manipulation for loose files,
- generic REFramework asset/mod-loading behavior.

These serve REFramework's mod-loading system, not the narrow anti-tamper objective of Capcom Patcher.

If a specific conditional branch inside this area is later proven to be both anti-tamper and PAK-related, split that logic explicitly rather than importing the whole PAK path.

---

## 15. RE9-family bypass extraction

### 15.1 BushClover / RE9+ constants

Current upstream comments identify a manually mapped component that can produce a fake UD2 exception through crafted exception dispatch.

Port the currently active constant-patch mechanism with strict validation.

### 15.2 Thread-scheduler corruption defense

The upstream analysis states that obfuscated anti-tamper code can replace normal scheduler job pointers with pointers to UD2 gadgets.

Any direct patch of the corruptor must remain pattern- and semantic-validation based.

### 15.3 JobQueue fallback

This is not merely a theoretical fallback. Existing DD2, RE9, and PRAGMATA logs show multiple call-site hooks being installed.

Port the fallback logic so a suspicious/invalid submitted job pointer can be replaced with a harmless no-op job rather than executed.

Requirements:

- preserve the upstream register-specific call-site handling,
- validate call-site shape before installing a hook,
- validate candidate job pointer at runtime,
- use structured exception protection around unsafe pointer probing,
- replace only the invalid/suspicious target,
- never mutate all jobs indiscriminately.

### 15.4 RE9-only slow-path discriminator

This must be tied to the explicit RE9 profile, not TDB version.

Current upstream behavior finds a validated discriminator and NOPs the conditional so the clean dispatch path remains selected.

Do not apply this to MHS3/PRAGMATA/DD2/Onimusha simply because those games share the broader RE9-family anti-tamper logic.

### 15.5 PE-header integrity protection

Current upstream searches for a PE-header integrity-check path and, when found, redirects the check toward a clean copied header region.

This should be ported as a fail-closed optional protection:

- no candidate -> log and continue,
- ambiguous/invalid candidate -> do not patch,
- valid candidate -> apply exact upstream behavior.

Do not make failure to find this pattern fatal to the entire ASI.

---

## 16. Heartbeat bypass architecture

This is the largest standalone-porting challenge because current REFramework obtains:

- `via.render.Renderer`,
- the renderer native singleton,
- `get_RenderFrame()`,

through its RE Engine SDK/type database.

Capcom Patcher should **not** replace the heartbeat algorithm with a more fragile fixed offset per game.

### 16.1 Preserve the upstream runtime invariant algorithm

Required behavior:

- only for explicit profiles that enable heartbeat,
- wait until renderer/type access is valid,
- obtain actual render frame count,
- scan the renderer memory window used by the upstream algorithm,
- locate six contiguous heartbeat values,
- require sentinel `1` before and sentinel `0` after the cluster,
- accept the known early state where heartbeat[0] is still zero while the others are valid,
- require values to be positive, not ahead of frame count, and within the allowed distance,
- intersect candidates across multiple independent frames,
- require a single candidate and at least three confirmations,
- only then store the heartbeat pointer,
- synchronize all six values to the actual frame count every frame,
- if candidates disappear before confirmation, restart discovery.

Current upstream constants to preserve initially:

```text
HEARTBEAT_COUNT = 6
CONFIRMATIONS_NEEDED = 3
MAX_DISTANCE = 1000
scan window approximately renderer + 0x2000 .. +0x4000
```

If these constants change upstream, treat that as an anti-tamper compatibility update and review before importing.

### 16.2 Renderer/type access strategy

Do not vendor the whole REFramework SDK if only a small subset is required.

Preferred architecture:

```text
HeartbeatBypass
    -> RendererLocator interface
        -> minimal RE Engine TypeDB / native-singleton adapter
            -> only the pieces required to locate via.render.Renderer
               and get_RenderFrame
```

The first implementation may adapt a pinned subset of REFramework's SDK code to preserve known-good discovery behavior. Keep that code behind a narrow adapter so it can later be reduced without changing heartbeat logic.

Do not introduce a fixed per-game heartbeat offset as the primary implementation. Known offsets such as PRAGMATA `renderer+0x32A0` are diagnostics, not architecture.

---

## 17. Stack-destroyer bypass

Port as an independent, optional fail-closed scan.

Rules:

- search only on profiles that explicitly enable it,
- require expected instruction/function structure,
- patch target to immediate return only after validation,
- no pattern match is not fatal,
- unexpected multiple matches must not be guessed between.

Existing sampled builds often log that the stack destroyer was not found, which is acceptable.

---

## 18. REFramework behavior intentionally not ported

This section is important. These are not arbitrary omissions; they do not have an equivalent responsibility in the new ASI.

### 18.1 Generic OptiPatcher game patches

Delete/omit all existing unrelated game catalog logic:

- Unreal DLSS checks,
- vendor checks,
- unrelated inline patch catalog,
- generic `CheckForPatch()` branches.

### 18.2 `ignore_application_entries()`

REFramework uses this to prevent **its own Application Hooks system** from hooking specific RE Engine application entries.

Capcom Patcher does not have REFramework's Application Hooks subsystem, so there is nothing equivalent to ignore. Porting the function without that subsystem would be meaningless.

### 18.3 PAK / `/natives/` / loose-file behavior

These are REFramework mod-loading features, not required for OptiScaler anti-tamper compatibility.

### 18.4 Overlay, renderer-hook, scripting, SDK UI features

No REFramework overlay or menu is part of this project.

### 18.5 Automatic module-path spoofing by default

REFramework relocates/proxies modules through its own `_storage_` architecture and therefore has reasons to spoof module paths back toward the game directory.

Capcom Patcher should not blindly reproduce `_storage_` path semantics it does not own.

However, module-path checks remain a tracked investigation item. If OptiScaler's actual loading arrangement triggers the same anti-tamper path in one of the selected games, add a **scoped Capcom Patcher path-spoof module** with evidence and explicit profile enablement.

This is an intentional architecture-context distinction, not a claim that the upstream code is unnecessary.

**PR7 review (2026-09-09):** `doc/analysis/PR7_MODULE_PATH_SPOOFING_CLASSIFICATION_2026-09-09.md` audited the exact upstream implementation (`cursey/kananlib@8c27b65` `src/Module.cpp:479` — it walks the PEB loader list and rewrites `LDR_DATA_TABLE_ENTRY.FullDllName` for **any** loaded non-exe DLL whose loader directory is the game exe directory; the `_storage_` file copy is the routine's output, not an input condition, and after an `error_code` copy failure it still rewrites to the `_storage_` path) against the current OptiScaler fork (`onehoon/OptiScaler@3809b221`: `LoadAsiPlugins()` loads `CapcomPatcher.asi` from the configured `PluginPath` verbatim via `LdrLoadDll`; `LoadLibraryExW_Ldr` / `hkLdrLoadDll` do no path rewriting; no `_storage_` equivalent). Classification: **`INCONCLUSIVE`**. Per module: the **OptiScaler proxy DLL is a game-root DLL** and therefore inside the upstream spoof-eligible set, but its disk / `GetModuleFileNameW` / PEB identities are consistent and nothing rewrites them; `CapcomPatcher.asi` is a game-*subdirectory* module — `<gamedir>\OptiScaler\plugins\` by default (`MainDllPath` defaults to `<exe dir>\OptiScaler`, not `<exe dir>`), or `<gamedir>\plugins\` only on fallback — which the upstream rule skips; its exact loader-input string is relative-vs-absolute-dependent on `PluginPath` config and not statically proven equal to its PEB string. It is not `NOT_APPLICABLE` because a spoof-eligible game-root module (the proxy) exists and no selected-game loader-path check was located / no runtime identity observation was possible; not `REQUIRED` because there is no positive penalty evidence. Module-path spoofing stays **deferred**; the analysis names the read-only evidence-collection tasks (loader-identity snapshot incl. the OptiScaler proxy; non-default `PluginPath` A/B; game-side check location; REF before/after capture) to be run in the six-game runtime validation phase. No production spoof / `_storage_` / PEB write was added.

### 18.6 Disabled historical MHS3 code

Do not import code currently disabled with `#if 0`, including the old UD2-writer-anchor fallback, unless a future upstream change reactivates it and provides a reason.

---

## 19. Memory safety and patching rules

Every patching module should use shared safety primitives.

### 19.1 Safe read

- `VirtualQuery` range validation,
- `MEM_COMMIT`,
- readable protection,
- overflow-safe address arithmetic,
- exact-size read.

### 19.2 Safe executable target validation

Require expected memory type and executable protection for dynamically generated anti-tamper payloads.

### 19.3 Patch identity

A patch object should record:

```cpp
struct PatchRecord
{
    uintptr_t address{};
    std::vector<std::byte> expected;
    std::vector<std::byte> replacement;
    std::vector<std::byte> original;
    const char* mechanism{};
};
```

Before applying:

```text
scan candidate
 -> semantic validation
 -> read expected bytes
 -> final re-read immediately before write
 -> write
 -> FlushInstructionCache when executable
 -> verify replacement
```

### 19.4 Thread suspension

For startup patches that REFramework applies while other threads are suspended, preserve the same atomicity intention.

Build a scoped `ThreadSuspender` that:

- never suspends the current thread,
- handles threads created/disappearing during enumeration safely,
- always resumes acquired thread handles on scope exit,
- does not leave the game suspended after an exception.

Do not suspend threads around the long-lived Dbg watcher or heartbeat loop.

---

## 20. Hook backend and dependencies

Avoid reimplementing complex inline/mid-function hooks by hand merely to reduce dependency count.

Use a pinned, reviewed hook backend suitable for:

- normal function detours,
- call-site or mid-function context hooks,
- trampoline lifetime for process duration.

Where code is adapted from REFramework, preserve the relevant SafetyHook/MinHook semantics or provide a tested equivalent.

The heartbeat runtime algorithm does **not** require the developer-time emulator/asmjit machinery that was used by praydog to discover the invariant. Do not vendor analysis-only dependencies unless active runtime code truly needs them.

---

## 21. Logging and diagnostics

Use one project prefix, for example:

```text
[CapcomPatcher]
[CapcomPatcher][DbgUi]
[CapcomPatcher][DD2Family]
[CapcomPatcher][RE9Family]
[CapcomPatcher][Heartbeat]
```

### Normal log level

Normal users should be able to provide one log that is sufficient for initial triage.

Log once for:

- detected game/profile,
- each enabled mechanism,
- each successful startup patch count,
- fallback activation,
- DbgUi hook type/validated target event,
- heartbeat cluster confirmation,
- actual syscall repair,
- actual blocked VEH,
- actual process-exit guard use,
- unsupported hook/pattern form.

### Debug log level

Debug mode may include:

- pattern candidates,
- candidate rejection reason,
- call-site register selection,
- heartbeat candidate intersections,
- memory-protection details,
- caller modules for VEH decisions.

Do not spam the normal log every 500 ms or every frame.

---

## 22. Update-resilience policy

Capcom anti-tamper code changes across game updates. The project must make breakage diagnosable and safe.

### 22.1 No blind patch after mismatch

If an expected signature or semantic relationship changes, skip the patch and report it.

### 22.2 Prefer invariants over brittle patterns

The heartbeat approach is a model for future work: when upstream replaces a brittle direct pattern with a higher-level invariant, prefer the active upstream invariant.

### 22.3 Preserve exact upstream provenance

For each ported mechanism, source comments should identify:

- REFramework source file/function,
- upstream commit or snapshot used as the baseline,
- any intentional deviations/hardening.

Suggested header comment:

```cpp
// Adapted from REFramework IntegrityCheckBypass::<function> behavior.
// Upstream baseline: praydog/REFramework @ <commit>
// Capcom Patcher deviations: <brief hardening summary>
```

### 22.4 Do not automatically follow upstream TDB expansion

When REFramework adds `tdb >= 84`, Capcom Patcher does nothing until an explicit supported-game decision is made.

---

## 23. License and attribution

Both the current OptiPatcher source and REFramework source are MIT-licensed, but copied/adapted code still requires preservation of applicable copyright/license notices.

The repository should contain:

- project `LICENSE`,
- `THIRD_PARTY_NOTICES.md`,
- source-level attribution near substantively adapted algorithms.

At minimum document:

- REFramework / praydog,
- original OptiPatcher source if utility/build/watcher code is reused,
- any hook/disassembly library added to the final implementation.

Do not make release packaging dependent on an accidental local file layout; when releases are eventually created, include the required notices with distributed binaries.

---

## 24. Proposed implementation sequence

The work should be split so each stage can be reviewed and runtime-tested independently.

### Phase 0 - repository bootstrap

Deliverables:

- x64 ASI project that builds to one `.asi`,
- explicit six-game detector/profile table,
- logging,
- MIT/license/third-party notice skeleton,
- no anti-tamper patches yet.

Success criteria:

- loads only in selected games,
- unsupported executable performs no hooks/patches,
- `PatchResult()` semantics cannot accidentally disable OptiScaler spoofing.

### Phase 1 - hardened DbgUi watcher migration

Import the completed hardened watcher from the OptiPatcher PoC.

Extend allowlist/profile support to all six games, including MHS3.

Success criteria:

- behavior matches the tested PoC in MHW/DD2/RE9,
- no regression to unsafe first-8-byte / raw FF25 dereference behavior,
- immediate + polling checks work,
- unsupported hook forms fail closed.

### Phase 2 - common runtime guards

Implement:

- pristine `NtProtectVirtualMemory`,
- VirtualProtect repair guard,
- VEH guard,
- process-exit guard.

Success criteria:

- no conflict with OptiScaler/Steam/XeFG normal operation,
- blocked/repaired events are logged,
- no blanket VEH rejection.

### Phase 3 - DD2-family anti-tamper core

Implement only anti-tamper portions of current `immediate_patch_dd2()`:

- MHW scanner/crasher path,
- `createBLAS` corruption guard,
- DD2-family constants,
- validated penalty-path branches where purpose is confirmed.

Explicitly exclude PAK and `/natives/` support.

Success criteria:

- MHW reproduces observed scanner/crasher/createBLAS patch sequence,
- DD2/RE9/PRAGMATA find/create the expected `createBLAS` guard where current builds do,
- absent patterns are non-fatal.

### Phase 4 - RE9-family anti-tamper core

Implement:

- RE9-family constants,
- scheduler-corruption detection,
- JobQueue fallback,
- RE9-only slow-path discriminator,
- optional PE-header integrity protection.

Success criteria:

- RE9 reproduces the observed slow-path + JobQueue behavior,
- DD2/PRAGMATA can use JobQueue fallback without receiving RE9-only slow-path patches,
- no unsafe generic job suppression.

### Phase 5 - heartbeat service

Implement minimal RE Engine renderer/type access and port current heartbeat discovery/synchronization logic.

Success criteria:

- PRAGMATA detects the cluster dynamically rather than using `0x32A0` as a hard-coded production offset,
- three-confirmation candidate logic is preserved,
- six heartbeats synchronize every frame after confirmation,
- no writes before confirmation,
- MHS3 profile is ready for runtime validation.

### Phase 6 - stack destroyer + integration hardening

Implement the remaining selected-game fail-closed stack-destroyer path and perform cross-feature race/lifecycle review.

### Phase 7 - six-game validation and cleanup

No new mechanisms unless evidence requires them.

Focus on:

- runtime matrices,
- log clarity,
- update resilience,
- dependency reduction,
- source provenance,
- release packaging only after functionality is stable.

---

## 25. Runtime validation matrix

For each supported game, test at least:

```text
A. Vanilla / no OptiScaler (control where practical)
B. OptiScaler only
C. OptiScaler + Capcom Patcher
```

For mechanism isolation during development, developer-only feature switches may additionally test:

```text
C1. watcher only
C2. + common runtime guards
C3. + DD2 family
C4. + RE9 family
C5. + heartbeat
```

These switches are diagnostic tools, not necessarily user-facing configuration.

### Minimum scenario checklist

- cold process start,
- remain at title/menu beyond the old delayed-crash window,
- load gameplay,
- 30+ minutes gameplay when practical,
- Alt+Tab repeatedly,
- graphics settings changes,
- OptiScaler FG/upscaler enabled,
- Intel XeFG path where relevant,
- clean game exit,
- repeated second launch without reboot.

### Expected evidence examples

MHW should be able to demonstrate:

- scanner/crasher patch success,
- createBLAS guard success,
- DD2-family constants where current build contains them,
- DbgUi event when Capcom installs the redirect.

RE9 should be able to demonstrate:

- DD2-family createBLAS guard,
- RE9+ constant patch,
- slow-path discriminator,
- JobQueue fallback hooks,
- DbgUi event,
- heartbeat enabled even if no cluster is confirmed in every session.

PRAGMATA should be able to demonstrate:

- createBLAS guard,
- RE9-family fallback hooks,
- dynamic heartbeat cluster confirmation,
- no requirement that DbgUi must fire in every session.

MHS3 should specifically validate the heartbeat path because upstream history identifies it as a crash-fix mechanism.

Onimusha should initially emphasize diagnostics to determine which inherited TDB82-family mechanisms actually match in its current retail build.

---

## 26. Success definition

Capcom Patcher is not complete merely when the six games launch once.

The project reaches its first stable milestone when:

1. the six-game scope is explicit and no unrelated games are patched,
2. the hardened DbgUi watcher is retained,
3. the common early runtime protections are represented or explicitly proven unnecessary for this loading architecture,
4. the anti-tamper portions of DD2-family logic are ported,
5. the active RE9-family protections are ported for the five selected TDB82+ profiles,
6. the RE9-only discriminator remains RE9-only,
7. the current heartbeat algorithm works without fixed per-build offsets,
8. the known historical/disabled MHS3 fallback is not resurrected accidentally,
9. PAK/loose-file/overlay/general REFramework functionality is absent,
10. all destructive patches fail closed when validation fails,
11. logs are sufficient to diagnose the next Capcom update without a debugger-first workflow,
12. OptiScaler `PatchResult()`/spoofing behavior is unaffected.

---

## 27. Current working hypothesis and design stance

The previous narrow investigation established that the delayed OptiScaler-only crash in MHW/DD2/RE9 strongly correlates with the `DbgUiRemoteBreakin` heap-payload mechanism, and the minimal watcher PoC successfully solved that immediate problem.

That result remains valid.

What changes with this new project is the definition of completeness.

The evidence now shows that REFramework actively applies additional mitigations in the selected games:

- MHW actually patches scanner/crasher/createBLAS paths and five DD2-family constants.
- DD2 actually uses createBLAS mitigation and RE9-family JobQueue fallback in the sampled build.
- RE9 actually uses createBLAS, RE9+ constants, the RE9-only slow-path patch, JobQueue fallback, and the DbgUi watcher.
- PRAGMATA actually uses createBLAS, RE9-family JobQueue protection, and a dynamically confirmed heartbeat cluster even though the sampled session did not show a DbgUi hook.
- MHS3 upstream history explicitly drove the RE9-family integration and the later robust heartbeat-based crash fix.
- Onimusha is deliberately classified by current REFramework into the same modern TDB82 anti-tamper family, though its exact runtime hit matrix still needs collection.

Therefore the correct engineering stance is:

> Use the proven hardened watcher as the first module, but build Capcom Patcher toward selected-game REFramework anti-tamper parity rather than assuming the watcher is the entire solution.

---

## 28. Reference baselines

Implementation/review should compare against pinned sources rather than memory or summaries.

Primary reference snapshot used for this architecture analysis:

- `praydog/REFramework` around commit `b6baf6b406efc65e077b99cb4d9ad25b0a0a9095`
- `src/mods/IntegrityCheckBypass.cpp`
- `src/mods/IntegrityCheckBypass.hpp`
- `shared/sdk/GameIdentity.cpp`
- `src/Main.cpp`
- `src/REFramework.cpp`

DbgUi hardening reference:

- `onehoon/OptiPatcher` PR #1, `reengine-antitamper-fork`
- use the latest reviewed hardened implementation rather than the initial PoC commit

OptiScaler ASI integration reference:

- current `optiscaler/OptiScaler` ASI loader behavior that loads `.asi`, calls `InitializeASI()` when exported, and separately inspects `PatchResult()` when exported.

When implementation starts, record exact source SHAs again because these upstream repositories can change.

---

## 29. Final architectural decision

Capcom Patcher should be implemented as a **new, narrow, process-lifetime x64 ASI** whose sole purpose is anti-tamper compatibility for the six selected Capcom RE Engine games.

It should not inherit the original OptiPatcher's unrelated game catalog.

It should not attempt to become a smaller REFramework.

It should instead extract the anti-tamper behaviors that matter to these six games, preserve upstream intent and timing where required, retain the safety hardening learned from the DbgUi proof-of-concept, and make every destructive operation explicit, profile-scoped, and fail-closed.
