# PR4 Work Order — Standalone Renderer Heartbeat Bypass

**Repository:** `onehoon/Capcom_Patcher`  
**Base:** current `main` after merged PR3 (`77102e7fcfa8222b18dff5cebeabe4b2de5e9463` at the time this work order was written)  
**Target branch:** new feature branch from latest `main`  
**PR type:** focused implementation / anti-tamper parity  
**Scope:** standalone renderer heartbeat discovery + synchronization for the five heartbeat-enabled selected games  
**Open as Draft. Do not merge automatically.**

---

## 1. Objective

PR0 established the six-game ASI, explicit profiles, and the hardened `DbgUiRemoteBreakin` watcher.

PR1 added the common early/runtime guards.

PR2 added the DD2-family anti-tamper core.

PR3 added the RE9-family suspicious constant, JobQueue corruption guard, and RE9-only slow-path discriminator.

PR4 adds the next high-priority parity layer from current REFramework:

> **Renderer heartbeat bypass** — discover the six renderer heartbeat/frame-like values with repeated structural confirmation and continuously synchronize them to the engine's real `via.render.Renderer.get_RenderFrame()` value.

This is not speculative parity work. Existing working REF + OptiScaler evidence already showed PRAGMATA successfully locating the heartbeat cluster at `renderer + 0x32A0` after three confirmations and then synchronizing it every frame.

The implementation must remain standalone. Capcom Patcher must not require REFramework to be loaded.

---

## 2. Current `main` — build on it, do not redesign prior layers

Current `main` at the time of writing:

```text
77102e7fcfa8222b18dff5cebeabe4b2de5e9463
```

Relevant current files:

```text
src/GameProfile.h
src/GameProfile.cpp
src/dllmain.cpp
src/memory/MemoryScan.*
src/memory/MemoryPatch.*
src/memory/ThreadSuspension.*
src/antitamper/RuntimeGuards.*
src/antitamper/DbgUiRemoteBreakinWatcher.*
src/antitamper/DD2FamilyBypass.*
src/antitamper/RE9FamilyBypass.*
third_party/bddisasm/
third_party/minhook/
third_party/safetyhook/
third_party/zydis/
```

The existing profile table already has the required `heartbeat` capability flag. Do not replace it with TDB heuristics.

Current policy is already:

```text
MHW        heartbeat=false
DD2        heartbeat=true
RE9        heartbeat=true
PRAGMATA   heartbeat=true
Onimusha   heartbeat=true
MHS3       heartbeat=true
```

Keep this exact profile-level behavior.

Do not enable heartbeat for MHW.

---

## 3. Primary behavioral source of truth

Use current analyzed REFramework as the behavioral source of truth:

- Repository: `praydog/REFramework`
- Commit: `b6baf6b406efc65e077b99cb4d9ad25b0a0a9095`
- Heartbeat implementation:
  - `src/mods/IntegrityCheckBypass.cpp`
  - `IntegrityCheckBypass::re9_heartbeat_bypass()`
- Frame integration:
  - `IntegrityCheckBypass::on_frame()`
- Minimal RE Engine metadata/runtime pieces used by the heartbeat path:
  - `shared/sdk/REContext.cpp`
  - `shared/sdk/RETypeDB.hpp`
  - `shared/sdk/RETypeDB.cpp`
  - `shared/sdk/RETypeDefinition.hpp/.cpp`
  - `shared/sdk/REType.hpp/.cpp`
  - `shared/sdk/RETypeDefDispatch.hpp`

Pinned links:

```text
https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.cpp
https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/shared/sdk/REContext.cpp
https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/shared/sdk/RETypeDB.hpp
https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/shared/sdk/RETypeDB.cpp
https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/shared/sdk/RETypeDefinition.cpp
https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/shared/sdk/REType.cpp
```

Do not replace the heartbeat algorithm with a guessed fixed offset, a Present counter, or a generic memory patch.

---

## 4. Why this PR needs a standalone renderer bridge

Current REFramework calls heartbeat code from:

```cpp
void IntegrityCheckBypass::on_frame()
{
    ...
    re9_heartbeat_bypass();
    ...
}
```

and the heartbeat function obtains:

```cpp
static auto renderer_t = sdk::find_type_definition("via.render.Renderer");
static auto get_RenderFrame = renderer_t != nullptr
    ? renderer_t->get_method("get_RenderFrame")
    : nullptr;

auto renderer = sdk::get_native_singleton("via.render.Renderer");
const auto frame_count = get_RenderFrame->call<uint32_t>();
```

Capcom Patcher has neither REFramework's `on_frame()` callback nor its full RE Engine SDK.

OptiScaler's ASI contract only calls the existing ASI entry points (`InitializeASI()` / `PatchResult()`). There is no per-frame ASI callback to consume.

Therefore PR4 must add **two narrowly scoped pieces**:

1. a **minimal RE Engine renderer bridge** sufficient to resolve:
   - `via.render.Renderer` native singleton,
   - `via.render.Renderer.get_RenderFrame()` native function,
   - actual `uint32_t` render-frame value;
2. a **process-lifetime heartbeat worker** started from `InitializeASI()` that executes the heartbeat state machine without DXGI/Present hooking.

### Hard architectural rule

**Do not hook `IDXGISwapChain::Present`, ResizeBuffers, D3D11, D3D12, or any OptiScaler/XeFG swapchain path for heartbeat cadence.**

This project already exists specifically in an environment where swapchain-hook coexistence matters. Adding a new Present hook only to drive heartbeat would create a new compatibility surface for no good reason.

---

## 5. Scope matrix

| Game | Heartbeat worker | Expected current TDB layout |
|---|---:|---:|
| Monster Hunter Wilds | **No** | n/a for PR4 |
| Dragon's Dogma 2 | Yes | 83 |
| Resident Evil Requiem | Yes | 83 |
| PRAGMATA | Yes | 83 |
| Onimusha: Way of the Sword | Yes | 82 |
| Monster Hunter Stories 3 | Yes | 82 |

`profile.heartbeat` is the feature gate.

The expected TDB version is a **layout validation**, not an auto-support rule.

Do not implement:

```cpp
if (tdbVersion >= 82) enableHeartbeatForAnyGame();
```

Instead, validate the detected TDB version against the already selected explicit `GameId`:

```cpp
std::optional<uint32_t> ExpectedTdbVersion(GameId id)
{
    switch (id)
    {
    case GameId::DragonsDogma2:
    case GameId::ResidentEvilRequiem:
    case GameId::Pragmata:
        return 83;

    case GameId::OnimushaWots:
    case GameId::MonsterHunterStories3:
        return 82;

    default:
        return std::nullopt;
    }
}
```

If a future game update changes one of these TDB layouts, heartbeat should fail-soft and log the mismatch until the bridge is reviewed.

Other anti-tamper layers must continue running.

---

## 6. Proposed source structure

Recommended additions:

```text
src/
├─ antitamper/
│  ├─ RendererHeartbeatBypass.h
│  └─ RendererHeartbeatBypass.cpp
│
└─ reengine/
   ├─ RendererBridge.h
   └─ RendererBridge.cpp
```

Optional if keeping layout declarations separate is cleaner:

```text
src/reengine/MinimalTdb82_83.h
```

Do not import the complete REFramework `shared/sdk/` tree.

Do not create a general-purpose public RE Engine modding SDK in this PR.

The renderer bridge exists only to supply:

```cpp
struct RendererFrameSource
{
    void* renderer{};
    uint32_t (*getRenderFrame)(){};
};
```

or an equivalent minimal abstraction.

---

# 7. Minimal RE Engine bridge — reuse only the necessary REF mechanics

## 7.1 VM / TDB discovery

Port the current REFramework VM/TDB discovery behavior from `shared/sdk/REContext.cpp` only as far as needed for TDB82/83.

The current primary VM context pattern is:

```text
48 8B 0D ? ? ? ? BA FF FF FF FF E8 ? ? ? ?
```

Current REF behavior counts references to the same resolved context pointer and treats a repeated candidate (`> 10` references) as the reliable VM-context location.

Preserve this anti-false-positive behavior.

Conceptual shape:

```cpp
struct VmDiscovery
{
    void** globalContextSlot{};
    void* vm{};
    void* tdb{};
    uint32_t tdbVersion{};
    size_t tdbOffset{};
};
```

Required validation:

```text
pattern candidate decodes as RIP-relative reference
resolved global context slot is readable
*globalContextSlot is non-null and readable
scan only the bounded VM object region used by REF (0 .. 0x20000, pointer stride)
potential TDB pointer is naturally aligned and readable
first DWORD matches the TDB magic used by REF
version is exactly the expected profile version (82 or 83)
```

Do not scan the entire process for arbitrary `TDB` strings.

Do not guess a fixed VM/TDB offset.

## 7.2 TDB82 / TDB83 only

Extract only the exact TDB82 and TDB83 structures/field-dispatch logic needed for:

```text
numTypes
types pointer
typesImpl pointer
numMethods
methods pointer
methodsImpl pointer
stringPool
```

and the fields required to resolve:

```text
via.render.Renderer
get_RenderFrame
```

Use the pinned REFramework `RETypeDB.hpp` and `RETypeDefDispatch.hpp` as the source of truth.

Do not simplify a field offset from TDB83 and reuse it for TDB82 unless the pinned upstream structures prove the layouts are identical for that field.

Add `static_assert` checks for every copied structure size/offset that upstream itself makes explicit.

## 7.3 Find `via.render.Renderer`

Port the minimal equivalent of current REF:

```cpp
sdk::find_type_definition("via.render.Renderer")
```

A focused implementation may iterate the TDB type array and reconstruct only enough name/namespace information to compare:

```text
namespace == "via.render"
name      == "Renderer"
```

or use the exact pinned full-name/FQN mechanism if that produces less fragile code.

Do not hardcode a type-array index.

Do not hardcode a renderer singleton pointer.

## 7.4 Obtain the native singleton

Current REF ultimately uses:

```cpp
RETypeDefinition::get_instance()
    -> get_type()
    -> utility::re_type::get_singleton_instance(REType*)
```

with the native singleton path:

```cpp
using SingletonFunc = void (*)(::REType*, void**, void*);
auto f = (*(SingletonFunc**)t)[1];
void* out = nullptr;
f(t, &out, nullptr);
```

Port only this focused native-singleton mechanism.

Before calling the singleton function:

```text
REType* pointer readable
vtable readable
the selected vtable function pointer is executable
```

After the call:

```text
renderer result non-null
renderer result readable
renderer + heartbeat scan window can be safely probed before scanning
```

All calls must be SEH/fail-soft.

## 7.5 Resolve `get_RenderFrame`

Port the minimal equivalent of:

```cpp
renderer_t->get_method("get_RenderFrame")
```

for TDB82/83.

Do not hardcode a method index.

Current REFramework's `REMethodDefinition::get_function()` for modern TDBs uses the encoded method offset path. Port the required TDB82/83 subset from the pinned source, including its existing encoded-pointer resolution/fallback behavior where actually required by these games.

Reuse the project's existing pinned `bddisasm` for instruction decoding/scans where helpful.

Do not add another disassembler.

The final frame getter is invoked by current REF as:

```cpp
get_RenderFrame->call<uint32_t>();
```

and `REMethodDefinition::call` simply invokes the resolved native function with the supplied arguments. Because this call has no arguments, the standalone bridge may expose the verified native address as:

```cpp
using GetRenderFrameFn = uint32_t (*)();
```

but only after verifying:

```text
resolved function != null
function address is committed + executable
preferably belongs to the main game module / validated executable image range
```

Do not call an unvalidated encoded pointer.

---

# 8. Bridge readiness is asynchronous

At ASI load time the RE Engine VM/TDB/renderer singleton may not yet be ready.

`RendererBridge::Resolve()` must therefore distinguish:

```cpp
enum class ResolveStatus
{
    Ready,
    NotReadyYet,
    UnsupportedLayout,
    Invalid,
};
```

or equivalent.

`NotReadyYet` is normal during startup and must not permanently disable heartbeat.

The heartbeat worker should retry with bounded backoff until the bridge is ready.

`UnsupportedLayout` (for example expected TDB83 but actual TDB84 after an update) should log once and disable heartbeat for that process session rather than attempting unsafe layout guesses.

---

# 9. Heartbeat algorithm — preserve current REF semantics

Constants from current REF:

```cpp
static constexpr int CONFIRMATIONS_NEEDED = 3;
static constexpr int32_t MAX_DISTANCE = 1000;
static constexpr size_t HEARTBEAT_COUNT = 6;
static constexpr size_t SCAN_BEGIN = 0x2000;
static constexpr size_t SCAN_END = 0x4000;
```

Do not hardcode the known offsets `0x32A0` (observed PRAGMATA) or `0x3328` (current REF debug comment for RE9) as the detection method.

Those offsets may be diagnostic expectations only.

## 9.1 Frame source

Each active heartbeat iteration must obtain the actual engine frame value from the resolved `get_RenderFrame()` native method.

Fail-soft rules:

```text
function call faults -> do not write heartbeat memory; invalidate/retry bridge if persistent
frame value obviously regresses unexpectedly -> do not blindly write; reset discovery or reacquire
```

A normal 32-bit wraparound does not need special production handling today, but do not write code with signed overflow assumptions.

## 9.2 When discovery runs

Match REF:

```cpp
if (frameCount > 100 && frameCount != lastScanFrame)
{
    lastScanFrame = frameCount;
    ScanCandidates();
}
```

Do not repeatedly rescan the full renderer window multiple times inside the same engine frame.

## 9.3 Candidate structural sentinels

For each 4-byte aligned candidate start in:

```text
renderer + 0x2000 ... renderer + 0x4000
```

interpret:

```text
ints[-1]               sentinel before cluster
ints[0..5]             six heartbeats
ints[HEARTBEAT_COUNT]   sentinel after cluster
```

Required sentinel values:

```cpp
ints[-1] == 1
ints[6]  == 0
```

Reject immediately if either sentinel does not match.

Use SEH-safe reads / `TryReadBytes` style helpers. Do not rely on C++ `try/catch` for access violations.

## 9.4 Normal heartbeat candidate

For every heartbeat value:

```cpp
bool inRange =
    value > 0 &&
    value <= frameCount &&
    (frameCount - value) < MAX_DISTANCE;
```

All six must pass for normal detection.

## 9.5 Early detection mode

Preserve the current upstream early-detection rule added for modern RE9 behavior:

```text
ints[0] == 0
ints[1..5] all satisfy the normal in-range test
sentinel before == 1
sentinel after  == 0
```

Current REF comments explain that heartbeat `[0]` in RE9 may not receive its first write until roughly frame 930 even though anti-tamper scheduler corruption begins earlier.

Do not remove early detection just because the first sampled game has all six populated.

## 9.6 Repeated confirmation

Preserve the current candidate-intersection logic.

First valid scan:

```cpp
candidates = thisFrame;
confirmationCount = 1;
```

Subsequent scan:

```cpp
candidates = intersection(candidates, thisFrame);
++confirmationCount;
```

Confirm only when:

```cpp
candidates.size() == 1 &&
confirmationCount >= CONFIRMATIONS_NEEDED
```

If the intersection becomes empty:

```text
clear/reset confirmation state
restart discovery
```

Do not choose the first candidate when multiple candidates survive.

Do not write to any heartbeat candidate before confirmation.

### Recommended hardening over REF

Store **offsets relative to the renderer**, not permanent absolute addresses, during candidate tracking:

```cpp
std::vector<uint32_t> candidateOffsets;
std::optional<uint32_t> confirmedOffset;
```

If the renderer singleton pointer changes, reset discovery.

This avoids preserving a stale absolute heap pointer across renderer recreation/device lifecycle changes.

---

# 10. Confirmed heartbeat synchronization

Once exactly one cluster has survived the required confirmations, current REF writes:

```cpp
for (size_t i = 0; i < HEARTBEAT_COUNT; ++i)
{
    heartbeat[i] = frameCount;
}
```

Capcom Patcher should do the same.

Before every synchronization cycle, revalidate:

```text
renderer pointer still matches the renderer used for confirmation
confirmed offset remains inside 0x2000..0x4000 bounds
cluster memory is writable/readable
sentinel before is still 1
sentinel after is still 0
```

If validation fails:

```text
do not write
clear confirmed state
restart discovery
```

Use six aligned 32-bit stores under an SEH-safe helper.

No instruction-cache flush is needed because this is data, not executable code.

Do not use the executable-code `BytePatchCandidate` pipeline for heartbeat values.

---

# 11. Worker lifecycle / cadence

## 11.1 Start location

Add heartbeat initialization only in `InitializeASI()`.

Do not start a persistent heartbeat thread from `DllMain`.

Recommended integration order:

```text
runtime_guards::PostLoadInitialize()
-> dd2_family::Initialize()      if dd2Family
-> re9_family::Initialize()      if re9Family
-> heartbeat::Initialize()       if heartbeat
-> dbg_ui::Initialize()          if dbgUiWatcher
```

`heartbeat::Initialize()` should only establish lifecycle state/start its worker and return quickly.

Keep `PatchResult()` exactly `false`.

## 11.2 Idempotency

`InitializeASI()` may be called more than once.

Heartbeat must start at most one worker.

Reuse the proven lifecycle/module-pin approach already used by the hardened DbgUi watcher rather than inventing a detached thread with no module-lifetime guarantee.

Required properties:

```text
unsupported / heartbeat=false -> no worker
successful first Initialize -> one worker
second Initialize -> no duplicate worker
module code cannot be unloaded while worker may execute it
```

## 11.3 Retry cadence before renderer is ready

Do not busy-spin during startup.

Suggested state-specific backoff:

```text
RendererBridge NotReadyYet -> retry about every 100 ms
Ready, frame <= 100         -> sample about every 5 ms
Active discovery/sync       -> high-resolution short wait, approximately 1 ms
```

Exact implementation may use a waitable timer/event.

Do **not** call `timeBeginPeriod()` merely for this feature.

Do not use an unbounded zero-sleep loop.

## 11.4 Why worker polling is acceptable here

The worker is not generic process polling and does not enumerate windows/devices/processes.

After bridge resolution it performs only:

```text
one tiny static engine frame getter
plus, when the frame changed, a bounded 0x2000-byte renderer-local candidate scan during discovery
or six 32-bit writes after confirmation
```

This is preferred over adding another DXGI/swapchain hook to an OptiScaler/XeFG compatibility module.

---

# 12. Thread-safety and memory-safety rules

Heartbeat is live game-memory manipulation, so fail-soft/fail-closed rules are mandatory.

### Renderer pointer unavailable

```text
no write, retry later
```

### Frame getter unavailable

```text
no write, retry bridge resolution
```

### TDB layout mismatch

```text
log once, disable heartbeat layer for session
other Capcom Patcher layers continue
```

### Candidate memory unreadable

```text
skip candidate
```

### Candidate set ambiguous

```text
keep confirming / do not write
```

### Candidate set lost

```text
reset and restart discovery
```

### Confirmed cluster later loses sentinels

```text
stop writes immediately
clear confirmation
rediscover
```

### Renderer pointer changes

```text
stop writes immediately
reset all candidate/confirmation state
rediscover against new renderer
```

### Getter call faults

```text
never use a stale/guessed frame count for writes
back off and reacquire bridge
```

Do not substitute `GetTickCount`, QPC, Present count, or a locally incremented fake frame number.

---

# 13. Logging policy

Logs must allow runtime validation without per-frame spam.

Recommended logs:

```text
[CapcomPatcher][Heartbeat] worker started for PRAGMATA
[CapcomPatcher][Heartbeat][Bridge] VM context resolved
[CapcomPatcher][Heartbeat][Bridge] TDB83 validated
[CapcomPatcher][Heartbeat][Bridge] via.render.Renderer resolved
[CapcomPatcher][Heartbeat][Bridge] get_RenderFrame resolved @ +0x...
[CapcomPatcher][Heartbeat] renderer instance @ 0x...
[CapcomPatcher][Heartbeat] seeded N candidate(s) at frame ...
[CapcomPatcher][Heartbeat] candidate set reduced to N after confirmation ...
[CapcomPatcher][Heartbeat] confirmed cluster renderer+0x32A0 after 3 confirmations at frame 1677
[CapcomPatcher][Heartbeat] synchronization active
[CapcomPatcher][Heartbeat] renderer changed; resetting discovery
[CapcomPatcher][Heartbeat] confirmed sentinels changed; resetting discovery
[CapcomPatcher][Heartbeat][Bridge] expected TDB83, observed TDB84; disabled for this session
```

Do not print six heartbeat values every frame.

Do not print the frame count every poll.

After confirmation, ordinary synchronization should be silent.

Useful counters may be retained internally:

```text
bridge attempts
frames observed
candidate scans
candidate resets
confirmation count
sync writes
validation failures
```

---

# 14. Runtime evidence expectations

Do not assert a game-specific fixed offset in code.

But runtime validation can compare observed diagnostics against known evidence.

### PRAGMATA

Known working REF + OptiScaler evidence:

```text
heartbeat cluster found at renderer + 0x32A0
after 3 confirmations
frame count around 1677 in the captured session
```

A Capcom Patcher runtime test finding the same current-build offset would be strong parity evidence.

### RE9

Current REF source contains a disabled debug comment mentioning a known heartbeat location near:

```text
renderer + 0x3328
```

This is diagnostic context only. Do not hardcode it.

### DD2 / Onimusha / MHS3

Heartbeat is profile-enabled because current REF routes these selected games through the TDB82+ heartbeat path. A zero-hit / unresolved candidate in one test session is not automatically a code failure if bridge resolution is valid and the detector remains fail-soft.

---

# 15. Deterministic tests — heartbeat state machine

Factor the candidate evaluation/intersection logic into pure or synthetic-buffer-testable functions where practical.

Required tests:

## 15.1 Candidate acceptance

Synthetic renderer buffer:

```text
sentinel 1 + six valid values + sentinel 0 -> accepted
wrong leading sentinel -> rejected
wrong trailing sentinel -> rejected
one heartbeat == 0 in normal mode -> normal reject
heartbeat > frameCount -> rejected
frameCount - heartbeat == 1000 -> rejected
frameCount - heartbeat == 999 -> accepted
```

## 15.2 Early mode

```text
heartbeat[0] == 0 + heartbeat[1..5] valid -> accepted
heartbeat[0] == 0 + one of [1..5] invalid -> rejected
heartbeat[0] nonzero + another zero -> rejected unless all six normal-valid
```

## 15.3 Confirmation

```text
first scan seeds candidate set and count=1
same single offset survives second -> count=2, not confirmed
same single offset survives third -> confirmed
multiple candidates after third -> not confirmed
intersection becomes empty -> reset count/state
```

## 15.4 No premature writes

```text
0 confirmations -> no writes
1 confirmation  -> no writes
2 confirmations -> no writes
3 confirmations + exactly one candidate -> writes allowed
```

## 15.5 Confirmed sync

```text
all six values become exactly frameCount
sentinels remain untouched
```

## 15.6 Revalidation

```text
leading sentinel changes after confirmation -> no write + reset
trailing sentinel changes -> no write + reset
renderer pointer changes -> no write to old renderer + reset
confirmed range becomes unreadable -> no write + reset
```

---

# 16. Deterministic tests — minimal renderer bridge

The bridge is the highest-risk new infrastructure in PR4. Add focused validation rather than relying only on game runtime.

Required checks where practical:

```text
VM context RIP-relative reference resolver rejects malformed instructions
repeated-context-reference confirmation prefers the same resolved slot (>10) as current REF
TDB magic validation rejects random aligned pointers
TDB82 accepted only for the two explicit TDB82 profiles
TDB83 accepted only for the three explicit TDB83 profiles
TDB version mismatch returns UnsupportedLayout, not Ready
renderer type search does not use a hardcoded type index
get_RenderFrame method search does not use a hardcoded method index
resolved native function must be executable before use
heartbeat=false profile never starts bridge/worker
MHW never starts heartbeat
```

Add `static_assert` checks for copied TDB82/83 layout pieces.

If a synthetic full TDB fixture is impractical, keep the resolver pieces small enough that version/layout and scan behavior can still be tested independently.

---

# 17. Existing regression requirements

All prior deterministic checks must continue to pass.

At minimum preserve:

```text
PR0 explicit six-game identity/profile checks
PR1 MinHook/runtime-guard checks
PR2 bddisasm / CFG / thread-suspension / createBLAS checks
PR3 glob / DecodeOne / LinearDecode / JobGuard decision / CAS checks
```

Do not weaken or delete an existing test merely to make the heartbeat branch compile.

---

# 18. Explicit exclusions from PR4

Do **not** include the following in this PR:

1. PE-header integrity redirection
2. stack-destroyer patch
3. module-path spoofing
4. PAK / `/natives/` / DirectStorage features
5. `ignore_application_entries()`
6. old disabled MHS3 `#if 0` UD2 writer fallback
7. a new DbgUi watcher
8. DD2-family reimplementation
9. RE9 JobQueue reimplementation
10. TDB-based automatic future-game support
11. full REFramework SDK import
12. generic scripting/reflection/object APIs
13. DXGI / D3D11 / D3D12 / swapchain / Present hooks
14. OptiScaler source modification
15. change to `PatchResult()` semantics
16. hardcoded heartbeat offset as the primary implementation
17. locally synthesized frame counter

PE-header and stack-destroyer remain planned parity work; they are not being judged unnecessary.

---

# 19. Licensing / attribution

No new third-party dependency should be required.

PR4 adapts additional MIT-licensed REFramework behavior, especially:

```text
IntegrityCheckBypass::re9_heartbeat_bypass
VM/TDB discovery subset
TDB82/TDB83 metadata structures/dispatch subset
native singleton resolution subset
method/function resolution subset
```

Update `THIRD_PARTY_NOTICES.md` to make this new adaptation explicit while preserving all existing notices.

Do not remove existing OptiPatcher / REFramework / Kananlib / bddisasm / MinHook / SafetyHook / Zydis / Zycore attribution.

If any REFramework source file is copied nearly verbatim rather than behaviorally adapted, retain a clear source comment next to that code in addition to the project-level notice.

---

# 20. Build / validation requirements

Before opening the PR:

```text
[ ] branch created from latest main (not from the work-order commit's stale parent)
[ ] Debug x64 builds
[ ] Release x64 builds
[ ] committed project remains x64-only
[ ] no generic CI added
[ ] exports remain exactly InitializeASI + PatchResult
[ ] PatchResult() still returns false
[ ] git diff --check passes for project-owned code
[ ] no Present/DXGI/D3D hook introduced
[ ] no full REFramework SDK tree imported
[ ] no new third-party dependency unless absolutely required and separately justified
[ ] MHW heartbeat remains OFF
[ ] DD2/RE9/PRAGMATA/Onimusha/MHS3 heartbeat remains ON by explicit profile
[ ] TDB82/83 layout validation is profile-specific, not `>=82` auto-support
[ ] no heartbeat write before 3 confirmations + exactly one candidate
[ ] early heartbeat[0]==0 mode preserved
[ ] candidate-loss reset works
[ ] renderer-pointer-change reset works
[ ] sentinel revalidation after confirmation works
[ ] all new deterministic heartbeat tests pass
[ ] all existing PR0-PR3 regression tests pass
```

If local v143 is still unavailable and the PR is built with the existing v145 override pattern, disclose that exactly as prior PRs did. Do not modify the committed toolset just for the local machine.

---

# 21. Runtime validation matrix

Runtime testing is highly desirable for this PR because the new renderer bridge cannot be proven completely by synthetic data.

However do not falsify test results if the game runtime is unavailable.

Report each game explicitly:

| Game | Bridge | Cluster discovery | Sync | Result |
|---|---|---|---|---|
| MHW | N/A (must not start) | N/A | N/A | NOT RUN / PASS gate |
| DD2 | READY / unresolved | confirmed / no candidate | active / inactive | ... |
| RE9 | READY / unresolved | confirmed / no candidate | active / inactive | ... |
| PRAGMATA | READY / unresolved | **expected strong validation target** | active / inactive | ... |
| Onimusha | READY / unresolved | confirmed / no candidate | active / inactive | ... |
| MHS3 | READY / unresolved | confirmed / no candidate | active / inactive | ... |

For PRAGMATA, capture the diagnostic offset and confirmation frame if runtime is available.

Example desired evidence:

```text
[CapcomPatcher][Heartbeat][Bridge] TDB83 validated
[CapcomPatcher][Heartbeat][Bridge] via.render.Renderer resolved
[CapcomPatcher][Heartbeat] confirmed cluster renderer+0x32A0 after 3 confirmations at frame 1677
[CapcomPatcher][Heartbeat] synchronization active
```

The exact frame count may differ between runs.

---

# 22. PR description requirements

The PR body must clearly state:

```text
Base main SHA
REFramework behavioral pin
which minimal RE Engine source areas were adapted
no full REFramework SDK dependency
no DXGI/Present hook
five-game heartbeat matrix, MHW OFF
TDB82/83 bridge validation policy
heartbeat constants and early-detection semantics
confirmation/sentinel/reset behavior
worker lifecycle/cadence
Debug/Release build result
new deterministic test count/result
existing regression result
runtime status per game, including NOT RUN where applicable
```

Do not say "full anti-tamper parity complete" after PR4.

Remaining planned layers still include at least:

```text
PE-header integrity redirection
stack-destroyer mitigation
module-path spoofing parity review
```

---

# 23. Reject invariants

Reject the implementation before merge if any of these are true:

1. Heartbeat is enabled for MHW.
2. Any unknown future game is enabled because `TDB >= 82`.
3. The implementation hardcodes `0x32A0` / `0x3328` instead of discovering the cluster.
4. Heartbeat memory is written before repeated confirmation.
5. More than one surviving candidate is arbitrarily selected.
6. Early `heartbeat[0] == 0` detection is omitted.
7. A fake local frame counter, QPC, or Present count replaces `get_RenderFrame()`.
8. A DXGI/Present/swapchain hook is introduced just to drive heartbeat.
9. A worker is started from `DllMain`.
10. A detached worker can outlive unloadable module code.
11. Full REFramework SDK/modding infrastructure is imported.
12. TDB82/83 layouts are guessed instead of ported/validated from the pinned source.
13. A confirmed stale renderer pointer remains writable after renderer recreation.
14. Sentinel loss does not disable writes immediately.
15. `PatchResult()` changes from `false`.
16. PE-header / stack-destroyer / unrelated later parity work is mixed into PR4.
17. Runtime tests are claimed PASS when they were not run.

---

# 24. Completion criteria

PR4 is complete when the code demonstrates all of the following:

```text
explicit heartbeat profiles only
standalone TDB82/83 renderer/frame bridge
no REFramework runtime dependency
no swapchain hook
asynchronous startup readiness
exact current REF heartbeat candidate semantics
normal + early detection modes
3-confirmation unique-candidate requirement
renderer-relative candidate identity
continuous synchronization to real RenderFrame
post-confirmation sentinel/renderer revalidation
safe reset/reacquire behavior
single process-lifetime worker
clean Debug/Release x64 build
prior regression suite intact
honest runtime validation report
```

The desired result is a standalone equivalent of the current REFramework heartbeat protection for the five selected modern TDB82/83 games, while keeping Capcom Patcher small and avoiding a new graphics-hook compatibility surface.
