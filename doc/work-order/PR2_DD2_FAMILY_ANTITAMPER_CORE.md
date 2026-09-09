# PR2 Work Order — DD2-Family Anti-Tamper Core

**Repository:** `onehoon/Capcom_Patcher`  
**Base:** current `main` after merged PR1 (`cc42aaba72c3e00d960bd084ff594959f65e1d0e` at the time this work order was written)  
**Target branch:** new feature branch from latest `main`  
**PR type:** focused implementation / anti-tamper parity  
**Scope:** DD2-family direct anti-tamper/stability core only  
**Do not merge automatically. Open as Draft and leave it for review.**

---

## 1. Objective

PR0 established the dedicated Capcom Patcher ASI, the explicit six-game profile table, and the hardened `DbgUiRemoteBreakin` watcher.

PR1 added the common REFramework runtime guards:

- pristine `NtProtectVirtualMemory` capture,
- `VirtualProtect` / `NtProtectVirtualMemory` integrity protection,
- `AddVectoredExceptionHandler` filtering,
- `RtlExitUserProcess -> TerminateProcess` protection.

PR2 adds the next selected-game parity layer: the **direct DD2-family anti-tamper core extracted from current REFramework `IntegrityCheckBypass::immediate_patch_dd2()`**.

Port only the following confirmed anti-tamper/stability mechanisms in this PR:

1. **MHW-only scanner/crasher suppression**
   - locate the QueryPerformanceFrequency / QueryPerformanceCounter-related crasher path,
   - find and disable the scanner function,
   - patch the crasher conditional branch.
2. **Renderer `createBLAS` corruption guard**
   - locate `createBLAS`,
   - locate the `corruption_when_zero` global,
   - hook `createBLAS`,
   - restore the last known non-zero corruption value if anti-tamper zeros it.
3. **DD2-family suspicious constant patches**
   - scan the DD2-family instruction pattern,
   - replace the suspicious immediate with `0x1337BEEF` exactly as current REFramework does.

Do **not** add the RE9-family layer, heartbeat, stack destroyer, PE-header defense, JobQueue defense, PAK support, or module-path spoofing in this PR.

---

## 2. Primary source of truth — port, do not reinvent

Use the current analyzed REFramework implementation as the behavioral source of truth:

- Repository: `praydog/REFramework`
- Commit: `b6baf6b406efc65e077b99cb4d9ad25b0a0a9095`
- Main source:
  - `https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.cpp`
- Header:
  - `https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.hpp`

Relevant upstream functions / state:

```text
IntegrityCheckBypass::immediate_patch_dd2()
IntegrityCheckBypass::renderer_create_blas_hook()

s_corruption_when_zero
s_last_non_zero_corruption
s_renderer_create_blas_hook
```

Current REFramework explicitly describes this family as dealing with scans performed every frame against game memory and avoiding the indirect renderer corruption / crash path.

The new code should remain recognizable as a focused extraction of this behavior.

Do not redesign the anti-tamper mechanism because the local project is smaller.

---

## 3. Important source discovery — scanner/crasher is MHW-only in current REF

This is a critical scope rule.

Current REFramework does **not** run the QueryPerformanceFrequency / QueryPerformanceCounter scanner/crasher path for the whole DD2 family.

The pinned source currently gates it like this:

```cpp
// TODO: Check if full release of Pragmata needs this
// right now it freezes the game
if (gi.is_mhwilds()) {
    ... scanner/crasher path ...
}
```

Therefore PR2 must **not** enable the scanner/crasher sub-path for DD2, RE9, PRAGMATA, Onimusha, or MHS3.

That would be broader than current upstream and is specifically risky for PRAGMATA.

### Required sub-capability

Refine `GameProfile` so this is explicit rather than hidden in a loose executable-name check inside the bypass module.

Recommended addition:

```cpp
struct GameProfile
{
    ...
    bool dd2Family{false};
    bool dd2ScannerCrasher{false};
    bool re9Family{false};
    ...
};
```

Profile policy:

```text
MHW        dd2Family=true   dd2ScannerCrasher=true
DD2        dd2Family=true   dd2ScannerCrasher=false
RE9        dd2Family=true   dd2ScannerCrasher=false
PRAGMATA   dd2Family=true   dd2ScannerCrasher=false
Onimusha   dd2Family=true   dd2ScannerCrasher=false
MHS3       dd2Family=true   dd2ScannerCrasher=false
```

No TDB-derived auto-enable logic.

---

## 4. Reuse strategy — use existing OptiPatcher / REF support code

This project should not waste time recreating generic scanner and patcher infrastructure from scratch.

### 4.1 Basic pattern scanning — reuse OptiPatcher

The original OptiPatcher already has a small Windows PE scanner that is sufficient as the starting point for ordinary byte-pattern scans.

Pinned reference:

- Repository: `onehoon/OptiPatcher`
- Commit: `72e716b3274ce9dfc3a4ffde54fd2b54b4172cb2`
- `Scanner.cpp`:
  - `https://github.com/onehoon/OptiPatcher/blob/72e716b3274ce9dfc3a4ffde54fd2b54b4172cb2/OptiPatcher/Scanner.cpp`
- `Scanner.h`:
  - `https://github.com/onehoon/OptiPatcher/blob/72e716b3274ce9dfc3a4ffde54fd2b54b4172cb2/OptiPatcher/Scanner.h`

Reuse/adapt the useful parts:

- PE section enumeration,
- wildcard pattern parsing,
- `FindPattern`,
- executable-section / whole-image scans,
- RIP-relative offset helper shape.

Do **not** copy the old generic game patch database or old `CheckForPatch()` logic.

### 4.2 Raw byte writing — reuse OptiPatcher shape, harden it

Pinned reference:

- `Patcher.cpp`:
  - `https://github.com/onehoon/OptiPatcher/blob/72e716b3274ce9dfc3a4ffde54fd2b54b4172cb2/OptiPatcher/Patcher.cpp`
- `Patcher.h`:
  - `https://github.com/onehoon/OptiPatcher/blob/72e716b3274ce9dfc3a4ffde54fd2b54b4172cb2/OptiPatcher/Patcher.h`

Its core behavior is already correct in shape:

```cpp
VirtualProtect(..., PAGE_EXECUTE_READWRITE, ...);
memcpy(...);
VirtualProtect(..., oldProtect, ...);
FlushInstructionCache(...);
```

For Capcom Patcher, harden it rather than copying it blindly:

- validate non-null address / non-zero length,
- verify the target is inside the expected game module / committed region,
- check `VirtualProtect` return values,
- perform the write under SEH or equivalent fail-soft protection,
- restore protection even on a failed write when possible,
- always `FlushInstructionCache` after a successful executable-code patch,
- return explicit success/failure,
- never log a patch as applied unless the bytes verify afterward.

Suggested API:

```cpp
bool WriteBytes(void* address, std::span<const uint8_t> bytes) noexcept;
```

### 4.3 Advanced reference / unwind helpers — reuse the same Kananlib revision REF uses

The MHW scanner/crasher and `createBLAS` discovery paths rely on helpers beyond OptiPatcher's basic scanner.

REFramework at the pinned commit fetches Kananlib at:

```text
cursey/kananlib
8c27b656734355db0f2893581fd62e838fa130ad
```

Reference in REFramework CMake:

`https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/CMakeLists.txt`

Pinned Kananlib sources:

- `Scan.hpp`
  - `https://github.com/cursey/kananlib/blob/8c27b656734355db0f2893581fd62e838fa130ad/include/utility/Scan.hpp`
- `Scan.cpp`
  - `https://github.com/cursey/kananlib/blob/8c27b656734355db0f2893581fd62e838fa130ad/src/Scan.cpp`
- `Thread.hpp`
  - `https://github.com/cursey/kananlib/blob/8c27b656734355db0f2893581fd62e838fa130ad/include/utility/Thread.hpp`
- `Thread.cpp`
  - `https://github.com/cursey/kananlib/blob/8c27b656734355db0f2893581fd62e838fa130ad/src/Thread.cpp`

Relevant scan helpers include:

```text
scan_ptr
scan_displacement_reference
scan_relative_reference_scalar
find_function_start
find_function_start_unwind
find_function_with_refs
find_function_from_string_ref
find_pattern_in_path
calculate_absolute
```

Do **not** vendor the entire Kananlib tree merely to get these functions unless that proves materially simpler than a small focused extraction.

Preferred approach:

- keep the existing small OptiPatcher-style scanner for generic byte scans,
- port/adapt only the advanced Kananlib helpers actually required by this PR,
- remove Kananlib logging/benchmark/general utility dependencies,
- keep the function behavior traceable to the pinned source.

If copying/adapting Kananlib code, add its Boost Software License notice to `THIRD_PARTY_NOTICES.md` and identify the pinned revision.

Kananlib license reference:

`https://github.com/cursey/kananlib/blob/8c27b656734355db0f2893581fd62e838fa130ad/LICENSE`

---

## 5. Proposed source structure

Recommended:

```text
src/
├─ memory/
│  ├─ MemoryScan.h
│  ├─ MemoryScan.cpp
│  ├─ MemoryPatch.h
│  ├─ MemoryPatch.cpp
│  ├─ ThreadSuspension.h
│  └─ ThreadSuspension.cpp
│
└─ antitamper/
   ├─ DD2FamilyBypass.h
   └─ DD2FamilyBypass.cpp
```

Exact naming may differ, but do not place the new logic into `dllmain.cpp`.

`dllmain.cpp` should remain a dispatcher.

Suggested public API:

```cpp
namespace antitamper::dd2_family
{
    void Initialize(const game_profile::GameProfile& profile) noexcept;
}
```

Each internal sub-layer must fail independently.

A missing MHW scanner pattern must not disable `createBLAS`, constants, runtime guards, or the DbgUi watcher.

---

## 6. InitializeASI integration order

Current order after PR1:

```text
PostLoad runtime guards
    -> DbgUi watcher
```

PR2 should become:

```text
PostLoad runtime guards
    -> DD2-family core
    -> DbgUi watcher
```

Conceptually:

```cpp
extern "C" __declspec(dllexport) void InitializeASI()
{
    const auto& profile = game_profile::Current();
    if (profile.id == game_profile::GameId::Unsupported)
        return;

    antitamper::runtime_guards::PostLoadInitialize();

    if (profile.dd2Family)
        antitamper::dd2_family::Initialize(profile);

    if (profile.dbgUiWatcher)
        antitamper::dbg_ui::Initialize();
}
```

Do not move DD2-family scanning or patching into `DllMain`.

Do not move the persistent DbgUi worker into `DllMain`.

`PatchResult()` must remain exactly `false`.

---

# 7. MHW-only scanner/crasher suppression

This subsection ports the MHW-specific part of `immediate_patch_dd2()`.

Only execute it when:

```cpp
profile.dd2ScannerCrasher == true
```

which is MHW only in PR2.

## 7.1 Locate QPF / QPC imports

Preserve the upstream sequence:

```cpp
const auto queryPerformanceFrequency = &QueryPerformanceFrequency;
const auto queryPerformanceCounter = &QueryPerformanceCounter;

const auto qpfImport = ScanPointer(game, reinterpret_cast<uintptr_t>(queryPerformanceFrequency));
const auto qpcImport = ScanPointer(game, reinterpret_cast<uintptr_t>(queryPerformanceCounter));
```

If either import cannot be found:

- log `not found`,
- skip this MHW-only sub-layer,
- continue with `createBLAS` and constants.

## 7.2 Locate crasher function

Port the current Kananlib/REF behavior of:

```cpp
utility::find_function_with_refs(game, { *qpf_import, *qpc_import });
```

The helper should resolve a function whose code references both import locations and should use unwind/function-boundary information equivalent to the pinned utility code.

Do not replace this with a fixed RVA.

Do not hard-code one currently observed MHW address.

## 7.3 Resolve the real crasher reference

Preserve upstream behavior:

```cpp
auto crasherFnRef = ScanDisplacementReference(game, crasherFn);

if (crasherFnRef && *reinterpret_cast<uint8_t*>(*crasherFnRef - 1) == 0xE9)
    crasherFnRef = FindFunctionStart(*crasherFnRef - 1);
else
    crasherFnRef = crasherFn;
```

The exact local API may differ, but preserve the logic.

## 7.4 Find the scanner function

Current REF then searches the module for a relative call to the resolved crasher reference:

```cpp
const auto scannerFnMiddle = ScanRelativeReferenceScalar(
    gameBase,
    gameSize - 0x1000,
    crasherFnRef,
    [](uintptr_t addr) {
        return *reinterpret_cast<uint8_t*>(addr - 1) == 0xE8;
    });
```

Then:

```cpp
const auto scannerFn = FindFunctionStartUnwind(scannerFnMiddle);
```

If a valid function start is found, current REF makes the function return immediately:

```cpp
// ret
C3
```

Capcom Patcher should do the same.

### Required final validation before patch

Before writing `0xC3`:

- candidate must be inside the main executable image,
- candidate must be in executable committed memory,
- function-start resolution must still map to the same candidate,
- the byte must not already be `0xC3` unless treating an existing identical patch as success,
- revalidate after acquiring the raw-patch suspension scope.

Do not patch an ambiguous function start.

## 7.5 Patch the crasher conditional branch

Current REF searches inside the crasher function path for:

```text
39 0C 82 74 ?
```

and changes the `JZ` opcode to an unconditional short jump:

```text
74 -> EB
```

Equivalent upstream logic:

```cpp
const auto cmpJz = FindPatternInPath(crasherFn, 1000, "39 0C 82 74 ?");
if (cmpJz)
    PatchByte(cmpJz + 3, 0xEB);
```

Before writing, revalidate the entire local pattern and explicitly verify that byte `+3` is still `0x74`.

If the pattern is absent or changed, do not guess.

---

# 8. Renderer `createBLAS` corruption guard

This is a DD2-family core mechanism and should run for **all six profiles with `dd2Family == true`**.

Existing working logs have confirmed it on MHW, DD2, RE9, and PRAGMATA.

## 8.1 Locate `createBLAS`

Port current REF/Kananlib behavior:

```cpp
const auto createBlasFn = FindFunctionFromStringRef(game, "createBLAS");
```

The pinned Kananlib implementation is based on:

```text
scan string
 -> scan displacement reference to the string
 -> find containing function start
```

Do not use a fixed RVA.

## 8.2 Find unwind start for local scan

Current REF separately resolves:

```cpp
const auto createBlasFnUnwind = FindFunctionStartUnwind(createBlasFn);
```

This value is used as the scan origin for locating the global pointer.

Do not silently change the actual hook target to the unwind result; current REF hooks `createBlasFn` itself.

## 8.3 Locate `corruption_when_zero`

Current REF searches the first ~1000 bytes of the unwound createBLAS function for:

```text
48 8D 0D ? ? ? ?
```

which is the first expected:

```asm
lea rcx, [rip+disp32]
```

Then resolve the RIP-relative address from the displacement at `+3`.

Conceptually:

```cpp
const auto leaRcx = FindPatternInPath(createBlasFnUnwind, 1000, "48 8D 0D ? ? ? ?");
if (leaRcx)
    corruptionWhenZero = ResolveRipRelative(leaRcx + 3);
```

### Pointer validation

Before accepting the resolved pointer:

- it must be non-null,
- `VirtualQuery` must report `MEM_COMMIT`,
- it must not be `PAGE_NOACCESS` or `PAGE_GUARD`,
- reading a `uint32_t` must be safe,
- writing a `uint32_t` must be safe when the runtime hook needs to restore it.

Do not invent a pointer when the LEA scan fails.

## 8.4 Reuse PR1 MinHook wrapper

Current REFramework uses its SafetyHook-backed `FunctionHook` for this function hook.

Capcom Patcher already has a reviewed, pinned, retry-safe inline hook backend from PR1:

```text
src/hooking/MinHookInlineHook.*
```

Do **not** add SafetyHook solely for `createBLAS` in PR2.

The semantics required here are only:

- ordinary inline function hook,
- original/trampoline pointer,
- enable,
- process-lifetime ownership.

Reuse the existing MinHook wrapper.

Use the same publish-before-enable pattern established in PR1.

Suggested shape:

```cpp
using CreateBlasFn = void* (*)(void*, void*, void*, void*, void*);

std::unique_ptr<hooking::MinHookInlineHook> g_createBlasHook;
uint32_t* g_corruptionWhenZero{};
uint32_t g_lastNonZeroCorruption{};
```

## 8.5 Hook behavior — preserve REF semantics

Port this behavior faithfully:

```cpp
void* RendererCreateBlasHook(void* a1, void* a2, void* a3, void* a4, void* a5)
{
    if (g_corruptionWhenZero != nullptr)
    {
        if (*g_corruptionWhenZero == 0)
        {
            *g_corruptionWhenZero = g_lastNonZeroCorruption;
            Log("[CapcomPatcher][DD2Family] restored corruption_when_zero");
        }

        g_lastNonZeroCorruption = *g_corruptionWhenZero;
    }

    return OriginalCreateBlas()(a1, a2, a3, a4, a5);
}
```

The local implementation may add SEH / validated access around the `uint32_t` load/store, but do not change the state semantics.

In particular:

- do not force an arbitrary constant when the value is zero,
- do not update `g_lastNonZeroCorruption` from guessed data,
- do not skip calling the original createBLAS function.

### Logging

Avoid logging every healthy createBLAS call.

Log only:

- discovery result,
- hook installed/failed,
- actual runtime restoration when zero corruption is detected,
- first invalid-pointer fault if one occurs (rate-limited / one-shot).

---

# 9. DD2-family suspicious constants

Current REF scans the game image for:

```text
81 ? E1 53 BD 4C
```

For each match it replaces the four-byte immediate at `match + 2`:

```text
E1 53 BD 4C
```

with:

```text
EF BE 37 13
```

which is little-endian:

```cpp
0x1337BEEF
```

Equivalent behavior:

```cpp
for (auto ref = Scan(game, "81 ? E1 53 BD 4C"); ref; ref = ScanNext(...))
{
    PatchBytes(ref + 2, {0xEF, 0xBE, 0x37, 0x13});
}
```

### Preserve the exact semantic validation

Before each write:

- revalidate the complete pattern at the candidate,
- verify the original four immediate bytes are still exactly `E1 53 BD 4C`,
- verify the patch destination lies inside the main executable image,
- skip if already `EF BE 37 13` and count it separately as already patched,
- never patch a partial / ambiguous match.

### Expected observed counts are diagnostics, not assertions

Existing sampled REF logs:

```text
MHW       -> Patched 5 sus_constants! (DD2+ variant)
DD2       -> Patched 0 sus_constants! (DD2+ variant)
RE9       -> Patched 0 sus_constants! (DD2+ variant)
PRAGMATA  -> Patched 0 sus_constants! (DD2+ variant)
```

Do **not** hard-code these counts as required values. Game updates can change them.

The requirement is safe matching and fail-soft behavior.

---

## 10. Thread/race safety for raw patches

Current REFramework runs its immediate RE-engine anti-tamper patch block under `utility::ThreadSuspender`.

Capcom Patcher should preserve equivalent race safety, but does not need to hold every game thread suspended during expensive read-only scanning.

### Recommended two-phase model

```text
Phase 1: discovery (read-only)
  -> locate scanner/crasher candidates
  -> locate constants
  -> locate createBLAS + corruption pointer

Phase 2: raw patch commit
  -> suspend other process threads
  -> revalidate every raw patch candidate
  -> apply scanner RET / crasher JZ->JMP / constant replacements
  -> flush instruction cache
  -> resume threads

Separate:
  -> install createBLAS MinHook using the existing PR1 hook wrapper
     (MinHook already owns its own thread-freeze mechanics)
```

This keeps the suspension window short while preserving final-write atomicity/race safety.

### Thread suspension implementation

Use the pinned Kananlib `Thread.hpp/.cpp` as the behavioral reference, but do not blindly preserve known fragile RAII details.

A local `ThreadSuspensionScope` may be implemented with:

- `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ...)`,
- skip current thread,
- `OpenThread(THREAD_SUSPEND_RESUME, ...)`,
- treat `SuspendThread(...) != DWORD(-1)` as success,
- retain each successfully suspended thread handle until resume,
- `ResumeThread()` exactly once for each suspension performed by this scope,
- always close handles,
- always release local mutex/state even if zero threads were suspended,
- destructor must be noexcept/fail-safe.

Do not run this from `DllMain`.

Do not terminate the process merely because a thread could not be opened or suspended; log and continue conservatively.

If reliable world suspension cannot be established, raw writes should be skipped rather than performed against unvalidated racing code.

---

## 11. Patch transaction / revalidation requirements

Do not treat scan discovery as permission to write later without rechecking.

Each candidate should carry enough expected bytes to revalidate immediately before the patch.

Recommended model:

```cpp
struct BytePatchCandidate
{
    uintptr_t address{};
    std::vector<uint8_t> expected;
    std::vector<uint8_t> replacement;
    const char* name{};
};
```

Before commit:

```text
candidate address valid?
expected bytes still identical?
expected module still the main game exe?
memory committed?
patch size within same valid region?
```

Only then call `WriteBytes`.

After write:

- read back and verify replacement,
- log `patched` only on verified success.

This requirement applies especially to:

- scanner function `C3`,
- crasher branch `74 -> EB`,
- suspicious constant replacement.

---

## 12. Idempotency / retry model

`InitializeASI()` may be called more than once.

PR2 must not double-hook or corrupt already-patched bytes.

Rules:

### createBLAS

- if `g_createBlasHook` is valid/active, return success immediately,
- if hook creation/enabling failed transiently, a later `Initialize()` call may retry,
- do not create a second hook on the same target.

### byte patches

- expected original bytes -> patch,
- already replacement bytes -> treat as already applied,
- neither expected nor replacement -> skip as changed/unsafe,
- no blind overwrite.

Do not add a single top-level permanent `done=true` latch that makes all sub-layers unrecoverable after one partial failure.

---

## 13. Explicit exclusions from `immediate_patch_dd2()`

`immediate_patch_dd2()` contains functionality that does **not** belong in the direct anti-tamper core.

Do not port the function wholesale.

### Exclude in PR2

- `restore_unencrypted_paks()`
- PAK count/version manipulation
- PAK SHA/decryption-related mod loading support
- `/natives/` enablement
- custom PAK directory support
- DirectStorage/custom PAK path correction
- generic REFramework application-hook integration
- `ignore_application_entries()`
- REFramework's own `init_anti_debug_watcher()` call
  - Capcom Patcher already has the hardened PR0 watcher
  - never start a second DbgUi watcher from DD2FamilyBypass

The DD2 conditional-jump blocks adjacent to the PAK-related portion of the upstream function are **not part of the direct anti-tamper core selected for PR2**. Do not import them in this PR unless a separate source-level analysis proves their anti-tamper purpose and the work order is explicitly revised.

They are **deferred**, not declared permanently unnecessary.

---

## 14. Do not implement RE9-family code here

PR2 must not contain:

- RE9+ suspicious constant pattern `E1 53 BD 4C 75 ?`,
- thread scheduler / fake-UD2 mitigation,
- JobQueue `SubmitDescriptor` guard,
- BushClover/manual-map logic,
- PE header integrity check,
- RE9-only slow-path discriminator,
- heartbeat discovery/synchronization.

Those belong in later PRs.

This PR must remain independently reviewable as the DD2-family core.

---

## 15. Logging requirements

Use lightweight `OutputDebugStringA` style consistent with the existing project.

Suggested prefixes:

```text
[CapcomPatcher][DD2Family]
[CapcomPatcher][DD2Family][MHW]
[CapcomPatcher][DD2Family][createBLAS]
[CapcomPatcher][DD2Family][Constants]
[CapcomPatcher][MemoryScan]
[CapcomPatcher][MemoryPatch]
```

Log states distinctly:

```text
scan started
candidate found
candidate validated
patched
already patched
not found
skipped: validation mismatch
hook installed
hook failed
runtime corruption restored
```

Do not collapse `not found` and `patched 0` into an error that aborts the patcher.

Pattern absence is expected to be fail-soft across game updates.

Do not spam every frame/createBLAS call.

---

## 16. Known runtime evidence to use for review

### MHW — strongest DD2-family proof

Existing working REF + OptiScaler log previously showed:

```text
Found crasher_fn_ref
Found crasher fn (real)
Found scanner_fn_middle
Found scanner_fn!
Patched scanner_fn!
Patched crasher_fn!
Found createBLAS!
Found corruption_when_zero!
Hooked createBLAS!
Patched 5 sus_constants! (DD2+ variant)
```

This is the primary PR2 runtime target.

### DD2

Existing log showed:

```text
Found createBLAS!
Found corruption_when_zero!
Hooked createBLAS!
Patched 0 sus_constants! (DD2+ variant)
```

No MHW scanner/crasher path should execute.

### RE9

Existing log showed DD2-family createBLAS/corruption protection and zero DD2 constants in the sampled build.

No MHW scanner/crasher path should execute.

### PRAGMATA

Existing log showed DD2-family createBLAS/corruption protection and zero DD2 constants.

**Do not enable the MHW scanner/crasher path here; current upstream explicitly notes that doing so freezes PRAGMATA.**

### Onimusha / MHS3

Source-path/profile applicability is confirmed but current local runtime hit data is incomplete.

Scanners must fail-soft.

---

## 17. Build/static validation

Required before opening the PR:

```text
Debug | x64   PASS
Release | x64 PASS
git diff --check PASS
```

Verify exports remain exactly:

```text
InitializeASI
PatchResult
```

and:

```cpp
PatchResult() == false
```

No Win32 target.

Do not add generic CI unless separately requested.

---

## 18. Focused deterministic tests

Do not add a huge testing framework, but PR2 introduces reusable scanning/patching primitives and should have focused verification where practical.

### 18.1 Pattern scanner

Test synthetic buffers for:

```text
exact pattern
single wildcard
multiple wildcards
not found
next-match iteration
end-of-buffer boundary
```

### 18.2 RIP / displacement resolver

Build small synthetic instruction buffers and verify:

```text
RIP + disp32 resolution
rel32 call resolution
out-of-range / invalid input fails
```

### 18.3 Function unwind helper

Where practical, use a small compiled test function and verify the helper maps an interior instruction address to the expected x64 unwind function start.

If this cannot be made deterministic without a large harness, document `NOT RUN` rather than fabricating coverage.

### 18.4 Patch writer

In a disposable executable memory page:

```text
expected bytes -> replacement succeeds
replacement verifies
protection restored
instruction cache flush path reached
invalid/null address fails
mismatching expected bytes skip
```

### 18.5 Thread suspension scope

At minimum verify:

- current thread is never suspended,
- a worker thread can be observed frozen during the scope,
- worker resumes after scope destruction,
- zero-thread / snapshot-failure paths do not leave a mutex permanently locked,
- each successfully suspended thread is resumed exactly once.

### 18.6 Profile gating

Verify:

```text
MHW        dd2Family=1 dd2ScannerCrasher=1
other five dd2Family=1 dd2ScannerCrasher=0
unsupported executable -> no PR2 path
```

---

## 19. Runtime validation order

Preferred order:

```text
1. MHW
2. DD2
3. RE9
4. PRAGMATA
5. Onimusha WotS
6. MHS3
```

If a game is unavailable, report `NOT RUN`.

Do not claim success without runtime evidence.

### MHW minimum validation

Confirm:

```text
profile identifies MHW
common PR1 guards remain active
MHW scanner/crasher sub-capability is enabled
QPF/QPC import discovery succeeds
crasher function discovery succeeds
scanner function discovery succeeds
scanner RET patch validates/applies
crasher JZ->JMP validates/applies
createBLAS discovered
corruption_when_zero discovered
createBLAS hook installed
DD2 constants scan runs
DbgUi watcher still initializes afterward
game reaches rendering / gameplay
no immediate crash/hang introduced by PR2
```

Do not require exactly five constants as a hard pass criterion; report the observed count.

### DD2 / RE9 / PRAGMATA minimum validation

Confirm explicitly:

```text
MHW-only scanner/crasher = SKIPPED BY PROFILE
createBLAS path runs
constants path runs
DbgUi still initializes
startup reaches rendering
```

For PRAGMATA, the absence of MHW scanner/crasher execution is a required regression check.

---

## 20. Failure policy

Every sub-layer is fail-soft.

Examples:

```text
MHW QPF/QPC discovery fails
  -> skip MHW scanner/crasher
  -> continue createBLAS + constants + DbgUi

createBLAS string/function scan fails
  -> log
  -> do not install hook
  -> continue constants + DbgUi

corruption pointer validation fails
  -> do not hook createBLAS with an invalid state pointer
  -> continue constants + DbgUi

one suspicious constant candidate revalidation fails
  -> skip that candidate
  -> continue remaining candidates

thread suspension cannot establish a safe raw-patch window
  -> skip raw byte writes
  -> do not crash or force writes
  -> createBLAS hook / DbgUi may still proceed if safe
```

Never use guessed RVAs.

Never patch bytes merely because they are near an expected pattern.

Never turn a scanner miss into a process crash.

---

## 21. Review-sensitive invariants / reject conditions

Request changes if any of the following occur:

1. The MHW scanner/crasher path is enabled for any of the other five games.
2. TDB version is used to auto-enable a future unsupported game.
3. Fixed RVAs replace the source-based discovery logic.
4. Basic scanning/patch infrastructure is reinvented without using the available OptiPatcher / pinned Kananlib references.
5. The whole Kananlib/REFramework runtime is dragged in when only a few helpers are needed.
6. Kananlib-derived code is copied without the Boost license notice / attribution.
7. Raw patches are written without final byte revalidation.
8. Scanner function is patched to `RET` without a validated x64 function start.
9. Crasher branch is changed without confirming the exact `39 0C 82 74 ?` local pattern / `0x74` byte.
10. DD2 constants are patched without verifying `81 ? E1 53 BD 4C` and the original immediate.
11. `createBLAS` uses a fixed address instead of string/ref/function discovery.
12. The resolved `corruption_when_zero` pointer is dereferenced without basic memory validation / fail-soft protection.
13. The createBLAS hook fails to call the original function.
14. SafetyHook is added solely for createBLAS instead of reusing the existing PR1 MinHook wrapper without a demonstrated requirement.
15. A second DbgUi watcher is started from DD2FamilyBypass.
16. PAK / `/natives/` / custom PAK functionality leaks into PR2.
17. RE9-family / heartbeat / stack-destroyer code leaks into PR2.
18. `PatchResult()` changes from `false`.
19. A top-level one-shot latch makes all PR2 layers permanently unrecoverable after a partial failure.
20. Existing PR0/PR1 behavior is weakened to make PR2 easier to implement.

---

## 22. Expected PR contents

Likely changed/new files:

```text
src/GameProfile.h
src/GameProfile.cpp
src/dllmain.cpp
src/CapcomPatcher.vcxproj
src/CapcomPatcher.vcxproj.filters

src/memory/MemoryScan.h
src/memory/MemoryScan.cpp
src/memory/MemoryPatch.h
src/memory/MemoryPatch.cpp
src/memory/ThreadSuspension.h
src/memory/ThreadSuspension.cpp

src/antitamper/DD2FamilyBypass.h
src/antitamper/DD2FamilyBypass.cpp

README.md
THIRD_PARTY_NOTICES.md      # if Kananlib code is copied/adapted
```

Do not modify the hardened DbgUi watcher unless an integration-only include/build change is genuinely required.

Do not rewrite PR1 runtime guards.

---

## 23. PR body requirements

The PR description must state:

1. base commit,
2. exact REFramework pin,
3. exact OptiPatcher scanner/patcher pin used as reference,
4. exact Kananlib pin if any code is adapted,
5. which code was copied/adapted vs locally written,
6. MHW-only scanner/crasher gating,
7. all-six createBLAS + constant behavior,
8. thread/race-safety approach,
9. deliberate deviations/hardening from upstream,
10. Debug/Release build results,
11. deterministic test results,
12. runtime game results or `NOT RUN`,
13. confirmation that PAK/RE9/heartbeat/etc. are not part of PR2,
14. confirmation that `PatchResult()` remains false.

Open the PR as **Draft** and do not merge it automatically.

---

## 24. Completion criteria

PR2 is complete when all of the following are true:

```text
[ ] all six selected games still resolve explicitly
[ ] MHW alone has dd2ScannerCrasher=true
[ ] MHW scanner/crasher behavior is a source-faithful port
[ ] createBLAS discovery is source-based, not RVA-based
[ ] corruption_when_zero is validated and guarded
[ ] createBLAS hook reuses existing PR1 MinHook wrapper
[ ] DD2-family constant pattern is implemented exactly
[ ] raw writes are revalidated immediately before commit
[ ] raw patching has equivalent thread/race safety
[ ] scanner/patcher code reuses existing OptiPatcher/Kananlib source where practical
[ ] no PAK / natives behavior imported
[ ] no duplicate DbgUi watcher imported
[ ] no RE9-family / heartbeat / stack-destroyer behavior imported
[ ] Debug x64 builds
[ ] Release x64 builds
[ ] git diff --check passes
[ ] exports remain InitializeASI + PatchResult
[ ] PatchResult() remains false
[ ] attribution/licenses updated for any newly adapted third-party code
[ ] PR body reports runtime tests honestly
[ ] PR is left open for review
```

---

# Final implementation principle

The target is not a new approximation of Capcom anti-tamper behavior.

The target for PR2 is:

> Extract the confirmed direct DD2-family anti-tamper/stability behavior from current REFramework, reuse existing OptiPatcher/Kananlib infrastructure where it already solves the generic scanning problem, preserve current per-game gating, and integrate it into the already-reviewed Capcom Patcher lifecycle without importing unrelated REFramework mod-loader functionality.
