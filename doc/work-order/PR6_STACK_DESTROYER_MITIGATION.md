# PR6 Work Order — Stack-Destroyer Mitigation

**Repository:** `onehoon/Capcom_Patcher`  
**Base:** latest `main` after merged PR5 (`84d6c1d84e1b4c3eebb6c6d56c0d3adba9f7efc8` at the time this work order was written)  
**Target branch:** new feature branch from latest `main`  
**PR type:** focused implementation / anti-tamper parity  
**Scope:** optional, fail-closed stack-destroyer scan and neutralization for the six explicitly supported games  
**Open as Draft. Do not merge automatically.**

---

# 1. Objective

PR0 through PR5 now provide the following focused REFramework anti-tamper parity layers:

- PR0 — explicit six-game profiles + hardened `DbgUiRemoteBreakin` watcher,
- PR1 — common runtime guards,
- PR2 — DD2-family direct anti-tamper core,
- PR3 — RE9-family scheduler / JobQueue protection + RE9-only slow path,
- PR4 — renderer heartbeat bridge / synchronization,
- PR5 — RE9-family PE-header integrity redirection.

PR6 adds the next remaining planned parity layer:

> Detect the specific REFramework "stack destroyer" routine, prove that the candidate has the expected instruction/function structure, and neutralize it by replacing the function entry with an immediate `RET` (`0xC3`).

This is intentionally a **small, isolated startup patch**.

It is not a generic stack-repair subsystem, exception hook, crash suppressor, control-flow patch framework, or heuristic search for suspicious epilogues.

The layer must remain **fail-closed**:

```text
no candidate       -> no patch, continue startup
invalid candidate  -> no patch, continue startup
multiple valid candidates -> ambiguous, no patch
safe unique candidate -> patch exactly one byte at function entry
```

No failure in PR6 may prevent the other anti-tamper layers from initializing.

---

# 2. Current source state — build on PR5, do not redesign earlier layers

Current `main` when this work order was written:

```text
84d6c1d84e1b4c3eebb6c6d56c0d3adba9f7efc8
```

Relevant current project files:

```text
src/GameProfile.h
src/GameProfile.cpp
src/dllmain.cpp

src/memory/MemoryScan.h
src/memory/MemoryScan.cpp
src/memory/MemoryPatch.h
src/memory/MemoryPatch.cpp
src/memory/ThreadSuspension.h
src/memory/ThreadSuspension.cpp

src/antitamper/DD2FamilyBypass.*
src/antitamper/RE9FamilyBypass.*
src/antitamper/PeHeaderIntegrityBypass.*
src/antitamper/RendererHeartbeatBypass.*

README.md
```

Pinned current-main examples:

```text
https://github.com/onehoon/Capcom_Patcher/blob/84d6c1d84e1b4c3eebb6c6d56c0d3adba9f7efc8/src/GameProfile.h
https://github.com/onehoon/Capcom_Patcher/blob/84d6c1d84e1b4c3eebb6c6d56c0d3adba9f7efc8/src/dllmain.cpp
https://github.com/onehoon/Capcom_Patcher/blob/84d6c1d84e1b4c3eebb6c6d56c0d3adba9f7efc8/src/memory/MemoryScan.h
https://github.com/onehoon/Capcom_Patcher/blob/84d6c1d84e1b4c3eebb6c6d56c0d3adba9f7efc8/src/memory/MemoryPatch.h
```

## 2.1 Existing infrastructure that must be reused

Do **not** add parallel implementations for infrastructure already hardened by PR2-PR5.

Reuse:

- `memory::MainModule()` for the host executable image,
- `memory::Scan()` for the exact byte pattern,
- `memory::DecodeOne()` for instruction-level semantic validation,
- `memory::FindFunctionStart()` / `memory::FindFunctionStartUnwind()` for function-boundary proof,
- `memory::TryReadBytes()` / `memory::IsReadable()` for safe reads,
- `memory::ThreadSuspensionScope` for the short final code-patch window,
- `memory::BytePatchCandidate` + `memory::CommitPatch()` for the actual validated write.

Do not add:

- another scanner,
- another decoder,
- another thread suspender,
- another raw `VirtualProtect` writer,
- MinHook/SafetyHook usage for this PR,
- a worker thread or timer.

PR6 needs only a one-byte startup patch after strong discovery/revalidation.

---

# 3. Source of truth

Use the same already-pinned REFramework behavioral source:

```text
praydog/REFramework
b6baf6b406efc65e077b99cb4d9ad25b0a0a9095
```

Primary function:

```text
src/mods/IntegrityCheckBypass.cpp
IntegrityCheckBypass::remove_stack_destroyer()
```

Pinned link:

```text
https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.cpp
```

Current upstream behavior is intentionally small:

```cpp
void IntegrityCheckBypass::remove_stack_destroyer() {
    spdlog::info("[IntegrityCheckBypass]: Searching for stack destroyer...");

    const auto game = utility::get_executable();
    const auto fn = utility::scan(
        game,
        "48 89 11 48 c7 04 24 00 00 00 00 48 81 c4 28 01 00 00"
    );

    if (!fn) {
        spdlog::error("[IntegrityCheckBypass]: Could not find stack destroyer!");
        return;
    }

    // Create a patch that returns instantly.
    static auto patch = Patch::create(*fn, { 0xC3 }, true);
}
```

REFramework invokes this in the RE Engine anti-tamper startup block while its startup `ThreadSuspender` is still active, after the immediate DD2/RE9 patch layers and before resuming threads.

PR6 should preserve that **behavioral meaning** while applying the stricter Capcom Patcher safety rules established in PR2-PR5.

---

# 4. Selected-game scope

The architecture plan explicitly marks the stack-destroyer scan as fail-closed for **all six** selected games:

| Game | PR6 stack-destroyer |
|---|---:|
| Monster Hunter Wilds | FAIL-CLOSED |
| Dragon's Dogma 2 | FAIL-CLOSED |
| Resident Evil Requiem | FAIL-CLOSED |
| PRAGMATA | FAIL-CLOSED |
| Onimusha: Way of the Sword | FAIL-CLOSED |
| Monster Hunter Stories 3 | FAIL-CLOSED |
| Unsupported / future game | OFF |

Do not use:

```text
TDB >= N
is_reengine_at()-style broad inference
future-game fallback
```

## 4.1 Add an explicit profile capability

Extend `GameProfile` with a dedicated capability:

```cpp
bool stackDestroyer{false};
```

Set it `true` for the six current explicit entries and `false` for unsupported.

Conceptually:

```cpp
struct GameProfile
{
    ...
    bool heartbeat{false};
    bool stackDestroyer{false};
};
```

Update the canonical six-entry table and profile tests accordingly.

Also add a module-local explicit `GameId` allowlist (or equivalent switch) as defense in depth, following PR5's pattern:

```cpp
bool SupportsStackDestroyer(game_profile::GameId id) noexcept
{
    using game_profile::GameId;
    switch (id)
    {
    case GameId::MonsterHunterWilds:
    case GameId::DragonsDogma2:
    case GameId::ResidentEvilRequiem:
    case GameId::Pragmata:
    case GameId::OnimushaWots:
    case GameId::MonsterHunterStories3:
        return true;
    default:
        return false;
    }
}
```

Initialization requires **both**:

```text
profile.stackDestroyer == true
SupportsStackDestroyer(profile.id) == true
```

This prevents a future profile edit from silently enabling a destructive code patch on an unknown game.

---

# 5. Exact upstream signature

Preserve the current upstream signature exactly:

```text
48 89 11 48 C7 04 24 00 00 00 00 48 81 C4 28 01 00 00
```

Length:

```text
18 bytes
```

Do not weaken it with wildcards in PR6.

Do not add alternate signatures based on speculation.

Do not add a generic search for `mov [rsp],0` or `add rsp,0x128`.

If a future game update changes this signature, treat that as a new compatibility change with runtime evidence and a separate review.

---

# 6. Required semantic validation

The raw 18-byte signature is the anchor, but PR6 must additionally prove the decoded meaning before writing anything.

Decode from the candidate start using the already-pinned bddisasm path and require the following exact three-instruction structure.

## 6.1 Instruction 1

Bytes:

```text
48 89 11
```

Required meaning:

```asm
mov qword ptr [rcx], rdx
```

Required checks:

```text
instruction == MOV
length == 3
operand 0 == memory
operand 0 base == RCX
operand 0 has no index-based ambiguity
operand 1 == RDX
64-bit operation
```

## 6.2 Instruction 2

Bytes:

```text
48 C7 04 24 00 00 00 00
```

Required meaning:

```asm
mov qword ptr [rsp], 0
```

Required checks:

```text
instruction == MOV
length == 8
destination == qword memory [RSP]
displacement == 0 / no nonzero displacement
immediate == 0
```

This is the critical destructive behavior: it overwrites the qword at the current stack pointer.

## 6.3 Instruction 3

Bytes:

```text
48 81 C4 28 01 00 00
```

Required meaning:

```asm
add rsp, 0x128
```

Required checks:

```text
instruction == ADD
length == 7
destination register == RSP
immediate == 0x128
64-bit operation
```

The three decoded instruction lengths must sum to exactly 18 bytes.

No decode failure, truncated instruction, unexpected operand form, or boundary mismatch may be accepted.

---

# 7. Function-entry proof is mandatory

Upstream patches the **first byte of the matched address** to `RET`.

That is only safe if the matched address is truly the function entry being neutralized.

Therefore PR6 must require function-start proof before treating a hit as valid.

Preferred validation:

```cpp
const auto unwindStart = memory::FindFunctionStartUnwind(hit);
if (!unwindStart || *unwindStart != hit)
{
    // fail closed
}
```

If there is a project-proven reason to use the non-chain helper as a fallback, an equivalent shape is acceptable:

```cpp
auto functionStart = memory::FindFunctionStartUnwind(hit);
if (!functionStart)
{
    functionStart = memory::FindFunctionStart(hit);
}
if (!functionStart || *functionStart != hit)
{
    reject;
}
```

Do **not** accept:

```text
signature in the middle of another function
signature merely on an instruction boundary
signature in executable data without function-entry proof
```

This hardening is intentional even though current upstream only performs a raw scan. A false negative is safer than inserting `RET` into the middle of valid game code.

---

# 8. Candidate discovery and ambiguity policy

Do not stop at the first raw match.

Scan the entire main executable image and collect all hits.

Recommended internal representation:

```cpp
struct StackDestroyerCandidate
{
    uintptr_t address{};
    std::array<uint8_t, 18> expected{};
};
```

Discovery flow:

```text
1. get main module
2. scan every exact raw signature occurrence
3. log raw match count
4. for each raw hit:
   - range must be inside the main image
   - range must be committed executable memory
   - decode exact three-instruction structure
   - prove function start == hit
   - capture the exact 18 original bytes
5. collect validated candidates
6. require exactly one validated candidate
```

Result policy:

```text
validated_count == 0 -> normal NotFound / no patch
validated_count == 1 -> continue to commit phase
validated_count > 1  -> Ambiguous / no patch
```

Do not choose:

- lowest address,
- first raw match,
- first executable match,
- first unwind match,
- game-specific guessed offset.

If multiple candidates survive the full semantic/function validation, PR6 has insufficient evidence to know which one is the intended target.

---

# 9. Patch shape

For one validated candidate, the upstream behavior is exactly:

```asm
RET
```

Encoding:

```text
C3
```

Patch **one byte only** at the validated function entry.

Do not NOP the full 18-byte block.

Do not replace the body with a larger stub.

Do not allocate executable memory.

Do not create a trampoline.

Do not hook the function.

Build a normal existing `memory::BytePatchCandidate`:

```cpp
memory::BytePatchCandidate patch{};
patch.address = candidate.address;
patch.expected.assign(candidate.expected.begin(), candidate.expected.end());
patch.writeOffset = 0;
patch.replacement = {0xC3};
patch.name = "stack-destroyer immediate return";
patch.requireExecutable = true;
patch.requireUnwindFunctionStart = true;
```

Then commit with `memory::CommitPatch()`.

The full 18-byte `expected` context must still match even though only byte 0 is written.

This preserves the strongest local identity available immediately before the write.

---

# 10. Two-phase commit and thread suspension

Follow the existing PR2/PR5 code-patch safety policy.

## 10.1 Discovery phase — no writes

During discovery:

- scan,
- decode,
- validate function entry,
- count candidates,
- capture bytes,
- prepare the patch candidate,

with **no game-memory writes**.

## 10.2 Pre-suspension uniqueness re-check

Immediately before acquiring the suspension scope, re-run enough discovery to ensure the unique candidate still resolves to the same address.

This may be a second full signature scan because it runs before suspension.

Required:

```text
still exactly one validated candidate
same candidate address
same captured 18 bytes
```

If not, fail closed.

This prevents a startup unpacking / mutation transition from turning an earlier unique result into stale evidence while avoiding a long whole-image scan with other threads suspended.

## 10.3 Short suspended commit window

Then:

```cpp
memory::ThreadSuspensionScope suspension;
if (!suspension.Ok())
{
    // fail closed
    return;
}
```

While suspended, perform only bounded local revalidation:

1. main module base/range unchanged,
2. exact 18 bytes unchanged,
3. target remains executable/committed,
4. the three decoded instructions still have the required semantics,
5. function-start proof still resolves exactly to the candidate address,
6. `CommitPatch()` performs its own expected-byte / executable / unwind-start validation immediately before writing.

No whole-module rescan is required while threads are suspended if the pre-suspension uniqueness re-check has already succeeded.

Always rely on RAII to resume threads on every return path.

Do not call this from `DllMain`.

---

# 11. Idempotency / lifecycle

PR6 is a one-shot startup component.

It must be safe if `InitializeASI()` is called more than once.

Suggested state:

```cpp
enum class State
{
    Uninitialized,
    Patched,
    NotFound,
    Ambiguous,
    Failed,
};
```

Requirements:

```text
Patched    -> terminal
NotFound   -> terminal for the process
Ambiguous  -> terminal for the process
Failed     -> terminal for the process (no automatic worker/retry loop)
```

A small mutex/state equivalent to PR5 is fine.

There must be:

- at most one successful stack-destroyer patch,
- no repeated thread suspension after terminal state,
- no polling,
- no recurring rescan.

---

# 12. Proposed source layout

Add a focused component:

```text
src/antitamper/StackDestroyerBypass.h
src/antitamper/StackDestroyerBypass.cpp
```

Update:

```text
src/GameProfile.h
src/GameProfile.cpp
src/dllmain.cpp
src/CapcomPatcher.vcxproj
src/CapcomPatcher.vcxproj.filters
README.md
```

No new third-party dependency is needed.

`THIRD_PARTY_NOTICES.md` should not require a new license entry because this PR uses existing project infrastructure and a small behavior/pattern already covered by the existing REFramework attribution.

If the README status list is maintained, add PR6 and change the remaining-parity text so module-path spoofing review/classification is the only explicitly deferred architecture item before final six-game validation/cleanup.

---

# 13. Startup ordering

Current high-level startup order after PR5:

```text
RuntimeGuards
  -> DD2Family
  -> RE9Family
  -> PEHeaderIntegrity
  -> RendererHeartbeat
  -> DbgUi watcher
```

PR6 should become:

```text
RuntimeGuards
  -> DD2Family
  -> RE9Family
  -> PEHeaderIntegrity
  -> StackDestroyer          <-- PR6
  -> RendererHeartbeat
  -> DbgUi watcher
```

Reason:

- upstream runs the stack-destroyer neutralization in the immediate startup anti-tamper block after its DD2/RE9 immediate patches and before resuming threads,
- PR6 is a one-shot code patch,
- heartbeat and DbgUi are long-lived services and should start only after startup code patching is complete.

Conceptual `InitializeASI()` shape:

```cpp
if (profile.re9Family)
{
    antitamper::re9_family::Initialize(profile);
    antitamper::pe_header::Initialize(profile);
}

if (profile.stackDestroyer)
{
    antitamper::stack_destroyer::Initialize(profile);
}

if (profile.heartbeat)
{
    antitamper::heartbeat::Initialize(profile);
}
```

MHW therefore still runs PR6 even though it does not enter the RE9-family block.

`PatchResult()` must remain `false`.

---

# 14. Logging

Startup-only logs should be concise and diagnostic.

Recommended shape:

```text
[CapcomPatcher][StackDestroyer] scan started
[CapcomPatcher][StackDestroyer] raw matches=N validated=M
[CapcomPatcher][StackDestroyer] candidate @ +0x... validated
[CapcomPatcher][StackDestroyer] patched @ +0x... -> RET
```

Normal no-match:

```text
[CapcomPatcher][StackDestroyer] not found; no patch applied
```

Ambiguous:

```text
[CapcomPatcher][StackDestroyer] multiple validated candidates (N); no patch applied
```

Fail-closed diagnostics:

```text
candidate outside executable image
candidate is not a proven function entry
instruction semantics mismatch
candidate changed before suspension
safe suspension window unavailable
final revalidation changed; skipped
commit failed
```

Do not log every raw address in normal builds unless more than one match exists or debug logging is explicitly enabled.

No-match is expected on many sampled builds and must not be logged as a fatal ASI error.

---

# 15. Deterministic tests

Add focused PR6 checks to the existing test harness style.

Do not introduce a large new test framework.

## 15.1 Scope/profile tests

Verify:

```text
MHW       -> true
DD2       -> true
RE9       -> true
PRAGMATA  -> true
Onimusha  -> true
MHS3      -> true
Unsupported -> false
```

Verify both the profile capability and module-local explicit allowlist.

## 15.2 Exact decode/semantic tests

Use the real upstream 18-byte fixture:

```text
48 89 11 48 C7 04 24 00 00 00 00 48 81 C4 28 01 00 00
```

Require production semantic validation to observe:

```text
MOV [RCX], RDX      len=3
MOV QWORD [RSP], 0  len=8
ADD RSP, 0x128      len=7
sum                 len=18
```

Reject fixtures where one semantic element is changed, for example:

```text
MOV [RAX], RDX
MOV [RSP+8], 0
MOV [RSP], 1
ADD RSP, 0x120
truncated final ADD
extra/missing byte causing a boundary shift
```

Where possible, mutate bytes and decode with the actual production `DecodeOne()` path rather than testing only a duplicated boolean model.

## 15.3 Function-entry proof tests

Reuse existing unwind/function-start helpers.

At minimum verify on a known compiled test function that:

```text
actual function entry -> accepted by the function-start helper
interior instruction address -> not equal to function start
```

PR6 production code must still require `candidate == function start`.

Do not create a test-only production bypass that allows synthetic non-function entries.

## 15.4 Candidate-count policy tests

Test the production selection logic (or a narrow helper used by production):

```text
0 validated -> NotFound
1 validated -> Selected
2 validated -> Ambiguous / no selection
```

Never test "first candidate wins" because that behavior is forbidden.

## 15.5 Patch construction tests

For a valid candidate require:

```text
expected.size() == 18
writeOffset == 0
replacement == { 0xC3 }
requireExecutable == true
requireUnwindFunctionStart == true
```

Ensure PR6 does not generate 18 NOPs or a trampoline.

## 15.6 Final revalidation mutation tests

Before any raw writer is allowed, reject when:

```text
one of the 18 bytes changes
function-start proof changes/fails
executable-memory validation fails
candidate address changes between discovery and pre-suspension re-check
candidate count changes from 1 to 2
thread suspension reports failure
```

No invalidation test may invoke `CommitPatch()` after the failure is detected.

## 15.7 Existing regression suites

Run all existing PR0-PR5 deterministic checks unchanged.

PR6 must not regress:

```text
PR0 profile / DbgUi behavior
PR1 runtime guards
PR2 bddisasm / CFG / thread suspension / DD2-family core
PR3 glob / JobGuard / CAS / RE9 slow path
PR4 renderer bridge / heartbeat
PR5 BDShemu / PE-header redirection
```

---

# 16. Build and static verification

Required:

```text
x64 Debug build
x64 Release build
git diff --check
```

Keep the committed toolset policy unchanged.

Verify exports remain exactly:

```text
InitializeASI
PatchResult
```

`PatchResult()` must still return `false`.

No x86 support.

No CI addition is required solely for PR6 unless repository policy changes separately.

---

# 17. Runtime validation matrix

Do not claim success merely because the game launches.

For every available game, capture at least:

```text
game/profile detected
stackDestroyer gate enabled
raw match count
validated match count
candidate/function-start result
patch result if unique candidate exists
game reaches menu/gameplay without new crash
```

Matrix:

| Game | Expected gate | Valid outcome |
|---|---:|---|
| MHW | ON | not found / unique safe patch |
| DD2 | ON | not found / unique safe patch |
| RE9 | ON | not found / unique safe patch |
| PRAGMATA | ON | not found / unique safe patch |
| Onimusha | ON | not found / unique safe patch |
| MHS3 | ON | not found / unique safe patch |
| Unsupported | OFF | no scan |

Existing sampled builds often do not expose this signature. Therefore:

```text
not found / no patch applied
```

is a legitimate runtime result and must not be converted into a fake success/failure.

If a real candidate is found and patched, additionally verify:

```text
candidate was unique after semantic/function validation
pre-patch first byte was 0x48
post-patch first byte is 0xC3
remaining 17 bytes are unchanged
protection was restored
instruction cache was flushed
no persistent worker/hook was created
```

If runtime games are unavailable, report `NOT RUN` honestly.

---

# 18. Explicit non-goals

Do **not** include any of the following in PR6:

- module-path spoofing,
- `_storage_` path behavior,
- PAK / natives / loose-file features,
- new DD2-family patterns,
- new RE9-family constants,
- new JobQueue behavior,
- new PE-header behavior,
- heartbeat changes,
- renderer bridge changes,
- DbgUi changes,
- generic stack unwinding/repair,
- VEH-based crash suppression,
- exception swallowing,
- generic `RET` patch catalog,
- alternate stack-destroyer patterns without evidence,
- fixed per-game offsets,
- DXGI / Present / ResizeBuffers / D3D hooks,
- OptiScaler changes,
- Special K integration,
- new hook backends,
- worker/timer/polling logic,
- future/TDB-derived game support.

Keep this PR reviewable as one tiny anti-tamper parity layer.

---

# 19. Reject invariants

The implementation is incorrect if any of the following become possible:

1. An unsupported or future game runs the stack-destroyer scan.
2. A TDB threshold automatically enables PR6.
3. A wildcard/weakened signature is used without dedicated evidence/review.
4. The first raw signature hit is patched without scanning for ambiguity.
5. Multiple validated candidates are resolved by guessing.
6. A candidate that is not a proven function entry is patched.
7. The exact three-instruction semantics are not decoded/validated.
8. Discovery performs a game-memory write.
9. Code is patched without a successful `ThreadSuspensionScope`.
10. The 18-byte identity is not revalidated before commit.
11. The patch writes more than the single intended `0xC3` byte.
12. The patch bypasses `BytePatchCandidate` / `CommitPatch()`.
13. Executable protection is not required.
14. Unwind-function-start validation is disabled for the final patch candidate.
15. Protection restoration / instruction-cache flush / read-back verification are bypassed.
16. No-match is treated as fatal to the ASI.
17. PR6 adds a worker, hook, timer, trampoline, or executable allocation.
18. `PatchResult()` becomes true.

---

# 20. Suggested implementation skeleton

Illustrative only; use existing project style/helpers.

```cpp
namespace antitamper::stack_destroyer
{
namespace detail
{
inline constexpr std::array<uint8_t, 18> kSignatureBytes{
    0x48, 0x89, 0x11,
    0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x81, 0xC4, 0x28, 0x01, 0x00, 0x00,
};

struct Candidate
{
    uintptr_t address{};
    std::array<uint8_t, 18> expected{};
};

bool ValidateSequence(uintptr_t address) noexcept;
bool IsProvenFunctionEntry(uintptr_t address) noexcept;
std::vector<Candidate> DiscoverValidated(const memory::ModuleRange& game) noexcept;
bool CandidateStillValid(const memory::ModuleRange& game, const Candidate& candidate) noexcept;
}

void Initialize(const game_profile::GameProfile& profile) noexcept
{
    if (!profile.stackDestroyer || !SupportsStackDestroyer(profile.id))
        return;

    // lifecycle mutex / terminal state omitted here for brevity

    const auto game = memory::MainModule();
    if (!game)
        return;

    const auto first = detail::DiscoverValidated(game);
    if (first.empty())
        return; // normal no-match
    if (first.size() != 1)
        return; // ambiguous

    const auto candidate = first.front();

    // Re-scan before suspension so uniqueness is current without holding
    // all other threads during a whole-image scan.
    const auto second = detail::DiscoverValidated(game);
    if (second.size() != 1 || second.front().address != candidate.address ||
        second.front().expected != candidate.expected)
        return;

    memory::ThreadSuspensionScope suspension;
    if (!suspension.Ok())
        return;

    const auto currentGame = memory::MainModule();
    if (!currentGame || currentGame.base != game.base || currentGame.size != game.size ||
        !detail::CandidateStillValid(game, candidate))
        return;

    memory::BytePatchCandidate patch{};
    patch.address = candidate.address;
    patch.expected.assign(candidate.expected.begin(), candidate.expected.end());
    patch.writeOffset = 0;
    patch.replacement = {0xC3};
    patch.name = "stack-destroyer immediate return";
    patch.requireExecutable = true;
    patch.requireUnwindFunctionStart = true;

    (void)memory::CommitPatch(patch);
}
}
```

Do not copy the skeleton blindly if an existing helper already provides the same validation.

---

# 21. Completion criteria

PR6 is complete only when all of the following are true:

- [ ] branch is based on latest `main` containing merged PR5 (`84d6c1d8...` or newer)
- [ ] `GameProfile` explicitly represents stack-destroyer capability
- [ ] all six selected games opt in explicitly
- [ ] unsupported/future games are statically OFF
- [ ] module-local six-game allowlist provides defense in depth
- [ ] upstream exact 18-byte signature is preserved without speculative alternates
- [ ] all raw matches are scanned rather than first-hit-wins
- [ ] exact three-instruction bddisasm semantics are validated
- [ ] candidate must be a proven function entry
- [ ] only exactly one validated candidate may proceed
- [ ] zero candidates is a normal no-op
- [ ] multiple validated candidates is fail-closed / no patch
- [ ] discovery performs no writes
- [ ] uniqueness/address/bytes are re-checked immediately before suspension
- [ ] final local meaning is revalidated under successful thread suspension
- [ ] actual write uses `BytePatchCandidate` / `CommitPatch()`
- [ ] full 18-byte expected context is carried into final commit
- [ ] replacement is exactly one byte: `C3`
- [ ] `requireExecutable = true`
- [ ] `requireUnwindFunctionStart = true`
- [ ] no worker/timer/hook/trampoline/executable allocation is added
- [ ] `PatchResult()` remains false
- [ ] README status is updated for PR6 / remaining parity work
- [ ] x64 Debug build passes
- [ ] x64 Release build passes
- [ ] `git diff --check` passes
- [ ] new PR6 deterministic tests pass
- [ ] PR0-PR5 regression suites pass
- [ ] runtime results unavailable to the coding environment are reported `NOT RUN`
- [ ] PR opened as Draft

---

# 22. Expected PR summary shape

The implementation PR body should clearly report:

```text
Base main SHA
REFramework behavioral pin
six-game explicit gate / Unsupported OFF
exact stack-destroyer signature
raw match count / validated candidate policy
three-instruction semantic validation
function-entry proof strategy
one-byte RET patch strategy
pre-suspension uniqueness re-check
thread-suspended final revalidation
BytePatchCandidate / CommitPatch usage
build results
deterministic PR6 test count
PR0-PR5 regression results
runtime six-game matrix (including NOT RUN)
remaining parity work
```

Remaining architecture work after PR6 should be stated accurately:

```text
module-path spoofing review / classification
six-game runtime validation and cleanup
```

Do not claim full REFramework anti-tamper parity until the module-path item has been explicitly classified and the selected-game runtime validation phase is complete.
