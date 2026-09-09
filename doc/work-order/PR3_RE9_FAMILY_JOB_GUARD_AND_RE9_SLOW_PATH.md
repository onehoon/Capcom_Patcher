# PR3 Work Order — RE9-Family Job Guard + RE9-Only Slow-Path Discriminator

**Repository:** `onehoon/Capcom_Patcher`  
**Base:** current `main` after merged PR2 (`d1a828c8eaf5c9e5655974018c0391e173503e40` at the time this work order was written)  
**Target branch:** new feature branch from latest `main`  
**PR type:** focused implementation / anti-tamper parity  
**Scope:** RE9-family scheduler/job corruption defense + RE9-only slow-path discriminator  
**Open as Draft. Do not merge automatically.**

---

## 1. Objective

PR0 established the dedicated six-game Capcom Patcher ASI and the hardened `DbgUiRemoteBreakin` watcher.

PR1 added the common early/runtime guards:

- pristine `NtProtectVirtualMemory` capture,
- `VirtualProtect` / `NtProtectVirtualMemory` integrity protection,
- `AddVectoredExceptionHandler` filtering,
- `RtlExitUserProcess -> TerminateProcess` protection.

PR2 added the DD2-family direct core:

- MHW-only scanner/crasher suppression,
- all-six `createBLAS` corruption recovery,
- all-six DD2-family suspicious constant patches,
- fail-closed scan / patch / thread-suspension infrastructure,
- pinned `bddisasm` decoder matching REFramework/Kananlib.

PR3 adds the next anti-tamper parity layer from current REFramework `IntegrityCheckBypass::immediate_patch_re9()`:

1. **RE9-family BushClover / suspicious constant patch**
2. **RE9-family integrity-job function-pointer guard at scheduler callsites**
3. **RE9-only slow-path discriminator patch**
4. the minimum scan/decode/context infrastructure required by those mechanisms

This PR intentionally does **not** add heartbeat, PE-header redirection, stack-destroyer handling, or module-path spoofing. Those remain tracked parity work, not rejected features.

The reason for keeping PE-header redirection out of PR3 is implementation isolation: current REFramework's PE-header path also pulls in emulation/JIT-style patch construction, while the known DD2/RE9/PRAGMATA logs scan for it but do not currently match a candidate. PR3 should land the scheduler/job crash defense that is known to activate in working sessions without mixing a second, materially different emulation subsystem into the same review.

---

## 2. Current `main` — do not rebuild what PR2 already provides

Use the merged PR2 code as the starting point, not the older work-order assumptions.

Current `main` at the time of writing:

```text
d1a828c8eaf5c9e5655974018c0391e173503e40
```

Relevant existing files:

```text
src/GameProfile.h
src/GameProfile.cpp
src/dllmain.cpp
src/hooking/MinHookInlineHook.*
src/memory/MemoryScan.*
src/memory/MemoryPatch.*
src/memory/ThreadSuspension.*
src/antitamper/DD2FamilyBypass.*
third_party/bddisasm/
third_party/minhook/
```

### Existing capabilities already correct

`GameProfile` already contains:

```cpp
bool re9Family{false};
bool re9SlowPath{false};
bool heartbeat{false};
```

and current profile policy is already:

```text
MHW        re9Family=false  re9SlowPath=false  heartbeat=false
DD2        re9Family=true   re9SlowPath=false  heartbeat=true
RE9        re9Family=true   re9SlowPath=true   heartbeat=true
PRAGMATA   re9Family=true   re9SlowPath=false  heartbeat=true
Onimusha   re9Family=true   re9SlowPath=false  heartbeat=true
MHS3       re9Family=true   re9SlowPath=false  heartbeat=true
```

Do not redesign this table. PR3 should consume `re9Family` and `re9SlowPath` exactly as they already exist.

Do not derive support from TDB values.

Do not add demo/trial executables.

---

## 3. Primary behavioral source of truth — port current REF, do not invent a substitute

Use current analyzed REFramework as the behavioral source of truth:

- Repository: `praydog/REFramework`
- Commit: `b6baf6b406efc65e077b99cb4d9ad25b0a0a9095`
- Main implementation:
  - <https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.cpp>
- Header:
  - <https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.hpp>

Relevant current REF code/state includes:

```text
IntegrityCheckBypass::immediate_patch_re9()
noop_job
validate_job_func<reg>()
get_submit_descriptor_original_func_ptr()
remember_submit_descriptor_original_func_ptr()
RE9 slow-path discriminator scan
RE9+ suspicious constants
JobQueue callsite mid-hooks
```

The new implementation should remain visibly traceable to those mechanisms.

Do not replace them with a different anti-tamper theory merely because Capcom Patcher is a smaller project.

---

## 4. Runtime evidence that defines priority

The architecture analysis has already established the following from working REF + OptiScaler sessions:

### DD2

Current REF executes the RE9-family path because DD2 is now in the TDB83 route.

Observed behavior includes:

```text
Patched 1 sus_constants! (RE9+)
Could not find conditional move instruction for thread scheduler corruptor
Could not find thread scheduler corruptor
Attempting to hook JobQueue::SubmitDescriptor as a fallback for RE9
```

Multiple integrity-check job callsites were then actually hooked.

### RE9

Observed behavior includes:

```text
Patched 1 sus_constants! (RE9+)
Found slow path discriminator ... patching
Patched slow path discriminator!
Attempting to hook JobQueue::SubmitDescriptor as a fallback
```

The JobQueue callsite fallback is installed even when the slow-path patch succeeds. Current REF explicitly comments:

```text
Hook this anyways as a backup plan.
```

PR3 must preserve that.

### PRAGMATA

Observed behavior includes RE9-family callsite hooks even though Opti-only currently survives and no DbgUiRemoteBreakin payload was observed in that particular REF session.

Therefore the JobQueue defense is not an RE9-only feature.

### MHS3

Upstream history explicitly lowered the RE9-family gate to include TDB82 because the same anti-tamper family was found in MHS3.

Current REF job-callsite pattern comments explicitly state the main candidate was observed in both RE9 PC and MHSTORIES3.

### Onimusha

No runtime hit log is currently available, but current REF deliberately routes the TDB82 game through `immediate_patch_re9()`. Capcom Patcher should therefore scan/apply the generic RE9-family mechanisms fail-soft under its explicit Onimusha profile.

### MHW

MHW is TDB81 and current REF does not run `immediate_patch_re9()` for it.

**PR3 must never install any RE9-family mechanism on MHW.**

---

# 5. Scope matrix

PR3 policy must be explicit:

| Game | RE9+ constant | Job callsite guard | RE9 slow-path |
|---|---:|---:|---:|
| MHW | No | No | No |
| DD2 | Yes | Yes | No |
| RE9 | Yes | Yes | **Yes** |
| PRAGMATA | Yes | Yes | No |
| Onimusha WotS | Yes | Yes | No |
| MHS3 | Yes | Yes | No |

Implementation gate:

```cpp
if (profile.re9Family)
    antitamper::re9_family::Initialize(profile);
```

Inside the module:

```cpp
if (profile.re9SlowPath)
    DiscoverRe9SlowPath(...);
```

Do not hide this distinction behind executable-name checks inside the low-level scan functions.

---

# 6. Proposed source structure

Recommended additions:

```text
src/
├─ antitamper/
│  ├─ RE9FamilyBypass.h
│  └─ RE9FamilyBypass.cpp
│
├─ hooking/
│  ├─ SafetyHookMid.h          # optional thin project wrapper
│  └─ SafetyHookMid.cpp        # optional thin project wrapper
│
└─ memory/
   ├─ MemoryScan.h             # extend existing implementation only as needed
   └─ MemoryScan.cpp

third_party/
├─ safetyhook/
├─ zydis/
└─ zycore/
```

Exact wrapper naming may differ.

Do not put RE9-family logic in `dllmain.cpp`.

`dllmain.cpp` remains dispatch-only.

---

# 7. Dependency strategy — reuse REF's exact mid-hook stack

## 7.1 Why MinHook alone is not sufficient here

PR1/PR2 use MinHook for normal inline hooks. Keep doing that for ordinary function detours.

However the current REF JobQueue fallback uses **mid-hooks** at specific scheduler callsites because it must inspect and potentially rewrite live register context before the indirect call executes.

Do not build a custom context-save trampoline or hand-written code-cave system merely to avoid a dependency.

Use the same SafetyHook family current REF uses.

## 7.2 SafetyHook pin

Current pinned REFramework fetches:

```text
cursey/safetyhook
b046e123dc69821f2c375161e0adef3c6d9c9db4
```

Reference:

- <https://github.com/cursey/safetyhook/tree/b046e123dc69821f2c375161e0adef3c6d9c9db4>
- mid-hook API:
  - `include/safetyhook/mid_hook.hpp`
  - `src/mid_hook.cpp`
  - Windows x64 assembly/context support from the same revision

License: Boost Software License 1.0.

## 7.3 SafetyHook decoder dependency

That SafetyHook revision explicitly uses:

```text
Zydis v4.0.0
```

Zydis v4.0.0 in turn pins the Zycore submodule at:

```text
zyantific/zycore-c
1401fb85ac313f6605ec795c52bf99ea3f292a69
```

If dependencies are vendored for this Visual Studio solution, pin all three exactly and document them.

Do not silently use today's SafetyHook or Zydis `master`.

## 7.4 Keep decoder responsibilities separate

PR2 already vendors `bddisasm@70db095...` for Capcom Patcher's own REFramework/Kananlib-style scan semantics.

Do **not** replace the PR2 scanner decoder with Zydis just because SafetyHook internally needs Zydis.

Required separation:

```text
Capcom Patcher scan / RE9 structural decoding -> existing pinned bddisasm
SafetyHook internal relocation/mid-hook engine  -> SafetyHook's pinned Zydis
MinHook trampoline internals                   -> MinHook's existing HDE64
```

Three decoder implementations are not elegant, but they have different ownership and keeping their upstream pins intact is safer than cross-wiring dependencies during anti-tamper work.

## 7.5 Visual Studio integration

The repository currently uses a `.sln/.vcxproj`, not CMake.

Vendor/build only the x64 Windows portions required for SafetyHook. Do not add SafetyHook tests, examples, docs, Linux sources, or generic CMake conversion to Capcom Patcher.

SafetyHook at this pin declares C++23. Keep Capcom Patcher's own default at C++20 if possible; compile SafetyHook and any translation unit that directly requires its C++23 API with the minimum necessary per-file language-standard override.

Do not globally refactor the project language standard unless the actual build requires it.

Update:

```text
.gitattributes
THIRD_PARTY_NOTICES.md
src/CapcomPatcher.vcxproj
src/CapcomPatcher.vcxproj.filters
```

for exact vendored pins and licenses.

---

# 8. RE9-family suspicious constant / BushClover defense

Current REF explains this as a fix for calls into **BushClover**, a manually mapped RE Engine DLL that can trigger a crafted fake-UD2 exception through `KiUserExceptionDispatcher`.

Current pattern:

```text
E1 53 BD 4C 75 ?
```

Current patch:

```text
E1 53 BD 4C
    ->
EF BE 37 13
```

which is little-endian:

```cpp
0x1337BEEF
```

### Required discovery

Reuse the PR2 byte scanner and `BytePatchCandidate` machinery.

Conceptually:

```cpp
for (auto ref = memory::Scan(game, "E1 53 BD 4C 75 ?");
     ref;
     ref = FindNext(...))
{
    uint8_t local[6]{};
    if (!memory::TryReadBytes(*ref, local, sizeof(local)))
        continue;

    if (local[0] != 0xE1 || local[1] != 0x53 ||
        local[2] != 0xBD || local[3] != 0x4C ||
        local[4] != 0x75)
        continue;

    memory::BytePatchCandidate c{};
    c.address = *ref;
    c.expected.assign(local, local + sizeof(local));
    c.writeOffset = 0;
    c.replacement = {0xEF, 0xBE, 0x37, 0x13};
    c.name = "re9 sus_constant / BushClover";
    c.requireExecutable = true;
    out.push_back(std::move(c));
}
```

Use the same PR2 two-phase policy:

```text
read-only discovery
-> short ThreadSuspensionScope
-> full expected-byte revalidation
-> write
-> read-back verify
-> resume
```

Do not use a separate raw-write implementation.

A zero-match result is not fatal.

Log the number of scanned/matched/patched candidates separately.

---

# 9. The actual scheduler corruption mechanism

Preserve the current REF model.

Current source comments describe the anti-tamper as locating **UD2 gadgets**, including byte sequences in the middle of otherwise valid instructions, and replacing random scheduler job function pointers with those UD2 addresses.

The desired defense is therefore not "disable all scheduler jobs".

It is:

```text
normal function pointer -> preserve/cache it
UD2 function pointer     -> restore previously observed legitimate pointer if known
                         -> otherwise replace only the pending call with harmless noop_job
unreadable/bad state     -> fail safe, never execute an obviously corrupt pointer
```

Do not turn every integrity-related job into a no-op unconditionally.

---

# 10. JobQueue callsite discovery — port the current patterns exactly

Current REF uses these two callsite candidates:

```text
? 8b ? 08 ? 8b ? 10 ? 8b ? 18 48 85 c9 0f 84 ? ? ? ? ff d0
? 8b ? 08 ? 8b ? 10 ? 8b ? 18 48 85 c9 74 ? ff d0
```

Current comments identify:

- the first as observed in **RE9 PC and MHS3**,
- the second as a rare path observed in both.

PR3 must scan **all occurrences** of both patterns for every `re9Family` profile.

Do not stop after the first match.

Do not install duplicate hooks if both patterns or repeated initialization resolve to the same hook address.

### 10.1 Descriptor/entry register inference

Current REF decodes the first instruction at the candidate and inspects operand 1 when it is a memory operand:

```cpp
int reg = NDR_RDX; // current upstream fallback

if (dec && dec->OperandsCount >= 2 &&
    dec->Operands[1].Type == ND_OP_MEM)
{
    reg = dec->Operands[1].Info.Memory.Base;
}
```

Use the already-vendored `bddisasm` for this semantic decoding.

Do not infer the register from ModRM bytes manually.

### 10.2 Mid-hook location

Current REF installs the mid-hook at:

```cpp
candidate + 4
```

At that point `RAX` contains the pending job function pointer in the known pattern family.

Preserve that location only after verifying the decoded first instruction is actually 4 bytes long and the candidate structurally matches the expected callsite.

**Hardening requirement:** do not blindly assume `+4` from a pattern match. Re-decode before hook creation:

```cpp
const auto first = memory::DecodeOne(candidate);
if (!first || first->length != 4 || first->operandCount < 2 || ...)
{
    Log("candidate failed semantic validation; skipped");
    continue;
}
```

The exact public decode API may differ. Add a small reusable decode abstraction over the existing PR2 bddisasm code rather than duplicating another bddisasm wrapper inside `RE9FamilyBypass.cpp`.

---

# 11. `noop_job`

Port the current harmless replacement exactly in spirit:

```cpp
static void __fastcall noop_job(int64_t, int64_t)
{
}
```

This is a fallback for an already-corrupted pending function pointer.

Do not return an invented status or call into the scheduler again.

---

# 12. Descriptor original-function cache

Current REF keeps a map from the observed scheduler entry/descriptor identity to its last legitimate function pointer.

Capcom Patcher should retain the same behavior so a UD2 replacement can be repaired rather than simply discarded when a valid prior pointer is known.

Recommended local state:

```cpp
std::unordered_map<uintptr_t, uintptr_t> g_originalJobFunctions;
std::shared_mutex g_originalJobFunctionsMutex;
```

Required helpers:

```cpp
uintptr_t GetRememberedJobFunction(uintptr_t entry) noexcept;
void RememberJobFunction(uintptr_t entry, uintptr_t func) noexcept;
```

Behavior:

```cpp
if (entry == 0 || func == 0)
    return;

if (same value is already cached)
    avoid exclusive-lock churn;

otherwise
    update under exclusive lock;
```

The scheduler path can be hot. Preserve the current REF preference for a shared-lock fast path rather than adding expensive logging/locking on every frame.

Do not keep an unbounded per-call verbose log.

---

# 13. Mid-hook validation behavior

The callback must operate on the live register context from SafetyHook.

Conceptual behavior equivalent to current REF:

```cpp
void ValidateJobFunc(SafetyHookContext& ctx, int descriptorReg)
{
    uintptr_t func = ctx.rax;
    if (func == 0)
        return;

    uintptr_t entry = GetContextRegister(ctx, descriptorReg);

    // Fail-soft readable probe.
    uint16_t head = 0;
    if (!memory::TryReadBytes(func, &head, sizeof(head)))
    {
        // Current REF's exception path ultimately substitutes noop_job
        // when validation itself faults. Keep execution fail-closed.
        ctx.rax = reinterpret_cast<uintptr_t>(&noop_job);
        return;
    }

    if (head == 0x0B0F) // UD2 bytes 0F 0B in little-endian uint16
    {
        const uintptr_t remembered = GetRememberedJobFunction(entry);

        if (remembered != 0 && remembered != func)
        {
            ctx.rax = remembered;

            // Current REF also repairs entry+8 when possible.
            SafeWriteJobEntryFunction(entry, remembered);
        }
        else
        {
            ctx.rax = reinterpret_cast<uintptr_t>(&noop_job);
        }
    }
    else
    {
        RememberJobFunction(entry, func);
    }
}
```

### 13.1 Important UD2 byte order

Current source checks:

```cpp
*reinterpret_cast<uint16_t*>(func_ptr) == 0x0B0F
```

That corresponds to byte sequence:

```text
0F 0B
```

Do not reverse it.

### 13.2 Repairing `entry + 8`

Current REF, when a remembered legitimate function is available, repairs both:

```text
ctx.rax
entry + 8
```

Preserve this behavior if `entry + 8` is writable/readable and still contains the same corrupt function pointer.

Harden the write compared with raw upstream dereferencing:

```cpp
uintptr_t current{};
if (memory::TryReadBytes(entry + 8, &current, sizeof(current)) && current == corrupt)
{
    SafeWritePointer(entry + 8, remembered);
}
```

Do not overwrite an entry that changed between read and repair.

This write is data, not executable code, so it does not need the PR2 executable-code patch pipeline or instruction-cache flush.

It still must be SEH/fail-soft and must not crash the game if the entry is stale.

### 13.3 Fault behavior

The anti-tamper defense itself must not become a new crash source.

Any exception/unreadable pointer while validating a pending job function should result in one of:

- leaving a clearly legitimate value untouched,
- substituting `noop_job` when the pending function cannot safely be trusted,
- skipping the persistent `entry+8` repair if that location cannot be verified.

Never dereference an unvalidated descriptor/entry address outside SEH/fail-soft helpers.

---

# 14. Register-context helper — port only what is needed

Current REF uses `disasm_utils::get_register_value(ctx, reg)`.

Do not port the entire `DisasmUtils` subsystem.

Implement a focused helper for the 16 GPRs needed by the observed patterns:

```cpp
uintptr_t GetContextRegister(const SafetyHookContext& ctx, int reg) noexcept
{
    switch (reg)
    {
    case NDR_RAX: return ctx.rax;
    case NDR_RCX: return ctx.rcx;
    case NDR_RDX: return ctx.rdx;
    case NDR_RBX: return ctx.rbx;
    case NDR_RSP: return ctx.rsp;
    case NDR_RBP: return ctx.rbp;
    case NDR_RSI: return ctx.rsi;
    case NDR_RDI: return ctx.rdi;
    case NDR_R8:  return ctx.r8;
    case NDR_R9:  return ctx.r9;
    case NDR_R10: return ctx.r10;
    case NDR_R11: return ctx.r11;
    case NDR_R12: return ctx.r12;
    case NDR_R13: return ctx.r13;
    case NDR_R14: return ctx.r14;
    case NDR_R15: return ctx.r15;
    default:      return 0;
    }
}
```

Use actual SafetyHook context field names from the pinned API; adjust spelling only if the pinned structure differs.

Do not silently default an unknown decoded register to a random live GPR at runtime.

Current REF uses `RDX` as a historical fallback, but Capcom Patcher has stronger fail-closed policy. If semantic validation cannot identify a supported GPR reliably, skip that callsite rather than hooking it with an uncertain descriptor register.

This is an intentional hardening over upstream, not a semantic redesign of the anti-tamper mechanism.

---

# 15. Mid-hook ownership and idempotency

Keep installed mid-hooks alive for the process lifetime.

Recommended state:

```cpp
struct JobCallsiteHook
{
    uintptr_t address{};
    int descriptorReg{};
    SafetyHookMid hook{};
};

std::vector<JobCallsiteHook> g_jobCallsiteHooks;
```

Before creating another hook:

```cpp
if (std::ranges::any_of(g_jobCallsiteHooks,
    [&](const auto& h) { return h.address == hookAddress; }))
{
    continue;
}
```

`InitializeASI()` can be called more than once. PR3 must remain idempotent.

One failing callsite must not tear down already-valid callsite hooks.

One pattern absent in one game/update must not disable the RE9 constant patch or DbgUi layer.

---

# 16. RE9-only slow-path discriminator

This sub-layer runs **only** when:

```cpp
profile.re9SlowPath == true
```

which is RE9 only.

Do not run this scan on DD2, PRAGMATA, Onimusha, or MHS3 merely because they share `re9Family`.

## 16.1 Current REF invariant signature

Current REFramework uses:

```text
48 31 E1 E8 ? ? ? ? *[5] C5 F8 28 B4 24 D0 01 00 00 *[5] 48 81 C4 E8 01 00 00
```

The source explains the invariant:

```text
xor rcx, rsp
call __security_check_cookie
vmovaps xmm6, ...
...
add rsp, 0x1e8
```

The `*[5]` tokens are **not five fixed wildcard bytes**.

Kananlib Pattern semantics define `*[5]` as a multi-segment glob with a **maximum gap of 5 bytes** before the next segment.

Do not translate it to exactly five `?` bytes.

## 16.2 Extend the existing PR2 pattern scanner, do not add another scanner

Current `MemoryScan` supports `?`/`??` but not Kananlib's `*[N]` segment-gap syntax.

Extend the existing pattern parser with the focused Kananlib behavior from:

- `cursey/kananlib@8c27b656734355db0f2893581fd62e838fa130ad`
- `include/utility/Pattern.hpp`
- `src/Pattern.cpp`

Required semantics:

```text
AA BB * CC DD      -> next segment may begin within default max gap
AA BB *[5] CC DD   -> next segment may begin 0..5 bytes after the previous segment
```

Use segment-based matching, not regex and not backtracking over the entire module.

Keep the existing simple single-segment path fast.

Add deterministic tests for:

```text
zero-byte gap
1..5 byte gaps
>5 byte rejection
multiple *[N] segments
retry after a first-segment candidate whose later segment fails
ordinary old patterns unchanged
```

The Kananlib Boost license is already tracked from PR2; update the notice text if the project now directly adapts `Pattern.cpp` behavior as well.

## 16.3 Candidate filtering by POP count

Current REF does not accept every epilogue signature hit.

For each candidate it linearly decodes up to 100 instructions and counts `POP` category instructions until a stop condition:

```text
RET
interrupt
non-CALL branch
```

If:

```cpp
popCount > 2
```

skip that candidate.

Preserve this structural filter.

Do not replace it with "take the second pattern match" or a fixed occurrence index.

## 16.4 Find the slow-path selector structurally

After an accepted epilogue candidate, current REF linearly decodes farther into the dispatch block and looks for either:

### Old/variant path — `CMOVcc`

A conditional move is itself the dispatch selector.

Current source rationale:

```text
The conditional move overwrites the clean/default path with the penalty path.
NOPing it leaves the clean path selected.
```

When a valid `CMOVcc` is found in the structurally validated dispatch block:

```cpp
condAddr = instruction.address;
condNopSize = instruction.length;
hasDispatchTable = true;
```

### New path — `SETcc` + indexed dispatch-table load

Current source looks for:

```text
SETcc
...
MOV ..., [base + index*8]
```

The MOV memory operand must have:

```cpp
HasIndex == true
HasBase == true
Scale == 8
```

Only after both the flag-dependent selector and scale-8 dispatch-table access are seen is the candidate accepted.

Do not NOP a random `SETcc` seen after the epilogue without this semantic confirmation.

## 16.5 Patch

For the accepted selector:

```cpp
replacement = std::vector<uint8_t>(selectorLength, 0x90);
```

Use the existing PR2 `BytePatchCandidate` and suspended commit pipeline.

Capture the full original selector bytes during discovery and require an exact match at commit time.

Set:

```cpp
requireExecutable = true;
```

If no slow-path selector is found:

- log `not found`,
- continue,
- **still install JobQueue callsite hooks**.

Current REF deliberately installs the JobQueue defense as backup even when the slow-path patch succeeds, so successful slow-path patching must not suppress callsite hooks either.

---

# 17. Public decoder utility needed by PR3

PR2's `bddisasm` decode helper is currently implementation-private inside `MemoryScan.cpp`.

PR3 needs decoded instruction metadata for:

- JobQueue descriptor-register inference,
- RE9 epilogue POP counting,
- CMOVcc / SETcc detection,
- scale-8 memory operand validation.

Do not duplicate `NdDecodeEx` wrappers in the anti-tamper module.

Expose a focused reusable API from `memory/MemoryScan.*`.

One acceptable shape:

```cpp
struct DecodedInstruction
{
    uintptr_t address{};
    INSTRUX instrux{};
    size_t length{};
};

std::optional<DecodedInstruction> DecodeOne(uintptr_t address) noexcept;
```

Optionally add a bounded `LinearDecode` helper if it clearly reduces duplicate loops:

```cpp
template <class Callback>
void LinearDecode(uintptr_t start,
                  size_t maxInstructions,
                  Callback&& callback);
```

Keep `bddisasm.h` exposure localized if practical; if exposing `INSTRUX` publicly makes the header unnecessarily coupled, provide project-owned decoded fields sufficient for these operations.

Correctness and source traceability matter more than abstraction aesthetics.

---

# 18. InitializeASI integration order

Current order after PR2:

```text
runtime_guards::PostLoadInitialize()
-> dd2_family::Initialize()
-> dbg_ui::Initialize()
```

PR3 becomes:

```text
runtime_guards::PostLoadInitialize()
-> dd2_family::Initialize()      if dd2Family
-> re9_family::Initialize()      if re9Family
-> dbg_ui::Initialize()          if dbgUiWatcher
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

    if (profile.re9Family)
        antitamper::re9_family::Initialize(profile);

    if (profile.dbgUiWatcher)
        antitamper::dbg_ui::Initialize();
}
```

Do not move RE9 scanning, SafetyHook creation, or persistent containers into `DllMain`.

`PatchResult()` remains exactly:

```cpp
return false;
```

---

# 19. Raw patch commit policy

Both RE9+ constants and RE9-only slow-path NOP are executable code modifications.

Reuse PR2's existing patch commit infrastructure.

Recommended discovery/commit split:

```cpp
std::vector<memory::BytePatchCandidate> rawPatches;

DiscoverRe9Constants(game, rawPatches);

if (profile.re9SlowPath)
    DiscoverRe9SlowPath(game, rawPatches);

CommitRawPatches(rawPatches); // same fail-closed short suspension policy

InstallJobCallsiteGuards(game); // SafetyHook manages its own hook installation
```

Do not hold `ThreadSuspensionScope` while doing whole-module scans or pattern glob searches.

Do not hold the PR2 suspension mutex while creating SafetyHook mid-hooks.

---

# 20. Logging policy

Keep logs useful for game-side validation without generating per-frame noise.

Examples:

```text
[CapcomPatcher][RE9Family] scan started
[CapcomPatcher][RE9Family][Constants] 1 candidate(s) located
[CapcomPatcher][RE9Family][SlowPath] skipped by profile
[CapcomPatcher][RE9Family][SlowPath] candidate @ +0x...
[CapcomPatcher][RE9Family][SlowPath] patched selector (3 bytes)
[CapcomPatcher][RE9Family][JobGuard] callsite @ +0x..., entry-reg=RCX
[CapcomPatcher][RE9Family][JobGuard] installed 7 callsite hook(s)
[CapcomPatcher][RE9Family][JobGuard] restored corrupted UD2 job pointer
[CapcomPatcher][RE9Family][JobGuard] substituted noop_job for corrupted UD2 pointer
```

Runtime corruption messages should be one-shot or rate-limited.

Do not log every legitimate job function pointer on every submission.

Counters are useful:

```text
callsites scanned
callsites matched
callsites semantically accepted
hooks installed
UD2 detections
restored from cache
noop substitutions
validation faults
```

---

# 21. Fail-soft / fail-closed rules

PR3 modifies control-flow-sensitive code and live job pointers. Apply these rules consistently.

### Scan not found

```text
log -> skip that sub-layer -> continue other layers
```

### Pattern found but semantic decode fails

```text
skip candidate
```

Never guess the register or patch address.

### Slow-path selector ambiguous

```text
skip slow-path patch
JobQueue guard still runs
```

### One JobQueue callsite hook fails

```text
log failure
keep already-installed valid callsite hooks
continue trying other unique callsites
```

### Pending function pointer unreadable/corrupt

Do not execute it merely because validation failed.

Use the upstream defense model and substitute `noop_job` where the pending call cannot be trusted.

### Cached persistent entry changed concurrently

Do not overwrite it unless the expected corrupt value still matches immediately before the repair.

---

# 22. Explicit exclusions from PR3

Do **not** include the following in this PR:

1. renderer heartbeat
2. PE-header integrity redirection
3. stack destroyer scan/patch
4. module-path spoofing
5. PAK / `/natives/` / DirectStorage support
6. `ignore_application_entries()`
7. MHS3's old disabled `#if 0` UD2-writer fallback
8. a second DbgUiRemoteBreakin watcher
9. DD2-family reimplementation
10. changes to `PatchResult()` semantics
11. TDB-based future-game auto-support
12. broad refactoring of PR0/PR1/PR2 modules

### PE-header parity note

The omission of PE-header redirection from PR3 is **only a PR-isolation decision**.

Current REF still scans it inside the RE9-family path, and Capcom Patcher's architecture plan continues to track it.

Do not delete it from the architecture plan or mark it "unnecessary".

A later work order should port it with the exact current REF candidate semantics:

```text
before_sig = "4C 89 ? 24 40 00 00 00 41 ?"
structural +0x20 / +0x28 / [rsp+0x90] confirmation
clean 0x1000-byte PE-header copy
redirect image-base use to clean copy
```

That later PR must decide explicitly whether to port REF's emulation/asmjit dependencies or implement a smaller proven equivalent.

---

# 23. Licensing / attribution

Current project license remains MIT.

PR3 adds/adapts new third-party code/dependencies, so update attribution accurately.

At minimum track:

### REFramework

```text
praydog/REFramework
MIT
b6baf6b406efc65e077b99cb4d9ad25b0a0a9095
IntegrityCheckBypass::immediate_patch_re9()
validate_job_func
slow-path discriminator logic
```

### Kananlib

Already tracked from PR2 under Boost Software License 1.0.

If `Pattern.cpp` `*[N]` multi-segment behavior is now directly adapted, update the existing Kananlib notice to mention that code path.

### SafetyHook

```text
cursey/safetyhook
Boost Software License 1.0
b046e123dc69821f2c375161e0adef3c6d9c9db4
```

### Zydis

```text
zyantific/zydis
MIT
v4.0.0
```

### Zycore

```text
zyantific/zycore-c
pin from Zydis v4.0.0 submodule:
1401fb85ac313f6605ec795c52bf99ea3f292a69
```

Include full upstream license files for vendored source trees and update `THIRD_PARTY_NOTICES.md`.

Do not remove existing MinHook/bddisasm/OptiPatcher/REFramework notices.

---

# 24. Focused deterministic tests

PR3 must add focused tests/checks for the new reusable semantics.

Do not report a test as run if it was not actually run.

## 24.1 Glob pattern matching

Synthetic buffers:

```text
*[5] with 0-byte gap -> match
*[5] with 1-byte gap -> match
*[5] with 5-byte gap -> match
*[5] with 6-byte gap -> reject
multiple glob segments -> correct match
first candidate fails later segment -> scanner finds later valid first segment
existing ? / ?? patterns -> unchanged
```

## 24.2 Job callsite decoding

Use synthetic instruction bytes for both current candidate families.

Verify:

```text
first instruction decodes to length 4
memory-base register extracted correctly
invalid/non-memory operand candidate is rejected
unknown register is rejected, not silently treated as RDX
hook address resolves to candidate+4 only after semantic validation
```

## 24.3 Job function decision logic

Factor the state decision into a pure/testable helper where practical.

Required cases:

```text
func == 0 -> unchanged
normal readable func -> remember it
UD2 + cached original -> choose cached original
UD2 + no cached original -> choose noop_job
unreadable func -> fail-closed/noop decision
entry persistent slot changed since observation -> do not overwrite
```

## 24.4 Register helper

Validate mapping for all supported x64 GPR enum values used by bddisasm/SafetyHook context.

## 24.5 Slow-path structural selection

Synthetic decoded/control-flow fixtures should cover:

```text
epilogue candidate with >2 POP -> reject
candidate with <=2 POP -> continue
CMOVcc selector -> accepted
SETcc without scale-8 MOV -> reject
SETcc + MOV [base+index*8] -> accepted
selector patch length equals decoded selector length
non-RE9 profile -> slow-path discovery never called
```

## 24.6 Idempotency

Verify logically or in a small harness:

```text
same callsite encountered twice -> one live mid-hook
Initialize called twice -> no duplicate raw patch / no duplicate mid-hook ownership
```

## 24.7 Existing regression set

All PR2 deterministic checks must still pass, especially:

```text
VEX2/VEX3/EVEX decode traversal
CFG path scanning
ThreadSuspensionScope fail-closed behavior
createBLAS fallback 8
MHW-only scanner/crasher gating
PatchResult == false
```

---

# 25. Build / validation requirements

Before opening the PR:

```text
[ ] Debug x64 builds
[ ] Release x64 builds
[ ] committed project still targets x64 only
[ ] no generic CI added
[ ] exports are exactly InitializeASI + PatchResult
[ ] PatchResult() returns false
[ ] git diff --check passes for project-owned code
[ ] SafetyHook/Zydis/Zycore pins recorded
[ ] vendored third-party files are byte-identical to their selected pins where claimed
[ ] all new deterministic checks pass
[ ] all existing PR2 deterministic checks pass
[ ] no MHW RE9-family activation
[ ] DD2/RE9/PRAGMATA/Onimusha/MHS3 generic RE9-family activation
[ ] RE9-only slow-path gating
[ ] no heartbeat implementation in PR3
[ ] no PE-header redirection implementation in PR3
```

If the local machine lacks v143 and builds with a v145 override as in PR2, state that explicitly again in the PR body.

Do not silently modify the committed toolset merely to match the local machine.

---

# 26. Runtime validation matrix

If game runtime is available, collect Capcom Patcher debug output with OptiScaler for:

| Game | Main checks |
|---|---|
| MHW | **No** `[RE9Family]` initialization at all; PR2 behavior unchanged |
| DD2 | RE9 constant scan + JobGuard callsites; no slow-path scan |
| RE9 | RE9 constants + JobGuard + slow-path scan/patch |
| PRAGMATA | RE9 constants + JobGuard; no slow-path; no freeze/regression |
| Onimusha | generic scans fail-soft or match safely; no slow-path |
| MHS3 | generic JobGuard callsites expected to be especially relevant; no slow-path |

Minimum useful evidence per game:

```text
startup reaches gameplay
no immediate crash caused by hook installation
Alt+Tab/basic scene transition if practical
which patterns matched
number of JobGuard callsites installed
whether any UD2 runtime event fired
whether cached restore/noop was used
```

If games are unavailable in the development environment, write:

```text
NOT RUN — no game runtime in build environment
```

Do not fabricate runtime PASS.

---

# 27. PR body requirements

Open as **Draft**.

The PR body must state:

1. base `main` SHA,
2. REFramework behavioral pin,
3. Kananlib pin for pattern semantics,
4. SafetyHook pin,
5. Zydis and Zycore pins,
6. exact five-game `re9Family` gating,
7. exact RE9-only `re9SlowPath` gating,
8. RE9+ constant pattern and patch,
9. the two JobQueue callsite patterns,
10. mid-hook location/semantic validation,
11. UD2 detection + cached restore + `noop_job` fallback behavior,
12. `*[5]` pattern glob support added to the existing scanner,
13. Debug/Release build results,
14. deterministic test results,
15. runtime test results or explicit `NOT RUN`,
16. PE-header/heartbeat/stack-destroyer/module-spoof exclusions,
17. confirmation that `PatchResult()` remains false.

Do not claim "full RE9-family parity" after PR3 because PE-header and heartbeat work are still outstanding.

Preferred wording:

```text
PR3 adds the RE9-family scheduler/job corruption defense and the RE9-only
slow-path discriminator. Full selected-game anti-tamper parity remains in
progress; PE-header integrity redirection, heartbeat, stack-destroyer and
module-path layers are intentionally deferred to later focused PRs.
```

---

# 28. Review rejection conditions

Do not consider PR3 complete if any of these are true:

- MHW receives an RE9-family scan/hook.
- DD2/PRAGMATA/Onimusha/MHS3 receive the RE9-only slow-path patch.
- `*[5]` is incorrectly implemented as exactly five wildcard bytes.
- only the first JobQueue callsite is hooked.
- duplicate callsites install duplicate mid-hooks.
- a descriptor register is guessed after semantic decode fails.
- a raw `entry+8` write is performed without revalidation/fail-soft handling.
- legitimate job pointers are unconditionally replaced with `noop_job`.
- the JobGuard is skipped when the RE9 slow-path patch succeeds.
- SafetyHook/Zydis are taken from unpinned current branches.
- the existing PR2 bddisasm scanner is replaced with SafetyHook's Zydis.
- long whole-module scans run while all game threads are suspended.
- SafetyHook setup or persistent worker logic is moved into `DllMain`.
- heartbeat or PE-header logic is partially/half-ported without its full required semantics.
- existing PR0/PR1/PR2 behavior regresses.
- `PatchResult()` becomes true.

---

# 29. Expected final architecture after PR3

```text
DllMain (supported game only)
├─ pristine NtProtectVirtualMemory
├─ AddVectoredExceptionHandler guard
└─ RtlExitUserProcess guard

InitializeASI
├─ PostLoad VirtualProtect/NtProtect guard
├─ DD2-family core
│  ├─ MHW-only scanner/crasher
│  ├─ DD2-family constants
│  └─ createBLAS corruption guard
├─ RE9-family core                 [PR3]
│  ├─ RE9+/BushClover constants
│  ├─ JobQueue callsite mid-hooks
│  │  ├─ cache legitimate job pointers
│  │  ├─ restore cached pointer on UD2 corruption
│  │  └─ fallback to noop_job
│  └─ RE9-only slow-path NOP
└─ hardened DbgUiRemoteBreakin watcher

Deferred
├─ PE-header integrity redirection
├─ renderer heartbeat
├─ stack destroyer
└─ module-path spoofing
```

This PR should leave Capcom Patcher materially closer to the anti-tamper behavior that makes REFramework + OptiScaler stable, while keeping each mechanism explicit, game-profile-gated, update-resilient, and reviewable.
