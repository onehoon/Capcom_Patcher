# PR5 Work Order — RE9-Family PE-Header Integrity Redirection

**Repository:** `onehoon/Capcom_Patcher`  
**Base:** latest `main` after merged PR4 (`90e82d71ae913c318f91591a69b0a58cddc20aba` at the time this work order was written)  
**Target branch:** new feature branch from latest `main`  
**PR type:** focused implementation / anti-tamper parity  
**Scope:** fail-closed PE-header integrity-check redirection for the five `re9Family` selected games  
**Open as Draft. Do not merge automatically.**

---

## 1. Objective

PR0 established the six-game ASI, explicit profiles, and hardened `DbgUiRemoteBreakin` watcher.

PR1 added the common early/runtime guards.

PR2 added the DD2-family anti-tamper core.

PR3 added the RE9-family constant/JobQueue protections and the RE9-only slow-path discriminator.

PR4 added the standalone renderer heartbeat bridge/service for the five TDB82/83 games.

PR5 adds the REFramework PE-header integrity defense that was deliberately deferred from PR3 so it could be reviewed independently:

> Find the validated RE9-family PE-header integrity-check path, determine by emulation which GPR receives the live game image base, create a process-lifetime copy of the first PE-header page, and replace the image-base-producing instruction sequence with `movabs <that GPR>, <clean header copy>` plus NOP padding.

The purpose is **not** to disable arbitrary PE parsing. The purpose is to redirect the specific anti-tamper integrity reader away from the live, potentially modified in-memory PE header and toward the preserved startup copy, matching current REFramework behavior.

This layer is fail-closed. If any part of discovery, structural validation, emulation, allocation, instruction-boundary validation, thread suspension, or final revalidation is uncertain, **write nothing**.

---

## 2. Current source state — build on it, do not redesign earlier PRs

Current `main` when this work order was written:

```text
90e82d71ae913c318f91591a69b0a58cddc20aba
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

src/antitamper/RE9FamilyBypass.h
src/antitamper/RE9FamilyBypass.cpp
src/antitamper/RendererHeartbeatBypass.*

third_party/bddisasm/
THIRD_PARTY_NOTICES.md
```

Pinned current-main links:

```text
https://github.com/onehoon/Capcom_Patcher/blob/90e82d71ae913c318f91591a69b0a58cddc20aba/src/GameProfile.cpp
https://github.com/onehoon/Capcom_Patcher/blob/90e82d71ae913c318f91591a69b0a58cddc20aba/src/dllmain.cpp
https://github.com/onehoon/Capcom_Patcher/blob/90e82d71ae913c318f91591a69b0a58cddc20aba/src/memory/MemoryScan.h
https://github.com/onehoon/Capcom_Patcher/blob/90e82d71ae913c318f91591a69b0a58cddc20aba/src/memory/MemoryPatch.h
https://github.com/onehoon/Capcom_Patcher/blob/90e82d71ae913c318f91591a69b0a58cddc20aba/src/antitamper/RE9FamilyBypass.cpp
```

### Existing infrastructure that must be reused

Do **not** create parallel replacements for code we already hardened:

- `memory::MainModule()` for the host image range.
- `memory::Scan()` for the byte signature.
- `memory::DecodeOne()` / `memory::LinearDecode()` for structural decoding.
- pinned `bddisasm` for x64 instruction semantics.
- `memory::TryReadBytes()` / `memory::IsReadable()` for safe reads.
- `memory::ThreadSuspensionScope` for the final code-patch window.
- `memory::BytePatchCandidate` + `memory::CommitPatch()` / `WriteBytes()` for validated writes, protection restoration, icache flush, and post-write verification.

Do not add another disassembler, raw scanner, thread suspender, or byte writer.

---

## 3. Source of truth and current-reference check

### 3.1 REFramework behavioral source

Continue using the already pinned upstream source of truth:

```text
praydog/REFramework
b6baf6b406efc65e077b99cb4d9ad25b0a0a9095
```

Primary function:

```text
src/mods/IntegrityCheckBypass.cpp
IntegrityCheckBypass::immediate_patch_re9()
```

Pinned link:

```text
https://github.com/praydog/REFramework/blob/b6baf6b406efc65e077b99cb4d9ad25b0a0a9095/src/mods/IntegrityCheckBypass.cpp
```

As of this work order, `b6baf6b...` is still the latest upstream `praydog/REFramework` commit. The current `onehoon/REFramework` fork has newer XeFG-focused commits, but its `src/mods/IntegrityCheckBypass.cpp` blob is still exactly the same blob as upstream (`3a26fc067b27c903935d121634c6fc8e19f517a4`). Therefore there is no newer project-fork PE-header implementation to substitute here.

### 3.2 Kananlib emulation source

REFramework's `utility::emulate(...)` is from the same Kananlib revision already used as our PR2/PR3 algorithmic reference:

```text
cursey/kananlib
8c27b656734355db0f2893581fd62e838fa130ad
```

Pinned files:

```text
https://github.com/cursey/kananlib/blob/8c27b656734355db0f2893581fd62e838fa130ad/include/utility/Emulation.hpp
https://github.com/cursey/kananlib/blob/8c27b656734355db0f2893581fd62e838fa130ad/src/Emulation.cpp
```

Reuse/adapt this behavior. Do not invent a home-grown symbolic executor or guess the register statically from one known game build.

### 3.3 BDShemu source

Kananlib emulation uses the BDShemu emulator that belongs to the exact `bddisasm` revision we already vendor:

```text
bitdefender/bddisasm
70db095765ab2066dd88dfb7bbcc42259ed167c5
```

Pinned files required by this PR:

```text
https://github.com/bitdefender/bddisasm/blob/70db095765ab2066dd88dfb7bbcc42259ed167c5/bdshemu/bdshemu.c
https://github.com/bitdefender/bddisasm/blob/70db095765ab2066dd88dfb7bbcc42259ed167c5/inc/bdshemu.h
```

At this pin the upstream CMake target for BDShemu consists of `bdshemu/bdshemu.c` + `inc/bdshemu.h` and links against the same bddisasm decoder.

Do not update bddisasm to a newer revision as part of PR5.

---

## 4. Exact selected-game scope

PE-header integrity protection is part of current REFramework's RE9-family path, not the MHW TDB81 path.

Apply PR5 only to:

```text
Dragon's Dogma 2
Resident Evil Requiem
PRAGMATA
Onimusha: Way of the Sword
Monster Hunter Stories 3: Twisted Reflection
```

Do not run it for:

```text
Monster Hunter Wilds
Unsupported executables
future games inferred only from a TDB version
```

The existing `GameProfile::re9Family` flag already maps **exactly** to these five games on current `main`, so do not add profile-schema churn merely to duplicate the same boolean matrix in this PR.

However, the PE-header module itself should contain a defense-in-depth explicit `GameId` allowlist (or equivalent switch) so a future accidental change to `re9Family` cannot silently make PE-header code run on a newly added game.

Conceptual gate:

```cpp
bool SupportsPeHeaderIntegrity(game_profile::GameId id) noexcept
{
    using game_profile::GameId;
    switch (id)
    {
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

Required matrix:

| Game | PR5 |
|---|---:|
| MHW | **OFF** |
| DD2 | FAIL-CLOSED |
| RE9 | FAIL-CLOSED |
| PRAGMATA | FAIL-CLOSED |
| Onimusha WotS | FAIL-CLOSED |
| MHS3 | FAIL-CLOSED |

"FAIL-CLOSED" means the layer is enabled for discovery, but no validated candidate is a normal **no-op**, not a startup failure.

---

## 5. Upstream mechanism — preserve the meaning, not just the bytes

Current REFramework performs the following steps inside `immediate_patch_re9()`.

### 5.1 Anchor signature

The primary anchor is:

```text
4C 89 ? 24 40 00 00 00 41 ?
```

Call this `before_sig` / `kBeforeSig`.

REFramework scans all anchor occurrences until the first candidate that passes the downstream structural test.

### 5.2 Structural candidate discriminator

Starting at the anchor, current REF linearly decodes up to `0x200` instructions and requires the following **ordered state machine**:

1. any decoded instruction with a memory operand that has a base and displacement `0x20`;
2. later, any decoded instruction with a memory operand that has a base and displacement `0x28`;
3. later, a memory operand specifically using:

```text
base = RSP
displacement = 0x90
```

This is not three independent regex searches. Preserve the order.

Pseudo-shape:

```cpp
bool found20 = false;
bool found28 = false;
bool found90 = false;

memory::LinearDecode(ref, 0x200, [&](auto& step) {
    const auto& ix = step.insn.instrux;

    if (!found20 && HasMemDisp(ix, 0x20)) {
        found20 = true;
        return;
    }
    if (found20 && !found28 && HasMemDisp(ix, 0x28)) {
        found28 = true;
        return;
    }
    if (found20 && found28 && HasRspMemDisp(ix, 0x90)) {
        found90 = true;
        step.stop = true;
    }
});
```

Do not weaken this to "anchor pattern found => patch".

### 5.3 Patch address

For a structurally accepted anchor, current REF uses:

```cpp
patch_addr = ref + 10;
```

The `10` is the byte length represented by the anchor pattern.

PR5 must additionally harden this assumption: verify that `patch_addr` is an actual x64 instruction boundary before any emulation or patching. Use the already pinned bddisasm path; do not accept a mid-instruction raw byte offset.

A suitable fail-closed approach is:

1. resolve the containing unwind function start with existing `FindFunctionStart`/`FindFunctionStartUnwind` support;
2. decode forward from that anchored function boundary;
3. require an instruction to start exactly at `ref` and another boundary to exist exactly at `ref + 10`;
4. reject if decoding overshoots either address.

Do not patch if boundary proof fails.

### 5.4 Determine the image-base register by emulation

This is the essential part of the upstream implementation.

REF does **not** hardcode `RAX`, `RCX`, `RDX`, etc. It emulates from `patch_addr` for up to 15 instructions. After each emulated step it checks **all sixteen x64 GPRs** and stops when one equals the live game module base.

Conceptually:

```cpp
size_t patchSpan = 0;
std::optional<int> imageBaseReg;

Emulate(game, patchAddr, 15, [&](const auto& ctx) {
    patchSpan += LastEmulatedInstructionLength(ctx);

    for (int reg = NDR_RAX; reg <= NDR_R15; ++reg) {
        if (ReadEmulatedGpr(ctx, reg) == game.base) {
            imageBaseReg = reg;
            return Break;
        }
    }
    return Continue;
});
```

Do not infer the register from one sample binary.

Do not replace this with "scan for a LEA and assume its destination register" unless the upstream behavior itself changes in a later dedicated review.

### 5.5 Preserve a PE-header copy

Only after a structurally validated candidate is found, current REF allocates one page and copies the first page of the loaded game module:

```cpp
VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
memcpy(copy, GetModuleHandle(nullptr), 0x1000);
```

PR5 should keep this semantic source: copy the **loaded image's first 0x1000 bytes at PR5 initialization time**.

Do not silently substitute an on-disk executable parser in this PR. That is a different semantic model and can be reviewed separately only if runtime evidence shows the upstream strategy is insufficient.

Required safety checks:

```text
main module exists
SizeOfImage >= 0x1000
first 0x1000 bytes readable
VirtualAlloc succeeds
copy itself succeeds under SEH/fail-soft handling
allocation is data only (RW is sufficient; do not make it executable)
```

The allocation is process-lifetime data. Do not free it while the patch can execute.

### 5.6 Replacement

REF generates:

```asm
movabs <discovered GPR>, <clean_header_copy>
```

then fills the remainder of the emulated original sequence with NOPs.

Result:

```text
original code computes/loads live image base
        ↓
PR5 replaces that computation
        ↓
selected GPR = address of preserved PE-header page
        ↓
integrity path reads the preserved copy instead of the live modified header
```

This is a **data-source redirection**, not a return/branch bypass.

---

## 6. Proposed source layout

Add a focused anti-tamper component:

```text
src/antitamper/PeHeaderIntegrityBypass.h
src/antitamper/PeHeaderIntegrityBypass.cpp
```

Add only the minimal Kananlib/BDShemu adapter needed for register discovery:

```text
src/memory/Emulation.h
src/memory/Emulation.cpp
```

Extend the already vendored bddisasm tree with the BDShemu files from the **same pin**:

```text
third_party/bddisasm/bdshemu/bdshemu.c
third_party/bddisasm/inc/bdshemu.h
```

Update:

```text
src/CapcomPatcher.vcxproj
src/CapcomPatcher.vcxproj.filters
src/dllmain.cpp
THIRD_PARTY_NOTICES.md
README.md (only if the parity/status list is maintained there)
```

Do not add a worker thread.

Do not add a hook.

Do not add AsmJit as a new project dependency solely for one `mov r64, imm64` instruction.

---

# 7. Minimal BDShemu adapter

## 7.1 Reuse Kananlib behavior

Adapt the minimal behavior of:

```text
cursey/kananlib@8c27b65
include/utility/Emulation.hpp
src/Emulation.cpp
```

Keep the important setup semantics:

```text
Shellcode      = main module base
ShellcodeBase  = main module base
ShellcodeSize  = SizeOfImage
StackBase      = 0x100000
StackSize      = 0x2000
RegRsp         = 0x101000
RegFlags       = IF | 2
Mode           = ND_CODE_64
Ring           = 3
MaxInstructionsCount bounded
MemThreshold   = 100 for the callback-style path
```

The external-memory callback must follow the same safety purpose:

```text
load  -> read actual process memory only when safely readable
store -> discard; never write game memory during emulation
```

PR5 emulation is analysis only. **Shemu must never be allowed to commit a game-memory store.**

Use `memory::TryReadBytes`/readability helpers rather than introducing `IsBadReadPtr` as new project code if practical.

## 7.2 Step semantics

Preserve Kananlib's callback ordering because the upstream PE-header logic depends on it:

1. callback sees the context before the next instruction is executed;
2. `ctx->Instruction` describes the last instruction Shemu actually emulated;
3. the PE logic adds the previous instruction's length to the accumulated patch span;
4. then it checks all GPR values;
5. if no register matches, emulate one more instruction.

On a Shemu failure, match Kananlib's fail-soft stepping behavior only where it is safe and deterministic: decode the current instruction with the existing bddisasm decoder, advance by that decoded length, account for the instruction, and continue within the strict 15-instruction budget.

If decode fails, external memory access is invalid, RIP escapes the validated main image unexpectedly, or the state becomes structurally unusable, stop and report emulation failure. Do not guess.

## 7.3 Explicit GPR mapping

Do not reproduce the upstream `reinterpret_cast<uint64_t*>(&Registers)[reg]` trick in new code.

Use explicit fields from `SHEMU_GPR_REGS`:

```cpp
uint64_t GetGpr(const SHEMU_GPR_REGS& r, int reg) noexcept
{
    switch (reg)
    {
    case NDR_RAX: return r.RegRax;
    case NDR_RCX: return r.RegRcx;
    case NDR_RDX: return r.RegRdx;
    case NDR_RBX: return r.RegRbx;
    case NDR_RSP: return r.RegRsp;
    case NDR_RBP: return r.RegRbp;
    case NDR_RSI: return r.RegRsi;
    case NDR_RDI: return r.RegRdi;
    case NDR_R8:  return r.RegR8;
    case NDR_R9:  return r.RegR9;
    case NDR_R10: return r.RegR10;
    case NDR_R11: return r.RegR11;
    case NDR_R12: return r.RegR12;
    case NDR_R13: return r.RegR13;
    case NDR_R14: return r.RegR14;
    case NDR_R15: return r.RegR15;
    default:      return 0;
    }
}
```

This preserves upstream semantics while avoiding a struct-layout indexing assumption.

## 7.4 Result type

Expose a narrow result rather than leaking the full emulator into anti-tamper code:

```cpp
struct ImageBaseRegisterResult
{
    int reg{};            // NDR_RAX .. NDR_R15
    size_t consumedBytes{};
};

std::optional<ImageBaseRegisterResult>
FindRegisterHoldingValue(const memory::ModuleRange& game,
                         uintptr_t start,
                         uintptr_t wantedValue,
                         size_t maxInstructions = 15) noexcept;
```

Equivalent structure is fine.

No result means no patch.

---

# 8. `movabs` encoding — keep it tiny and fully tested

Upstream uses AsmJit to emit one instruction:

```cpp
a.movabs(gpq(reg), (uintptr_t)allocated_memory);
```

Do **not** vendor all of AsmJit solely for this one fixed x64 encoding.

Use a tiny local encoder with an explicit supported-register check.

For a 64-bit GPR, `mov r64, imm64` is always 10 bytes:

```text
RAX..RDI : 48 B8+r imm64_le
R8..R15  : 49 B8+(r-8) imm64_le
```

Conceptual implementation:

```cpp
std::optional<std::array<uint8_t, 10>> EncodeMovAbs(int ndrReg, uint64_t value) noexcept
{
    const auto index = ToX64GprIndex(ndrReg); // explicit switch, 0..15
    if (!index)
        return std::nullopt;

    std::array<uint8_t, 10> out{};
    const unsigned r = *index;
    out[0] = static_cast<uint8_t>(0x48 | (r >= 8 ? 0x01 : 0x00)); // REX.W | B
    out[1] = static_cast<uint8_t>(0xB8 + (r & 7));
    std::memcpy(out.data() + 2, &value, sizeof(value));
    return out;
}
```

Do not assume `NDR_RAX == 0 ... NDR_R15 == 15` unless an explicit conversion function proves it. Reuse the explicit register mapping style already present in `RE9FamilyBypass.cpp`.

Hard rule:

```text
consumedBytes < 10 -> reject, no patch
consumedBytes unreasonably large / outside main image -> reject
```

Replacement is:

```cpp
replacement.assign(consumedBytes, 0x90);
memcpy(replacement.data(), movabs.data(), movabs.size());
```

No trampoline, no executable allocation, no indirect jump.

---

# 9. Candidate discovery

Recommended internal representation:

```cpp
struct PeHeaderCandidate
{
    uintptr_t anchor{};       // before_sig address
    uintptr_t patchAddress{}; // anchor + 10
    int imageBaseReg{};
    size_t patchSpan{};
    std::vector<uint8_t> expectedPatchBytes;
};
```

The clean-header allocation need not be created until one candidate passes all read-only discovery checks.

Discovery sequence:

```text
1. main module validated
2. scan next `before_sig`
3. anchor is an actual instruction boundary
4. `anchor+10` is an actual instruction boundary
5. ordered 0x20 -> 0x28 -> [rsp+0x90] structural discriminator passes
6. emulate from anchor+10, max 15 instructions
7. exactly one supported GPR is observed holding game.base at the stopping state
8. accumulated patch span >= 10
9. [patchAddress, patchAddress+patchSpan) is inside committed executable main-image memory
10. capture exact original bytes for final revalidation
```

If steps 3-9 fail for a raw anchor hit before the structural discriminator is established, continue scanning later anchor hits.

Once a candidate passes the full structural discriminator but the emulation/register proof fails, **fail closed and stop rather than blindly trying to patch a later lookalike**. This mirrors the safety intent of current REF, which stops after the first fully recognized PE-integrity candidate path.

No candidate is a normal result:

```text
[CapcomPatcher][PEHeader] integrity path not found; no patch applied
```

Do not treat that as failure of the whole ASI.

---

# 10. Clean-header allocation

After a fully validated candidate exists:

```cpp
constexpr size_t kHeaderCopySize = 0x1000;
```

Create exactly one process-lifetime copy.

Conceptual helper:

```cpp
void* CreateHeaderCopy(const memory::ModuleRange& game) noexcept
{
    if (game.size < 0x1000 || !memory::IsReadable(game.base, 0x1000))
        return nullptr;

    void* copy = VirtualAlloc(nullptr, 0x1000,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!copy)
        return nullptr;

    bool ok = false;
    __try {
        std::memcpy(copy, reinterpret_cast<void*>(game.base), 0x1000);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }

    if (!ok) {
        VirtualFree(copy, 0, MEM_RELEASE);
        return nullptr;
    }
    return copy;
}
```

Keep the successful allocation reachable for the entire process lifetime.

Do not make the copy executable.

Do not use `VirtualProtect` on the original PE header.

Do not modify the live header itself.

---

# 11. Two-phase commit and final revalidation

This is a code patch. Keep the PR2/PR3 two-phase policy.

## 11.1 Discovery phase — no writes

Perform all scans, structural validation, emulation, byte capture, and replacement generation with no game-memory writes.

## 11.2 Safe commit window

Before writing:

```cpp
memory::ThreadSuspensionScope suspension;
if (!suspension.Ok()) {
    // fail closed
    return;
}
```

Do not suspend from `DllMain`.

## 11.3 Revalidate dynamic meaning under suspension

Immediately after suspension and **before** `CommitPatch()`:

1. main module base/range is unchanged;
2. anchor bytes still match the captured bytes/signature context;
3. anchor and `patchAddress` are still instruction boundaries;
4. the ordered `0x20 -> 0x28 -> [rsp+0x90]` discriminator still passes;
5. re-run the bounded emulation;
6. require the same `imageBaseReg` as discovery;
7. require the same `patchSpan` as discovery;
8. require the exact captured patch bytes still match.

If any of these change, release suspended threads and skip.

This dynamic revalidation matters because the patch's meaning depends on both **which register** is being established and **how many whole instructions** are being replaced.

## 11.4 Commit with existing raw writer

Build a normal `memory::BytePatchCandidate` for the exact patch span:

```cpp
memory::BytePatchCandidate patch{};
patch.address = candidate.patchAddress;
patch.expected = candidate.expectedPatchBytes;
patch.writeOffset = 0;
patch.replacement = replacement;
patch.name = "RE9-family PE-header image-base redirection";
patch.requireExecutable = true;
```

`requireUnwindFunctionStart` must stay **false** because this is an interior instruction sequence, not a function entry.

Then call `memory::CommitPatch(patch)` while the thread-suspension scope is still active.

Do not bypass the existing `MemoryPatch` validation/write path.

Required outcomes/logging:

```text
Patched        -> log one success with game-relative address, GPR name, span
AlreadyPatched -> log once, no duplicate action
Skipped        -> validation changed; no write
Failed         -> write/protection/verification failure; no retry loop
```

---

# 12. Startup ordering

Add the focused PR5 layer after current RE9-family startup patching and before heartbeat startup:

```text
RuntimeGuards
  -> DD2Family
  -> RE9Family (constants / slow path / JobGuard)
  -> PEHeaderIntegrity              <-- PR5
  -> RendererHeartbeat
  -> DbgUi watcher
```

Conceptual `InitializeASI()` change:

```cpp
if (profile.re9Family)
{
    antitamper::re9_family::Initialize(profile);
    antitamper::pe_header::Initialize(profile);
}

if (profile.heartbeat)
{
    antitamper::heartbeat::Initialize(profile);
}
```

Equivalent separation is fine, but do not move PR5 into `DllMain`.

PR5 is one-shot startup discovery/patching. It needs no polling thread, timer, Present hook, or recurring callback.

`PatchResult()` must remain `false`.

---

# 13. Idempotency and lifetime

The component must be safe if `InitializeASI()` is called more than once.

Requirements:

```text
at most one successful PE-header allocation
at most one successful raw patch
no duplicate thread suspension on a known-complete state
no second copy with a different address after success
```

Use a small lifecycle mutex/state or equivalent.

Suggested states:

```cpp
enum class State
{
    Uninitialized,
    Patched,
    NotFound,
    Failed,
};
```

A completed `Patched` state is terminal.

`NotFound` is also terminal for the current process because the main executable code is already mapped and this is an immediate startup pattern, not asynchronously loaded code.

If the only failure was inability to obtain a safe thread-suspension window, it is acceptable either to leave the state retryable for a later explicit `InitializeASI()` call or to fail closed for the session. Do not create an automatic retry worker.

The chosen policy must be deterministic and documented in the PR.

---

# 14. BDShemu project integration

Extend the existing pinned bddisasm vendoring; do not create a second bddisasm copy.

Add from **exactly** `70db095765ab2066dd88dfb7bbcc42259ed167c5`:

```text
third_party/bddisasm/bdshemu/bdshemu.c
third_party/bddisasm/inc/bdshemu.h
```

Compile `bdshemu.c` as C, no PCH, warnings disabled in the same third-party style as the existing bddisasm translation units.

Use the existing bddisasm include roots.

Do not update or replace the current decoder sources.

Add a pin/source note if the existing `PINNED_REVISION.md` enumerates vendored file scope.

### License

BDShemu is part of the same Bitdefender repository and the same Apache-2.0 license already included under `third_party/bddisasm/LICENSE`.

Update `THIRD_PARTY_NOTICES.md` so it no longer claims the bddisasm vendoring is "decoder only, no emulator". State that PR5 adds the pinned BDShemu emulator subset.

Update the Kananlib notice to state that PR5 adapts `include/utility/Emulation.hpp` / `src/Emulation.cpp` at the already recorded `8c27b65...` pin.

No new license family is introduced.

---

# 15. Logging — useful but not noisy

This is startup-only, so concise stage logs are appropriate.

Recommended examples:

```text
[CapcomPatcher][PEHeader] scan started
[CapcomPatcher][PEHeader] anchor @ +0x..., validating
[CapcomPatcher][PEHeader] structural candidate accepted
[CapcomPatcher][PEHeader] image base observed in R11 after 17 byte(s)
[CapcomPatcher][PEHeader] clean header copy allocated
[CapcomPatcher][PEHeader] patched @ +0x... (reg=R11 span=17)
```

Normal no-match:

```text
[CapcomPatcher][PEHeader] integrity path not found; no patch applied
```

Fail-closed diagnostics:

```text
candidate not on instruction boundary
structural discriminator failed
emulation did not resolve image-base register
patch span shorter than movabs
header copy allocation failed
safe suspension window unavailable
final revalidation changed; skipped
```

Do not dump every emulated instruction or every raw anchor hit in normal builds.

Do not log the same normal no-match repeatedly.

---

# 16. Deterministic tests

Runtime game validation is important but this mechanism must also have focused synthetic tests because current sampled DD2/RE9/PRAGMATA logs did **not** show a successful PE-header candidate hit.

Add a small dedicated test harness consistent with existing PR2/PR3/PR4 deterministic checks.

## 16.1 Scope tests

Verify:

```text
MHW -> false
DD2 -> true
RE9 -> true
PRAGMATA -> true
Onimusha -> true
MHS3 -> true
Unsupported -> false
```

## 16.2 Structural state-machine tests

Synthetic decoded sequences:

```text
0x20 -> 0x28 -> [rsp+0x90]       ACCEPT
0x28 -> 0x20 -> [rsp+0x90]       REJECT
0x20 -> [rsp+0x90] -> 0x28       REJECT
0x20 -> 0x28 -> [rax+0x90]       REJECT
0x20 only                         REJECT
raw signature with bad boundary   REJECT
```

Use actual bddisasm-decoded instruction bytes for the test fixtures where practical; do not test only a duplicated boolean helper disconnected from production decoding.

## 16.3 GPR accessor tests

Verify all 16 `NDR_R*` mappings return the corresponding `SHEMU_GPR_REGS::Reg*` field.

Include a case where two unrelated fields (e.g. RIP/CR registers) equal the wanted value; they must not be considered GPR candidates.

## 16.4 BDShemu step test

Use a small executable/readable synthetic buffer or equivalent controlled memory image containing a simple instruction stream such as:

```asm
mov r11, <wantedValue>
nop
```

Verify:

```text
emulation resolves R11
consumed span is exactly 10 bytes
no external-memory stores are committed
```

Repeat at least one low register (e.g. RAX) and one high register (e.g. R11/R15).

## 16.5 `movabs` encoder tests

This must cover **all sixteen GPRs**.

At minimum verify exact bytes for:

```text
RAX -> 48 B8 <imm64>
RDI -> 48 BF <imm64>
R8  -> 49 B8 <imm64>
R15 -> 49 BF <imm64>
```

and round-trip decode every generated form with the existing bddisasm decoder:

```text
instruction == MOV
length == 10
destination register == requested GPR
immediate == requested 64-bit value
```

Unsupported NDR register values must return no encoding.

## 16.6 Patch-span tests

Verify:

```text
span 0..9   -> reject
span 10     -> movabs exactly, no NOP tail
span 11     -> 10-byte movabs + 1 NOP
span N      -> exact N-byte replacement
```

No replacement may split an original instruction: the production candidate span comes only from completed emulated/decode steps.

## 16.7 Final-revalidation tests

Simulate/mutate discovery state so commit is rejected when:

```text
anchor bytes change
patch bytes change
structural 0x20/0x28/0x90 order changes
image-base register changes between discovery and commit
patch span changes between discovery and commit
candidate moves outside executable main-module range
thread suspension reports failure
```

No test case above may invoke the raw writer after the invalidation is detected.

## 16.8 Existing regression tests

Run all existing deterministic checks from PR0-PR4 unchanged.

PR5 must not regress:

```text
DbgUi watcher/profile gates
runtime guards
PR2 bddisasm/CFG/thread suspension/createBLAS
PR3 glob/JobGuard/CAS/slow-path
PR4 renderer bridge/heartbeat 60-check suite
```

---

# 17. Build and static verification

Required:

```text
x64 Debug build
x64 Release build
git diff --check
```

Keep the committed toolset policy unchanged.

Verify exports remain exactly the intended ASI ABI:

```text
InitializeASI
PatchResult
```

`PatchResult()` must still return false.

No CI addition is required unless the repository's existing policy changes separately.

No x86 support.

---

# 18. Runtime validation matrix

Do not invent a successful PE-header match if current game builds do not contain it.

Existing sampled working REF logs for DD2 / RE9 / PRAGMATA previously showed the PE-header scan running without a validated match. Therefore `not found / no patch` is a legitimate runtime outcome and **must not** be converted into a fake success criterion.

For every available game test, capture:

```text
game/profile detected
PEHeader layer gate
anchor/structural result
emulation result if candidate exists
patch result if candidate exists
game reaches menu/gameplay without new crash
```

Matrix:

| Game | Expected gate | Required observation |
|---|---:|---|
| MHW | OFF | no PR5 scan/alloc/patch |
| DD2 | ON | clean no-match or validated patch; never unsafe fallback |
| RE9 | ON | clean no-match or validated patch; never unsafe fallback |
| PRAGMATA | ON | clean no-match or validated patch; heartbeat remains unaffected |
| Onimusha | ON | clean no-match or validated patch |
| MHS3 | ON | clean no-match or validated patch |

If a game/build produces a real candidate and patch, additionally verify:

```text
clean header allocation is RW data, not executable
replacement disassembles to mov r64, imm64 + NOPs
immediate equals the preserved header-copy address
selected register equals the emulated image-base register
original live PE header is not written
```

If runtime games are unavailable, report them as `NOT RUN`; do not claim parity from synthetic tests alone.

---

# 19. Explicit non-goals

Do **not** include any of the following in PR5:

- stack-destroyer mitigation (next focused parity layer),
- module-path spoofing,
- PAK/natives/loose-file behavior,
- `ignore_application_entries()` / REFramework `Hooks` subsystem,
- old disabled MHS3 UD2-writer fallback,
- new JobQueue logic,
- new heartbeat behavior,
- renderer bridge changes unrelated to compilation,
- DXGI / Present / ResizeBuffers / D3D hooks,
- OptiScaler changes,
- Special K integration,
- a generic PE parser or on-disk pristine-image subsystem,
- generic support for TDB84+ or future Capcom games,
- full Kananlib vendoring,
- full REFramework SDK vendoring,
- all of AsmJit merely to emit one `movabs`,
- arbitrary anti-tamper pattern cleanup/refactor outside this mechanism.

Keep the PR reviewable as one anti-tamper parity layer.

---

# 20. Reject invariants

The implementation is incorrect if any of these become possible:

1. MHW enters the PE-header patch path.
2. Any future unknown/TDB-derived game enters the path automatically.
3. A raw `before_sig` hit is patched without the ordered structural discriminator.
4. `anchor + 10` is not proven to be an instruction boundary.
5. The image-base GPR is guessed or hardcoded instead of emulated.
6. Emulation can write to real game memory.
7. A register outside RAX..R15 is accepted.
8. The patch span is shorter than the 10-byte `movabs`.
9. The replacement splits an original instruction.
10. The PE-header copy is executable.
11. The live PE header itself is modified by PR5.
12. Code is patched without a successful `ThreadSuspensionScope` safe window.
13. Discovery-time register/span evidence is not revalidated after threads are suspended.
14. Changed bytes are overwritten despite final mismatch.
15. `VirtualProtect` state is not restored / instruction cache is not flushed after code write.
16. PR5 adds a worker, timer, Present hook, or swapchain hook.
17. `PatchResult()` becomes true.
18. No-match is treated as fatal to the other anti-tamper layers.

---

# 21. Suggested implementation skeleton

This is illustrative, not a request to bypass existing helpers.

```cpp
namespace antitamper::pe_header
{
namespace detail
{
struct Discovery
{
    uintptr_t anchor{};
    uintptr_t patchAddress{};
    int reg{};
    size_t span{};
    std::vector<uint8_t> expected;
};

bool ValidateStructure(uintptr_t anchor) noexcept;
bool IsAnchoredInstructionBoundary(uintptr_t address) noexcept;
std::optional<Discovery> Discover(const memory::ModuleRange& game) noexcept;
std::optional<std::array<uint8_t, 10>> EncodeMovAbs(int reg, uint64_t value) noexcept;
}

void Initialize(const game_profile::GameProfile& profile) noexcept
{
    if (!profile.re9Family || !SupportsPeHeaderIntegrity(profile.id))
        return;

    const auto game = memory::MainModule();
    if (!game)
        return;

    auto candidate = detail::Discover(game);
    if (!candidate)
        return; // normal fail-closed no-match

    void* cleanHeader = CreateHeaderCopy(game);
    if (!cleanHeader)
        return;

    auto mov = detail::EncodeMovAbs(candidate->reg,
                                    reinterpret_cast<uint64_t>(cleanHeader));
    if (!mov || candidate->span < mov->size())
        return;

    std::vector<uint8_t> replacement(candidate->span, 0x90);
    std::copy(mov->begin(), mov->end(), replacement.begin());

    memory::ThreadSuspensionScope suspension;
    if (!suspension.Ok())
        return;

    // IMPORTANT: rerun structural + boundary + emulation checks here.
    const auto final = detail::DiscoverAtKnownAnchor(game, candidate->anchor);
    if (!final || final->reg != candidate->reg || final->span != candidate->span ||
        final->expected != candidate->expected)
        return;

    memory::BytePatchCandidate patch{};
    patch.address = candidate->patchAddress;
    patch.expected = candidate->expected;
    patch.replacement = std::move(replacement);
    patch.requireExecutable = true;
    patch.name = "RE9-family PE-header image-base redirection";

    (void)memory::CommitPatch(patch);
}
}
```

Production code should use explicit state/lifetime handling and logging rather than copying this skeleton verbatim.

---

# 22. Completion criteria

PR5 is complete only when all of the following are true:

- [ ] branch is based on latest `main` containing PR4 (`90e82d71...` or newer)
- [ ] only the five intended RE9-family selected games can run the layer
- [ ] MHW is statically verified OFF
- [ ] upstream `before_sig` is preserved
- [ ] ordered `0x20 -> 0x28 -> [rsp+0x90]` semantic discriminator is preserved
- [ ] anchor and `anchor+10` instruction boundaries are proven
- [ ] Kananlib-style BDShemu register discovery is ported at the pinned revisions
- [ ] BDShemu cannot write real game memory
- [ ] all sixteen GPRs are checked explicitly
- [ ] clean first-page copy is process-lifetime RW data
- [ ] `movabs` encoding is correct for all RAX-R15 and bddisasm round-trip tested
- [ ] patch span is whole-instruction and at least 10 bytes
- [ ] no write occurs during discovery
- [ ] final commit requires successful thread suspension
- [ ] structural/register/span/byte evidence is revalidated after suspension
- [ ] existing `BytePatchCandidate`/`CommitPatch` path performs the actual write
- [ ] no Present/DXGI hook or worker is added
- [ ] `PatchResult()` remains false
- [ ] THIRD_PARTY_NOTICES accurately describes Kananlib Emulation + BDShemu use
- [ ] Debug and Release x64 builds pass
- [ ] new deterministic PR5 tests pass
- [ ] PR0-PR4 regression suites pass
- [ ] runtime results, if unavailable, are explicitly reported `NOT RUN`
- [ ] PR opened as Draft

---

# 23. Expected PR summary shape

The implementation PR body should clearly report:

```text
Base main SHA
REFramework behavioral pin
Kananlib pin
bddisasm/BDShemu pin
five-game gate / MHW OFF
anchor + semantic discriminator
instruction-boundary validation
emulated register result strategy
clean-header allocation strategy
movabs encoder strategy
thread-suspended final revalidation
build results
deterministic test counts
existing regression results
runtime matrix (including NOT RUN)
remaining parity work
```

Remaining parity after PR5 should still explicitly include:

```text
stack-destroyer mitigation
module-path spoofing review / classification
six-game runtime validation and cleanup
```

Do not claim "full REFramework anti-tamper parity" after PR5.
