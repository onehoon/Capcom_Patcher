#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "../GameProfile.h"
#include "../memory/MemoryScan.h" // brings <bddisasm.h> (INSTRUX) in extern "C"

// RE9-family PE-header integrity-check redirection.
//
// Focused extraction of praydog/REFramework @ b6baf6b
// IntegrityCheckBypass::immediate_patch_re9() PE-header section:
//   - anchor signature "4C 89 ? 24 40 00 00 00 41 ?"
//   - ordered structural discriminator: a memory operand with base+disp 0x20,
//     then one with base+disp 0x28, then one with base RSP + disp 0x90
//   - emulate 15 instructions from anchor+10, find the GPR that ends up holding
//     the live image base (bounded BDShemu, no game-memory writes)
//   - preserve a process-lifetime copy of the first PE-header page
//   - replace the image-base computation with `movabs <that GPR>, <copy>` + NOPs
//
// Fail-closed: if any discovery / structural / emulation / boundary / suspension
// / revalidation step is uncertain, nothing is written. "No candidate" is a
// normal no-op, not a startup failure.
//
// Not in scope: stack-destroyer, module-path spoofing, PAK/natives.

namespace antitamper::pe_header
{
// Startup one-shot. Call from InitializeASI() for re9Family profiles (inside the
// same block as re9_family::Initialize). Idempotent; no worker/timer/hook.
void Initialize(const game_profile::GameProfile& profile) noexcept;

// Defense-in-depth explicit allowlist (independent of GameProfile::re9Family).
bool SupportsPeHeaderIntegrity(game_profile::GameId id) noexcept;

namespace detail
{
// A fully validated PE-header patch candidate (discovery output).
struct Candidate
{
    uintptr_t anchor{};
    uintptr_t patchAddress{}; // anchor + 10
    int reg{};                // NDR_RAX..NDR_R15 holding the image base
    size_t span{};            // whole-instruction bytes to replace
    std::array<uint8_t, 10> anchorBytes{}; // exact anchor bytes at capture time
    std::vector<uint8_t> patchBytes;       // exact bytes at [patchAddress, +span)
};

// Read-only completion for an anchor that already passed the boundary +
// structural checks: emulate the image-base register, capture the anchor + patch
// bytes, confirm the wildcard signature. nullopt = fail closed.
std::optional<Candidate> CompleteCandidateAt(const memory::ModuleRange& game, uintptr_t anchor) noexcept;

// Re-prove `prior` against live memory (final under-suspension revalidation):
// anchor identity + signature, anchor->patch instruction boundary, structural
// discriminator, emulated register + span, and the captured patch bytes.
bool CandidateStillValid(const memory::ModuleRange& game, const Candidate& prior) noexcept;

// NDR_RAX..NDR_R15 -> 0..15 (explicit; never assumes the enum values).
std::optional<unsigned> ToX64GprIndex(int ndrReg) noexcept;

// `mov r64, imm64` is always 10 bytes:
//   RAX..RDI : 48 B8+r  imm64_le
//   R8..R15  : 49 B8+(r-8) imm64_le
std::optional<std::array<uint8_t, 10>> EncodeMovAbs(int ndrReg, uint64_t value) noexcept;

// Any memory operand with a base and displacement == `disp`.
bool HasMemDisp(const INSTRUX& ix, uint64_t disp) noexcept;
// Memory operand with base == RSP and displacement == `disp`.
bool HasRspMemDisp(const INSTRUX& ix, uint64_t disp) noexcept;

// Ordered 0x20 -> 0x28 -> [rsp+0x90] state machine over a linear decode from
// `start` (REF's linear_decode, stopping at ret / int / unconditional jmp).
bool StructuralDiscriminatorMatches(uintptr_t start, size_t maxInstructions = 0x200) noexcept;

// Decode forward from `from`; true iff an instruction boundary falls exactly on
// `target` without the decode overshooting it.
bool DecodeReachesBoundary(uintptr_t from, uintptr_t target, size_t maxInstructions = 0x2000) noexcept;

// `span` bytes: the 10-byte movabs followed by (span - 10) NOPs. nullopt if
// span < 10 (would split the movabs) - the production span always comes from
// whole emulated/decoded instructions.
std::optional<std::vector<uint8_t>> BuildReplacement(size_t span, const std::array<uint8_t, 10>& movabs) noexcept;
} // namespace detail
} // namespace antitamper::pe_header
