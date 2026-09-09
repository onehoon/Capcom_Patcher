#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "../GameProfile.h"
#include "../memory/MemoryPatch.h"
#include "../memory/MemoryScan.h" // brings <bddisasm.h>

// REFramework "stack destroyer" mitigation.
//
// Focused extraction of praydog/REFramework @ b6baf6b
// IntegrityCheckBypass::remove_stack_destroyer(): find the exact 18-byte
// routine
//     mov  qword ptr [rcx], rdx        ; 48 89 11
//     mov  qword ptr [rsp], 0          ; 48 C7 04 24 00 00 00 00
//     add  rsp, 0x128                  ; 48 81 C4 28 01 00 00
// and neutralize it by replacing the function entry with a single `RET` (0xC3).
//
// Stricter than upstream: the three instructions are decode-validated, the hit
// must be a proven function entry, and more than one validated candidate is
// fail-closed. Opt-in for all six explicit games (MHW included); one-shot
// startup patch, no worker / hook / trampoline.

namespace antitamper::stack_destroyer
{
// Startup one-shot. Call from InitializeASI() for profiles with
// stackDestroyer == true, after pe_header::Initialize and before heartbeat.
// Idempotent; terminal state machine.
void Initialize(const game_profile::GameProfile& profile) noexcept;

// Defense-in-depth explicit allowlist (independent of GameProfile::stackDestroyer).
bool SupportsStackDestroyer(game_profile::GameId id) noexcept;

namespace detail
{
inline constexpr std::array<uint8_t, 18> kSignatureBytes{
    0x48, 0x89, 0x11,                               // mov [rcx], rdx
    0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // mov qword [rsp], 0
    0x48, 0x81, 0xC4, 0x28, 0x01, 0x00, 0x00,       // add rsp, 0x128
};

struct Candidate
{
    uintptr_t address{};
    std::array<uint8_t, 18> expected{};
};

// Decode from `address` and require exactly:
//   MOV  [RCX], RDX      len 3   (64-bit, plain base RCX, no index, disp 0)
//   MOV  qword [RSP], 0  len 8   (64-bit, base RSP, disp 0, imm 0)
//   ADD  RSP, 0x128      len 7   (64-bit, imm 0x128)
// with the three lengths summing to exactly 18.
bool ValidateSequence(uintptr_t address) noexcept;

// FindFunctionStartUnwind(address) (then FindFunctionStart) must resolve
// exactly to `address`.
bool IsProvenFunctionEntry(uintptr_t address) noexcept;

enum class Selection
{
    NotFound,   // 0 validated candidates
    Selected,   // exactly 1
    Ambiguous,  // > 1
};
Selection SelectFrom(size_t validatedCount) noexcept;

// Whole-image scan -> every raw signature hit -> committed-executable + semantic
// + function-entry validation -> the surviving candidates (bytes captured).
std::vector<Candidate> DiscoverValidated(const memory::ModuleRange& game) noexcept;

// Re-prove one candidate against live memory (pre-suspension / under-suspension).
bool CandidateStillValid(const memory::ModuleRange& game, const Candidate& candidate) noexcept;

// The exact one-byte-RET patch for a validated candidate (18-byte expected
// context, writeOffset 0, replacement {0xC3}, requireExecutable +
// requireUnwindFunctionStart).
memory::BytePatchCandidate BuildPatch(const Candidate& candidate) noexcept;
} // namespace detail
} // namespace antitamper::stack_destroyer
