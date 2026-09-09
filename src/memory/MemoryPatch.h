#pragma once

// Hardened raw byte writer. Shape follows onehoon/OptiPatcher Patcher.cpp
// (@ 72e716b3274ce9dfc3a4ffde54fd2b54b4172cb2):
//   VirtualProtect RWX -> memcpy -> restore protection -> FlushInstructionCache
// with added validation, SEH, read-back verification and explicit status.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace memory
{
// Validate + write `bytes` at `address`, restore protection, flush the icache,
// and verify the write. Returns false (writing nothing lasting) on any failure.
bool WriteBytes(void* address, std::span<const uint8_t> bytes) noexcept;

// A pending patch that carries enough context to revalidate immediately before
// the write (work order section 11).
struct BytePatchCandidate
{
    uintptr_t address{};
    std::vector<uint8_t> expected;    // full local pattern that must still match
    size_t writeOffset{};             // offset within `expected` to overwrite
    std::vector<uint8_t> replacement; // bytes written at address + writeOffset
    const char* name{"patch"};
};

enum class PatchOutcome
{
    Patched,       // expected bytes matched, replacement written and verified
    AlreadyPatched, // replacement bytes were already in place
    Skipped,       // validation mismatch / unsafe target - nothing written
    Failed,        // write attempted but could not be completed/verified
};

// Revalidate the candidate against the main game image and commit it.
PatchOutcome CommitPatch(const BytePatchCandidate& candidate) noexcept;
} // namespace memory
