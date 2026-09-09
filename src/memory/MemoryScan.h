#pragma once

// Focused extraction of the scan helpers used by REFramework's
// IntegrityCheckBypass::immediate_patch_dd2().
//
// Byte-pattern scanning follows the shape of onehoon/OptiPatcher
// (Scanner.cpp @ 72e716b3274ce9dfc3a4ffde54fd2b54b4172cb2). The advanced
// helpers are adapted from cursey/kananlib
// (src/Scan.cpp @ 8c27b656734355db0f2893581fd62e838fa130ad):
// scan_ptr, scan_string, scan_displacement_reference,
// scan_relative_reference_scalar, find_function_start,
// find_function_start_unwind, find_pattern_in_path, find_function_with_refs,
// find_function_from_string_ref, calculate_absolute.
//
// The advanced helpers use the vendored HDE64 length disassembler in place of
// Kananlib's bddisasm dependency, but keep the important semantics:
//  - displacement / relative-reference matches are validated by decoding forward
//    from the containing pdata function start until the instruction that owns
//    the candidate offset (mirrors Kananlib resolve_instruction); a raw 4-byte
//    window that falls inside another instruction is rejected;
//  - FindPatternInPath is a bounded control-flow walk after exhaustive_decode:
//    `maxSize` is an instruction-count bound per traversed path, direct and
//    RIP-relative-indirect unconditional jumps are followed, conditional-branch
//    targets are queued, CALLs are stepped over, and the walk stops at
//    ret / int3 / an unresolvable jump.
// Remaining deviation: indirect branch targets other than `jmp [rip+disp32]`
// are not resolved (the walk stops there rather than guessing).

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>
#include <vector>

#include <windows.h>

namespace memory
{
struct ModuleRange
{
    uintptr_t base{};
    size_t size{};

    uintptr_t end() const { return base + size; }
    explicit operator bool() const { return base != 0 && size != 0; }
};

// The host game executable (GetModuleHandle(nullptr)) and its SizeOfImage.
ModuleRange MainModule();

// addr + customOffset + *(int32_t*)addr  (Kananlib calculate_absolute).
uintptr_t CalculateAbsolute(uintptr_t address, uint8_t customOffset = 4) noexcept;

// SEH-guarded read of `size` bytes. False (and `out` untouched) on fault.
bool TryReadBytes(uintptr_t address, void* out, size_t size) noexcept;

// True when [address, address+size) is committed and readable.
bool IsReadable(uintptr_t address, size_t size) noexcept;

// First occurrence of a space-separated hex pattern ("39 0C 82 74 ?", "?"/"??"
// are wildcards) within [start, start+length). Nullopt if not found.
std::optional<uintptr_t> Scan(uintptr_t start, size_t length, std::string_view pattern);
std::optional<uintptr_t> Scan(const ModuleRange& range, std::string_view pattern);

// 8-byte-aligned search for the pointer value `ptr` inside the module image
// (e.g. an IAT slot holding &QueryPerformanceCounter). Returns the slot address.
std::optional<uintptr_t> ScanPointer(const ModuleRange& range, uintptr_t ptr);

// First occurrence of the byte string `text` (optionally including the NUL).
std::optional<uintptr_t> ScanString(const ModuleRange& range, std::string_view text, bool zeroTerminated = true);

// First position i in [start, start+length-4] where CalculateAbsolute(i, 4) ==
// target and (optional) filter(i) is true. `i` is the displacement field address.
std::optional<uintptr_t> ScanRelativeReferenceScalar(uintptr_t start, size_t length, uintptr_t target,
                                                     const std::function<bool(uintptr_t)>& filter = {});

// First RIP-relative displacement in the module image that resolves to `target`.
std::optional<uintptr_t> ScanDisplacementReference(const ModuleRange& range, uintptr_t target);

// x64 unwind info: the RUNTIME_FUNCTION.BeginAddress covering `addr`.
// FindFunctionStartUnwind additionally follows UNW_FLAG_CHAININFO to the root.
std::optional<uintptr_t> FindFunctionStart(uintptr_t addr) noexcept;
std::optional<uintptr_t> FindFunctionStartUnwind(uintptr_t addr) noexcept;

// Walk instruction boundaries from `ip` (up to maxSize bytes, stopping at RET /
// decode error) and return the first boundary where `pattern` matches.
std::optional<uintptr_t> FindPatternInPath(uintptr_t ip, size_t maxSize, std::string_view pattern);

// The unwind function start that references every pointer in `targets`.
std::optional<uintptr_t> FindFunctionWithRefs(const ModuleRange& range, const std::vector<uintptr_t>& targets);

// scan_string -> scan_displacement_reference -> find_function_start.
std::optional<uintptr_t> FindFunctionFromStringRef(const ModuleRange& range, std::string_view text);
} // namespace memory
