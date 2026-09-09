#include "pch.h"

#include "MemoryScan.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <unordered_set>

extern "C" {
#include "../../third_party/minhook/src/hde/hde64.h"
}

namespace memory
{
namespace
{
// ---- SEH-guarded raw reads ----------------------------------------------

bool SafeRead(const void* address, void* out, size_t size) noexcept
{
    __try
    {
        std::memcpy(out, address, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

template <typename T>
bool SafeReadT(uintptr_t address, T& out) noexcept
{
    return SafeRead(reinterpret_cast<const void*>(address), &out, sizeof(T));
}

bool IsReadableRange(uintptr_t address, size_t size) noexcept
{
    if (address == 0 || size == 0 || size > (UINTPTR_MAX - address))
    {
        return false;
    }

    uintptr_t cursor = address;
    const uintptr_t end = address + size;
    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi))
        {
            return false;
        }
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 ||
            (mbi.Protect & 0xFF) == 0)
        {
            return false;
        }
        cursor = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return true;
}

uintptr_t SkipUnreadableRegion(uintptr_t address) noexcept
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        return reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return address + 0x1000;
}

// ---- pattern parsing / matching (OptiPatcher Scanner.cpp shape) ---------

struct PatternByte
{
    uint8_t value;
    bool wildcard;
};

std::vector<PatternByte> ParsePattern(std::string_view mask)
{
    std::vector<PatternByte> pattern;
    for (size_t i = 0; i < mask.size();)
    {
        if (mask[i] == ' ')
        {
            ++i;
            continue;
        }
        if (mask[i] == '?')
        {
            pattern.push_back({0x00, true});
            i += (i + 1 < mask.size() && mask[i + 1] == '?') ? 2 : 1;
        }
        else
        {
            char buf[3] = {mask[i], (i + 1 < mask.size() ? mask[i + 1] : '\0'), '\0'};
            pattern.push_back({static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)), false});
            i += 2;
        }
    }
    return pattern;
}

// Scan [start, start+length) for `pattern`, walking past unreadable pages.
std::optional<uintptr_t> ScanParsed(uintptr_t start, size_t length, const std::vector<PatternByte>& pattern)
{
    if (start == 0 || pattern.empty() || length < pattern.size())
    {
        return std::nullopt;
    }

    const size_t plen = pattern.size();
    const PatternByte* pat = pattern.data();
    const uintptr_t last = start + length - plen;
    uintptr_t addr = start;

    while (addr <= last)
    {
        uintptr_t found = 0;
        bool faulted = false;
        __try
        {
            for (uintptr_t a = addr; a <= last; ++a)
            {
                const auto* p = reinterpret_cast<const uint8_t*>(a);
                bool ok = true;
                for (size_t j = 0; j < plen; ++j)
                {
                    if (!pat[j].wildcard && p[j] != pat[j].value)
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                {
                    found = a;
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            faulted = true;
        }

        if (faulted)
        {
            addr = SkipUnreadableRegion(addr);
            continue;
        }
        return found != 0 ? std::optional<uintptr_t>{found} : std::nullopt;
    }
    return std::nullopt;
}

// ---- x64 unwind info ---------------------------------------------------

#pragma pack(push, 1)
struct UnwindInfo
{
    uint8_t VersionAndFlags;
    uint8_t SizeOfProlog;
    uint8_t CountOfCodes;
    uint8_t FrameRegisterAndOffset;
    uint16_t UnwindCode[1];
};
#pragma pack(pop)

constexpr uint8_t kUnwFlagChainInfo = 0x4;

std::optional<uintptr_t> FunctionStartImpl(uintptr_t addr, bool followChain) noexcept
{
    if (addr == 0)
    {
        return std::nullopt;
    }

    DWORD64 imageBase = 0;
    PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(addr, &imageBase, nullptr);
    if (function == nullptr || imageBase == 0)
    {
        return std::nullopt;
    }

    if (followChain)
    {
        for (int guard = 0; guard < 16; ++guard)
        {
            auto* ui = reinterpret_cast<UnwindInfo*>(imageBase + function->UnwindData);
            if (!IsReadableRange(reinterpret_cast<uintptr_t>(ui), sizeof(UnwindInfo)))
            {
                break;
            }
            if (((ui->VersionAndFlags >> 3) & kUnwFlagChainInfo) == 0)
            {
                break;
            }
            const size_t slot = (static_cast<size_t>(ui->CountOfCodes) + 1) & ~static_cast<size_t>(1);
            function = reinterpret_cast<PRUNTIME_FUNCTION>(&ui->UnwindCode[slot]);
            if (!IsReadableRange(reinterpret_cast<uintptr_t>(function), sizeof(RUNTIME_FUNCTION)))
            {
                return std::nullopt;
            }
        }
    }

    return static_cast<uintptr_t>(imageBase) + function->BeginAddress;
}

// ---- instruction decoding (vendored HDE64) --------------------------

// Decode at `ip`; returns length (0 on error) and fills `hs`.
size_t DecodeAt(uintptr_t ip, hde64s& hs) noexcept
{
    uint8_t bytes[32]{};
    if (!SafeRead(reinterpret_cast<const void*>(ip), bytes, sizeof(bytes)))
    {
        return 0;
    }
    hs = hde64s{};
    const unsigned int len = hde64_disasm(bytes, &hs);
    if ((hs.flags & F_ERROR) != 0 || len == 0)
    {
        return 0;
    }
    return len;
}

bool IsTerminatorOpcode(uint8_t opcode) noexcept
{
    return opcode == 0xC3 || opcode == 0xC2 || opcode == 0xCB || opcode == 0xCA || opcode == 0xCC;
}

size_t ImmediateBytes(const hde64s& hs) noexcept
{
    if (hs.flags & F_IMM64) return 8;
    if (hs.flags & F_IMM32) return 4;
    if (hs.flags & F_IMM16) return 2;
    if (hs.flags & F_IMM8) return 1;
    return 0;
}

// Does the instruction at `ip` (already decoded into `hs`/`len`) carry a 4-byte
// operand (rel32 branch or RIP-relative disp32 memory operand) whose field is
// exactly at `dispAddr`?
bool OperandIsAt(uintptr_t ip, const hde64s& hs, size_t len, uintptr_t dispAddr) noexcept
{
    // rel32 branch / call: E8, E9, 0F 8x. rel32 is the last 4 bytes.
    if ((hs.flags & F_RELATIVE) != 0 && (hs.flags & F_IMM32) != 0 && len >= 4 && ip + len - 4 == dispAddr)
    {
        return true;
    }

    // RIP-relative memory operand: modrm mod=00 rm=101, F_DISP32 set. The disp32
    // precedes any immediate.
    if ((hs.flags & F_DISP32) != 0 && hs.modrm_mod == 0 && hs.modrm_rm == 5)
    {
        const size_t immBytes = ImmediateBytes(hs);
        if (len >= 4 + immBytes && ip + (len - 4 - immBytes) == dispAddr)
        {
            return true;
        }
    }
    return false;
}

// Instruction-validity gate anchored to the containing function (mirrors
// Kananlib resolve_instruction): decode forward from the pdata function start
// until the instruction that contains `dispAddr`, and check its operand field.
// Rejects raw byte-window coincidences that fall inside another instruction.
bool IsDecodedOperandAt(uintptr_t dispAddr) noexcept
{
    const auto functionStart = FunctionStartImpl(dispAddr, /*followChain=*/false);
    if (!functionStart || *functionStart > dispAddr)
    {
        return false;
    }

    uintptr_t ip = *functionStart;
    for (size_t guard = 0; guard < 4096 && ip <= dispAddr; ++guard)
    {
        hde64s hs{};
        const size_t len = DecodeAt(ip, hs);
        if (len == 0)
        {
            return false;
        }
        if (dispAddr < ip + len)
        {
            return OperandIsAt(ip, hs, len, dispAddr);
        }
        ip += len;
    }
    return false;
}

// Scan [start, start+length-4] for a rel32/disp32 whose absolute target ==
// `target` that is also a real decoded instruction operand.
std::optional<uintptr_t> RelReferenceScalar(uintptr_t start, size_t length, uintptr_t target,
                                            const std::function<bool(uintptr_t)>& filter)
{
    if (start == 0 || length < 4)
    {
        return std::nullopt;
    }

    const uintptr_t last = start + length - 4;
    uintptr_t addr = start;
    while (addr <= last)
    {
        uintptr_t found = 0;
        bool faulted = false;
        __try
        {
            for (uintptr_t a = addr; a <= last; ++a)
            {
                const int32_t disp = *reinterpret_cast<const int32_t*>(a);
                if (a + 4 + static_cast<intptr_t>(disp) == target)
                {
                    found = a;
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            faulted = true;
        }

        if (faulted)
        {
            addr = SkipUnreadableRegion(addr);
            continue;
        }

        if (found == 0)
        {
            return std::nullopt;
        }
        if (IsDecodedOperandAt(found) && (!filter || filter(found)))
        {
            return found;
        }
        addr = found + 1; // keep scanning past a rejected candidate
    }
    return std::nullopt;
}

// Signed rel operand value of a direct jump, plus its kind.
struct DirectJump
{
    bool isJump{false};
    bool unconditional{false};
    uintptr_t target{};
};

DirectJump ClassifyJump(uintptr_t ip, const hde64s& hs, size_t len) noexcept
{
    DirectJump out{};
    const uint8_t op = hs.opcode;
    int64_t rel = 0;

    if (op == 0xEB) // jmp rel8
    {
        rel = static_cast<int8_t>(hs.imm.imm8);
        out = {true, true, ip + len + static_cast<uintptr_t>(rel)};
    }
    else if (op == 0xE9) // jmp rel32
    {
        rel = static_cast<int32_t>(hs.imm.imm32);
        out = {true, true, ip + len + static_cast<uintptr_t>(rel)};
    }
    else if (op >= 0x70 && op <= 0x7F) // jcc rel8
    {
        rel = static_cast<int8_t>(hs.imm.imm8);
        out = {true, false, ip + len + static_cast<uintptr_t>(rel)};
    }
    else if (op == 0x0F && hs.opcode2 >= 0x80 && hs.opcode2 <= 0x8F) // jcc rel32
    {
        rel = static_cast<int32_t>(hs.imm.imm32);
        out = {true, false, ip + len + static_cast<uintptr_t>(rel)};
    }
    return out;
}
} // namespace

ModuleRange MainModule()
{
    static const ModuleRange range = [] {
        const HMODULE module = GetModuleHandleW(nullptr);
        if (module == nullptr)
        {
            return ModuleRange{};
        }
        const auto base = reinterpret_cast<uintptr_t>(module);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        return ModuleRange{base, nt->OptionalHeader.SizeOfImage};
    }();
    return range;
}

uintptr_t CalculateAbsolute(uintptr_t address, uint8_t customOffset) noexcept
{
    int32_t displacement = 0;
    if (!SafeReadT(address, displacement))
    {
        return 0;
    }
    return address + customOffset + static_cast<intptr_t>(displacement);
}

bool TryReadBytes(uintptr_t address, void* out, size_t size) noexcept
{
    return SafeRead(reinterpret_cast<const void*>(address), out, size);
}

bool IsReadable(uintptr_t address, size_t size) noexcept
{
    return IsReadableRange(address, size);
}

std::optional<uintptr_t> Scan(uintptr_t start, size_t length, std::string_view pattern)
{
    return ScanParsed(start, length, ParsePattern(pattern));
}

std::optional<uintptr_t> Scan(const ModuleRange& range, std::string_view pattern)
{
    return range ? ScanParsed(range.base, range.size, ParsePattern(pattern)) : std::nullopt;
}

std::optional<uintptr_t> ScanPointer(const ModuleRange& range, uintptr_t ptr)
{
    if (!range)
    {
        return std::nullopt;
    }

    const uintptr_t start = range.base & ~static_cast<uintptr_t>(sizeof(uintptr_t) - 1);
    uintptr_t addr = start;
    while (addr + sizeof(uintptr_t) <= range.end())
    {
        uintptr_t value = 0;
        if (SafeReadT(addr, value))
        {
            if (value == ptr)
            {
                return addr;
            }
            addr += sizeof(uintptr_t);
        }
        else
        {
            addr = SkipUnreadableRegion(addr);
        }
    }
    return std::nullopt;
}

std::optional<uintptr_t> ScanString(const ModuleRange& range, std::string_view text, bool zeroTerminated)
{
    if (!range || text.empty())
    {
        return std::nullopt;
    }

    std::vector<PatternByte> pattern;
    pattern.reserve(text.size() + 1);
    for (const char ch : text)
    {
        pattern.push_back({static_cast<uint8_t>(ch), false});
    }
    if (zeroTerminated)
    {
        pattern.push_back({0x00, false});
    }
    return ScanParsed(range.base, range.size, pattern);
}

std::optional<uintptr_t> ScanRelativeReferenceScalar(uintptr_t start, size_t length, uintptr_t target,
                                                     const std::function<bool(uintptr_t)>& filter)
{
    return RelReferenceScalar(start, length, target, filter);
}

std::optional<uintptr_t> ScanDisplacementReference(const ModuleRange& range, uintptr_t target)
{
    return range ? RelReferenceScalar(range.base, range.size, target, {}) : std::nullopt;
}

std::optional<uintptr_t> FindFunctionStart(uintptr_t addr) noexcept
{
    return FunctionStartImpl(addr, /*followChain=*/false);
}

std::optional<uintptr_t> FindFunctionStartUnwind(uintptr_t addr) noexcept
{
    return FunctionStartImpl(addr, /*followChain=*/true);
}

std::optional<uintptr_t> FindPatternInPath(uintptr_t ip, size_t maxSize, std::string_view pattern)
{
    if (ip == 0 || maxSize == 0)
    {
        return std::nullopt;
    }

    const std::vector<PatternByte> parsed = ParsePattern(pattern);
    if (parsed.empty())
    {
        return std::nullopt;
    }

    // Bounded control-flow walk after Kananlib's exhaustive_decode: `maxSize` is
    // an instruction-count bound *per traversed path* (upstream calls this with
    // 1000), not a byte window. Follows direct and RIP-relative-indirect
    // unconditional jumps to their real target, queues conditional-branch
    // targets, steps over CALLs, and stops at ret / int3 / decode error or an
    // unresolvable unconditional jump. A global unique-instruction cap bounds
    // total work; the pattern is only ever matched at a reachable instruction
    // boundary.
    std::vector<uintptr_t> worklist{ip};
    std::unordered_set<uintptr_t> visited;
    size_t globalBudget = (maxSize > 2048 ? maxSize : 2048) * 16;

    while (!worklist.empty() && globalBudget > 0)
    {
        uintptr_t cursor = worklist.back();
        worklist.pop_back();

        for (size_t step = 0; step < maxSize && globalBudget > 0; ++step)
        {
            --globalBudget;

            if (!visited.insert(cursor).second)
            {
                break;
            }

            if (!IsReadableRange(cursor, 16))
            {
                break;
            }
            if (ScanParsed(cursor, parsed.size(), parsed) == cursor)
            {
                return cursor;
            }

            hde64s hs{};
            const size_t len = DecodeAt(cursor, hs);
            if (len == 0 || IsTerminatorOpcode(hs.opcode))
            {
                break;
            }

            // RIP-relative indirect JMP:  FF /4  with mod=00 rm=101.
            if (hs.opcode == 0xFF && hs.modrm_reg == 4)
            {
                if (hs.modrm_mod == 0 && hs.modrm_rm == 5 && (hs.flags & F_DISP32) != 0)
                {
                    const uintptr_t slot = cursor + len + static_cast<intptr_t>(static_cast<int32_t>(hs.disp.disp32));
                    uintptr_t target = 0;
                    if (TryReadBytes(slot, &target, sizeof(target)) && target != 0 && target != cursor)
                    {
                        cursor = target;
                        continue;
                    }
                }
                break; // never linearly fall through an unresolved indirect JMP
            }

            const DirectJump jump = ClassifyJump(cursor, hs, len);
            if (jump.isJump)
            {
                if (jump.unconditional)
                {
                    if (jump.target != 0 && jump.target != cursor)
                    {
                        cursor = jump.target;
                        continue;
                    }
                    break;
                }
                if (jump.target != 0)
                {
                    worklist.push_back(jump.target);
                }
            }

            cursor += len;
        }
    }
    return std::nullopt;
}

std::optional<uintptr_t> FindFunctionWithRefs(const ModuleRange& range, const std::vector<uintptr_t>& targets)
{
    if (!range || targets.empty())
    {
        return std::nullopt;
    }

    std::vector<uintptr_t> common;
    for (size_t t = 0; t < targets.size(); ++t)
    {
        std::vector<uintptr_t> owners;
        uintptr_t search = range.base;
        while (true)
        {
            const auto ref = RelReferenceScalar(search, range.end() - search, targets[t], {});
            if (!ref)
            {
                break;
            }
            if (const auto owner = FindFunctionStartUnwind(*ref))
            {
                if (std::find(owners.begin(), owners.end(), *owner) == owners.end())
                {
                    owners.push_back(*owner);
                }
            }
            search = *ref + 1;
            if (search + 4 > range.end())
            {
                break;
            }
        }

        if (t == 0)
        {
            common = std::move(owners);
        }
        else
        {
            std::vector<uintptr_t> next;
            for (const uintptr_t fn : common)
            {
                if (std::find(owners.begin(), owners.end(), fn) != owners.end())
                {
                    next.push_back(fn);
                }
            }
            common = std::move(next);
        }

        if (common.empty())
        {
            return std::nullopt;
        }
    }

    return std::optional<uintptr_t>{common.front()};
}

std::optional<uintptr_t> FindFunctionFromStringRef(const ModuleRange& range, std::string_view text)
{
    const auto stringData = ScanString(range, text, /*zeroTerminated=*/true);
    if (!stringData)
    {
        return std::nullopt;
    }

    const auto stringRef = ScanDisplacementReference(range, *stringData);
    if (!stringRef)
    {
        return std::nullopt;
    }

    return FindFunctionStart(*stringRef);
}
} // namespace memory
