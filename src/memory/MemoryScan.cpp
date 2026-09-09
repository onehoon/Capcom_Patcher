#include "pch.h"

#include "MemoryScan.h"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_set>

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

// ---- segment glob (kananlib Pattern.cpp shape) -----------------------

struct PatternSegment
{
    std::vector<PatternByte> bytes;
    size_t maxGapBefore{0}; // 0 for the first segment
};

// Split a pattern string on `*` / `*[N]` tokens into segments.
std::vector<PatternSegment> CompilePattern(std::string_view mask)
{
    std::vector<PatternSegment> segments;
    std::string current;
    std::vector<size_t> gaps; // gap declared before segment i (i>=1)

    size_t i = 0;
    while (i < mask.size())
    {
        while (i < mask.size() && mask[i] == ' ')
        {
            ++i;
        }
        if (i >= mask.size())
        {
            break;
        }
        const size_t tokStart = i;
        while (i < mask.size() && mask[i] != ' ')
        {
            ++i;
        }
        const std::string_view tok = mask.substr(tokStart, i - tokStart);

        if (!tok.empty() && tok[0] == '*')
        {
            segments.push_back({ParsePattern(current), 0});
            current.clear();

            size_t gap = kDefaultGlobMaxGap;
            if (tok.size() > 2 && tok[1] == '[')
            {
                const size_t close = tok.find(']', 2);
                if (close != std::string_view::npos)
                {
                    std::from_chars(tok.data() + 2, tok.data() + close, gap);
                }
            }
            gaps.push_back(gap);
        }
        else
        {
            if (!current.empty())
            {
                current += ' ';
            }
            current += tok;
        }
    }
    if (!current.empty())
    {
        segments.push_back({ParsePattern(current), 0});
    }

    for (size_t s = 1; s < segments.size() && s - 1 < gaps.size(); ++s)
    {
        segments[s].maxGapBefore = gaps[s - 1];
    }
    return segments;
}

// Multi-segment match: find segment 0, then each later segment within its gap
// window; retry from the next segment-0 hit on failure. Returns segment-0 start.
std::optional<uintptr_t> ScanCompiled(uintptr_t start, size_t length,
                                      const std::vector<PatternSegment>& segments)
{
    if (segments.empty() || segments[0].bytes.empty())
    {
        return std::nullopt;
    }
    if (segments.size() == 1)
    {
        return ScanParsed(start, length, segments[0].bytes);
    }

    const uintptr_t end = start + length;
    uintptr_t searchStart = start;
    while (searchStart < end)
    {
        const auto seg0 = ScanParsed(searchStart, end - searchStart, segments[0].bytes);
        if (!seg0)
        {
            return std::nullopt;
        }

        uintptr_t cursor = *seg0 + segments[0].bytes.size();
        bool allFound = true;
        for (size_t s = 1; s < segments.size(); ++s)
        {
            const auto& seg = segments[s];
            const size_t segLen = seg.bytes.size();
            const uintptr_t windowEnd = (std::min)(cursor + seg.maxGapBefore + segLen, end);
            if (cursor >= windowEnd || windowEnd - cursor < segLen)
            {
                allFound = false;
                break;
            }
            const auto hit = ScanParsed(cursor, windowEnd - cursor, seg.bytes);
            if (!hit)
            {
                allFound = false;
                break;
            }
            cursor = *hit + segLen;
        }

        if (allFound)
        {
            return *seg0;
        }
        searchStart = *seg0 + 1;
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

// ---- instruction decoding (vendored bddisasm @ 70db095) -------------
//
// The advanced anti-tamper scan helpers use the same decoder REFramework /
// kananlib use (via NdDecodeEx), so they have full VEX / EVEX / XOP coverage.

struct Decoded
{
    INSTRUX ix{};
    size_t length{0};
    bool ok{false};
};

Decoded DecodeAt(uintptr_t ip) noexcept
{
    Decoded d{};
    uint8_t bytes[ND_MAX_INSTRUCTION_LENGTH]{};
    if (!SafeRead(reinterpret_cast<const void*>(ip), bytes, sizeof(bytes)))
    {
        return d;
    }
    const NDSTATUS status = NdDecodeEx(&d.ix, bytes, sizeof(bytes), ND_CODE_64, ND_DATA_64);
    if (!ND_SUCCESS(status) || d.ix.Length == 0)
    {
        return d;
    }
    d.length = d.ix.Length;
    d.ok = true;
    return d;
}

int64_t SignExtend(uint32_t value, uint8_t sizeBytes) noexcept
{
    switch (sizeBytes)
    {
    case 1: return static_cast<int8_t>(value);
    case 2: return static_cast<int16_t>(value);
    default: return static_cast<int32_t>(value);
    }
}

bool IsTerminator(const INSTRUX& ix) noexcept
{
    return ix.Category == ND_CAT_RET || ix.Instruction == ND_INS_INT3 || ix.Instruction == ND_INS_UD0 ||
           ix.Instruction == ND_INS_UD1 || ix.Instruction == ND_INS_UD2;
}

// Does this instruction carry a 4-byte operand field exactly at `dispAddr` that
// resolves to `target`? (rel32 branch, or RIP-relative disp32 memory operand)
bool OperandResolvesTo(uintptr_t ip, const Decoded& d, uintptr_t dispAddr, uintptr_t target) noexcept
{
    const INSTRUX& ix = d.ix;
    if (ix.HasRelOffs && ix.RelOffsLength == 4 && ip + ix.RelOffsOffset == dispAddr)
    {
        return ip + d.length + SignExtend(ix.RelativeOffset, ix.RelOffsLength) == target;
    }
    if (ix.HasDisp && ix.IsRipRelative && ix.DispLength == 4 && ip + ix.DispOffset == dispAddr)
    {
        return ip + d.length + SignExtend(ix.Displacement, ix.DispLength) == target;
    }
    return false;
}

// Anchored instruction-validity gate (mirrors kananlib resolve_instruction):
// decode forward from the pdata function start until the instruction that owns
// `dispAddr`; accept only if that 4-byte operand field is exactly there and
// resolves to `target`. Rejects raw windows that fall inside another instruction.
bool IsDecodedOperandAt(uintptr_t dispAddr, uintptr_t target) noexcept
{
    const auto functionStart = FunctionStartImpl(dispAddr, /*followChain=*/false);
    if (!functionStart || *functionStart > dispAddr)
    {
        return false;
    }

    uintptr_t ip = *functionStart;
    for (size_t guard = 0; guard < 8192 && ip <= dispAddr; ++guard)
    {
        const Decoded d = DecodeAt(ip);
        if (!d.ok)
        {
            return false;
        }
        if (dispAddr < ip + d.length)
        {
            return OperandResolvesTo(ip, d, dispAddr, target);
        }
        ip += d.length;
    }
    return false;
}

// Scan [start, start+length-4] for a rel32/disp32 whose absolute target ==
// `target` that is also a real decoded instruction operand resolving to it.
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
        if (IsDecodedOperandAt(found, target) && (!filter || filter(found)))
        {
            return found;
        }
        addr = found + 1; // keep scanning past a rejected candidate
    }
    return std::nullopt;
}

struct BranchInfo
{
    enum Kind
    {
        NotABranch,
        Call,
        DirectUncond,
        DirectCond,
        IndirectResolvable,
        IndirectUnresolvable,
    } kind{NotABranch};
    uintptr_t target{0};
};

BranchInfo ClassifyBranch(uintptr_t ip, const Decoded& d) noexcept
{
    const INSTRUX& ix = d.ix;
    BranchInfo out{};

    if (ix.Category == ND_CAT_CALL)
    {
        out.kind = BranchInfo::Call;
        return out;
    }
    if (!ix.BranchInfo.IsBranch)
    {
        return out;
    }

    if (ix.BranchInfo.IsIndirect)
    {
        // jmp qword ptr [rip+disp32]: resolvable via its pointer slot.
        if (ix.Category == ND_CAT_UNCOND_BR && ix.HasDisp && ix.IsRipRelative && ix.DispLength == 4)
        {
            const uintptr_t slot = ip + d.length + static_cast<uintptr_t>(SignExtend(ix.Displacement, 4));
            uintptr_t ptr = 0;
            if (TryReadBytes(slot, &ptr, sizeof(ptr)) && ptr != 0 && ptr != ip)
            {
                out.kind = BranchInfo::IndirectResolvable;
                out.target = ptr;
                return out;
            }
        }
        out.kind = BranchInfo::IndirectUnresolvable;
        return out;
    }

    if (ix.HasRelOffs)
    {
        out.target = ip + d.length + static_cast<uintptr_t>(SignExtend(ix.RelativeOffset, ix.RelOffsLength));
        out.kind = ix.BranchInfo.IsConditional ? BranchInfo::DirectCond : BranchInfo::DirectUncond;
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
    return ScanCompiled(start, length, CompilePattern(pattern));
}

std::optional<uintptr_t> Scan(const ModuleRange& range, std::string_view pattern)
{
    return range ? ScanCompiled(range.base, range.size, CompilePattern(pattern)) : std::nullopt;
}

std::optional<DecodedInstruction> DecodeOne(uintptr_t address) noexcept
{
    const Decoded d = DecodeAt(address);
    if (!d.ok)
    {
        return std::nullopt;
    }
    return DecodedInstruction{address, d.ix, d.length};
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

    // Bounded control-flow walk after kananlib's exhaustive_decode: `maxSize` is
    // an instruction-count bound *per traversed path* (upstream calls this with
    // 1000), not a byte window. Follows direct and RIP-relative-indirect
    // unconditional jumps to their real target, queues conditional-branch
    // targets, steps over CALLs, and stops at ret / int3 / ud / decode error or
    // an unresolvable indirect jump. A global unique-instruction cap bounds total
    // work; the pattern is only ever matched at a reachable instruction boundary.
    std::vector<uintptr_t> worklist{ip};
    std::unordered_set<uintptr_t> visited;
    size_t globalBudget = (maxSize > 2048 ? maxSize : 2048) * 16;

    while (!worklist.empty() && globalBudget > 0)
    {
        uintptr_t cursor = worklist.back();
        worklist.pop_back();

        for (size_t step = 0; step < maxSize && globalBudget > 0;)
        {
            ++step;
            --globalBudget;

            if (!visited.insert(cursor).second || !IsReadableRange(cursor, ND_MAX_INSTRUCTION_LENGTH))
            {
                break;
            }
            if (ScanParsed(cursor, parsed.size(), parsed) == cursor)
            {
                return cursor;
            }

            const Decoded d = DecodeAt(cursor);
            if (!d.ok || IsTerminator(d.ix))
            {
                break;
            }

            const BranchInfo b = ClassifyBranch(cursor, d);
            if (b.kind == BranchInfo::DirectUncond || b.kind == BranchInfo::IndirectResolvable)
            {
                if (b.target != 0 && b.target != cursor)
                {
                    cursor = b.target;
                    continue;
                }
                break; // dead-end / self-loop
            }
            if (b.kind == BranchInfo::IndirectUnresolvable)
            {
                break; // never linearly fall through an unresolved jump
            }
            if (b.kind == BranchInfo::DirectCond && b.target != 0)
            {
                worklist.push_back(b.target);
            }

            cursor += d.length; // fall through (also the CALL step-over path)
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
