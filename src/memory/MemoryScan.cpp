#include "pch.h"

#include "MemoryScan.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

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

// ---- instruction stepping (vendored HDE64) ---------------------------

size_t InstructionLength(uintptr_t ip) noexcept
{
    uint8_t bytes[32]{};
    if (!SafeRead(reinterpret_cast<const void*>(ip), bytes, sizeof(bytes)))
    {
        return 0;
    }
    hde64s hs{};
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

// Scan [start, start+length-4] for a rel32 whose absolute target == `target`.
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
        if (!filter || filter(found))
        {
            return found;
        }
        addr = found + 1; // keep scanning past a filtered-out candidate
    }
    return std::nullopt;
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

    const uintptr_t end = ip + maxSize;
    uintptr_t cursor = ip;
    while (cursor < end)
    {
        if (ScanParsed(cursor, parsed.size(), parsed) == cursor)
        {
            return cursor;
        }

        uint8_t opcode = 0;
        if (!SafeReadT(cursor, opcode) || IsTerminatorOpcode(opcode))
        {
            break;
        }
        const size_t len = InstructionLength(cursor);
        if (len == 0)
        {
            break;
        }
        cursor += len;
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
