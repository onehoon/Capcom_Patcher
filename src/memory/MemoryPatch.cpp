#include "pch.h"

#include "MemoryPatch.h"

#include "MemoryScan.h"

#include <cstring>

namespace memory
{
namespace
{
void Log(const char* message)
{
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

bool RangeIsCommitted(uintptr_t address, size_t size) noexcept
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
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi) ||
            mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
        {
            return false;
        }
        cursor = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return true;
}

bool RangeIsExecutable(uintptr_t address, size_t size) noexcept
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
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi) ||
            mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
        {
            return false;
        }
        switch (mbi.Protect & 0xFF)
        {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            break;
        default:
            return false;
        }
        cursor = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return true;
}

bool SafeCompare(const void* address, const uint8_t* expected, size_t size) noexcept
{
    __try
    {
        return std::memcmp(address, expected, size) == 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
} // namespace

bool WriteBytes(void* address, std::span<const uint8_t> bytes) noexcept
{
    if (address == nullptr || bytes.empty())
    {
        return false;
    }

    const auto target = reinterpret_cast<uintptr_t>(address);
    if (!RangeIsCommitted(target, bytes.size()))
    {
        Log("[CapcomPatcher][MemoryPatch] target not committed; skipped");
        return false;
    }

    DWORD oldProtect = 0;
    if (VirtualProtect(address, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE)
    {
        Log("[CapcomPatcher][MemoryPatch] VirtualProtect failed; skipped");
        return false;
    }

    bool wrote = true;
    __try
    {
        std::memcpy(address, bytes.data(), bytes.size());
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        wrote = false;
    }

    DWORD ignored = 0;
    const bool restored = VirtualProtect(address, bytes.size(), oldProtect, &ignored) != FALSE;
    FlushInstructionCache(GetCurrentProcess(), address, bytes.size());

    if (!wrote || !restored)
    {
        Log("[CapcomPatcher][MemoryPatch] write or protection restore failed");
        return false;
    }

    if (!SafeCompare(address, bytes.data(), bytes.size()))
    {
        Log("[CapcomPatcher][MemoryPatch] post-write verification mismatch");
        return false;
    }
    return true;
}

PatchOutcome CommitPatch(const BytePatchCandidate& candidate) noexcept
{
    const ModuleRange game = MainModule();
    if (!game || candidate.expected.empty() || candidate.replacement.empty())
    {
        return PatchOutcome::Skipped;
    }

    const uintptr_t writeAddr = candidate.address + candidate.writeOffset;
    if (candidate.writeOffset + candidate.replacement.size() > candidate.expected.size())
    {
        return PatchOutcome::Skipped;
    }

    // Patch destination must lie inside the main executable image.
    if (candidate.address < game.base || candidate.address + candidate.expected.size() > game.end())
    {
        Log("[CapcomPatcher][MemoryPatch] candidate outside main image; skipped");
        return PatchOutcome::Skipped;
    }

    if (!RangeIsCommitted(candidate.address, candidate.expected.size()))
    {
        return PatchOutcome::Skipped;
    }

    // Already patched?
    if (SafeCompare(reinterpret_cast<void*>(writeAddr), candidate.replacement.data(), candidate.replacement.size()))
    {
        return PatchOutcome::AlreadyPatched;
    }

    // Full local pattern must still match exactly before we touch anything.
    if (!SafeCompare(reinterpret_cast<void*>(candidate.address), candidate.expected.data(),
                     candidate.expected.size()))
    {
        Log("[CapcomPatcher][MemoryPatch] expected bytes changed; skipped");
        return PatchOutcome::Skipped;
    }

    // Extra final validations, immediately before the write.
    if (candidate.requireExecutable && !RangeIsExecutable(candidate.address, candidate.expected.size()))
    {
        Log("[CapcomPatcher][MemoryPatch] target not executable; skipped");
        return PatchOutcome::Skipped;
    }
    if (candidate.requireUnwindFunctionStart)
    {
        const auto start = FindFunctionStartUnwind(candidate.address);
        if (!start || *start != candidate.address)
        {
            Log("[CapcomPatcher][MemoryPatch] function-start revalidation failed; skipped");
            return PatchOutcome::Skipped;
        }
    }

    return WriteBytes(reinterpret_cast<void*>(writeAddr),
                      std::span<const uint8_t>(candidate.replacement.data(), candidate.replacement.size()))
               ? PatchOutcome::Patched
               : PatchOutcome::Failed;
}
} // namespace memory
