#include "pch.h"

#include "RuntimeGuards.h"

#include "../hooking/MinHookInlineHook.h"

#include <winternl.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <memory>

#pragma intrinsic(_ReturnAddress)

namespace antitamper::runtime_guards
{
namespace
{
// ---- logging ---------------------------------------------------------------

void Log(const char* message)
{
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

// ---- local NT types (do not import REFramework's NT utility layer) ----------

using NtProtectVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE ProcessHandle,
                                                  PVOID* BaseAddress,
                                                  PSIZE_T RegionSize,
                                                  ULONG NewProtect,
                                                  PULONG OldProtect);

constexpr bool NtSuccess(NTSTATUS status) noexcept
{
    return status >= 0;
}

constexpr NTSTATUS kStatusInvalidPageProtection = static_cast<NTSTATUS>(0xC0000045);

// ---- state ----------------------------------------------------------------

HMODULE g_selfModule{};

// Guard A: the callable original entry, and a 256-byte private executable copy
// used for the 32-byte integrity comparison / restore (a separate mechanism
// from the DbgUi watcher's 32-byte live baseline).
NtProtectVirtualMemoryFn g_ogNtProtect{};
NtProtectVirtualMemoryFn g_pristineNtProtect{};

std::unique_ptr<hooking::MinHookInlineHook> g_virtualProtectHook;
std::unique_ptr<hooking::MinHookInlineHook> g_vehHook;
std::unique_ptr<hooking::MinHookInlineHook> g_exitHook;

std::atomic<bool> g_vehAllowed{false};
std::atomic<bool> g_vehCalled{false};

// ---- small local helpers --------------------------------------------------

wchar_t AsciiLower(wchar_t ch) noexcept
{
    return (ch >= L'A' && ch <= L'Z') ? static_cast<wchar_t>(ch - L'A' + L'a') : ch;
}

// Allocation-free ASCII case-insensitive substring test.
bool PathContainsFold(const wchar_t* haystack, const wchar_t* needle) noexcept
{
    for (const wchar_t* base = haystack; *base != L'\0'; ++base)
    {
        const wchar_t* h = base;
        const wchar_t* n = needle;
        while (*n != L'\0' && AsciiLower(*h) == AsciiLower(*n))
        {
            ++h;
            ++n;
        }
        if (*n == L'\0')
        {
            return true;
        }
    }
    return false;
}

void* ResolveExport(const wchar_t* module, const char* name) noexcept
{
    const HMODULE handle = GetModuleHandleW(module);
    return handle ? reinterpret_cast<void*>(GetProcAddress(handle, name)) : nullptr;
}

// ---- Guard A: pristine NtProtectVirtualMemory capture ----------------------

bool SetupPristineNtProtectVirtualMemory()
{
    if (g_pristineNtProtect != nullptr)
    {
        return true;
    }

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        Log("[CapcomPatcher][NtProtect] could not find ntdll.dll");
        return false;
    }

    auto entry = reinterpret_cast<NtProtectVirtualMemoryFn>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
    if (entry == nullptr)
    {
        Log("[CapcomPatcher][NtProtect] could not resolve NtProtectVirtualMemory");
        return false;
    }

    // Follow a leading E9 rel32 redirect to the real entry, as upstream does.
    if (*reinterpret_cast<const uint8_t*>(entry) == 0xE9)
    {
        int32_t rel = 0;
        std::memcpy(&rel, reinterpret_cast<const uint8_t*>(entry) + 1, sizeof(rel));
        entry = reinterpret_cast<NtProtectVirtualMemoryFn>(reinterpret_cast<uintptr_t>(entry) + 5 +
                                                           static_cast<intptr_t>(rel));
        Log("[CapcomPatcher][NtProtect] resolved NtProtectVirtualMemory E9 redirect");
    }

    g_ogNtProtect = entry;

    // Mark the live entry RWX so a later restore of the previous protection can
    // never drop it below executable+writable (upstream rationale).
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void*>(entry), 256, PAGE_EXECUTE_READWRITE, &ignored);

    void* copy = VirtualAlloc(nullptr, 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (copy == nullptr)
    {
        Log("[CapcomPatcher][NtProtect] could not allocate pristine syscall buffer");
        g_ogNtProtect = nullptr;
        return false;
    }

    bool copied = true;
    __try
    {
        std::memcpy(copy, reinterpret_cast<void*>(entry), 256);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        copied = false;
    }

    if (!copied)
    {
        Log("[CapcomPatcher][NtProtect] could not copy pristine NtProtectVirtualMemory");
        VirtualFree(copy, 0, MEM_RELEASE);
        g_ogNtProtect = nullptr;
        return false;
    }

    g_pristineNtProtect = reinterpret_cast<NtProtectVirtualMemoryFn>(copy);
    Log("[CapcomPatcher][NtProtect] pristine syscall copy captured");
    return true;
}

// ---- Guard B: VirtualProtect / NtProtectVirtualMemory integrity guard ------

// Calls the saved NtProtectVirtualMemory directly; never recurses through the
// hooked VirtualProtect. Mirrors virtual_protect_impl().
BOOL WINAPI VirtualProtectImpl(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    static const HANDLE thisProcess = GetCurrentProcess();
    if (g_ogNtProtect == nullptr)
    {
        return FALSE;
    }

    PVOID address = lpAddress;
    SIZE_T size = dwSize;
    NTSTATUS result = g_ogNtProtect(thisProcess, &address, &size, flNewProtect, lpflOldProtect);

    if (result == kStatusInvalidPageProtection)
    {
        using RtlFlushSecureMemoryCacheFn = BOOLEAN(NTAPI*)(PVOID, SIZE_T);
        static const auto flush =
            reinterpret_cast<RtlFlushSecureMemoryCacheFn>(ResolveExport(L"ntdll.dll", "RtlFlushSecureMemoryCache"));

        if (flush != nullptr && flush(address, size) != FALSE)
        {
            result = g_ogNtProtect(thisProcess, &address, &size, flNewProtect, lpflOldProtect);
            if ((static_cast<ULONG>(result) & 0x80000000u) == 0)
            {
                return TRUE;
            }
        }
    }

    if (!NtSuccess(result))
    {
        Log("[CapcomPatcher][NtProtect] direct NtProtectVirtualMemory call failed");
    }
    return NtSuccess(result) ? TRUE : FALSE;
}

void MaybeRestoreNtProtectIntegrity()
{
    static std::atomic<bool> announced{false};
    if (!announced.exchange(true))
    {
        Log("[CapcomPatcher][NtProtect] VirtualProtect guard observing");
    }

    if (g_ogNtProtect == nullptr || g_pristineNtProtect == nullptr)
    {
        return;
    }

    __try
    {
        if (std::memcmp(reinterpret_cast<const void*>(g_ogNtProtect),
                        reinterpret_cast<const void*>(g_pristineNtProtect), 32) == 0)
        {
            return;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }

    Log("[CapcomPatcher][NtProtect] NtProtectVirtualMemory modification detected; attempting restore");

    // Stage 1: direct restore of the first 32 bytes.
    bool needsProtectionFix = false;
    __try
    {
        std::memcpy(reinterpret_cast<void*>(g_ogNtProtect),
                    reinterpret_cast<const void*>(g_pristineNtProtect), 32);
        needsProtectionFix = std::memcmp(reinterpret_cast<const void*>(g_ogNtProtect),
                                         reinterpret_cast<const void*>(g_pristineNtProtect), 32) != 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        needsProtectionFix = true;
    }

    if (!needsProtectionFix)
    {
        // Deliberate hardening over upstream: flush the icache after an
        // executable-code restore (documented in the PR body).
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(g_ogNtProtect), 32);
        Log("[CapcomPatcher][NtProtect] restore succeeded");
        return;
    }

    // Stage 2: make the surrounding region writable via the direct impl (never
    // the hooked VirtualProtect), restore, then restore protection.
    __try
    {
        DWORD oldProtect = 0;
        void* region = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_ogNtProtect) - 1);
        if (VirtualProtectImpl(region, 33, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            std::memcpy(reinterpret_cast<void*>(g_ogNtProtect),
                        reinterpret_cast<const void*>(g_pristineNtProtect), 32);
            DWORD restored = 0;
            VirtualProtectImpl(region, 33, oldProtect, &restored);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(g_ogNtProtect), 32);
            Log("[CapcomPatcher][NtProtect] restore succeeded (protection path)");
        }
        else
        {
            Log("[CapcomPatcher][NtProtect] restore failed");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Log("[CapcomPatcher][NtProtect] restore raised an exception");
    }
}

using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);

BOOL WINAPI VirtualProtectHook(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    __try
    {
        MaybeRestoreNtProtectIntegrity();
        return VirtualProtectImpl(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        const VirtualProtectFn original =
            g_virtualProtectHook ? g_virtualProtectHook->Original<VirtualProtectFn>() : nullptr;
        return original ? original(lpAddress, dwSize, flNewProtect, lpflOldProtect) : FALSE;
    }
}

bool InstallVirtualProtectGuard()
{
    if (g_virtualProtectHook && g_virtualProtectHook->IsValid())
    {
        return true;
    }

    if (!SetupPristineNtProtectVirtualMemory())
    {
        Log("[CapcomPatcher][NtProtect] VirtualProtect guard cannot activate without a pristine syscall");
        return false;
    }

    void* target = ResolveExport(L"kernelbase.dll", "VirtualProtect");
    if (target == nullptr)
    {
        target = ResolveExport(L"kernel32.dll", "VirtualProtect");
    }
    if (target == nullptr)
    {
        Log("[CapcomPatcher][NtProtect] could not resolve VirtualProtect");
        return false;
    }

    auto hook = std::make_unique<hooking::MinHookInlineHook>(target, reinterpret_cast<void*>(&VirtualProtectHook));
    if (!hook->IsValid() || !hook->Enable())
    {
        Log("[CapcomPatcher][NtProtect] VirtualProtect hook failed");
        return false;
    }

    g_virtualProtectHook = std::move(hook);
    Log("[CapcomPatcher][NtProtect] VirtualProtect hook installed");
    return true;
}

// ---- Guard C: AddVectoredExceptionHandler --------------------------------

using AddVehFn = PVOID(WINAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER);

PVOID WINAPI AddVectoredExceptionHandlerHook(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    g_vehCalled.store(true);
    const AddVehFn original = g_vehHook ? g_vehHook->Original<AddVehFn>() : nullptr;

    if (!g_vehAllowed.load())
    {
        HMODULE caller = nullptr;
        const bool haveCaller =
            GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(_ReturnAddress()), &caller) != 0;

        bool allowed = false;
        if (haveCaller && caller != nullptr)
        {
            if (caller == g_selfModule)
            {
                allowed = true;
            }
            else
            {
                wchar_t path[MAX_PATH]{};
                if (GetModuleFileNameW(caller, path, ARRAYSIZE(path)) != 0)
                {
                    allowed = PathContainsFold(path, L"vehdebug") || PathContainsFold(path, L"coreclr") ||
                              PathContainsFold(path, L"dinput8");
                }
            }
        }

        if (allowed)
        {
            Log("[CapcomPatcher][VEH] allowed early VEH registration");
            return original ? original(FirstHandler, VectoredHandler) : nullptr;
        }

        // Conservative: unresolved caller is treated as unapproved. The blocked
        // call still transitions state so later registrations pass (upstream).
        Log("[CapcomPatcher][VEH] blocked first unapproved VEH registration; subsequent registrations allowed");
        g_vehAllowed.store(true);
        return reinterpret_cast<PVOID>(VectoredHandler); // upstream non-null fake handle
    }

    return original ? original(FirstHandler, VectoredHandler) : nullptr;
}

bool InstallVectoredExceptionHandlerGuard()
{
    if (g_vehHook && g_vehHook->IsValid())
    {
        return true;
    }

    void* target = ResolveExport(L"kernelbase.dll", "AddVectoredExceptionHandler");
    if (target == nullptr)
    {
        target = ResolveExport(L"kernel32.dll", "AddVectoredExceptionHandler");
    }
    if (target == nullptr)
    {
        Log("[CapcomPatcher][VEH] could not resolve AddVectoredExceptionHandler");
        return false;
    }

    auto hook =
        std::make_unique<hooking::MinHookInlineHook>(target, reinterpret_cast<void*>(&AddVectoredExceptionHandlerHook));
    if (!hook->IsValid() || !hook->Enable())
    {
        Log("[CapcomPatcher][VEH] hook failed");
        return false;
    }

    g_vehHook = std::move(hook);
    Log("[CapcomPatcher][VEH] hook installed");
    return true;
}

// ---- Guard D: RtlExitUserProcess ----------------------------------------

// Upstream intentionally does NOT call the original: the normal
// RtlExitUserProcess cleanup (RtlpFlsDataCleanup / TLS destructors) can invoke
// heap-allocated code that no longer exists and crash. Parity is preserved for
// the six supported games; supported-game exit is abrupt via TerminateProcess.
void* NTAPI RtlExitUserProcessHook(uint32_t code)
{
    TerminateProcess(GetCurrentProcess(), code);
    return nullptr;
}

bool InstallRtlExitUserProcessGuard()
{
    if (g_exitHook && g_exitHook->IsValid())
    {
        return true;
    }

    void* target = ResolveExport(L"ntdll.dll", "RtlExitUserProcess");
    if (target == nullptr)
    {
        Log("[CapcomPatcher][Exit] could not resolve RtlExitUserProcess");
        return false;
    }

    auto hook =
        std::make_unique<hooking::MinHookInlineHook>(target, reinterpret_cast<void*>(&RtlExitUserProcessHook));
    if (!hook->IsValid() || !hook->Enable())
    {
        Log("[CapcomPatcher][Exit] RtlExitUserProcess hook failed");
        return false;
    }

    g_exitHook = std::move(hook);
    Log("[CapcomPatcher][Exit] RtlExitUserProcess hook installed");
    return true;
}
} // namespace

void EarlyInitialize(HMODULE selfModule) noexcept
{
    static std::atomic<bool> done{false};
    if (done.exchange(true))
    {
        return;
    }

    g_selfModule = selfModule;
    Log("[CapcomPatcher][RuntimeGuard] early runtime guard initialization started");

    // REFramework Main.cpp relative order. Each call is fail-soft.
    SetupPristineNtProtectVirtualMemory();
    InstallVectoredExceptionHandlerGuard();
    InstallRtlExitUserProcessGuard();
}

void PostLoadInitialize() noexcept
{
    // No outer latch: InstallVirtualProtectGuard() is idempotent via its own
    // IsValid() check and stays retryable on a later InitializeASI() call.
    InstallVirtualProtectGuard();
}
} // namespace antitamper::runtime_guards
