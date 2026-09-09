#include "pch.h"

#include "DD2FamilyBypass.h"

#include "../hooking/MinHookInlineHook.h"
#include "../memory/MemoryPatch.h"
#include "../memory/MemoryScan.h"
#include "../memory/ThreadSuspension.h"

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <vector>

namespace antitamper::dd2_family
{
namespace
{
void Log(const char* message)
{
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

void Logf(const char* format, ...)
{
    char buffer[256]{};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    Log(buffer);
}

// ---- createBLAS corruption guard state ---------------------------------

using CreateBlasFn = void* (*)(void*, void*, void*, void*, void*);

std::unique_ptr<hooking::MinHookInlineHook> g_createBlasHook;
uint32_t* g_corruptionWhenZero{};
std::atomic<uint32_t> g_lastNonZeroCorruption{detail::kDefaultCorruptionValue};
std::atomic<bool> g_restoreAnnounced{false};
std::atomic<bool> g_faultAnnounced{false};

void* CreateBlasHook(void* a1, void* a2, void* a3, void* a4, void* a5)
{
    uint32_t* const ptr = g_corruptionWhenZero;
    if (ptr != nullptr)
    {
        uint32_t value = 0;
        if (memory::TryReadBytes(reinterpret_cast<uintptr_t>(ptr), &value, sizeof(value)))
        {
            const auto action = detail::DecideCorruption(value, g_lastNonZeroCorruption.load());
            if (action.restore)
            {
                bool wrote = true;
                __try
                {
                    *ptr = action.writeValue;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    wrote = false;
                }
                if (wrote && !g_restoreAnnounced.exchange(true))
                {
                    Log("[CapcomPatcher][DD2Family][createBLAS] runtime corruption restored (corruption_when_zero)");
                }
                if (wrote)
                {
                    g_lastNonZeroCorruption.store(action.newLastNonZero);
                }
            }
            else
            {
                g_lastNonZeroCorruption.store(action.newLastNonZero);
            }
        }
        else if (!g_faultAnnounced.exchange(true))
        {
            Log("[CapcomPatcher][DD2Family][createBLAS] corruption_when_zero pointer became unreadable");
        }
    }

    const CreateBlasFn original = g_createBlasHook ? g_createBlasHook->Original<CreateBlasFn>() : nullptr;
    return original ? original(a1, a2, a3, a4, a5) : nullptr;
}

// ---- discovery: MHW scanner/crasher ------------------------------------

void DiscoverScannerCrasher(const memory::ModuleRange& game, std::vector<memory::BytePatchCandidate>& out)
{
    Log("[CapcomPatcher][DD2Family][MHW] scanner/crasher scan started");

    const auto qpf = reinterpret_cast<uintptr_t>(&QueryPerformanceFrequency);
    const auto qpc = reinterpret_cast<uintptr_t>(&QueryPerformanceCounter);

    const auto qpfImport = memory::ScanPointer(game, qpf);
    const auto qpcImport = memory::ScanPointer(game, qpc);
    if (!qpfImport || !qpcImport)
    {
        Log("[CapcomPatcher][DD2Family][MHW] QueryPerformance* imports not found; sub-layer skipped");
        return;
    }

    const auto crasherFn = memory::FindFunctionWithRefs(game, {*qpfImport, *qpcImport});
    if (!crasherFn)
    {
        Log("[CapcomPatcher][DD2Family][MHW] crasher_fn not found; sub-layer skipped");
        return;
    }
    Logf("[CapcomPatcher][DD2Family][MHW] crasher_fn @ +0x%llX", static_cast<unsigned long long>(*crasherFn - game.base));

    // Resolve the scanner-search target. Fail closed on the E9-thunk path:
    // once the E9 case is selected, the target is find_function_start(ref-1) or
    // nothing - never a silent fallback to crasher_fn (upstream behaviour).
    std::optional<uintptr_t> scannerTarget{*crasherFn};
    if (const auto ref = memory::ScanDisplacementReference(game, *crasherFn))
    {
        uint8_t prev = 0;
        if (memory::TryReadBytes(*ref - 1, &prev, 1) && prev == 0xE9)
        {
            scannerTarget = memory::FindFunctionStart(*ref - 1);
            if (!scannerTarget)
            {
                Log("[CapcomPatcher][DD2Family][MHW] E9 thunk owner not resolved; scanner RET sub-layer skipped");
            }
        }
    }

    // scanner_fn_middle: a rel32 E8 call to the resolved target.
    if (scannerTarget && game.size > 0x1000)
    {
        const auto scannerMiddle = memory::ScanRelativeReferenceScalar(
            game.base, game.size - 0x1000, *scannerTarget, [](uintptr_t addr) {
                uint8_t op = 0;
                return memory::TryReadBytes(addr - 1, &op, 1) && op == 0xE8;
            });

        if (scannerMiddle)
        {
            if (const auto scannerFn = memory::FindFunctionStartUnwind(*scannerMiddle))
            {
                uint8_t head[8]{};
                if (*scannerFn >= game.base && *scannerFn + sizeof(head) <= game.end() &&
                    memory::TryReadBytes(*scannerFn, head, sizeof(head)))
                {
                    memory::BytePatchCandidate c{};
                    c.address = *scannerFn;
                    c.expected.assign(head, head + sizeof(head));
                    c.writeOffset = 0;
                    c.replacement = {0xC3}; // ret
                    c.name = "scanner_fn RET";
                    c.requireExecutable = true;
                    c.requireUnwindFunctionStart = true;
                    out.push_back(std::move(c));
                    Logf("[CapcomPatcher][DD2Family][MHW] scanner_fn candidate @ +0x%llX",
                         static_cast<unsigned long long>(*scannerFn - game.base));
                }
            }
            else
            {
                Log("[CapcomPatcher][DD2Family][MHW] scanner_fn start not resolved; skipped");
            }
        }
        else
        {
            Log("[CapcomPatcher][DD2Family][MHW] scanner_fn_middle not found; skipped");
        }
    }

    // Crasher conditional branch:  39 0C 82 74 ?   ->   74 becomes EB
    if (const auto cmpJz = memory::FindPatternInPath(*crasherFn, 1000, "39 0C 82 74 ?"))
    {
        uint8_t local[5]{};
        if (memory::TryReadBytes(*cmpJz, local, sizeof(local)) && local[0] == 0x39 && local[1] == 0x0C &&
            local[2] == 0x82 && local[3] == 0x74)
        {
            memory::BytePatchCandidate c{};
            c.address = *cmpJz;
            c.expected.assign(local, local + sizeof(local));
            c.writeOffset = 3;
            c.replacement = {0xEB}; // jz -> jmp short
            c.name = "crasher JZ->JMP";
            c.requireExecutable = true;
            out.push_back(std::move(c));
            Logf("[CapcomPatcher][DD2Family][MHW] crasher cmp/jz candidate @ +0x%llX",
                 static_cast<unsigned long long>(*cmpJz - game.base));
        }
    }
    else
    {
        Log("[CapcomPatcher][DD2Family][MHW] crasher cmp/jz pattern not found; skipped");
    }
}

// ---- discovery: DD2-family suspicious constants -----------------------

void DiscoverConstants(const memory::ModuleRange& game, std::vector<memory::BytePatchCandidate>& out)
{
    Log("[CapcomPatcher][DD2Family][Constants] scan started");

    const uintptr_t end = game.end();
    size_t found = 0;
    for (auto ref = memory::Scan(game, "81 ? E1 53 BD 4C"); ref.has_value();)
    {
        uint8_t local[6]{};
        if (memory::TryReadBytes(*ref, local, sizeof(local)) && local[0] == 0x81 && local[2] == 0xE1 &&
            local[3] == 0x53 && local[4] == 0xBD && local[5] == 0x4C)
        {
            memory::BytePatchCandidate c{};
            c.address = *ref;
            c.expected.assign(local, local + sizeof(local));
            c.writeOffset = 2;
            c.replacement = {0xEF, 0xBE, 0x37, 0x13}; // 0x1337BEEF, little-endian
            c.name = "dd2 sus_constant";
            c.requireExecutable = true;
            out.push_back(std::move(c));
            ++found;
        }

        const uintptr_t next = *ref + 1;
        if (next + 0x1000 >= end)
        {
            break;
        }
        ref = memory::Scan(next, end - next - 0x1000, "81 ? E1 53 BD 4C");
    }

    Logf("[CapcomPatcher][DD2Family][Constants] %zu candidate(s) located", found);
}

// ---- discovery + hook: renderer createBLAS ---------------------------

void InstallCreateBlasGuard(const memory::ModuleRange& game)
{
    if (g_createBlasHook && g_createBlasHook->IsValid())
    {
        return;
    }

    const auto createBlasFn = memory::FindFunctionFromStringRef(game, "createBLAS");
    if (!createBlasFn)
    {
        Log("[CapcomPatcher][DD2Family][createBLAS] not found");
        return;
    }

    const auto createBlasUnwind = memory::FindFunctionStartUnwind(*createBlasFn);
    if (!createBlasUnwind)
    {
        Log("[CapcomPatcher][DD2Family][createBLAS] unwound function start not resolved");
        return;
    }
    Logf("[CapcomPatcher][DD2Family][createBLAS] found @ +0x%llX",
         static_cast<unsigned long long>(*createBlasFn - game.base));

    // First `lea rcx, [rip+disp32]` inside the function -> corruption_when_zero.
    if (const auto leaRcx = memory::FindPatternInPath(*createBlasUnwind, 1000, "48 8D 0D ? ? ? ?"))
    {
        const uintptr_t resolved = memory::CalculateAbsolute(*leaRcx + 3);
        uint32_t probe = 0;
        if (resolved != 0 && memory::IsReadable(resolved, sizeof(uint32_t)) &&
            memory::TryReadBytes(resolved, &probe, sizeof(probe)))
        {
            g_corruptionWhenZero = reinterpret_cast<uint32_t*>(resolved);
            if (probe != 0)
            {
                g_lastNonZeroCorruption.store(probe);
            }
            Log("[CapcomPatcher][DD2Family][createBLAS] corruption_when_zero validated");
        }
        else
        {
            Log("[CapcomPatcher][DD2Family][createBLAS] corruption_when_zero pointer failed validation; not tracked");
        }
    }
    else
    {
        Log("[CapcomPatcher][DD2Family][createBLAS] lea rcx pattern not found; corruption pointer not tracked");
    }

    auto hook = std::make_unique<hooking::MinHookInlineHook>(reinterpret_cast<void*>(*createBlasFn),
                                                            reinterpret_cast<void*>(&CreateBlasHook));
    if (!hook->IsValid())
    {
        Log("[CapcomPatcher][DD2Family][createBLAS] hook creation failed");
        return;
    }

    // Publish before enabling (PR1 pattern): the detour needs Original().
    g_createBlasHook = std::move(hook);
    if (!g_createBlasHook->Enable())
    {
        Log("[CapcomPatcher][DD2Family][createBLAS] hook enable failed");
        g_createBlasHook.reset();
        return;
    }
    Log("[CapcomPatcher][DD2Family][createBLAS] hook installed");
}

// ---- raw-patch commit -----------------------------------------------

void CommitRawPatches(std::vector<memory::BytePatchCandidate>& candidates)
{
    if (candidates.empty())
    {
        return;
    }

    memory::ThreadSuspensionScope suspension;
    if (!suspension.Ok())
    {
        Log("[CapcomPatcher][DD2Family] no safe raw-patch window; raw byte writes skipped");
        return;
    }
    Logf("[CapcomPatcher][DD2Family] raw-patch window: %zu thread(s) suspended", suspension.SuspendedCount());

    for (const auto& candidate : candidates)
    {
        switch (memory::CommitPatch(candidate))
        {
        case memory::PatchOutcome::Patched:
            Logf("[CapcomPatcher][DD2Family] patched: %s", candidate.name);
            break;
        case memory::PatchOutcome::AlreadyPatched:
            Logf("[CapcomPatcher][DD2Family] already patched: %s", candidate.name);
            break;
        case memory::PatchOutcome::Skipped:
            Logf("[CapcomPatcher][DD2Family] skipped (validation mismatch): %s", candidate.name);
            break;
        case memory::PatchOutcome::Failed:
            Logf("[CapcomPatcher][DD2Family] FAILED: %s", candidate.name);
            break;
        }
    }
}
} // namespace

void Initialize(const game_profile::GameProfile& profile) noexcept
{
    if (!profile.dd2Family)
    {
        return;
    }

    const memory::ModuleRange game = memory::MainModule();
    if (!game)
    {
        Log("[CapcomPatcher][DD2Family] main module unavailable; layer skipped");
        return;
    }

    Log("[CapcomPatcher][DD2Family] scan started");

    // Phase 1: read-only discovery.
    std::vector<memory::BytePatchCandidate> rawPatches;
    if (profile.dd2ScannerCrasher)
    {
        DiscoverScannerCrasher(game, rawPatches);
    }
    else
    {
        Log("[CapcomPatcher][DD2Family][MHW] scanner/crasher skipped by profile");
    }
    DiscoverConstants(game, rawPatches);

    // Phase 2: raw-patch commit under a short thread-suspension window.
    CommitRawPatches(rawPatches);

    // Separate: createBLAS inline hook (MinHook owns its own thread freeze).
    InstallCreateBlasGuard(game);

    Log("[CapcomPatcher][DD2Family] scan complete");
}
} // namespace antitamper::dd2_family
