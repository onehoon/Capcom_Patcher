#include "pch.h"

#include "RendererHeartbeatBypass.h"

#include "../memory/MemoryScan.h"
#include "../reengine/RendererBridge.h"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <exception>
#include <mutex>
#include <thread>

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

// Behavioral source: praydog/REFramework @ b6baf6b
// (src/mods/IntegrityCheckBypass.cpp: re9_heartbeat_bypass / on_frame).
// REFramework: Copyright (c) 2019 praydog, MIT License. See THIRD_PARTY_NOTICES.md.

namespace antitamper::heartbeat
{
namespace detail
{
namespace
{
bool InRange(uint32_t value, uint32_t frameCount) noexcept
{
    return value > 0 && value <= frameCount && (frameCount - value) < kMaxDistance;
}
} // namespace

bool AcceptCluster(const ClusterSnapshot& c, uint32_t frameCount) noexcept
{
    if (c.before != 1 || c.after != 0)
    {
        return false;
    }

    bool allValid = true;
    bool earlyDetect = (c.values[0] == 0);
    for (size_t j = 0; j < kHeartbeatCount; ++j)
    {
        const bool inRange = InRange(c.values[j], frameCount);
        if (!inRange)
        {
            allValid = false;
            if (j > 0)
            {
                earlyDetect = false;
            }
        }
    }
    return allValid || earlyDetect;
}

void Confirmation::Reset() noexcept
{
    m_candidateCount = 0;
    m_count = 0;
    m_seeded = false;
    m_confirmed.reset();
}

void Confirmation::Observe(const uint32_t* offsets, size_t count) noexcept
{
    if (m_confirmed.has_value())
    {
        return;
    }

    if (!m_seeded)
    {
        m_candidateCount = count < kMaxCandidates ? count : kMaxCandidates;
        for (size_t i = 0; i < m_candidateCount; ++i)
        {
            m_candidates[i] = offsets[i];
        }
        m_count = 1;
        m_seeded = true;
        return;
    }

    // Intersect the surviving candidates with this frame's set.
    size_t write = 0;
    for (size_t i = 0; i < m_candidateCount; ++i)
    {
        bool present = false;
        for (size_t j = 0; j < count; ++j)
        {
            if (offsets[j] == m_candidates[i])
            {
                present = true;
                break;
            }
        }
        if (present)
        {
            m_candidates[write++] = m_candidates[i];
        }
    }
    m_candidateCount = write;
    ++m_count;

    if (m_candidateCount == 1 && m_count >= kConfirmationsNeeded)
    {
        m_confirmed = m_candidates[0];
    }
    else if (m_candidateCount == 0)
    {
        // Lost every candidate - restart discovery on the next scan.
        m_count = 0;
        m_seeded = false;
    }
}
} // namespace detail

namespace
{
using detail::kHeartbeatCount;
using detail::kScanBegin;
using detail::kScanEnd;

void Log(const char* format, ...)
{
    char buffer[512]{};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
}

std::atomic<bool> g_started{false};
std::mutex g_lifecycleMutex;
const wchar_t* g_gameName = L"?";
uint32_t g_expectedTdb = 0;

bool ReadClusterAt(uintptr_t base, size_t offset, detail::ClusterSnapshot& out) noexcept
{
    // ints[-1] .. ints[6] : 8 dwords starting at base + offset - 4.
    uint32_t raw[kHeartbeatCount + 2]{};
    if (!memory::TryReadBytes(base + offset - sizeof(uint32_t), raw, sizeof(raw)))
    {
        return false;
    }
    out.before = raw[0];
    for (size_t i = 0; i < kHeartbeatCount; ++i)
    {
        out.values[i] = raw[i + 1];
    }
    out.after = raw[kHeartbeatCount + 1];
    return true;
}

bool ClusterWritable(uintptr_t address, size_t bytes) noexcept
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
    {
        return false;
    }
    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
    {
        return false;
    }
    const DWORD prot = mbi.Protect & 0xFFu;
    const bool writable = prot == PAGE_READWRITE || prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READWRITE ||
                          prot == PAGE_EXECUTE_WRITECOPY;
    if (!writable)
    {
        return false;
    }
    const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return address + bytes <= regionEnd;
}

bool WriteHeartbeats(uintptr_t clusterAddress, uint32_t frameCount) noexcept
{
    if (!ClusterWritable(clusterAddress, kHeartbeatCount * sizeof(uint32_t)))
    {
        return false;
    }
    __try
    {
        auto* p = reinterpret_cast<volatile uint32_t*>(clusterAddress);
        for (size_t i = 0; i < kHeartbeatCount; ++i)
        {
            p[i] = frameCount;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return true;
}

bool CallGetRenderFrame(uint32_t (*fn)(), uint32_t& out) noexcept
{
    __try
    {
        out = fn();
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

// High-resolution 1 ms wait for the active discovery/sync cadence. The work
// order requires this and forbids timeBeginPeriod(); CREATE_WAITABLE_TIMER_HIGH_
// RESOLUTION (Win10 1803+) gives a fine short expiration without the global
// timer-resolution side effect. Falls back to Sleep(1) (logged once).
class ActiveTicker
{
public:
    ActiveTicker()
        : m_timer(CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                         TIMER_MODIFY_STATE | SYNCHRONIZE))
    {
    }
    ~ActiveTicker()
    {
        if (m_timer != nullptr)
        {
            CloseHandle(m_timer);
        }
    }
    ActiveTicker(const ActiveTicker&) = delete;
    ActiveTicker& operator=(const ActiveTicker&) = delete;

    bool HighResolution() const noexcept { return m_timer != nullptr; }

    void Wait() noexcept
    {
        if (m_timer != nullptr)
        {
            LARGE_INTEGER due{};
            due.QuadPart = -10000LL; // relative 1 ms, 100 ns units
            if (SetWaitableTimerEx(m_timer, &due, 0, nullptr, nullptr, nullptr, 0) &&
                WaitForSingleObject(m_timer, INFINITE) == WAIT_OBJECT_0)
            {
                return;
            }
        }
        if (!m_warned)
        {
            Log("[CapcomPatcher][Heartbeat] high-resolution timer unavailable; active cadence falls back to Sleep(1)");
            m_warned = true;
        }
        Sleep(1);
    }

private:
    HANDLE m_timer{};
    bool m_warned{false};
};

void WorkerLoop()
{
    reengine::RendererBridge bridge{g_expectedTdb};
    detail::Confirmation discovery;
    ActiveTicker activeTicker;
    Log("[CapcomPatcher][Heartbeat] active-tick timer: %s",
        activeTicker.HighResolution() ? "high-resolution" : "Sleep(1) fallback");

    void* trackedRenderer = nullptr;
    uint32_t lastScanFrame = 0;
    uint32_t lastSyncFrame = 0;
    int getterFaults = 0;
    bool syncActiveLogged = false;
    size_t lastSeededCount = 0;
    size_t lastReducedCount = 0;

    reengine::RendererFrameSource fs{};
    bool forceResolve = true;
    uint32_t lastIdentityCheckFrame = 0;
    uint32_t lastObservedFrame = 0;
    bool haveObservedFrame = false;

    // Drop every piece of discovery/sync state and force a fresh bridge
    // resolution. Used when the engine frame counter regresses or a
    // read/write into the confirmed cluster faults - in both cases the
    // renderer identity we hold can no longer be trusted.
    const auto fullReset = [&]() {
        discovery.Reset();
        trackedRenderer = nullptr;
        fs = {};
        forceResolve = true;
        syncActiveLogged = false;
        lastScanFrame = 0;
        lastSyncFrame = 0;
        lastIdentityCheckFrame = 0;
        lastObservedFrame = 0;
        haveObservedFrame = false;
        lastSeededCount = 0;
        lastReducedCount = 0;
    };

    // Returns false (caller should `continue`) on a non-Ready bridge; returns
    // via `return` from WorkerLoop on UnsupportedLayout.
    const auto tryResolve = [&](bool& outReady) -> bool {
        reengine::RendererFrameSource fresh{};
        const auto status = bridge.Resolve(fresh);
        if (status == reengine::ResolveStatus::UnsupportedLayout)
        {
            Log("[CapcomPatcher][Heartbeat] disabled for this session (TDB layout mismatch)");
            outReady = false;
            return false; // signal: return from WorkerLoop
        }
        if (status != reengine::ResolveStatus::Ready)
        {
            fs = {};
            forceResolve = true;
            outReady = false;
            return true;
        }
        fs = fresh;
        forceResolve = false;
        outReady = true;
        return true;
    };

    for (;;)
    {
        bool resolvedThisIteration = false;
        if (forceResolve || fs.renderer == nullptr)
        {
            bool ready = false;
            if (!tryResolve(ready))
            {
                return;
            }
            if (!ready)
            {
                Sleep(100);
                continue;
            }
            resolvedThisIteration = true;
        }

        uint32_t frameCount = 0;
        if (!CallGetRenderFrame(fs.getRenderFrame, frameCount))
        {
            forceResolve = true;
            if (++getterFaults >= 10)
            {
                Log("[CapcomPatcher][Heartbeat] get_RenderFrame faulting; resetting discovery");
                discovery.Reset();
                trackedRenderer = nullptr;
                getterFaults = 0;
            }
            Sleep(100);
            continue;
        }
        getterFaults = 0;

        // Fail closed on an unexpected engine-frame regression (renderer/device
        // lifecycle that resets the counter). A confirmed cluster must never
        // receive the regressed value. A bare uint32 wrap is rare enough that
        // treating it as a reset is the safe choice.
        if (detail::FrameRegressed(haveObservedFrame, lastObservedFrame, frameCount))
        {
            Log("[CapcomPatcher][Heartbeat] render frame regressed (%u -> %u); reacquiring renderer and resetting discovery",
                lastObservedFrame, frameCount);
            fullReset();
            continue;
        }
        lastObservedFrame = frameCount;
        haveObservedFrame = true;

        // Revalidate the native singleton identity once per new engine frame
        // (REFramework resolves it every on_frame()). A replaced renderer whose
        // old allocation is still committed would otherwise keep receiving
        // heartbeat writes for up to a full resolution interval.
        if (!resolvedThisIteration && frameCount != lastIdentityCheckFrame)
        {
            bool ready = false;
            if (!tryResolve(ready))
            {
                return;
            }
            if (!ready)
            {
                Sleep(100);
                continue;
            }
        }
        lastIdentityCheckFrame = frameCount;

        if (fs.renderer != trackedRenderer)
        {
            if (trackedRenderer != nullptr)
            {
                Log("[CapcomPatcher][Heartbeat] renderer changed; resetting discovery");
            }
            trackedRenderer = fs.renderer;
            discovery.Reset();
            syncActiveLogged = false;
            lastScanFrame = 0;
            lastSyncFrame = 0;
            lastSeededCount = 0;
            lastReducedCount = 0;
        }

        const auto rendererAddr = reinterpret_cast<uintptr_t>(fs.renderer);

        if (discovery.Confirmed())
        {
            const uint32_t offset = *discovery.ConfirmedOffset();
            if (offset < kScanBegin || offset + kHeartbeatCount * sizeof(uint32_t) > kScanEnd)
            {
                fullReset();
                continue;
            }

            if (frameCount != lastSyncFrame)
            {
                detail::ClusterSnapshot snap{};
                const bool readOk = ReadClusterAt(rendererAddr, offset, snap);
                if (!readOk || snap.before != 1 || snap.after != 0 ||
                    !WriteHeartbeats(rendererAddr + offset, frameCount))
                {
                    Log("[CapcomPatcher][Heartbeat] confirmed sentinels changed; resetting discovery");
                    fullReset();
                    Sleep(1);
                    continue;
                }
                lastSyncFrame = frameCount;
            }
            activeTicker.Wait();
            continue;
        }

        if (frameCount > 100 && frameCount != lastScanFrame)
        {
            lastScanFrame = frameCount;

            // (kScanEnd-kScanBegin)/4 = 0x800 possible 4-byte-aligned starts.
            uint32_t offsets[(kScanEnd - kScanBegin) / sizeof(uint32_t)];
            size_t count = 0;
            for (size_t off = kScanBegin; off + kHeartbeatCount * sizeof(uint32_t) <= kScanEnd;
                 off += sizeof(uint32_t))
            {
                detail::ClusterSnapshot snap{};
                if (!ReadClusterAt(rendererAddr, off, snap))
                {
                    continue;
                }
                if (detail::AcceptCluster(snap, frameCount) && count < std::size(offsets))
                {
                    offsets[count++] = static_cast<uint32_t>(off);
                }
            }

            const bool wasSeeded = discovery.Count() > 0;
            discovery.Observe(offsets, count);

            if (discovery.Confirmed())
            {
                Log("[CapcomPatcher][Heartbeat] confirmed cluster renderer+0x%X after %d confirmations at frame %u",
                    *discovery.ConfirmedOffset(), discovery.Count(), frameCount);
                if (!syncActiveLogged)
                {
                    Log("[CapcomPatcher][Heartbeat] synchronization active");
                    syncActiveLogged = true;
                }
            }
            else if (!wasSeeded && discovery.Count() == 1)
            {
                if (discovery.CandidateCount() != lastSeededCount)
                {
                    Log("[CapcomPatcher][Heartbeat] seeded %zu candidate(s) at frame %u", discovery.CandidateCount(),
                        frameCount);
                    lastSeededCount = discovery.CandidateCount();
                }
            }
            else if (discovery.Count() > 1 && discovery.CandidateCount() != lastReducedCount)
            {
                Log("[CapcomPatcher][Heartbeat] candidate set reduced to %zu after confirmation %d",
                    discovery.CandidateCount(), discovery.Count());
                lastReducedCount = discovery.CandidateCount();
            }
        }

        if (frameCount <= 100)
        {
            Sleep(5);
        }
        else
        {
            activeTicker.Wait();
        }
    }
}
} // namespace

void Initialize(const game_profile::GameProfile& profile) noexcept
{
    std::lock_guard lock(g_lifecycleMutex);
    if (g_started.load())
    {
        return;
    }

    if (!profile.heartbeat)
    {
        return;
    }
    const auto expected = reengine::ExpectedTdbVersion(profile.id);
    if (!expected.has_value())
    {
        // Defense in depth: a heartbeat==true profile with no expected modern
        // TDB version (e.g. MHW) must never start the worker.
        Log("[CapcomPatcher][Heartbeat] no expected TDB version for this game; not starting");
        return;
    }

    g_gameName = profile.canonicalName;
    g_expectedTdb = *expected;

    HMODULE pinned = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                            reinterpret_cast<LPCWSTR>(&g_started), &pinned))
    {
        Log("[CapcomPatcher][Heartbeat] failed to pin module; not starting worker");
        return;
    }

    try
    {
        std::thread(WorkerLoop).detach();
    }
    catch (const std::exception&)
    {
        Log("[CapcomPatcher][Heartbeat] failed to start worker thread");
        return;
    }

    g_started.store(true);
    Log("[CapcomPatcher][Heartbeat] worker started for %ls (expected TDB%u)", g_gameName, g_expectedTdb);
}
} // namespace antitamper::heartbeat
