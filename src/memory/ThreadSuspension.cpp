#include "pch.h"

#include "ThreadSuspension.h"

#include <mutex>

#include <tlhelp32.h>

namespace memory
{
namespace
{
std::mutex g_suspendMutex;

void Log(const char* message)
{
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}
} // namespace

namespace
{
void ResumeAndClose(std::vector<HANDLE>& threads) noexcept
{
    for (const HANDLE thread : threads)
    {
        ResumeThread(thread);
        CloseHandle(thread);
    }
    threads.clear();
}
} // namespace

ThreadSuspensionScope::ThreadSuspensionScope()
{
    g_suspendMutex.lock();
    m_holdsLock = true;

    const DWORD pid = GetCurrentProcessId();
    const DWORD selfTid = GetCurrentThreadId();

    // Fail-closed: every other thread present in the snapshot must be suspended,
    // or the whole window is reported unavailable (Ok() == false) and any
    // threads we already suspended are resumed. Retry a few times to ride out
    // benign thread churn between snapshot and OpenThread.
    for (int attempt = 0; attempt < 4 && !m_ok; ++attempt)
    {
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == nullptr || snapshot == INVALID_HANDLE_VALUE)
        {
            continue;
        }

        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        bool failed = false;

        if (!Thread32First(snapshot, &entry))
        {
            CloseHandle(snapshot);
            continue;
        }

        for (;;)
        {
            if (entry.th32OwnerProcessID == pid && entry.th32ThreadID != selfTid)
            {
                const HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
                if (thread == nullptr)
                {
                    failed = true;
                    break;
                }
                if (SuspendThread(thread) == static_cast<DWORD>(-1))
                {
                    CloseHandle(thread);
                    failed = true;
                    break;
                }
                m_threads.push_back(thread);
            }

            SetLastError(ERROR_SUCCESS);
            if (!Thread32Next(snapshot, &entry))
            {
                // Only ERROR_NO_MORE_FILES is a clean end-of-list; anything else
                // is an incomplete enumeration and must fail closed.
                if (GetLastError() != ERROR_NO_MORE_FILES)
                {
                    failed = true;
                }
                break;
            }
        }

        CloseHandle(snapshot);

        if (failed)
        {
            ResumeAndClose(m_threads);
            continue;
        }
        m_ok = true;
    }

    if (!m_ok)
    {
        Log("[CapcomPatcher][MemoryPatch] could not suspend all threads; raw-patch window unavailable");
    }
}

ThreadSuspensionScope::~ThreadSuspensionScope()
{
    for (const HANDLE thread : m_threads)
    {
        ResumeThread(thread);
        CloseHandle(thread);
    }
    m_threads.clear();

    if (m_holdsLock)
    {
        m_holdsLock = false;
        g_suspendMutex.unlock();
    }
}
} // namespace memory
