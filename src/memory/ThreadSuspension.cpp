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

ThreadSuspensionScope::ThreadSuspensionScope()
{
    g_suspendMutex.lock();
    m_holdsLock = true;

    const DWORD pid = GetCurrentProcessId();
    const DWORD selfTid = GetCurrentThreadId();

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == nullptr || snapshot == INVALID_HANDLE_VALUE)
    {
        Log("[CapcomPatcher][MemoryPatch] thread snapshot failed; raw-patch window unavailable");
        return;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    if (Thread32First(snapshot, &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == selfTid)
            {
                continue;
            }

            const HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
            if (thread == nullptr)
            {
                continue; // conservative: log-free, do not abort
            }

            if (SuspendThread(thread) != static_cast<DWORD>(-1))
            {
                m_threads.push_back(thread);
            }
            else
            {
                CloseHandle(thread);
            }
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    m_ok = true;
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
