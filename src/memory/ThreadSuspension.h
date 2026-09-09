#pragma once

// Scoped "suspend every other thread in this process" window for the raw-patch
// commit phase. Behavioral reference: cursey/kananlib Thread.cpp
// (@ 8c27b656734355db0f2893581fd62e838fa130ad), with the fragile RAII details
// corrected per the PR2 work order:
//   - the scope mutex is always released on destruction, even if zero threads
//     were suspended;
//   - SuspendThread success is `!= (DWORD)-1`;
//   - every successfully suspended thread is resumed exactly once.
//
// Never construct this from DllMain.

#include <cstddef>
#include <vector>

#include <windows.h>

namespace memory
{
class ThreadSuspensionScope
{
public:
    ThreadSuspensionScope();
    ~ThreadSuspensionScope();

    ThreadSuspensionScope(const ThreadSuspensionScope&) = delete;
    ThreadSuspensionScope& operator=(const ThreadSuspensionScope&) = delete;

    // True when the thread snapshot succeeded (a safe raw-patch window exists).
    // Zero other threads still counts as ok.
    bool Ok() const { return m_ok; }
    size_t SuspendedCount() const { return m_threads.size(); }

private:
    std::vector<HANDLE> m_threads;
    bool m_ok{false};
    bool m_holdsLock{false};
};
} // namespace memory
