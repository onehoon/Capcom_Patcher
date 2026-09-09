#include "pch.h"

#include "MinHookInlineHook.h"

#include <MinHook.h>

#include <atomic>
#include <mutex>

namespace hooking
{
namespace
{
std::mutex g_minhookInitMutex;
std::atomic<bool> g_minhookReady{false};

void Log(const char* message)
{
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

// Retryable: the init attempt is repeated on every call until it actually
// succeeds, so a transient MH_Initialize() failure from DllMain does not
// permanently disable later guard installation.
bool EnsureMinHookInitialized()
{
    if (g_minhookReady.load(std::memory_order_acquire))
    {
        return true;
    }

    std::lock_guard lock(g_minhookInitMutex);
    if (g_minhookReady.load(std::memory_order_relaxed))
    {
        return true;
    }

    const MH_STATUS status = MH_Initialize();
    if (status == MH_OK || status == MH_ERROR_ALREADY_INITIALIZED)
    {
        g_minhookReady.store(true, std::memory_order_release);
        return true;
    }

    Log("[CapcomPatcher][Hook] MH_Initialize failed");
    return false;
}
} // namespace

MinHookInlineHook::MinHookInlineHook(void* target, void* destination)
{
    if (!EnsureMinHookInitialized() || target == nullptr || destination == nullptr)
    {
        return;
    }

    void* original = nullptr;
    if (MH_CreateHook(target, destination, &original) != MH_OK || original == nullptr)
    {
        Log("[CapcomPatcher][Hook] MH_CreateHook failed");
        return;
    }

    m_target = target;
    m_destination = destination;
    m_original = original;
}

MinHookInlineHook::~MinHookInlineHook()
{
    Remove();
}

bool MinHookInlineHook::Enable()
{
    if (m_target == nullptr || m_original == nullptr)
    {
        return false;
    }

    if (MH_EnableHook(m_target) == MH_OK)
    {
        return true;
    }

    Log("[CapcomPatcher][Hook] MH_EnableHook failed");

    // Remove the created-but-disabled entry so a later retry does not hit
    // MH_ERROR_ALREADY_CREATED.
    (void)MH_DisableHook(m_target);
    const MH_STATUS removeStatus = MH_RemoveHook(m_target);
    if (removeStatus != MH_OK && removeStatus != MH_ERROR_NOT_CREATED)
    {
        Log("[CapcomPatcher][Hook] cleanup after failed enable also failed");
    }

    m_target = nullptr;
    m_destination = nullptr;
    m_original = nullptr;
    return false;
}

bool MinHookInlineHook::Remove()
{
    if (m_target == nullptr)
    {
        return true;
    }

    const MH_STATUS disableStatus = MH_DisableHook(m_target);
    const MH_STATUS removeStatus = MH_RemoveHook(m_target); // always attempt

    const bool disableOk = disableStatus == MH_OK || disableStatus == MH_ERROR_DISABLED;
    const bool removeOk = removeStatus == MH_OK || removeStatus == MH_ERROR_NOT_CREATED;

    m_target = nullptr;
    m_destination = nullptr;
    m_original = nullptr;
    return disableOk && removeOk;
}
} // namespace hooking
