#include "pch.h"

#include "MinHookInlineHook.h"

#include <MinHook.h>

#include <atomic>
#include <mutex>

namespace hooking
{
namespace
{
std::once_flag g_minhookInitFlag;
std::atomic<bool> g_minhookReady{false};

void Log(const char* message)
{
    OutputDebugStringA(message);
    OutputDebugStringA("\n");
}

void EnsureMinHookInitialized()
{
    std::call_once(g_minhookInitFlag, [] {
        const MH_STATUS status = MH_Initialize();
        if (status == MH_OK || status == MH_ERROR_ALREADY_INITIALIZED)
        {
            g_minhookReady.store(true);
        }
        else
        {
            Log("[CapcomPatcher][Hook] MH_Initialize failed");
        }
    });
}
} // namespace

MinHookInlineHook::MinHookInlineHook(void* target, void* destination)
{
    EnsureMinHookInitialized();
    if (!g_minhookReady.load() || target == nullptr || destination == nullptr)
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

    if (MH_EnableHook(m_target) != MH_OK)
    {
        Log("[CapcomPatcher][Hook] MH_EnableHook failed");
        m_target = nullptr;
        m_destination = nullptr;
        m_original = nullptr;
        return false;
    }

    return true;
}

bool MinHookInlineHook::Remove()
{
    if (m_target == nullptr)
    {
        return true;
    }

    const bool ok =
        MH_DisableHook(m_target) == MH_OK && MH_RemoveHook(m_target) == MH_OK;

    m_target = nullptr;
    m_destination = nullptr;
    m_original = nullptr;
    return ok;
}
} // namespace hooking
