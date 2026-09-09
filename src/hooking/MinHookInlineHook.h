#pragma once

// Minimal inline-hook wrapper around vendored MinHook.
//
// Adapted from praydog/REFramework @ b6baf6b406efc65e077b99cb4d9ad25b0a0a9095
// (shared/utility/FunctionHookMinHook.{hpp,cpp}) with the REFramework
// Address / spdlog dependencies removed. Create/enable/original semantics are
// preserved: MinHook is initialized once, the hook is created before it is
// enabled, and a failed create or enable leaves the wrapper invalid with no
// silent partial success.
//
// Capcom Patcher stays loaded for process lifetime once active; there is no
// unhook/reload path beyond the destructor.

#include <cstdint>

namespace hooking
{
class MinHookInlineHook
{
public:
    MinHookInlineHook(void* target, void* destination);
    ~MinHookInlineHook();

    MinHookInlineHook(const MinHookInlineHook&) = delete;
    MinHookInlineHook& operator=(const MinHookInlineHook&) = delete;

    // Enable the created hook. Returns false (and invalidates the wrapper) if
    // the hook was never created or MH_EnableHook fails.
    bool Enable();

    // Disable + remove the hook. Called by the destructor.
    bool Remove();

    template <typename T>
    T Original() const
    {
        return reinterpret_cast<T>(m_original);
    }

    bool IsValid() const
    {
        return m_original != nullptr;
    }

private:
    void* m_target{};
    void* m_destination{};
    void* m_original{};
};
} // namespace hooking
