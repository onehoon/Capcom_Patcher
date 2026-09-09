#pragma once

// Common REFramework runtime anti-tamper guards.
//
// Adapted from praydog/REFramework @ b6baf6b406efc65e077b99cb4d9ad25b0a0a9095
// (src/mods/IntegrityCheckBypass.cpp): setup_pristine_syscall(),
// fix_virtual_protect() / virtual_protect_impl() / virtual_protect_hook(),
// hook_add_vectored_exception_handler() / add_vectored_exception_handler_hook(),
// hook_rtl_exit_user_process() / rtl_exit_user_process_hook().
//
// REFramework infrastructure (sdk::GameIdentity, g_framework, Mod base class,
// spdlog, utility tree) is intentionally not carried over. Support gating uses
// Capcom Patcher's GameProfile; logging uses OutputDebugStringA.
//
// Each guard is fail-soft: a failure is logged and leaves that guard inactive
// without aborting the rest of the patcher.

#include <windows.h>

namespace antitamper::runtime_guards
{
// Loader-lock phase (DLL_PROCESS_ATTACH). Call only for one of the six
// supported games. Installs, in REFramework's relative order:
//   1. pristine NtProtectVirtualMemory capture
//   2. AddVectoredExceptionHandler guard
//   3. RtlExitUserProcess guard
void EarlyInitialize(HMODULE selfModule) noexcept;

// Post-LoadLibrary phase, from InitializeASI() before the DbgUi watcher.
// Installs the VirtualProtect / NtProtectVirtualMemory integrity guard.
void PostLoadInitialize() noexcept;
} // namespace antitamper::runtime_guards
