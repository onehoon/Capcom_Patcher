// Adapted from onehoon/OptiPatcher @ b57408dc6efb7ae62229af028daef8f19caf2f66
// (OptiPatcher/Util.cpp). MIT License. See THIRD_PARTY_NOTICES.md.

#include "pch.h"

#include "Util.h"

std::filesystem::path Util::DllPath(HMODULE dllModule)
{
    static std::filesystem::path dll;

    if (dll.empty())
    {
        wchar_t dllPath[MAX_PATH];
        GetModuleFileNameW(dllModule, dllPath, MAX_PATH);
        dll = std::filesystem::path(dllPath);
    }

    return dll;
}

std::filesystem::path Util::ExePath()
{
    static std::filesystem::path exe;

    if (exe.empty())
    {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        exe = std::filesystem::path(exePath);
    }

    return exe;
}
