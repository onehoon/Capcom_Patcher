#pragma once

// Adapted from onehoon/OptiPatcher @ b57408dc6efb7ae62229af028daef8f19caf2f66
// (OptiPatcher/Util.h). MIT License. See THIRD_PARTY_NOTICES.md.

#include "pch.h"

#include <filesystem>

namespace Util
{
std::filesystem::path ExePath();
std::filesystem::path DllPath(HMODULE dllModule);
} // namespace Util
