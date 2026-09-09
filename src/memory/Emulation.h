#pragma once

// Minimal BDShemu adapter for one job: emulate a short straight-line instruction
// sequence and report which x64 GPR ends up holding a wanted value (the live
// game image base), plus how many whole bytes were consumed getting there.
//
// Behavioral source: cursey/kananlib @ 8c27b656734355db0f2893581fd62e838fa130ad
//   include/utility/Emulation.hpp / src/Emulation.cpp  (utility::emulate)
// Emulator: bitdefender/bddisasm @ 70db095765ab2066dd88dfb7bbcc42259ed167c5
//   bdshemu/bdshemu.c + inc/bdshemu.h  (vendored under third_party/bddisasm/)
//
// This is analysis only. The emulator is never allowed to commit a store into
// real game memory (the AccessMemory callback discards writes), and RIP is not
// allowed to leave a bounded window around the start address.

#include <cstddef>
#include <cstdint>
#include <optional>

#include "MemoryScan.h"

struct _SHEMU_GPR_REGS;

namespace memory
{
namespace detail
{
// The matching SHEMU_GPR_REGS field for NDR_RAX..NDR_R15; 0 for any other
// register id (RIP / CR / segment values are never GPR candidates). Exposed for
// deterministic tests; internal callers use it too.
uint64_t ShemuGpr(const _SHEMU_GPR_REGS& regs, int ndrReg) noexcept;
} // namespace detail

struct ImageBaseRegisterResult
{
    int reg{};             // NDR_RAX .. NDR_R15
    size_t consumedBytes{}; // whole-instruction byte span from `start` to the match
};

// Emulate up to `maxInstructions` instructions starting at `start` (which must
// be an instruction boundary inside `game`). After each emulated step every
// x64 GPR is checked; the first that equals `wantedValue` wins. CALLs and
// memory-writing instructions are stepped over (not executed). Returns nullopt
// if no register matched, on any decode/emulation failure, or if execution
// would leave the bounded window. Fail-closed: an uncertain result is no result.
std::optional<ImageBaseRegisterResult> FindRegisterHoldingValue(const ModuleRange& game, uintptr_t start,
                                                                uintptr_t wantedValue,
                                                                size_t maxInstructions = 15) noexcept;
} // namespace memory
