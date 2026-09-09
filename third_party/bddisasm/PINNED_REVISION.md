# Vendored bddisasm (decoder + BDShemu emulator)

Source: https://github.com/bitdefender/bddisasm
Pinned revision: `70db095765ab2066dd88dfb7bbcc42259ed167c5`
(the exact revision used by `praydog/REFramework@b6baf6b` via `cursey/kananlib@8c27b65`)

Vendored file scope:

```
inc/*.h                (includes inc/bdshemu.h)
bddisasm/bddisasm.c
bddisasm/crt.c
bddisasm/include/*.h    (generated instruction tables)
bdshemu/bdshemu.c       (added in PR5 - BDShemu emulator, same pin)
LICENSE                 (Apache-2.0)
```

`bddisasm.c` is the x86-64 length/branch **decoder** (no `bdformat.c` / bindings).
`bdshemu.c` is the BDShemu **emulator** from the same revision; PR5 uses it (via
`src/memory/Emulation.cpp`) to discover which GPR an RE9-family PE-header
integrity check loads the live image base into. `bdshemu.c` is compiled as C,
no PCH, warnings off, with the same `BDDISASM_HAS_MEMSET` / `BDDISASM_NO_FORMAT`
defines as `bddisasm.c`.

These files are unmodified. Built with `BDDISASM_HAS_MEMSET` (so `crt.c` supplies
`nd_memset` via `<string.h>`); instruction-text formatting is not compiled in.

`src/memory/MemoryScan.cpp` uses `NdDecodeEx` for the advanced anti-tamper scan
helpers so they have the same VEX / EVEX / XOP instruction coverage as the pinned
REFramework/kananlib path. MinHook keeps its own vendored HDE64 for trampoline
internals.
