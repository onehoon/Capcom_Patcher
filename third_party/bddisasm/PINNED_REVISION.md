# Vendored bddisasm (decoder only)

Source: https://github.com/bitdefender/bddisasm
Pinned revision: `70db095765ab2066dd88dfb7bbcc42259ed167c5`
(the exact revision used by `praydog/REFramework@b6baf6b` via `cursey/kananlib@8c27b65`)

Only the files needed to build the x86-64 length/branch **decoder** are vendored
(no `bdformat.c` / `bdshemu` / bindings):

```
inc/*.h
bddisasm/bddisasm.c
bddisasm/crt.c
bddisasm/include/*.h   (generated instruction tables)
LICENSE                 (Apache-2.0)
```

These files are unmodified. Built with `BDDISASM_HAS_MEMSET` (so `crt.c` supplies
`nd_memset` via `<string.h>`); instruction-text formatting is not compiled in.

`src/memory/MemoryScan.cpp` uses `NdDecodeEx` for the advanced anti-tamper scan
helpers so they have the same VEX / EVEX / XOP instruction coverage as the pinned
REFramework/kananlib path. MinHook keeps its own vendored HDE64 for trampoline
internals.
