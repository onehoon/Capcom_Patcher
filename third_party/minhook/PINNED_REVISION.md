# Vendored MinHook

Source: https://github.com/TsudaKageyu/minhook
Pinned revision: `98b74f1fc12d00313d91f10450e5b3e0036175e3`
(the exact revision used by `praydog/REFramework@b6baf6b406efc65e077b99cb4d9ad25b0a0a9095`)

Only the files required to build the x64 hooking engine are vendored:

```
include/MinHook.h
src/buffer.{c,h}
src/hook.c
src/trampoline.{c,h}
src/hde/*        (Hacker Disassembler Engine)
LICENSE.txt
```

These files are unmodified. See `LICENSE.txt` (BSD-2-Clause style) and the
project `THIRD_PARTY_NOTICES.md`.

The PR1 work order prefers a git submodule; this repository vendors the pinned
files instead because the implementation environment could not run
`git submodule add`. The revision is still exactly pinned and the sources are
byte-for-byte upstream.
