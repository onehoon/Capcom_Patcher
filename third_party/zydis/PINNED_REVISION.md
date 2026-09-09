# Vendored Zydis (amalgamated)

Source: https://github.com/zyantific/zydis
Pinned version: **v4.0.0** — the `zydis-amalgamated.tar.gz` release asset
(`Zydis.h` + `Zydis.c`, single-file each). The v4.0.0 amalgamation bundles the
Zycore submodule pinned at `zyantific/zycore-c@1401fb85ac313f6605ec795c52bf99ea3f292a69`.

This is the exact decoder revision that `cursey/safetyhook@b046e123` (see
`../safetyhook/`) requires for its relocation / mid-hook engine. It is **only**
used by SafetyHook — Capcom Patcher's own anti-tamper scans use the pinned
`bddisasm` (`../bddisasm/`), and MinHook uses its own HDE64.

`Zydis.h` / `Zydis.c` are unmodified. `Zydis.c` is compiled as a single C
translation unit (no PCH, warnings off). Licenses: `LICENSE` (Zydis, MIT),
`LICENSE.zycore` (Zycore, MIT).
