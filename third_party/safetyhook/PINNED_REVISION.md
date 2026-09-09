# Vendored SafetyHook

Source: https://github.com/cursey/safetyhook
Pinned revision: `b046e123dc69821f2c375161e0adef3c6d9c9db4`
(the exact revision `praydog/REFramework@b6baf6b` fetches)

Used for the PR3 RE9-family JobQueue mid-hooks (`SafetyHookMid`), which must
inspect / rewrite live register context before an indirect call. Ordinary inline
detours still use the vendored MinHook (PR1).

Vendored files (Windows x64 only — no Linux sources, tests, examples, docs):

```
include/safetyhook.hpp
include/safetyhook/*.hpp
src/allocator.cpp  easy.cpp  inline_hook.cpp  mid_hook.cpp  os.windows.cpp  utility.cpp  vmt_hook.cpp
LICENSE  (Boost Software License 1.0)
```

Unmodified. Built with per-file `/std:c++latest` (SafetyHook uses `std::expected`,
a C++23 feature). The rest of Capcom Patcher stays at C++20; only SafetyHook TUs
and `src/antitamper/RE9FamilyBypass.cpp` (which includes SafetyHook headers) get
the per-file override.

SafetyHook's relocation / mid-hook engine uses **Zydis v4.0.0**
(`third_party/zydis/`). That decoder is kept separate from Capcom Patcher's own
`bddisasm` scan decoder (PR2) and MinHook's HDE64 (PR1) — three decoders, three
owners, pins intact.
