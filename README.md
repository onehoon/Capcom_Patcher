# Capcom Patcher

Capcom Patcher is an OptiScaler-focused x64 ASI module that provides anti-tamper
**compatibility** for a small, explicit set of modern Capcom RE Engine games. Its
goal is to reproduce — as faithfully as practical — the anti-tamper mitigation
behavior that current [REFramework](https://github.com/praydog/REFramework)
applies to these games, so that OptiScaler and other injected code do not trigger
the delayed-crash / penalty paths in Capcom's anti-tamper.

This project is **not** a continuation of the generic OptiPatcher game-patching
catalog and does **not** aim to become a smaller REFramework (no overlay, no
scripting, no PAK/mod loader).

> **Status: experimental, under active development.**

## Supported games (release executables)

| Game | Executable |
|---|---|
| Monster Hunter Wilds | `MonsterHunterWilds.exe` |
| Dragon's Dogma 2 | `DD2.exe` |
| Resident Evil Requiem | `re9.exe` |
| PRAGMATA | `PRAGMATA.exe` |
| Onimusha: Way of the Sword | `OnimushaWotS.exe` |
| Monster Hunter Stories 3: Twisted Reflection | `MONSTER_HUNTER_STORIES_3_TWISTED_REFLECTION.exe` |

Executable matching is an explicit, case-insensitive allowlist. TDB version is
never used as an automatic opt-in for future Capcom games.

## What is implemented

- **PR0** — x64 C++20 ASI project (`CapcomPatcher.asi`), explicit six-game
  detector / profile table, the already-hardened `DbgUiRemoteBreakin` anti-debug
  watcher ported from `onehoon/OptiPatcher`
  (`b57408dc6efb7ae62229af028daef8f19caf2f66`), `InitializeASI()` export,
  `PatchResult()` kept `false`.
- **PR1** — the common REFramework runtime guards installed before any
  game-specific patch: pristine `NtProtectVirtualMemory` capture, the
  `VirtualProtect` / `NtProtectVirtualMemory` integrity guard,
  `AddVectoredExceptionHandler` registration guard, and `RtlExitUserProcess`
  guard. Ported from `praydog/REFramework`
  (`b6baf6b406efc65e077b99cb4d9ad25b0a0a9095`) using vendored MinHook (`98b74f1`).
  These apply to all six supported games. Note: the exit guard intentionally
  redirects supported-game process exit to `TerminateProcess`, matching current
  REFramework.
- **PR2** — the DD2-family direct anti-tamper core extracted from REFramework
  `IntegrityCheckBypass::immediate_patch_dd2()`: MHW-only QueryPerformance*
  scanner/crasher suppression (profile-gated), the renderer `createBLAS`
  corruption guard (all DD2-family profiles), and the DD2-family suspicious
  constant patch. Raw byte writes are revalidated and applied under a short
  thread-suspension window; the `createBLAS` inline hook reuses the PR1 MinHook
  wrapper. Scanning/patching primitives live in `src/memory/` (byte-scan shape
  from `onehoon/OptiPatcher@72e716b`, advanced helpers adapted from
  `cursey/kananlib@8c27b65` and decoding with the pinned
  `bitdefender/bddisasm@70db095` `NdDecodeEx` for full VEX/EVEX/XOP coverage).
  PAK/natives, RE9-family, heartbeat and
  stack-destroyer behavior are **not** included.
- **PR3** — the RE9-family scheduler/job corruption defense from REFramework
  `IntegrityCheckBypass::immediate_patch_re9()`: the RE9+/BushClover suspicious
  constant patch and the JobQueue callsite mid-hooks (all `re9Family` profiles —
  DD2/RE9/PRAGMATA/Onimusha/MHS3, never MHW), plus the RE9-only slow-path
  discriminator NOP. The mid-hooks validate the pending job function pointer,
  restore a cached legitimate pointer on UD2 corruption, or substitute a
  harmless `noop_job`. Uses vendored SafetyHook (`cursey/safetyhook@b046e123`)
  with its pinned Zydis v4.0.0 decoder; `memory::Scan` gains kananlib `*[N]`
  segment-glob support. PE-header integrity redirection, heartbeat,
  stack-destroyer and module-path layers are **not** included.

- **PR4** — the standalone renderer heartbeat bypass from REFramework
  `IntegrityCheckBypass::re9_heartbeat_bypass()`: discover the six renderer
  heartbeat/frame values with 3× structural confirmation (normal **and** early
  `heartbeat[0]==0` modes) and continuously synchronize them to the engine's real
  `via.render.Renderer.get_RenderFrame()` value. Profile-gated to the five
  modern-TDB games (DD2/RE9/PRAGMATA/Onimusha/MHS3 — never MHW). A minimal
  standalone RE Engine bridge (`src/reengine/`) resolves the VM context, the
  validated TDB **82/83** layout (explicit per-game, never `>= 82` auto-support),
  `via.render.Renderer` and the native `get_RenderFrame` function; no REFramework
  runtime dependency and **no DXGI/Present/swapchain hook**. A single
  process-lifetime worker started from `InitializeASI()` runs the state machine
  with bounded backoff; nothing is written before a unique cluster is confirmed,
  and confirmed clusters are sentinel/renderer-revalidated every sync. PE-header
  redirection, stack-destroyer and module-path layers are **not** included.

- **PR5** — the RE9-family PE-header integrity-check redirection from REFramework
  `IntegrityCheckBypass::immediate_patch_re9()` (PE-header section). Finds the
  validated integrity path via the `4C 89 ? 24 40 00 00 00 41 ?` anchor + the
  ordered `[+0x20] -> [+0x28] -> [rsp+0x90]` structural discriminator, proves the
  anchor / anchor+10 instruction boundaries, then emulates 15 instructions
  (vendored **BDShemu**, same bddisasm pin — analysis only, no game-memory
  writes) to learn which GPR receives the live image base and how many whole
  bytes to replace. It keeps a process-lifetime RW copy of the first PE-header
  page and rewrites the image-base computation with `movabs <that GPR>, <copy>`
  + NOPs, so the integrity reader sees the preserved header. Five `re9Family`
  games (never MHW), one-shot at startup, fail-closed (no candidate = no-op),
  committed through the PR2 `BytePatchCandidate` / thread-suspension path with
  full under-suspension revalidation. `src/memory/Emulation.*` adapts
  `cursey/kananlib@8c27b65` `utility::emulate`. Stack-destroyer and module-path
  layers are **not** included.

- **PR6** — the RE9-family "stack destroyer" mitigation from REFramework
  `IntegrityCheckBypass::remove_stack_destroyer()`. Scans the whole main image
  for the exact 18-byte routine (`mov [rcx],rdx` / `mov qword [rsp],0` /
  `add rsp,0x128`), decode-validates the three instructions with `bddisasm`,
  requires the hit to be a proven function entry, and — only when **exactly one**
  candidate survives (zero = no-op, more than one = fail-closed) — neutralizes it
  by writing a single `C3` (`RET`) at the entry via the PR2
  `BytePatchCandidate` / thread-suspension path with a pre-suspension uniqueness
  re-check and under-suspension revalidation of the full 18-byte context.
  Opt-in for all six explicit games (MHW included); one-shot at startup, no
  worker / hook / trampoline / allocation.
- **PR7** — module-path spoofing review / classification (documentation only, no
  production code). REFramework's `utility::spoof_module_paths_in_exe_dir()`
  (`cursey/kananlib@8c27b65`) rewrites `LDR_DATA_TABLE_ENTRY.FullDllName` for
  DLLs whose loader directory is the game executable directory, backed by a
  REFramework-owned copy into a game-local `_storage_`. The current OptiScaler
  fork (`onehoon/OptiScaler@3809b221`) loads `CapcomPatcher.asi` verbatim from
  its configured plugin subdirectory with all four path identities (disk /
  loader-input / `GetModuleFileNameW` / PEB) consistent and no relocation.
  Conclusion: **`INCONCLUSIVE`**, leaning `NOT_APPLICABLE` for the default
  topology; module-path spoofing stays deferred pending the runtime evidence
  named in
  [`doc/analysis/PR7_MODULE_PATH_SPOOFING_CLASSIFICATION_2026-09-09.md`](doc/analysis/PR7_MODULE_PATH_SPOOFING_CLASSIFICATION_2026-09-09.md).

**This does not yet provide full REFramework anti-tamper parity.** Module-path
spoofing is classified `INCONCLUSIVE` (deferred), and the six-game runtime
validation phase is still outstanding — see
[`doc/analysis/PR7_MODULE_PATH_SPOOFING_CLASSIFICATION_2026-09-09.md`](doc/analysis/PR7_MODULE_PATH_SPOOFING_CLASSIFICATION_2026-09-09.md)
and
[`doc/CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md`](doc/CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md).

## Build

Open `CapcomPatcher.sln` in Visual Studio 2022 (MSVC v143, Windows 10/11 SDK) and
build `x64 | Debug` or `x64 | Release`. Output: `CapcomPatcher.asi`.
All third-party code is vendored under `third_party/` — no submodule init.
The project is C++20; the vendored SafetyHook and `RE9FamilyBypass.cpp` are
compiled per-file with `/std:c++latest` (SafetyHook needs `std::expected`), so a
recent VS 2022 (17.3+) is required.

## License

MIT — see [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
