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

**This does not yet provide full REFramework anti-tamper parity.** The remaining
layers — DD2-family and RE9-family bypasses, JobQueue fallback, renderer
heartbeat, stack-destroyer scan, module-path spoofing — are deferred to later
PRs as described in
[`doc/CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md`](doc/CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md).

## Build

Open `CapcomPatcher.sln` in Visual Studio 2022 (MSVC v143, Windows 10/11 SDK) and
build `x64 | Debug` or `x64 | Release`. Output: `CapcomPatcher.asi`.
MinHook is vendored under `third_party/minhook/`; no submodule init is required.

## License

MIT — see [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
