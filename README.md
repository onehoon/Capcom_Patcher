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

## What PR0 implements

PR0 is the bootstrap slice only:

- x64 C++20 ASI project that builds to `CapcomPatcher.asi`
- explicit six-game detector / profile table
- the already-hardened `DbgUiRemoteBreakin` anti-debug watcher, ported from
  `onehoon/OptiPatcher` (pinned commit `b57408dc6efb7ae62229af028daef8f19caf2f66`)
- `InitializeASI()` export; `PatchResult()` kept semantically `false`

**PR0 does not provide full REFramework anti-tamper parity.** The remaining
layers — pristine syscall / VirtualProtect / VEH / exit guards, DD2-family and
RE9-family bypasses, JobQueue fallback, renderer heartbeat, stack-destroyer
scan — are deferred to later PRs as described in
[`doc/CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md`](doc/CAPCOM_PATCHER_ARCHITECTURE_AND_REF_ANTITAMPER_PARITY_PLAN_2026-09-09.md).

## Build

Open `CapcomPatcher.sln` in Visual Studio 2022 (MSVC v143, Windows 10/11 SDK) and
build `x64 | Debug` or `x64 | Release`. Output: `CapcomPatcher.asi`.

## License

MIT — see [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
