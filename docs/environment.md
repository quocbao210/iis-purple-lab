# Executed environment and version record

Inspection date: 2026-09-19. The starting workspace contained `Idea.txt` and two master briefs only; there was no git repository or applicable AGENTS.md in its ancestor path. Original user files are preserved. The expanded brief governs implementation.

| Component | Observed development state |
| --- | --- |
| Linux | Ubuntu 26.04 under WSL2, x64; kernel 6.18.33.2-microsoft-standard-WSL2. |
| Python | CPython 3.14.4; new isolated venv installation verified. |
| Python detection stack | pySigma 1.5.0, SQLite backend 1.2.4; dependencies in requirements.lock. |
| .NET | SDK 10.0.401; Microsoft.NETCore.App / ASP.NET Core 10.0.12; NuGet lock files verified. |
| Native host OS | Windows 11 Home Single Language, build 26200, used only for read-only preflight/static validation. |
| Native host PowerShell | Windows PowerShell 5.1.26100.9444. |
| IIS / Windows .NET10 / Sysmon | Required dedicated lab configuration unavailable; no native integration test executed. |
| Planned Sysmon | 15.22 pin; official signed binary not bundled or installed here. |
| Detection backend actually executed | SQLite 3.46.1 through Python sqlite3, in-memory database with pySigma-converted SELECT queries and explicit field/logsource mapping. |

The native host preflight found no IIS WebAdministration module, no Windows .NET10 runtime, no Sysmon channel, no elevated token and no readable Security channel. PowerShell operational channel presence alone was not counted as delivered scenario telemetry. Private preflight and raw .NET TRX files are gitignored; public validation summaries omit machine/account identifiers.

The SDK and temporary validation venv were installed outside the repository for development speed on WSL. The runbook supports ordinary fresh installs; no development path is required. Native setup records the actual edition/build, IIS/ANCM, runtimes, PowerShell and Sysmon details into each capture. It must be run before those versions can be reported as native-tested.
