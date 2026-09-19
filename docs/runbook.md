# Fresh-checkout runbook

Release: portable preview. Use this sequence from the repository root. [Fresh-copy verification evidence](../reports/validation/fresh-checkout.json) records the actual development-platform execution. [Hosted CI passed](https://github.com/quocbao210/iis-purple-lab/actions/runs/35430608975) for Python replay on Linux, Windows and macOS, plus the application and PowerShell static jobs. This does not validate native IIS installation or telemetry.

## Portable dependencies, replay and evaluation

Install Python 3.11+ (tested 3.14.4). On Linux/macOS:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m iis_purple demo --dataset datasets/fixtures/heldout --output artifacts/demo
python -m iis_purple evaluate --dataset datasets/fixtures/development --output artifacts/development
python -m iis_purple evaluate --dataset datasets/fixtures/heldout --output artifacts/evaluation
python -m pytest tests scenarios/test_harness.py -q
```

On Windows, replace activation with `.\.venv\Scripts\Activate.ps1`, or invoke `.\.venv\Scripts\python.exe` directly without changing execution policy. Python also needs internet access for the initial dependency install. SQLite comes with Python; the actual pySigma SQLite backend is pinned in the lock file.

Open `artifacts/demo/report.html` locally. The corresponding Markdown, normalized records, alerts, correlations, originals, effective policy, source manifest, rule snapshots and integrity manifest are in the same bundle. `artifacts/evaluation/evaluation.md` and JSON expose four-view metrics, individual case verdicts, prerequisites and comparison. `null` precision means no alerts, not zero precision. Do not equate these handcrafted fixture numbers with native Windows performance.

Example analysis of a different exported bundle:

```bash
python -m iis_purple analyze --dataset path/to/bundle --output artifacts/investigation
python -m iis_purple analyze --dataset path/to/bundle --sources sysmon security powershell --output artifacts/windows-only
```

Inputs and outputs must be separate directories. Native `manifest.json` must identify raw sources and hashes. A deployment at a different data root needs a reviewed `--policy path/to/policy.json`. Never include labels in detection policy. Source files are removed before parsing in reduced views.

## Application tests and actual portable HTTP

Install SDK 10.0.401 from [Microsoft](https://dotnet.microsoft.com/en-us/download/dotnet/10.0). `global.json` fixes the SDK, and NuGet lock files fix application/test dependencies.

```bash
dotnet restore app/IisPurpleLab.Tests/IisPurpleLab.Tests.csproj --locked-mode
dotnet test app/IisPurpleLab.Tests/IisPurpleLab.Tests.csproj --no-restore
python scenarios/portable_check.py --output artifacts/portable-http.json
```

The .NET suite mocks all host launches. The second command's build supplies the DLL used by `portable_check.py`, which starts temporary loopback Kestrel applications and checks real cookie-authenticated A requests in both modes plus hardened legitimate workflows. It does not execute the native B/C payloads or helper. Optional `--dotnet` selects a non-PATH SDK host; `--dll` selects another build output.

## Native Windows sequence

Inside the disposable Windows VM, follow [the complete Windows runbook](windows-runbook.md), including official IIS/Hosting Bundle/Sysmon prerequisites, snapshots, exact privileges and telemetry limits. The core command sequence is:

```powershell
.\lab\windows\Test-Scripts.ps1
.\lab\windows\Test-Lab.ps1
dotnet restore app\IisPurpleLab\IisPurpleLab.csproj --locked-mode
dotnet publish app\IisPurpleLab\IisPurpleLab.csproj -c Release --no-restore --self-contained false -o artifacts\publish
.\lab\windows\Install-Lab.ps1 -PublishPath .\artifacts\publish -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME
.\lab\windows\Install-Telemetry.ps1 -SysmonPath C:\Tools\Sysmon64.exe -AcceptSysmonEula -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME
.\lab\windows\Set-SupplementalAudit.ps1 -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME -Apply
.\lab\windows\Invoke-Capture.ps1 -Mode vulnerable -RunName vulnerable-01 -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME -RequireSupplemental
.\lab\windows\Invoke-Capture.ps1 -Mode hardened -RunName hardened-01 -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME
python -m iis_purple analyze --dataset C:\IISPurpleLab\evidence\vulnerable-01 --output C:\IISPurpleLab\evidence\analysis-vulnerable-01
python -m iis_purple analyze --dataset C:\IISPurpleLab\evidence\hardened-01 --output C:\IISPurpleLab\evidence\analysis-hardened-01
```

Capture wraps the bounded legitimate/A/B/C harness, starts before worker recycle, collects scoped originals, and tests actual event delivery. Review both scenario outcomes and correlation confidence. For a native four-view evaluation, create an evaluation-only ground-truth manifest from the captured scenario outcomes and exact raw references; do not feed the fixture labels to native data. Cases can share background worker context but must have disjoint labelled request/action records. The [evaluation schema example](../datasets/fixtures/heldout/ground_truth.json) defines its format.

## Preserve, contain, restore, retire

After preserving bundles, optional containment/rollback targets only the verified pool and defaults to dry run:

```powershell
.\lab\windows\Contain-Lab.ps1
.\lab\windows\Contain-Lab.ps1 -Apply
.\lab\windows\Restore-Lab.ps1 -Apply
.\lab\windows\Set-SupplementalAudit.ps1 -Restore -Apply
.\lab\windows\Remove-Lab.ps1 -RemoveOwnedSysmon
.\lab\windows\Remove-Lab.ps1 -RemoveOwnedSysmon -Apply
```

Removal retires data into a recoverable directory and leaves platform prerequisites installed. Revert the VM snapshot after preserving wanted evidence. Portable generated reports are under `artifacts/`; remove only your specific generated run directories if no longer needed. No repository publication is performed by these commands.
