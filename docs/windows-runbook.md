# Native Windows runbook — portable preview

Native IIS integration has **not been executed** for this preview. The development host's read-only preflight on 19 September 2026 observed Windows 11 Home Single Language build 26200 and Windows PowerShell 5.1.26100.9444, without elevation, IIS WebAdministration, a .NET 10 Windows runtime, or a Sysmon channel. Security log access was denied. The Windows PowerShell operational channel existed; that is not a captured scenario or proof of script-block delivery. Windows PowerShell parsed all lab scripts and the static/path checks passed. No IIS, audit-policy, Sysmon, firewall, or endpoint-protection configuration was changed on that host.

Use a **dedicated disposable Windows Server 2022/2025 or Windows 11 Pro/Enterprise x64 VM**, with a snapshot and synthetic data only. Do not run setup or attack reproduction on the development workstation, a shared CI runner, or a production server. No inbound firewall exception is needed: IIS binds only `127.0.0.1:5080`, and the dummy receiver binds only `127.0.0.1:8099`. Keep endpoint protections enabled. A prevented child process is an observation to preserve, not a reason to weaken protections.

## 1. Prerequisites inside the VM

Use an elevated **Windows PowerShell 5.1** console. `WebAdministration` and the supplementary logging baseline target this engine. PowerShell 7 uses a different logging provider/channel and is outside the native baseline. Clone/copy the repository locally and change to its root.

Install Python 3.11+ from [python.org](https://www.python.org/downloads/windows/), the .NET SDK specified by `global.json`, and the matching .NET 10 Hosting Bundle from [Microsoft's .NET download page](https://dotnet.microsoft.com/en-us/download/dotnet/10.0). Install IIS **before** the Hosting Bundle; repair the bundle if IIS was enabled later. Restart the VM if the installers require it. Record actual installer versions/hashes with your capture notes; do not substitute these instructions for successful runtime checks.

On Windows Server, enable IIS and management scripting:

```powershell
Install-WindowsFeature Web-Server,Web-Http-Logging,Web-Scripting-Tools -IncludeManagementTools
```

On Windows 11 Pro/Enterprise, use:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-WebServer,IIS-CommonHttpFeatures,IIS-HttpErrors,IIS-HttpLogging,IIS-ManagementConsole,IIS-ManagementScriptingTools -All -NoRestart
```

Obtain **Sysmon 15.22** from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), extract it to a local tools directory, and review the vendor licence. The installer script checks the Microsoft Authenticode signature and the pinned file version. Sysmon 15.22's documented supported baseline includes Windows 11 and Server 2019 or newer. No vendor executable is bundled with this repository. If Microsoft's current download has advanced beyond the pinned version, obtain the approved version through your managed vendor tooling or review/update the pin deliberately; the script will not silently change versions.

```powershell
dotnet --info
python --version
.\lab\windows\Test-Scripts.ps1
.\lab\windows\Test-Lab.ps1
```

The first preflight may report absent Sysmon before installation. Preserve its output; channel presence alone is not a successful telemetry test.

## 2. Publish and install the hardened application

Publish **on Windows** so the framework-dependent apphost is `IisPurpleLab.exe`. The legitimate helper uses that executable. Do not copy a Linux publish directory into IIS.

```powershell
dotnet restore app\IisPurpleLab\IisPurpleLab.csproj --locked-mode
dotnet publish app\IisPurpleLab\IisPurpleLab.csproj -c Release --no-restore --self-contained false -o artifacts\publish
.\lab\windows\Install-Lab.ps1 -PublishPath .\artifacts\publish -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME
```

Setup refuses existing `C:\IISPurpleLab`, an existing `IISPurpleLab` site/pool, or port 5080 conflicts. It checks ANCM and explicit `hostingModel="inprocess"`, sets a dedicated `ApplicationPoolIdentity`, grants the pool read/execute on code and Modify only on lab data, and records resource ownership. The IIS identity is not an administrator. Setup does not switch off host protections or enable anonymous remote bindings.

The app generates synthetic `alice`, `bob`, and `admin` application accounts. Their shared generated lab password is kept in `C:\IISPurpleLab\data\bootstrap-password.txt`; pass its **file path**, never its contents, to the harness. Application `admin` is a role in the synthetic portal, not a Windows administrator.

Installation is intentionally not an overwrite/update tool. If a partial setup fails, preserve the error and inspect `C:\IISPurpleLab\ownership.json`. The normal removal command requires a fully matching site/pool; restore the VM snapshot after preserving evidence if installation failed before those resources existed.

## 3. Install and verify telemetry prerequisites

```powershell
.\lab\windows\Install-Telemetry.ps1 -SysmonPath C:\Tools\Sysmon64.exe -AcceptSysmonEula -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME
.\lab\windows\Set-SupplementalAudit.ps1 -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME
.\lab\windows\Set-SupplementalAudit.ps1 -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME -Apply
.\lab\windows\Test-Lab.ps1 -RequireInstalled -OutputPath C:\IISPurpleLab\configuration\preflight.json
```

`Install-Telemetry` refuses any pre-existing Sysmon service. Sysmon captures process creation/termination and network connections VM-wide so a previously unknown descendant remains discoverable; file-create events are restricted to `C:\IISPurpleLab\data\`. This increases local event volume. **The collector** limits exported endpoint evidence to the observed lab process chain and requested window; it does not export the whole endpoint event log.

`Set-SupplementalAudit` first defaults to a dry run. Applying it snapshots the process-creation audit flags and two registry values, then enables successful process creation, Security 4688 command-line capture, and Windows PowerShell script-block logging. It does not disable failure auditing. The restore path checks for later policy changes before restoring only those saved values. Existing domain policy can override these settings; actual event checks remain mandatory. The C scenario launches a fresh Windows PowerShell process, allowing its logging policy to take effect.

The installed preflight requires the HTTP health response to identify `w3wp`, a non-admin/non-SYSTEM token, and `IIS APPPOOL\IISPurpleLab`. It independently queries the OS-observed worker and owner. A configured in-process flag alone is insufficient.

## 4. Capture attack and legitimate workloads

```powershell
.\lab\windows\Invoke-Capture.ps1 -Mode vulnerable -RunName vulnerable-01 -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME -RequireSupplemental
.\lab\windows\Invoke-Capture.ps1 -Mode hardened -RunName hardened-01 -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME
```

These commands set the mode explicitly, start the collection window, recycle **only** the owned app pool, warm it up, verify native topology, and run benign/A/B/C harness checks. Capture starts before the recycle so Sysmon observes the actual worker `ProcessGuid` and start time needed for high-confidence attribution. Benign controls include legitimate shared/admin/same-tenant access, repeated requests, managed report generation, and concurrent helper exports. Mode changes deliberately recycle the worker; each harness session authenticates again.

A demonstrates cross-tenant access without requiring a new process. B interpolates a bounded harmless `whoami` demonstration through the vulnerable report shell boundary. C uses that same request primitive to launch Windows PowerShell, stage synthetic text, and send it to the local receiver. The receiver is harness infrastructure, and its startup is not an exploit-derived action. The hardened run repeats the same payloads and requires denial while legitimate workflows continue.

The wrapper waits 30 seconds for ordinary log buffering and then exports evidence. It does not forcibly flush all host HTTP logs. If IIS rows are still absent, preserve the failed bundle and recollect the same window into a **new** bundle after normal buffering completes. Do not overwrite an existing collection. A missing required Sysmon/PowerShell/Security event fails the gate; it is unknown visibility, not proof that an action was prevented.

The vulnerable gate requires actual Sysmon events 1, 3, and 11 from the selected chain, plus a captured pool-specific worker root. With `-RequireSupplemental`, it also requires selected Security/PowerShell events and nonempty Security command-line fields. The hardened run need not create attack-derived network or script events. These gates do not by themselves prove correct detections or remediation; the harness outcomes, analysis links, process tree, artefact hashes, and both mode results must also be reviewed.

To run one scenario separately:

```powershell
python scenarios\run.py --base-url http://127.0.0.1:5080 --password-file C:\IISPurpleLab\data\bootstrap-password.txt --scenario A --mode hardened --output C:\IISPurpleLab\data\manual-A.json
```

Native B/C and benign helper execution additionally require `--disposable-vm`. Never represent a separately launched administrator command as a descendant of the web exploit.

## 5. Collect manually and analyse

Manual collection is read-only with respect to the sources, but creates a private evidence bundle under the owned root. It needs elevation to read the selected Security/operational channels and process metadata. It does not clear logs, stop processes, disable protections, or package credentials/SQLite data.

```powershell
$captureStart = [DateTimeOffset]::UtcNow
# Recycle the owned lab pool, warm up, and run the requested workload here.
$captureEnd = [DateTimeOffset]::UtcNow
.\lab\windows\Collect-Evidence.ps1 -StartUtc $captureStart -EndUtc $captureEnd -BundleName manual-01
.\lab\windows\Test-Capture.ps1 -BundlePath C:\IISPurpleLab\evidence\manual-01
```

Use the same Python analysis entry point as the portable demo:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.\.venv\Scripts\iis-purple.exe analyze --dataset C:\IISPurpleLab\evidence\vulnerable-01 --output C:\IISPurpleLab\evidence\analysis-vulnerable-01
.\.venv\Scripts\iis-purple.exe analyze --dataset C:\IISPurpleLab\evidence\hardened-01 --output C:\IISPurpleLab\evidence\analysis-hardened-01
```

A native collection contains `manifest.json`, application JSONL, dynamic-header IIS W3C rows, original selected Windows event XML, configuration, source-line references, and hashes. Receiver bytes are included only when their SHA-256 matches their receipt. Scenario outcome JSON remains outside the detector input manifest, under `configuration/`.

Review the collector's `source_status` before interpreting absent alerts. If no pool root was seen within the default 60-minute lookback, the collector does not guess from `w3wp` children or timestamps. Run a new capture beginning before a worker recycle. The maximum history lookback is two hours and the requested activity window is limited to four hours; bounded queries fail rather than silently truncate above 100,000 events per channel query.

Keep original bundles private. `manifest.json` declares `native-windows` origin and collection conditions; a sanitised derivative needs its own manifest, original hash links, and redaction notes. The web.config snapshot redacts environment settings named like credentials. IIS query strings, cookies, and request headers are not enabled in this project's log configuration. Event command lines and script blocks can still contain sensitive text, so review before sharing. Hashes support later integrity checks; they cannot establish that a compromised source originally told the truth.

## 6. Containment, rollback, and recoverable cleanup

Collect first. Containment stops only the verified owned pool, defaults to a dry run, and saves its prior state:

```powershell
.\lab\windows\Contain-Lab.ps1
.\lab\windows\Contain-Lab.ps1 -Apply
.\lab\windows\Restore-Lab.ps1
.\lab\windows\Restore-Lab.ps1 -Apply
```

Repeat health/benign checks after rollback. To retire the lab:

```powershell
.\lab\windows\Set-SupplementalAudit.ps1 -Restore
.\lab\windows\Set-SupplementalAudit.ps1 -Restore -Apply
.\lab\windows\Remove-Lab.ps1 -RemoveOwnedSysmon
.\lab\windows\Remove-Lab.ps1 -RemoveOwnedSysmon -Apply
```

Removal refuses changed ownership, foreign pool consumers, reparse points, an unrestored audit snapshot, a changed Sysmon executable, or a changed Sysmon configuration. It removes the named site/pool and optionally the Sysmon installation created by this project, then **moves** lab files to `C:\IISPurpleLab-retired-<instance-id>`. Evidence remains recoverable there. It leaves IIS/.NET prerequisites installed. Revert the VM snapshot for complete environment cleanup after securely preserving the wanted evidence. No generic process-name kill, host isolation, firewall rewrite, or recursive deletion of a user workspace is implemented.

## Required evidence before a validated Windows release

1. Passing installed preflight with actual Windows edition/build, IIS/ANCM/.NET/PowerShell/Sysmon versions and observed low-privilege `w3wp` identity.
2. Vulnerable and hardened harness outputs from identical A/B/C payloads plus benign/concurrent controls; preserve prevention/failure details.
3. Original relevant event 1/3/11 XML, configured 4688 command lines and Windows PowerShell script-block records; document actual fragment completeness and all missing sources.
4. App launch to native child correlation, observed parent `ProcessGuid`, PID reuse/concurrency review, and explicit ambiguity where prerequisites are missing.
5. Dummy transfer receipt and stored-byte hashes matched to staged data; no exfiltration claim from a connection alone.
6. Analysis/evaluation output and evidence-linked investigations generated from these native bundles, kept separate from handcrafted fixture results.
7. Attack denial and successful legitimate behaviour in hardened mode, then a containment/rollback exercise and verified recoverable cleanup.

These are pending native gates, not commands already reported as passed. Consult [the telemetry matrix](telemetry.md) for field-level limits and references.
