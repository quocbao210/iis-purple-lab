[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hardened','vulnerable')][string]$Mode,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_-]{0,50}$')][string]$RunName,
    [string]$Python = 'python',
    [switch]$DisposableVm,
    [Parameter(Mandatory)][string]$ComputerNameConfirmation,
    [switch]$RequireSupplemental
)
. "$PSScriptRoot\Common.ps1"
Assert-DisposableVm $DisposableVm $ComputerNameConfirmation
$state = Assert-OwnedIis
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$run = Assert-LabPath "$script:LabRoot\data\runs\$RunName"
if (Test-Path -LiteralPath $run) { throw 'Run path exists; choose a fresh run name.' }
New-Item -ItemType Directory -Path $run -Force | Out-Null
& "$PSScriptRoot\Set-LabMode.ps1" -Mode $Mode -DisposableVm -ComputerNameConfirmation $ComputerNameConfirmation
# Start before a dedicated worker recycle so its native ProcessGuid root is retained.
$start = [DateTimeOffset]::UtcNow.AddSeconds(-1)
Restart-WebAppPool $script:LabName
$ready = $false
for ($attempt=0; $attempt -lt 20; $attempt++) {
    try { $health = Invoke-RestMethod 'http://127.0.0.1:5080/health' -TimeoutSec 3; if ($health.mode -eq $Mode) { $ready=$true; break } } catch { }
    Start-Sleep -Milliseconds 500
}
if (-not $ready) { throw 'Lab did not become healthy in requested mode.' }
& "$PSScriptRoot\Test-Lab.ps1" -RequireInstalled -OutputPath "$run\preflight.json"
$failures = New-Object 'System.Collections.Generic.List[string]'
foreach ($scenario in @('benign','A','B','C')) {
    & $Python "$repo\scenarios\run.py" --base-url http://127.0.0.1:5080 --password-file "$script:LabRoot\data\bootstrap-password.txt" --scenario $scenario --mode $Mode --disposable-vm --output "$run\$scenario.json"
    if ($LASTEXITCODE -ne 0) { $failures.Add("$scenario exited $LASTEXITCODE") }
}
# Native command requests a log flush but is host-wide: do not invoke it here. Wait for normal IIS buffering instead.
Write-Output 'Waiting 30 seconds for ordinary IIS/Event Log buffering; this is not a live latency measurement.'
Start-Sleep -Seconds 30
$end = [DateTimeOffset]::UtcNow
$bundle = & "$PSScriptRoot\Collect-Evidence.ps1" -StartUtc $start -EndUtc $end -BundleName $RunName -ScenarioDirectory $run
& "$PSScriptRoot\Test-Capture.ps1" -BundlePath $bundle -RequireFollowOn:($Mode -eq 'vulnerable') -RequireSupplemental:$RequireSupplemental
if ($failures.Count) { throw "Scenario checks failed; preserved bundle: $bundle. $($failures -join '; ')" }
Write-Output "Collected $bundle. Analyse this native dataset with the same Python pipeline used for fixtures; keep the hardened/vulnerable bundles separate."
