[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SysmonPath,
    [switch]$AcceptSysmonEula,
    [switch]$DisposableVm,
    [Parameter(Mandatory)][string]$ComputerNameConfirmation
)
. "$PSScriptRoot\Common.ps1"
Assert-DisposableVm $DisposableVm $ComputerNameConfirmation
$state = Assert-OwnedIis
if (-not $AcceptSysmonEula) { throw 'Review the Microsoft Sysmon licence and pass -AcceptSysmonEula to install.' }
if (Get-Service -Name Sysmon,Sysmon64,SysmonDrv -ErrorAction SilentlyContinue) { throw 'Existing Sysmon installation found. Refusing to change non-owned telemetry; use a fresh VM.' }
$binary = (Resolve-Path -LiteralPath $SysmonPath).Path
Assert-NoReparse $binary
$signature = Get-AuthenticodeSignature -LiteralPath $binary
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Sysmon executable must have a valid Microsoft signature.' }
$version = (Get-Item -LiteralPath $binary).VersionInfo.FileVersion
if ($version -notmatch '^15\.22(?:\.|$)') { throw "This preview pins Sysmon 15.22; found $version. Review compatibility before changing the pin." }
Copy-Item -LiteralPath $binary -Destination "$script:LabRoot\tools\Sysmon64.exe"
Copy-Item -LiteralPath "$PSScriptRoot\sysmon.xml" -Destination "$script:LabRoot\configuration\sysmon.xml"
& "$script:LabRoot\tools\Sysmon64.exe" -accepteula -i "$script:LabRoot\configuration\sysmon.xml"
if ($LASTEXITCODE -ne 0) { throw "Sysmon installation failed ($LASTEXITCODE). Inspect actual service state before retrying." }
$installed = Get-CimInstance Win32_Service -Filter "Name='Sysmon64'"
if ($null -eq $installed) { throw 'Expected Sysmon64 service was not created.' }
$state.sysmon_owned = $true
$state | Add-Member NoteProperty sysmon_version $version -Force
$state | Add-Member NoteProperty sysmon_binary_sha256 (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -Force
$state | Add-Member NoteProperty sysmon_service_path $installed.PathName -Force
Write-LabJson $state "$script:LabRoot\ownership.json"
$dump = Get-SysmonConfiguration "$script:LabRoot\tools\Sysmon64.exe"
[IO.File]::WriteAllText("$script:LabRoot\configuration\sysmon-installed.txt", $dump, $script:Utf8)
Write-Output 'Sysmon installed. Event 3 is explicitly enabled. Run the capture workload and Test-Capture.ps1 to verify actual event delivery.'
