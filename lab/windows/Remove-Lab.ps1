[CmdletBinding()]
param([switch]$Apply, [switch]$RemoveOwnedSysmon)
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state = Assert-OwnedIis
$archive = "C:\IISPurpleLab-retired-$($state.instance_id)"
if (Test-Path -LiteralPath $archive) { throw 'Retirement destination already exists.' }
if (Test-Path -LiteralPath "$script:LabRoot\configuration\supplemental-audit.json") { throw 'Restore supplementary audit settings with Set-SupplementalAudit.ps1 -Restore -Apply before retirement.' }
if ($RemoveOwnedSysmon) {
    if (-not $state.sysmon_owned) { throw 'Sysmon was not installed by this lab.' }
    $service = Get-CimInstance Win32_Service -Filter "Name='Sysmon64'"
    $binary = Assert-LabPath "$script:LabRoot\tools\Sysmon64.exe"
    if ($null -eq $service -or $service.PathName -cne $state.sysmon_service_path -or (Get-FileHash -LiteralPath $binary).Hash -ine $state.sysmon_binary_sha256) { throw 'Sysmon ownership has changed.' }
    $serviceBinary = $service.PathName.Trim('"')
    if (-not (Test-Path -LiteralPath $serviceBinary -PathType Leaf) -or (Get-FileHash -LiteralPath $serviceBinary).Hash -ine $state.sysmon_binary_sha256) { throw 'Installed Sysmon executable hash no longer matches the owned version.' }
    $dump = Get-SysmonConfiguration $binary
    if ($dump -cne (Get-Content -LiteralPath "$script:LabRoot\configuration\sysmon-installed.txt" -Raw).Trim()) { throw 'Sysmon configuration changed since installation; refusing to uninstall.' }
}
if (-not $Apply) { Write-Output "Dry run: remove verified site and pool; move C:\IISPurpleLab to $archive (evidence retained). Remove owned Sysmon: $([bool]$RemoveOwnedSysmon)."; return }
Stop-Website $script:LabName
if ((Get-WebAppPoolState $script:LabName).Value -eq 'Started') { Stop-WebAppPool $script:LabName }
Remove-Website $script:LabName
Remove-WebAppPool $script:LabName
if ($RemoveOwnedSysmon) {
    & $binary -u
    if ($LASTEXITCODE -ne 0) { throw 'Sysmon uninstall failed; lab directory and evidence retained for manual inspection.' }
}
Move-Item -LiteralPath $script:LabRoot -Destination $archive
Write-Output "Removed only the owned IIS site/pool. Lab files and evidence can be recovered from $archive. IIS/.NET prerequisites remain installed; revert the VM snapshot for full environment cleanup."
