[CmdletBinding()]
param([switch]$Apply)
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state = Assert-OwnedIis
$path = "$script:LabRoot\configuration\containment.json"
$record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
if ($record.instance_id -cne $state.instance_id -or $record.action -cne 'stop-owned-app-pool') { throw 'Containment record does not belong to this lab.' }
if (-not $Apply) { Write-Output "Dry run: restore original app-pool state '$($record.previous_state)' for $script:LabName."; return }
if ($record.previous_state -eq 'Started') { Start-WebAppPool $script:LabName }
$archived = "$script:LabRoot\configuration\containment-restored-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')).json"
Move-Item -LiteralPath $path -Destination $archived
Write-Output 'Previous pool state restored. Verify /health and rerun the benign workload.'
