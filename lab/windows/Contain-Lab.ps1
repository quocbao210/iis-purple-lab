[CmdletBinding()]
param([switch]$Apply)
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state = Assert-OwnedIis
$current = (Get-WebAppPoolState $script:LabName).Value
$record = @{instance_id=$state.instance_id; action='stop-owned-app-pool'; previous_state=$current; timestamp=[DateTime]::UtcNow.ToString('o'); applied=[bool]$Apply}
if (-not $Apply) { $record | ConvertTo-Json; Write-Output 'Dry run. Collect evidence first; add -Apply to stop only the verified project pool.'; return }
$path = "$script:LabRoot\configuration\containment.json"
if (Test-Path -LiteralPath $path) { throw 'A containment record already exists. Resolve or roll back that operation first.' }
Write-LabJson $record $path
if ($current -eq 'Started') { Stop-WebAppPool $script:LabName }
Write-Output 'The dedicated pool is stopped. Existing process evidence may disappear; preserved bundles remain. Use Restore-Lab.ps1 for rollback.'
