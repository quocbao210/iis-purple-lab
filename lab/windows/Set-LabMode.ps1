[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hardened','vulnerable')][string]$Mode,
    [switch]$DisposableVm,
    [Parameter(Mandatory)][string]$ComputerNameConfirmation
)
. "$PSScriptRoot\Common.ps1"
Assert-DisposableVm $DisposableVm $ComputerNameConfirmation
$state = Assert-OwnedIis
$path = Assert-LabPath "$script:LabRoot\app\web.config"
[xml]$config = Get-Content -LiteralPath $path -Raw
$envNode = $config.SelectSingleNode('//aspNetCore/environmentVariables')
if ($null -eq $envNode) { throw 'Expected project environment settings are missing.' }
$envNode.SelectSingleNode("environmentVariable[@name='PurpleLab__Vulnerable']").SetAttribute('value', $(if ($Mode -eq 'vulnerable') { 'true' } else { 'false' }))
$envNode.SelectSingleNode("environmentVariable[@name='PurpleLab__Acknowledgement']").SetAttribute('value', $(if ($Mode -eq 'vulnerable') { 'I_ACCEPT_DISPOSABLE_LOCAL_LAB' } else { '' }))
$config.Save($path)
Restart-WebAppPool $script:LabName
Write-Output "Lab mode set to $Mode; worker recycle requested. Verify /health before reproduction."
