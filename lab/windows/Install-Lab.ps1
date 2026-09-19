[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PublishPath,
    [switch]$DisposableVm,
    [Parameter(Mandatory)][string]$ComputerNameConfirmation
)
. "$PSScriptRoot\Common.ps1"
Assert-DisposableVm $DisposableVm $ComputerNameConfirmation
Import-Module WebAdministration -ErrorAction Stop
if (Test-Path -LiteralPath $script:LabRoot) { throw 'C:\IISPurpleLab already exists. Refusing to overwrite it, even if it is empty.' }
if ((Test-Path "IIS:\Sites\$script:LabName") -or (Test-Path "IIS:\AppPools\$script:LabName")) { throw 'A conflicting IIS site or pool already exists.' }
if (Get-NetTCPConnection -LocalPort 5080 -State Listen -ErrorAction SilentlyContinue) { throw 'Port 5080 is already in use.' }
if (-not (Get-WebGlobalModule | Where-Object Name -eq 'AspNetCoreModuleV2')) { throw 'Install the .NET 10 Hosting Bundle after IIS, then rerun.' }
$publish = (Resolve-Path -LiteralPath $PublishPath).Path
Assert-NoReparse $publish
Get-NoReparseFiles $publish | Out-Null
foreach ($required in @('IisPurpleLab.dll','IisPurpleLab.exe','web.config')) {
    if (-not (Test-Path -LiteralPath (Join-Path $publish $required) -PathType Leaf)) { throw "Missing Windows publish artefact: $required" }
}
[xml]$config = Get-Content -LiteralPath (Join-Path $publish 'web.config') -Raw
$asp = $config.SelectSingleNode('//aspNetCore')
if ($null -eq $asp -or $asp.hostingModel -ine 'inprocess') { throw 'Publish output must explicitly use inprocess hosting.' }
$root = New-Item -ItemType Directory -Path $script:LabRoot
# Remove inherited broad write access before placing ownership metadata or code.
& icacls.exe $root.FullName /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE) { throw 'Failed to protect lab root ACL.' }
foreach ($folder in @('app','data','evidence','tools','configuration')) { New-Item -ItemType Directory -Path "$script:LabRoot\$folder" | Out-Null }
$state = [ordered]@{project=$script:LabName; root=$script:LabRoot; computer=$env:COMPUTERNAME; instance_id=[Guid]::NewGuid().ToString(); created_at=[DateTime]::UtcNow.ToString('o'); site_id=$null; stage='creating'; sysmon_owned=$false}
Write-LabJson $state "$script:LabRoot\ownership.json"
Copy-Item -Path (Join-Path $publish '*') -Destination "$script:LabRoot\app" -Recurse
$envNode = $asp.SelectSingleNode('environmentVariables')
if ($null -eq $envNode) { $envNode = $config.CreateElement('environmentVariables'); $asp.AppendChild($envNode) | Out-Null }
foreach ($entry in @{PurpleLab__DataRoot="$script:LabRoot\data"; PurpleLab__Vulnerable='false'; PurpleLab__Acknowledgement=''; ASPNETCORE_ENVIRONMENT='Production'}.GetEnumerator()) {
    $node = $envNode.SelectSingleNode("environmentVariable[@name='$($entry.Key)']")
    if ($null -eq $node) { $node = $config.CreateElement('environmentVariable'); $node.SetAttribute('name', $entry.Key); $envNode.AppendChild($node) | Out-Null }
    $node.SetAttribute('value', $entry.Value)
}
$config.Save("$script:LabRoot\app\web.config")
New-WebAppPool -Name $script:LabName | Out-Null
Set-ItemProperty "IIS:\AppPools\$script:LabName" -Name managedRuntimeVersion -Value ''
Set-ItemProperty "IIS:\AppPools\$script:LabName" -Name processModel.identityType -Value 4
Set-ItemProperty "IIS:\AppPools\$script:LabName" -Name enable32BitAppOnWin64 -Value $false
& icacls.exe $script:LabRoot /grant "IIS AppPool\${script:LabName}:(RX)" | Out-Null
if ($LASTEXITCODE) { throw 'Failed to grant root traversal.' }
& icacls.exe "$script:LabRoot\app" /grant "IIS AppPool\${script:LabName}:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE) { throw 'Failed to grant application read/execute permission.' }
& icacls.exe "$script:LabRoot\data" /grant "IIS AppPool\${script:LabName}:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE) { throw 'Failed to grant data directory Modify permission.' }
$site = New-Website -Name $script:LabName -PhysicalPath "$script:LabRoot\app" -ApplicationPool $script:LabName -IPAddress '127.0.0.1' -Port 5080
$state.site_id = [int]$site.id; $state.stage = 'installed'
Write-LabJson $state "$script:LabRoot\ownership.json"
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $script:LabName -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name userName -Value ''
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $script:LabName -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name enabled -Value $true
Set-ItemProperty "IIS:\Sites\$script:LabName" -Name logFile.directory -Value "$script:LabRoot\data\iis"
Set-ItemProperty "IIS:\Sites\$script:LabName" -Name logFile.logFormat -Value W3C
Set-ItemProperty "IIS:\Sites\$script:LabName" -Name logFile.logExtFileFlags -Value 'Date,Time,ClientIP,ServerIP,ServerPort,Method,UriStem,HttpStatus,HttpSubStatus,Win32Status,TimeTaken,ProtocolVersion'
Write-LabJson (Get-LabEnvironment) "$script:LabRoot\configuration\installation-environment.json"
Write-Output 'Installed hardened lab on http://127.0.0.1:5080. Run Test-Lab.ps1; no Windows validation result has been inferred from installation.'
