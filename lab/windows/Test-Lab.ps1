[CmdletBinding()]
param([switch]$RequireInstalled, [string]$OutputPath)
. "$PSScriptRoot\Common.ps1"
Assert-NativeWindows
$checks = New-Object 'System.Collections.Generic.List[object]'
function Add-Check([string]$Name, [bool]$Passed, $Observed) { $checks.Add(@{name=$Name; passed=$Passed; observed=$Observed}) }
$environment = Get-LabEnvironment
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Add-Check 'elevated' ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) $environment.collector_identity
$iisModule = Get-Module -ListAvailable WebAdministration
Add-Check 'IIS WebAdministration' ($null -ne $iisModule) @($iisModule | Select-Object Name,Version)
Add-Check '.NET 10 runtime' (@($environment.dotnet_runtimes | Where-Object { $_ -match '^Microsoft.AspNetCore.App 10\.' }).Count -gt 0) $environment.dotnet_runtimes
foreach ($channel in @('Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational','Security')) {
    try { $log = Get-WinEvent -ListLog $channel -ErrorAction Stop; Add-Check $channel ([bool]$log.IsEnabled) @{enabled=$log.IsEnabled; record_count=$log.RecordCount} }
    catch { Add-Check $channel $false @{status='unavailable'; reason=$_.Exception.Message} }
}
if ($RequireInstalled) {
    try {
        $state = Assert-OwnedIis
        Add-Check 'owned IIS pool and loopback binding' $true $state.instance_id
        [xml]$config = Get-Content -LiteralPath "$script:LabRoot\app\web.config" -Raw
        Add-Check 'in-process configuration' ($config.SelectSingleNode('//aspNetCore').hostingModel -ieq 'inprocess') $config.SelectSingleNode('//aspNetCore').hostingModel
        $health = Invoke-RestMethod 'http://127.0.0.1:5080/health' -TimeoutSec 15
        Add-Check 'actual in-process topology' ($health.process_name -ieq 'w3wp') $health
        Add-Check 'actual low-privilege identity' (-not $health.is_admin -and -not $health.is_system -and $health.windows_identity -ieq "IIS APPPOOL\$script:LabName") $health.windows_identity
        $worker = Get-CimInstance Win32_Process -Filter "ProcessId=$($health.process_id)"
        $owner = Invoke-CimMethod -InputObject $worker -MethodName GetOwner
        Add-Check 'OS-observed worker identity' ($owner.Domain -ieq 'IIS APPPOOL' -and $owner.User -ceq $script:LabName -and $worker.Name -ieq 'w3wp.exe') @{owner="$($owner.Domain)\$($owner.User)"; pid=$worker.ProcessId; image=$worker.ExecutablePath; command_line=$worker.CommandLine}
    } catch { Add-Check 'installed lab verification' $false $_.Exception.Message }
}
$result = @{kind='native-read-only-preflight'; collected_at=[DateTime]::UtcNow.ToString('o'); environment=$environment; checks=$checks.ToArray(); passed=(@($checks | Where-Object {-not $_.passed}).Count -eq 0); limitation='Channel presence is not a test event. Run capture and Test-Capture.ps1 to verify actual provider/events and topology.'}
if ($OutputPath) { Write-LabJson $result $OutputPath }
$result | ConvertTo-Json -Depth 15
if ($RequireInstalled -and -not $result.passed) { throw 'Native preflight failed. Preserve the result and resolve prerequisites before capture.' }
