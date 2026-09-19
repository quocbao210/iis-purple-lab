[CmdletBinding()]
param([Parameter(Mandatory)][string]$BundlePath, [switch]$RequireFollowOn, [switch]$RequireSupplemental)
. "$PSScriptRoot\Common.ps1"
$bundle = (Resolve-Path -LiteralPath $BundlePath).Path
Assert-NoReparse $bundle
Assert-NoReparse (Join-Path $bundle 'manifest.json')
if ((Get-Item -LiteralPath (Join-Path $bundle 'manifest.json')).Length -gt 1MB) { throw 'Manifest exceeds 1 MiB.' }
$manifest = Get-Content -LiteralPath (Join-Path $bundle 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.origin -cne 'native-windows') { throw 'This gate requires an actual native-windows collection, not fixtures or derivatives.' }
$checks = New-Object 'System.Collections.Generic.List[object]'
function Add-Check([string]$Name, [bool]$Passed, $Observed) { $checks.Add(@{name=$Name; passed=$Passed; observed=$Observed}) }
foreach ($file in $manifest.sha256.PSObject.Properties) {
    $path = [IO.Path]::GetFullPath((Join-Path $bundle $file.Name))
    if (-not $path.StartsWith(($bundle + [IO.Path]::DirectorySeparatorChar),[StringComparison]::OrdinalIgnoreCase)) { throw 'Manifest path escapes the evidence bundle.' }
    Assert-NoReparse $path
    if ((Get-Item -LiteralPath $path).Length -gt 64MB) { throw "Evidence file exceeds the supported 64 MiB bound: $path" }
    Add-Check "integrity:$($file.Name)" ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ieq $file.Value) $file.Value
}
foreach ($source in @('application','iis','sysmon')) {
    Add-Check "records:$source" ($manifest.source_status.$source.status -eq 'available') $manifest.source_status.$source
}
# Do not trust availability metadata when the actual source file or its integrity entry is absent.
# Every file read below must first pass the same path and size checks as the manifest inventory.
$requiredFiles = @('application.jsonl','iis.log','sysmon.xml')
if ($RequireSupplemental) { $requiredFiles += @('security.xml','powershell.xml') }
foreach ($name in $requiredFiles) {
    $path = Join-Path $bundle $name
    Assert-NoReparse $path
    $listed = $null -ne $manifest.sha256.PSObject.Properties[$name]
    $exists = Test-Path -LiteralPath $path -PathType Leaf
    Add-Check "hashed evidence:$name" ($listed -and $exists) @{listed=$listed; exists=$exists}
    if ($exists -and (Get-Item -LiteralPath $path).Length -gt 64MB) { throw "Evidence file exceeds the supported 64 MiB bound: $path" }
}
$sysPath = Join-Path $bundle 'sysmon.xml'
if ((Test-Path -LiteralPath $sysPath -PathType Leaf) -and $null -ne $manifest.sha256.PSObject.Properties['sysmon.xml']) {
    [xml]$events = Get-Content -LiteralPath $sysPath -Raw
    $nativeEvents = @($events.Events.Event)
    foreach ($eventId in $(if ($RequireFollowOn) {@(1,3,11)} else {@(1)})) {
        $matched = @($nativeEvents | Where-Object { $_.System.Provider.Name -ceq 'Microsoft-Windows-Sysmon' -and [int]$_.System.EventID -eq $eventId })
        Add-Check "actual Sysmon event $eventId" ($matched.Count -gt 0) $matched.Count
    }
    $roots = @($nativeEvents | Where-Object { [int]$_.System.EventID -eq 1 } | Where-Object {
        $data = @{}; foreach ($node in $_.EventData.Data) {$data[$node.Name]=$node.InnerText}
        $data.Image -match '(?i)\\inetsrv\\w3wp\.exe$' -and $data.CommandLine -match '(?i)-ap\s+"?IISPurpleLab"?(?:\s|$)'
    })
    Add-Check 'captured pool-specific w3wp root' ($roots.Count -gt 0) $roots.Count
}
if ($RequireSupplemental) {
    foreach ($source in @('security','powershell')) { Add-Check "actual $source events" ($manifest.source_status.$source.status -eq 'available') $manifest.source_status.$source }
    $securityPath = Join-Path $bundle 'security.xml'
    if ((Test-Path -LiteralPath $securityPath -PathType Leaf) -and $null -ne $manifest.sha256.PSObject.Properties['security.xml']) {
        [xml]$security = Get-Content -LiteralPath $securityPath -Raw
        $commandLines = @($security.SelectNodes("//*[local-name()='Data' and @Name='CommandLine']") | Where-Object {$_.InnerText})
        Add-Check '4688 command lines present' ($commandLines.Count -gt 0) $commandLines.Count
    }
}
$result = @{kind='native-capture-gate'; collected_at=[DateTime]::UtcNow.ToString('o'); bundle=$bundle; passed=(@($checks | Where-Object {-not $_.passed}).Count -eq 0); checks=$checks.ToArray(); limitation='Event delivery/integrity gate only; inspect analysis correlation, receiver hashes, scenario outcomes, and hardened retests separately.'}
$validationPath = Join-Path $bundle 'validation.json'
Assert-NoReparse $validationPath
Write-LabJson $result $validationPath
$result | ConvertTo-Json -Depth 15
if (-not $result.passed) { throw 'Native capture gate failed; missing telemetry is unknown, not prevention or a passed test.' }
