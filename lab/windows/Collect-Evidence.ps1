[CmdletBinding()]
param(
    [Parameter(Mandatory)][DateTimeOffset]$StartUtc,
    [Parameter(Mandatory)][DateTimeOffset]$EndUtc,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_-]{0,70}$')][string]$BundleName,
    [ValidateRange(1,120)][int]$AncestorLookbackMinutes = 60,
    [string]$ScenarioDirectory
)
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state = Assert-OwnedIis
$start = $StartUtc.UtcDateTime; $end = $EndUtc.UtcDateTime
if ($end -le $start -or ($end - $start).TotalHours -gt 4 -or $end -gt [DateTime]::UtcNow.AddSeconds(5)) { throw 'Provide a completed UTC collection window of no more than four hours.' }
$bundle = Assert-LabPath "$script:LabRoot\evidence\$BundleName"
if (Test-Path -LiteralPath $bundle) { throw 'Evidence directory already exists; refusing to overwrite.' }
New-Item -ItemType Directory -Path $bundle | Out-Null
New-Item -ItemType Directory -Path "$bundle\configuration" | Out-Null
$sources = New-Object 'System.Collections.Generic.List[object]'
$availability = [ordered]@{}
$references = New-Object 'System.Collections.Generic.List[object]'
$warnings = New-Object 'System.Collections.Generic.List[string]'
function Add-Source([string]$Name, [string]$Source, [string]$Format) {
    $path = Join-Path $bundle $Name
    $sources.Add([ordered]@{path=$Name; source=$Source; format=$Format; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); bytes=(Get-Item -LiteralPath $path).Length})
}

# Application records are original UTF-8 lines, selected by event time. Never include bootstrap secrets or SQLite customer contents.
$appPath = Assert-LabPath "$script:LabRoot\data\events\application.jsonl"
$appCount = 0
if (Test-Path -LiteralPath $appPath) {
    $writer = New-Object IO.StreamWriter("$bundle\application.jsonl", $false, $script:Utf8)
    try {
        $lineNumber = 0
        foreach ($line in Read-BoundedLines $appPath) {
            $lineNumber++
            if (-not $line.Trim()) { continue }
            $record = $line | ConvertFrom-Json
            $time = [DateTimeOffset]::Parse($record.timestamp, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
            if ($time -ge $start -and $time -le $end) {
                $writer.WriteLine($line); $appCount++
                $references.Add(@{output='application.jsonl'; output_line=$appCount; original_path=$appPath; original_line=$lineNumber})
            }
        }
    } finally { $writer.Dispose() }
    Add-Source 'application.jsonl' 'application' 'jsonl'
    $availability.application = @{status=$(if ($appCount) {'available'} else {'no_events_in_window'}); selected_count=$appCount}
} else { $availability.application = @{status='unavailable'; reason='Application log does not exist.'} }

# Event 1 roots must be genuine workers for this named pool. Root events may predate the requested window.
$sysmon = @(); $selectedSysmon = @(); $chain = @{}; $processes = @()
try {
    $sysmon = @(Get-BoundedEvents 'Microsoft-Windows-Sysmon/Operational' @(1,3,5,11) $start.AddMinutes(-$AncestorLookbackMinutes) $end)
    $processes = @($sysmon | Where-Object Id -eq 1 | ForEach-Object { @{event=$_; data=(Get-EventDataMap $_)} })
    $chain = Get-LabProcessChain $processes (Join-Path $env:windir 'System32\inetsrv\w3wp.exe')
    $selectedSysmon = @($sysmon | Where-Object {
        $d = Get-EventDataMap $_
        $chain.ContainsKey($d.ProcessGuid) -and ($_.Id -eq 1 -or $_.TimeCreated.ToUniversalTime() -ge $start)
    } | Sort-Object TimeCreated,RecordId)
    Write-EventXml $selectedSysmon "$bundle\sysmon.xml"
    Add-Source 'sysmon.xml' 'sysmon' 'event_xml'
    $availability.sysmon = @{status=$(if ($selectedSysmon.Count) {'available'} else {'no_project_chain_observed'}); selected_count=$selectedSysmon.Count; roots_and_descendants=$chain.Count; required_ids=@(1,3,11); observed_ids=@($selectedSysmon | Select-Object -ExpandProperty Id -Unique)}
    if (-not $chain.Count) { $warnings.Add('No verified pool process root in bounded Sysmon history. Endpoint evidence is unavailable for attribution; absence is not proof of no host activity. Recycle the owned pool before a new capture.') }
} catch { $availability.sysmon = @{status='unavailable'; reason=$_.Exception.Message}; $warnings.Add('Sysmon selection failed; no endpoint completeness claim is valid.') }

# Supplementary channels are PID/time candidate selection only, never promoted to ProcessGuid attribution.
function Test-ChainPid([string]$ProcessIdText, [DateTime]$Time) {
    if (-not $ProcessIdText) { return $false }
    try { $number = if ($ProcessIdText.StartsWith('0x')) { [Convert]::ToInt64($ProcessIdText.Substring(2),16) } else { [long]$ProcessIdText } } catch { return $false }
    foreach ($process in $chain.Values) {
        if ([long]$process.data.ProcessId -eq $number -and $process.event.TimeCreated.ToUniversalTime() -le $Time) {
            # Bound PID lifetimes by the next observed process creation with the same PID (including unrelated processes).
            $reused = @($processes | Where-Object { [long]$_.data.ProcessId -eq $number -and $_.event.TimeCreated -gt $process.event.TimeCreated -and $_.event.TimeCreated.ToUniversalTime() -le $Time })
            if (-not $reused.Count) { return $true }
        }
    }
    return $false
}
foreach ($spec in @(
    @{source='security'; channel='Security'; ids=@(4688)},
    @{source='powershell'; channel='Microsoft-Windows-PowerShell/Operational'; ids=@(4103,4104)}
)) {
    try {
        $events = @(Get-BoundedEvents $spec.channel $spec.ids $start $end)
        $selected = @($events | Where-Object {
            if ($spec.source -eq 'security') {
                $d = Get-EventDataMap $_
                (Test-ChainPid $d.NewProcessId $_.TimeCreated.ToUniversalTime()) -or (Test-ChainPid $d.ProcessId $_.TimeCreated.ToUniversalTime())
            } else {
                [xml]$x = $_.ToXml()
                Test-ChainPid $x.Event.System.Execution.ProcessID $_.TimeCreated.ToUniversalTime()
            }
        } | Sort-Object TimeCreated,RecordId)
        Write-EventXml $selected "$bundle\$($spec.source).xml"
        Add-Source "$($spec.source).xml" $spec.source 'event_xml'
        $availability[$spec.source] = @{status=$(if ($selected.Count) {'available'} else {'no_selected_events'}); selected_count=$selected.Count; scope='PID/time candidates, supplementary only'}
    } catch { $availability[$spec.source] = @{status='unavailable'; reason=$_.Exception.Message} }
}

# Read only the dedicated site's actual W3C files; retain dynamic #Fields and original selected rows.
$iisDirectory = Assert-LabPath "$script:LabRoot\data\iis\W3SVC$($state.site_id)"
$iisCount = 0; $outLine = 0
$iisStart = $start.AddTicks(-($start.Ticks % [TimeSpan]::TicksPerSecond))
$writer = New-Object IO.StreamWriter("$bundle\iis.log", $false, $script:Utf8)
try {
    if (Test-Path -LiteralPath $iisDirectory) {
        foreach ($file in Get-ChildItem -LiteralPath $iisDirectory -Filter '*.log' -File | Sort-Object Name) {
            Assert-NoReparse $file.FullName
            $fields = @(); $lineNumber = 0
            foreach ($line in Read-BoundedLines $file.FullName) {
                $lineNumber++
                if ($line.StartsWith('#Fields:')) { $fields = $line.Substring(8).Trim() -split '\s+'; $writer.WriteLine($line); $outLine++; continue }
                if ($line.StartsWith('#') -or -not $line.Trim()) { continue }
                if (-not ($fields -contains 'date') -or -not ($fields -contains 'time')) { throw 'IIS log lacks date/time #Fields; cannot scope safely.' }
                $values = $line -split '\s+'
                if ($values.Count -ne $fields.Count) { throw "Malformed IIS row in $($file.FullName):$lineNumber" }
                $time = [DateTimeOffset]::Parse(($values[[Array]::IndexOf($fields,'date')] + 'T' + $values[[Array]::IndexOf($fields,'time')] + 'Z')).UtcDateTime
                if ($time -ge $iisStart -and $time -le $end) {
                    $writer.WriteLine($line); $iisCount++; $outLine++
                    if ($iisCount -gt 250000 -or $writer.BaseStream.Length -gt 64MB) { throw 'Combined selected IIS output exceeds 250,000 records or 64 MiB.' }
                    $references.Add(@{output='iis.log'; output_line=$outLine; original_path=$file.FullName; original_line=$lineNumber})
                }
            }
        }
    }
} finally { $writer.Dispose() }
Add-Source 'iis.log' 'iis' 'w3c'
$availability.iis = @{status=$(if ($iisCount) {'available'} else {'no_events_in_window'}); selected_count=$iisCount; site_id=$state.site_id; note='IIS timestamps have one-second precision; start is rounded down to a second. Buffering can delay visibility; recollect into a NEW bundle if missing.'}

if ($ScenarioDirectory) {
    $scenario = Assert-LabPath $ScenarioDirectory
    $receipts = Join-Path $scenario 'receiver\receipts.jsonl'
    if (Test-Path -LiteralPath $receipts) {
        Assert-NoReparse $receipts
        Copy-Item -LiteralPath $receipts -Destination "$bundle\sink.jsonl"
        Add-Source 'sink.jsonl' 'sink' 'jsonl'
        New-Item -ItemType Directory -Path "$bundle\receiver" | Out-Null
        foreach ($receiptLine in Read-BoundedLines $receipts) {
            $receipt = $receiptLine | ConvertFrom-Json
            if ($receipt.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $receipt.artifact -cne ($receipt.sha256 + '.bin')) { throw 'Receiver receipt has an invalid artefact name/hash.' }
            $artefact = Assert-LabPath (Join-Path (Join-Path $scenario 'receiver') $receipt.artifact)
            if ((Get-Item -LiteralPath $artefact).Length -gt 4096) { throw 'Receiver artefact exceeds the harness 4096-byte bound.' }
            if ((Get-FileHash -LiteralPath $artefact -Algorithm SHA256).Hash -ine $receipt.sha256) { throw 'Receiver bytes do not match their receipt hash.' }
            Copy-Item -LiteralPath $artefact -Destination (Join-Path "$bundle\receiver" $receipt.artifact)
        }
    }
    # Evaluation observations stay outside detector input files.
    foreach ($result in Get-ChildItem -LiteralPath $scenario -Filter '*.json' -File) {
        Assert-NoReparse $result.FullName
        Copy-Item -LiteralPath $result.FullName -Destination "$bundle\configuration\scenario-$($result.Name)"
    }
}

$hashes = @()
foreach ($subdir in @('work','exports')) {
    $path = Assert-LabPath "$script:LabRoot\data\$subdir"
    if (Test-Path -LiteralPath $path) {
        foreach ($file in Get-NoReparseFiles $path) {
            Assert-NoReparse $file.FullName
            if ($file.LastWriteTimeUtc -lt $start -or $file.LastWriteTimeUtc -gt $end) { continue }
            $hashes += @{path=$file.FullName; size=$file.Length; last_write_utc=$file.LastWriteTimeUtc.ToString('o'); sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
    }
}
Write-LabJson $hashes "$bundle\artefact-hashes.json"
Write-LabJson $references.ToArray() "$bundle\source-references.json"
Copy-Item -LiteralPath "$script:LabRoot\ownership.json" -Destination "$bundle\configuration\ownership.json"
[xml]$savedConfig = Get-Content -LiteralPath "$script:LabRoot\app\web.config" -Raw
foreach ($entry in $savedConfig.SelectNodes('//environmentVariable')) {
    if ($entry.GetAttribute('name') -match '(?i)password|secret|token|credential|connectionstring') { $entry.SetAttribute('value','[REDACTED]') }
}
$savedConfig.Save("$bundle\configuration\web.config")
foreach ($name in @('sysmon.xml','sysmon-installed.txt','supplemental-audit.json')) {
    $path = "$script:LabRoot\configuration\$name"
    if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination "$bundle\configuration\$name" }
}
$pool = Get-Item "IIS:\AppPools\$script:LabName"
Write-LabJson @{name=$script:LabName; identity_type=$pool.processModel.identityType.ToString(); managed_runtime=$pool.managedRuntimeVersion; bitness32=$pool.enable32BitAppOnWin64; binding='127.0.0.1:5080:'; data_acl=(Get-Acl "$script:LabRoot\data").Sddl; code_acl=(Get-Acl "$script:LabRoot\app").Sddl} "$bundle\configuration\iis.json"
$live = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'w3wp.exe' -and $_.CommandLine -match '(?i)-ap\s+"?IISPurpleLab"?(?:\s|$)' } | ForEach-Object {
    $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
    @{pid=$_.ProcessId; parent_pid=$_.ParentProcessId; image=$_.ExecutablePath; creation_time=$_.CreationDate.ToUniversalTime().ToString('o'); owner="$($owner.Domain)\$($owner.User)"; command_line=$_.CommandLine}
})
Write-LabJson $live "$bundle\configuration\live-workers.json"
$environment = Get-LabEnvironment
$environment.sysmon = $(if ($state.sysmon_owned) {$state.sysmon_version} else {'not installed by this project'})
$allHashes = @{}
foreach ($file in Get-NoReparseFiles $bundle) {
    $relative = $file.FullName.Substring($bundle.Length+1).Replace('\','/')
    $allHashes[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifest = [ordered]@{
    schema_version=1; origin='native-windows'; collected_at=[DateTime]::UtcNow.ToString('o'); sanitization='none; original selected records, private local evidence; review before sharing'
    collection=@{start_utc=$start.ToString('o'); end_utc=$end.ToString('o'); ancestor_lookback_minutes=$AncestorLookbackMinutes; site=$script:LabName; pool=$script:LabName; process_selection='Sysmon ProcessGuid ancestry from pool-specific w3wp command line; supplementary Security/PowerShell PID-time candidates'}
    environment=$environment; files=$sources.ToArray(); sha256=$allHashes; source_status=$availability; warnings=$warnings.ToArray()
    collector=@{version='0.1.0'; collect_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant(); common_sha256=(Get-FileHash -LiteralPath "$PSScriptRoot\Common.ps1" -Algorithm SHA256).Hash.ToLowerInvariant(); configuration_redaction='web.config environment values whose names mention password, secret, token, credential or connectionstring are replaced with [REDACTED]'}
    limitations=@('Hashes protect later integrity comparisons, not truthfulness of a compromised source.','No raw EVTX is manufactured; original selected event XML is preserved.','No file-read conclusion follows from file creation.','Collector is a manual export; elapsed replay time is not live detection latency.','PowerShell 7 channel is not collected by this Windows PowerShell 5.1 baseline.','Finite ancestor lookback can omit older workers; missing roots fail attribution.')
}
Write-LabJson $manifest "$bundle\manifest.json"
Write-Output $bundle
