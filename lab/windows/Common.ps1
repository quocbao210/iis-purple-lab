Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:LabRoot = 'C:\IISPurpleLab'
$script:LabName = 'IISPurpleLab'
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-LabJson($Value, [string]$Path) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 30), $script:Utf8)
}
function Assert-NativeWindows {
    if ($env:OS -ne 'Windows_NT') { throw 'Run this command in native Windows PowerShell on the disposable Windows VM.' }
}
function Assert-Administrator {
    Assert-NativeWindows
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'An elevated PowerShell session is required.' }
}
function Assert-DisposableVm([switch]$Acknowledged, [string]$ComputerNameConfirmation) {
    Assert-Administrator
    if (-not $Acknowledged -or $ComputerNameConfirmation -cne $env:COMPUTERNAME) {
        throw 'Use -DisposableVm -ComputerNameConfirmation $env:COMPUTERNAME only inside your dedicated disposable VM after taking a snapshot.'
    }
}
function Assert-NoReparse([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse point: $current" }
        }
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
}
function Assert-LabPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith(($script:LabRoot + '\'), [StringComparison]::OrdinalIgnoreCase)) { throw "Path is outside the fixed lab root: $Path" }
    Assert-NoReparse $full
    return $full
}
function Get-NoReparseFiles([string]$Path) {
    Assert-NoReparse $Path
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($Path)
    $seen = 0
    while ($pending.Count) {
        $directory = $pending.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            $seen++
            if ($seen -gt 100000) { throw 'Directory entry limit exceeded; refusing unbounded traversal.' }
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse point: $($item.FullName)" }
            if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) } else { $item }
        }
    }
}
function Read-BoundedLines([string]$Path) {
    Assert-NoReparse $Path
    if ((Get-Item -LiteralPath $Path).Length -gt 64MB) { throw "Input exceeds 64 MiB: $Path" }
    $count = 0; $bytes = 0
    foreach ($line in [IO.File]::ReadLines($Path)) {
        $count++
        if ($count -gt 250000) { throw "Input exceeds 250,000 lines: $Path" }
        $lineBytes = [Text.Encoding]::UTF8.GetByteCount($line)
        $bytes += $lineBytes + 1
        if ($lineBytes -gt 1MB) { throw "Input line exceeds 1 MiB: $Path line $count" }
        if ($bytes -gt 64MB) { throw "Growing input exceeds 64 MiB: $Path" }
        $line
    }
}
function Get-SysmonConfiguration([string]$Binary) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Binary; $info.Arguments = '-c'; $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true; $info.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($info)
    try {
        $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) { throw 'Sysmon configuration query timed out; inspect that process before retrying.' }
        if ($process.ExitCode -ne 0) { throw "Sysmon configuration query failed: $($process.ExitCode)" }
        return ($out.GetAwaiter().GetResult() + $err.GetAwaiter().GetResult()).Trim()
    } finally { $process.Dispose() }
}
function Get-LabState {
    Assert-NativeWindows
    Assert-NoReparse $script:LabRoot
    $path = Join-Path $script:LabRoot 'ownership.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'No project ownership manifest; refusing mutation or collection.' }
    $state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($state.project -cne $script:LabName -or $state.root -cne $script:LabRoot -or $state.computer -cne $env:COMPUTERNAME -or $state.instance_id -notmatch '^[a-f0-9-]{36}$') {
        throw 'Ownership manifest does not identify this lab and computer.'
    }
    return $state
}
function Assert-OwnedIis {
    $state = Get-LabState
    Import-Module WebAdministration -ErrorAction Stop
    $site = Get-Website -Name $script:LabName
    if ($null -eq $site -or $site.physicalPath -ine "$script:LabRoot\app" -or [int]$site.id -ne [int]$state.site_id -or $site.applicationPool -cne $script:LabName) {
        throw 'IIS site ownership or physical path changed; refusing.'
    }
    $bindings = @($site.bindings.Collection)
    if ($bindings.Count -ne 1 -or $bindings[0].protocol -ne 'http' -or $bindings[0].bindingInformation -ne '127.0.0.1:5080:') { throw 'Lab binding changed; expected loopback only.' }
    $pool = Get-Item "IIS:\AppPools\$script:LabName"
    if ([int]$pool.processModel.identityType -ne 4) { throw 'Lab pool is not using ApplicationPoolIdentity.' }
    $consumers = @(Get-Website | Where-Object { $_.applicationPool -eq $script:LabName -and $_.Name -ne $script:LabName })
    $applications = @(Get-WebApplication | Where-Object { $_.applicationPool -eq $script:LabName })
    if ($consumers.Count -or $applications.Count) { throw 'Other IIS resources use this pool; refusing to affect them.' }
    return $state
}
function Get-LabEnvironment {
    $os = Get-CimInstance Win32_OperatingSystem
    $dotnet = Get-Command dotnet.exe -ErrorAction SilentlyContinue
    $runtimes = @()
    if ($dotnet) { $runtimes = @(& $dotnet.Source --list-runtimes) }
    $iis = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue
    [ordered]@{
        computer = $env:COMPUTERNAME; os_caption = $os.Caption; os_version = $os.Version; os_build = $os.BuildNumber
        powershell = $PSVersionTable.PSVersion.ToString(); powershell_edition = $PSVersionTable.PSEdition
        dotnet_runtimes = $runtimes; iis_version = $(if ($iis) { $iis.VersionString } else { $null })
        collector_identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        collected_at = [DateTime]::UtcNow.ToString('o')
    }
}
function Get-EventDataMap($Event) {
    [xml]$xml = $Event.ToXml()
    $fields = @{}
    foreach ($node in @($xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']"))) { $fields[$node.GetAttribute('Name')] = $node.InnerText }
    return $fields
}
function Get-LabProcessChain($Processes, [string]$WorkerImage) {
    if (-not $WorkerImage) { throw 'An explicit OS worker image path is required.' }
    $chain = @{}
    foreach ($process in $Processes) {
        $d = $process.data
        if ($d.Image -ieq $WorkerImage -and $d.CommandLine -match '(?i)(?:^|\s)-ap\s+"?IISPurpleLab"?(?:\s|$)') { $chain[$d.ProcessGuid] = $process }
    }
    do {
        $changed = $false
        foreach ($process in $Processes) {
            $d = $process.data
            if ($d.ProcessGuid -and $d.ParentProcessGuid -and -not $chain.ContainsKey($d.ProcessGuid) -and $chain.ContainsKey($d.ParentProcessGuid)) { $chain[$d.ProcessGuid] = $process; $changed = $true }
        }
    } while ($changed)
    return $chain
}
function Write-EventXml($Events, [string]$Path) {
    $writer = New-Object IO.StreamWriter($Path, $false, $script:Utf8)
    try {
        $writer.WriteLine('<Events>')
        $bytes = 0
        foreach ($event in @($Events)) {
            $xml = $event.ToXml(); $length = [Text.Encoding]::UTF8.GetByteCount($xml)
            $bytes += $length + 1
            if ($length -gt 1MB -or $bytes -gt (64MB - 100)) { throw 'Selected event XML exceeds the parser 1 MiB/event or 64 MiB/file limits. Shorten the collection window.' }
            $writer.WriteLine($xml)
        }
        $writer.WriteLine('</Events>')
    } finally { $writer.Dispose() }
}
function Get-BoundedEvents([string]$Channel, [int[]]$Ids, [DateTime]$Start, [DateTime]$End, [int]$Limit = 100000) {
    $queryErrors = @()
    $events = @(Get-WinEvent -FilterHashtable @{LogName=$Channel; Id=$Ids; StartTime=$Start; EndTime=$End} -MaxEvents ($Limit + 1) -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
    $unexpected = @($queryErrors | Where-Object { $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' })
    if ($unexpected.Count) { throw $unexpected[0] }
    if ($events.Count -gt $Limit) { throw "Event limit exceeded in $Channel. Shorten collection window; no silent truncation is allowed." }
    return $events
}
