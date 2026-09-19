[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$failures = New-Object 'System.Collections.Generic.List[string]'
$files = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File)
foreach ($file in $files) {
    $tokens = $null; $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    foreach ($error in @($errors)) { $failures.Add("$($file.Name):$($error.Extent.StartLineNumber): $($error.Message)") }
}
[xml]$sysmon = Get-Content -LiteralPath "$PSScriptRoot\sysmon.xml" -Raw
if ($sysmon.Sysmon.EventFiltering.RuleGroup[0].NetworkConnect.onmatch -ne 'exclude') { $failures.Add('Sysmon event 3 must be explicitly enabled.') }
if ($sysmon.Sysmon.EventFiltering.RuleGroup[0].ProcessCreate.onmatch -ne 'exclude') { $failures.Add('Process ancestry requires event 1.') }
. "$PSScriptRoot\Common.ps1"
# Handcrafted selector tests use the production ProcessGuid traversal, not real Windows captures.
$worker = 'C:\Windows\System32\inetsrv\w3wp.exe'
$processes = @(
    @{data=@{Image='C:\Windows\System32\whoami.exe'; CommandLine='whoami'; ProcessGuid='grandchild'; ParentProcessGuid='child'; ProcessId=12}},
    @{data=@{Image=$worker; CommandLine='w3wp -ap "IISPurpleLab-extra"'; ProcessGuid='foreign'; ParentProcessGuid='system'; ProcessId=8}},
    @{data=@{Image='C:\temp\inetsrv\w3wp.exe'; CommandLine='w3wp -ap IISPurpleLab'; ProcessGuid='spoof'; ParentProcessGuid='system'; ProcessId=9}},
    @{data=@{Image=$worker; CommandLine='w3wp -ap "IISPurpleLab" -v "v4.0"'; ProcessGuid='root'; ParentProcessGuid='system'; ProcessId=10}},
    @{data=@{Image='C:\Windows\System32\cmd.exe'; CommandLine='cmd'; ProcessGuid='child'; ParentProcessGuid='root'; ProcessId=11}},
    @{data=@{Image='C:\Windows\System32\cmd.exe'; CommandLine='cmd'; ProcessGuid='reused-pid'; ParentProcessGuid='foreign'; ProcessId=11}}
)
$chain = Get-LabProcessChain $processes $worker
if ($chain.Count -ne 3 -or -not $chain.ContainsKey('grandchild') -or $chain.ContainsKey('foreign') -or $chain.ContainsKey('spoof') -or $chain.ContainsKey('reused-pid')) { $failures.Add('ProcessGuid selection failed pool/image/PID-reuse/out-of-order isolation.') }
# Compile the fixed native audit interop definition without invoking its methods or changing policy.
if (-not ('PurpleLabAudit' -as [type])) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\Set-SupplementalAudit.ps1", [ref]$tokens, [ref]$errors)
    $definition = $ast.Find({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value.StartsWith('using System;')}, $true)
    if ($null -eq $definition) { $failures.Add('Native audit interop definition missing.') }
    else { Add-Type -TypeDefinition $definition.Value }
}
# Path tests are Windows-only because Linux interprets drive-letter paths differently.
$pathChecks = 'not run (non-Windows)'
if ($env:OS -eq 'Windows_NT') {
    foreach ($path in @('C:\','C:\Users','C:\IISPurpleLab2\data','C:\IISPurpleLab\..\Windows')) {
        $rejected = $false
        try { Assert-LabPath $path | Out-Null } catch { $rejected = $true }
        if (-not $rejected) { $failures.Add("Unsafe path accepted: $path") }
    }
    $pathChecks = 'four unsafe path cases rejected'
}
# These deliberately incomplete, temporary manifests are negative gate tests only.
# No IIS, process payload, event-log query or host-policy mutation is performed.
$captureFixture = Join-Path ([IO.Path]::GetTempPath()) ('iis-purple-capture-gate-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $captureFixture | Out-Null
try {
    $manifest = @{origin='native-windows'; sha256=@{}; source_status=@{
        application=@{status='available'}; iis=@{status='available'}; sysmon=@{status='available'}
    }}
    Write-LabJson $manifest (Join-Path $captureFixture 'manifest.json')
    foreach ($case in @('missing files','unhashed files')) {
        if ($case -eq 'unhashed files') {
            foreach ($name in @('application.jsonl','iis.log','sysmon.xml')) {
                [IO.File]::WriteAllText((Join-Path $captureFixture $name), '', $script:Utf8)
            }
        }
        $rejected = $false
        try { & "$PSScriptRoot\Test-Capture.ps1" -BundlePath $captureFixture | Out-Null }
        catch {
            if ($_.Exception.Message -notlike 'Native capture gate failed*') { throw }
            $rejected = $true
        }
        $result = Get-Content -LiteralPath (Join-Path $captureFixture 'validation.json') -Raw | ConvertFrom-Json
        $missingEvidence = @($result.checks | Where-Object {$_.name -like 'hashed evidence:*' -and -not $_.passed})
        if (-not $rejected -or $result.passed -or $missingEvidence.Count -ne 3) {
            $failures.Add("Native capture gate accepted $case or omitted required integrity checks.")
        }
    }
} finally {
    Assert-NoReparse $captureFixture
    Remove-Item -LiteralPath $captureFixture -Recurse -Force
}
if ($failures.Count) { throw ($failures -join [Environment]::NewLine) }
Write-Output "PASS: parsed $($files.Count) PowerShell files; compiled audit interop without invoking it; Sysmon XML event 1/3 configuration; handcrafted ProcessGuid selector isolation; $pathChecks; capture gate rejects missing/unhashed evidence. This is offline validation, not IIS or telemetry integration."
