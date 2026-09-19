[CmdletBinding()]
param([switch]$Restore, [switch]$Apply, [switch]$DisposableVm, [string]$ComputerNameConfirmation)
. "$PSScriptRoot\Common.ps1"
Assert-Administrator
$state = Assert-OwnedIis
if (-not $Restore) { Assert-DisposableVm $DisposableVm $ComputerNameConfirmation }
# Native APIs address the process-creation subcategory by GUID, avoiding localised auditpol text.
if (-not ('PurpleLabAudit' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class PurpleLabAudit {
    [StructLayout(LayoutKind.Sequential)] public struct Info { public Guid Subcategory; public uint Flags; public Guid Category; }
    [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.U1)] static extern bool AuditQuerySystemPolicy(Guid[] ids, uint count, out IntPtr result);
    [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.U1)] static extern bool AuditSetSystemPolicy(Info[] info, uint count);
    [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
    [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct Privileges { public uint Count; public Luid Id; public uint Attributes; }
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string system, string name, out Luid id);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref Privileges next, uint length, out Privileges previous, out uint required);
    public static Info Get() {
        IntPtr p;
        if (!AuditQuerySystemPolicy(new[]{new Guid("0CCE922B-69AE-11D9-BED3-505054503030")},1,out p)) throw new Win32Exception();
        try { return (Info)Marshal.PtrToStructure(p,typeof(Info)); } finally { AuditFree(p); }
    }
    public static void Set(uint flags) {
        // Zero means UNCHANGED to AuditSetSystemPolicy; restore an observed no-audit state with explicit NONE.
        if (flags==0) flags=4;
        if (flags>4) throw new ArgumentOutOfRangeException("flags");
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(),0x28,out token)) throw new Win32Exception();
        Privileges previous = new Privileges(); bool adjusted=false;
        try {
            Luid luid; if (!LookupPrivilegeValue(null,"SeSecurityPrivilege",out luid)) throw new Win32Exception();
            var next=new Privileges { Count=1, Id=luid, Attributes=2 }; uint required;
            if (!AdjustTokenPrivileges(token,false,ref next,(uint)Marshal.SizeOf(typeof(Privileges)),out previous,out required)) throw new Win32Exception();
            if (Marshal.GetLastWin32Error()==1300) throw new Win32Exception(1300);
            adjusted=true;
            var info=Get(); info.Flags=flags;
            if (!AuditSetSystemPolicy(new[]{info},1)) throw new Win32Exception();
        } finally {
            if (adjusted) { Privileges unused; uint required; AdjustTokenPrivileges(token,false,ref previous,(uint)Marshal.SizeOf(typeof(Privileges)),out unused,out required); }
            CloseHandle(token);
        }
    }
}
'@
}
$path = "$script:LabRoot\configuration\supplemental-audit.json"
$settings = @(
    @{path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; name='ProcessCreationIncludeCmdLine_Enabled'; value=1},
    @{path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; name='EnableScriptBlockLogging'; value=1}
)
if ($Restore) {
    $saved = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($saved.instance_id -cne $state.instance_id) { throw 'Audit snapshot does not belong to this lab.' }
    if ([PurpleLabAudit]::Get().Flags -ne $saved.applied_audit_flags) { throw 'Process-creation audit policy changed since setup; refusing to overwrite later changes.' }
    foreach ($setting in $saved.settings) {
        $current = Get-ItemPropertyValue -LiteralPath $setting.path -Name $setting.name -ErrorAction Stop
        if ($current -ne 1) { throw "Setting $($setting.name) changed; refusing to overwrite later changes." }
    }
    if (-not $Apply) { Write-Output 'Dry run: restore only saved process-creation audit flags and two registry values. Other policies and registry keys remain.'; return }
    [PurpleLabAudit]::Set([uint32]$saved.previous_audit_flags)
    foreach ($setting in $saved.settings) {
        if ($setting.existed) { Set-ItemProperty -LiteralPath $setting.path -Name $setting.name -Value $setting.previous -Type DWord }
        else { Remove-ItemProperty -LiteralPath $setting.path -Name $setting.name }
    }
    Move-Item -LiteralPath $path -Destination "$script:LabRoot\configuration\supplemental-audit-restored-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')).json"
    Write-Output 'Prior settings restored. Existing event records remain; a VM snapshot rollback is the full cleanup path.'
} else {
    if (Test-Path -LiteralPath $path) { throw 'A supplementary audit snapshot already exists.' }
    $previous = [PurpleLabAudit]::Get().Flags
    # Success=1, Failure=2, None=4. Enabling success removes NONE and preserves failure auditing.
    $applied = ($previous -band 2) -bor 1
    $records = @($settings | ForEach-Object {
        $value = Get-ItemProperty -LiteralPath $_.path -Name $_.name -ErrorAction SilentlyContinue
        @{path=$_.path; name=$_.name; existed=($null -ne $value); previous=$(if ($value) {$value.($_.name)} else {$null})}
    })
    if (-not $Apply) { Write-Output 'Dry run: enable successful process creation, Security 4688 command lines, and Windows PowerShell 5.1 script-block logging. Logs may contain sensitive command/script values.'; return }
    Write-LabJson @{instance_id=$state.instance_id; collected_at=[DateTime]::UtcNow.ToString('o'); previous_audit_flags=$previous; applied_audit_flags=$applied; settings=$records} $path
    [PurpleLabAudit]::Set([uint32]$applied)
    foreach ($setting in $settings) {
        if (-not (Test-Path -LiteralPath $setting.path)) { New-Item -Path $setting.path -Force | Out-Null }
        New-ItemProperty -LiteralPath $setting.path -Name $setting.name -Value 1 -PropertyType DWord -Force | Out-Null
    }
    Write-Output 'Supplementary policies configured. Run a fresh Windows PowerShell process via scenario C; require actual 4688/4104 events before declaring validation.'
}
