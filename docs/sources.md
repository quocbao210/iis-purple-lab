# Primary sources consulted

Checked 2026-09-19. These support implementation choices, not claims of successful native validation.

- [Microsoft IIS in-process hosting](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/in-process-hosting?view=aspnetcore-10.0): baseline worker topology and hosting model.
- [Microsoft .NET 10 download](https://dotnet.microsoft.com/en-us/download/dotnet/10.0): supported SDK/runtime acquisition; no vendor installers are bundled.
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): ProcessGuid, event 1 creation, event 3 explicitly enabled networking, event 11 file creation/overwrite.
- [Microsoft Security 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688): event versions, hexadecimal PIDs and separate command-line policy.
- [PowerShell Windows logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows): channel/engine differences.
- [OWASP logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): application context, sanitisation and secrets.
- [OWASP API1:2023](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/): object-level authorisation.
- [SigmaHQ SQLite backend](https://github.com/SigmaHQ/pySigma-backend-sqlite): real pySigma conversion and SQLite query execution.
- [MITRE T1059.003](https://attack.mitre.org/techniques/T1059/003/): Windows command shell behaviour; native proof still required.

Rules and fixture datasets in this repository are original lab implementations, AI-assisted. Third-party libraries retain their upstream licences. ATT&CK references are classifications, not proof of a new vulnerability, real intrusion, or public-facing deployment. This loopback lab does not establish T1190 in production and does not implement a web shell/T1505.003.
