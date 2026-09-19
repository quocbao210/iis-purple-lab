# Application access policy

Only a cookie created by a successful server-side login establishes an actor. Users and password hashes are stored in SQLite; generated synthetic credentials live outside source code. The `X-Actor`/tenant headers do not establish identity. Each request receives a fresh server-generated request ID. A supplied request ID is not trusted as identity or attribution.

| Operation | Allowed in hardened mode |
| --- | --- |
| Read ticket or its attachment | Same tenant, explicitly shared with actor's tenant, or application admin. |
| List tickets | Only tickets satisfying the same policy. |
| Generate/download report | Same ticket policy; export IDs do not replace resource authorization. |
| Ordinary report title | 1–60 ASCII letters/digits/spaces/underscore/hyphen. Managed CSV generation. |
| Optional compiled export helper | Same title policy; fixed executable and separate argument list, generated output path. |
| Login/logout/report mutation | Loopback request; required custom request header plus SameSite Strict cookie and no permissive CORS. |

Synthetic accounts: alice in north, bob in south, admin with the application admin role. Tickets: 1001 north private; 2001 south private; 2002 south shared with north. Attachment 1 belongs to south ticket 2001. Application admin does not grant Windows administrative privileges.

Hardened is the default. `PurpleLab:Vulnerable=true` additionally requires the exact local acknowledgement specified in `LabSettings.Read`. That teaching configuration deliberately bypasses object authorization and interpolates report input into a Windows shell command. It is confined to the disposable loopback VM. The policy decision is still logged independently so detection can compare observed success with intended authorization.

See [application source](../app/IisPurpleLab/Domain.cs), [route enforcement](../app/IisPurpleLab/Program.cs), [report boundary](../app/IisPurpleLab/Reports.cs), and [executed tests](../app/IisPurpleLab.Tests/ApplicationTests.cs). The [portable HTTP check](../scenarios/portable_check.py) performs real login/access/fix requests without native execution.

Limits: intentionally small lab authentication, shared generated bootstrap password for synthetic accounts, loopback HTTP rather than production TLS, no password-reset/lockout/MFA workflow. Do not deploy this teaching app as a public customer service.
