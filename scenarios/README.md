# Bounded workloads

All HTTP targets are explicit loopback addresses/ports. Credentials are read from a generated local password file, never included in command arguments or report logs. Redirects and proxies are disabled. Native B/C and helper tests require `--disposable-vm`; shared CI uses mocked launches.

| Family | Preconditions and reproduction | Expected behavior / controls | Remediation and cleanup |
| --- | --- | --- | --- |
| A | Authenticated alice; `run.py --scenario A --mode vulnerable` plus password/output arguments below. | Cross-tenant ticket/attachment access succeeds only in vulnerable mode. Same tenant, sharing and app admin succeed in both. No new process required. | Repeat identical requests in hardened mode. Preserve app/IIS evidence; retire owned lab after collection. |
| B | Native disposable Windows, low-privilege IIS pool, explicit vulnerable mode; `--scenario B --disposable-vm`. | Fixed harmless identity demonstration crosses the report command boundary. App launch and actual Sysmon process must agree. Ordinary compiled helper is a benign control. | Same input denied in hardened mode; normal report/helper still succeeds. Preserve prevention evidence if execution is blocked. |
| C | Same primitive/permissions as B; `--scenario C --disposable-vm`. | Discovery, synthetic file stage and local receiver. Sender and receiver hashes must match; receiver startup is separate harness infrastructure. | Hardened identical input denied, no receiver receipt; this is not proof of prevention without healthy collection. Preserve dummy bytes/receipts before cleanup. |

Example for an already configured lab (repeat with `--mode hardened` after the documented mode switch):

```powershell
python scenarios/run.py --base-url http://127.0.0.1:5080 --password-file C:\IISPurpleLab\data\bootstrap-password.txt --scenario all --mode vulnerable --disposable-vm --output C:\IISPurpleLab\data\manual-run.json
```

The [Windows runbook](../docs/windows-runbook.md) supplies setup, mode switching, capture, collection, analysis and recoverable cleanup commands. Prefer its wrapper: collection must start before worker recycle to capture parent identity. Do not reinterpret manually launched administrator actions as exploit descendants.

Portable actual HTTP check after `dotnet build app/IisPurpleLab/IisPurpleLab.csproj`:

```bash
python scenarios/portable_check.py
python -m pytest scenarios/test_harness.py -q
```

This starts temporary Kestrel apps, exercises A in both modes plus hardened legitimate reads/managed exports, then terminates its own processes and removes temporary synthetic state. It never exercises host payloads or validates IIS. [Observed portable output](../reports/validation/portable-http.json) and [.NET tests](../app/IisPurpleLab.Tests/ApplicationTests.cs) are separate from pending native results.

Native limitation: supplied scripts have syntax/static validation, but no B/C native execution/capture has passed in this workspace. Reports must remain a portable preview until the full Windows gates pass.
