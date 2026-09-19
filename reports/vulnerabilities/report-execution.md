# IPL-VULN-002: report data crosses a command boundary

This is an intentionally introduced CWE-78 teaching flaw. The implementation and mocked launch boundary were tested; **native command execution, its Windows telemetry and its remediation retest remain pending** on a disposable VM. No observed Windows process tree is claimed from a unit test.

Root cause: vulnerable report generation constructs `cmd.exe /d /c echo ...` with a title interpolated into the command text. Windows shell metacharacters can become control syntax. This violates the intended separation between report data and operating-system instructions.

Prerequisites: real authenticated access to the report's synthetic ticket, explicit acknowledged vulnerable mode, native Windows and the application's ordinary process-creation permission. The dedicated pool is not Administrator or SYSTEM. Native B/C use fixed harmless local demonstrations; they do not need privilege elevation. Endpoint protection remains enabled; a blocked launch must be preserved as prevention evidence.

Impact proven offline: [the launch seam test](../../app/IisPurpleLab.Tests/ApplicationTests.cs) observes the same request input reaching the shell argument in vulnerable mode; hardened tests reject it without invoking any launcher. This proves the unsafe construction and the repair boundary, not that Windows interpreted the command or allowed the later activity. Native impact must be demonstrated with request, app launch, Sysmon GUID ancestry and host outcome records.

Effective remediation difference:

```diff
- interpolate title into cmd.exe /d /c command text
+ validate title against the documented allowlist
+ write CSV with managed File.WriteAllTextAsync
+ if a helper is required, use the fixed apphost with ProcessStartInfo.ArgumentList
```

See [Reports.cs](../../app/IisPurpleLab/Reports.cs). Generated job IDs choose output names; input cannot choose arbitrary paths. The allowed title alphabet also excludes spreadsheet formula prefixes for this small lab CSV format. The helper retains the same allowlist and checks its output is within the export directory.

Retest: [hardened rejection, managed export/download and helper-argument tests](../../app/IisPurpleLab.Tests/ApplicationTests.cs) passed with a mocked launcher. The portable HTTP check tests a real managed export. [Native capture](../../docs/windows-runbook.md) must repeat identical B/C inputs in hardened mode, verify 400 denial with retained application events, verify successful legitimate reports/concurrent helpers, and check no corresponding unexpected child/stage/transfer occurs with demonstrated collection health. A lack of events alone is not a passing fix test.

Investigation: [B](../cases/B-execution.md) and [C](../cases/C-follow-on.md) are explicitly fixture-based until native evidence exists. Collect before stopping the dedicated pool. Inspect root/descendant GUIDs, launch confidence, dummy artifact hashes and receiver receipts; a file-create event does not prove a read and a connection does not prove exfiltration. Cleanup is limited to owned lab resources with recoverable evidence retention.
