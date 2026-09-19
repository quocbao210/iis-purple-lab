# Scope and threat model

Northwind Support (fictional) runs a multi-tenant IIS support portal. All users, tickets and exports in this lab are synthetic. An authenticated ordinary tenant may know another ticket identifier and may submit report input. The study asks what each log source can establish about successful cross-tenant access and a report execution boundary violation.

Assets: private tickets, attachments, generated reports, application integrity, and the trustworthiness of investigation evidence. Boundaries: authenticated identity to object policy; report data to operating-system commands; application launch record to Windows process events; untrusted logs to a local report viewer.

The native application uses an isolated low-privilege application pool and loopback binding on one disposable VM. It has write access only to its data/log/work directories and read/execute access to published code. Vulnerable mode requires explicit local configuration. Hardened mode enforces policy and removes unnecessary shell interpretation. A lab control can limit reachable payloads while retaining the real unsafe data-to-command boundary for the bounded reproduction.

Excluded: arbitrary target scanning, remote shells, credential theft, elevation, protection bypass, persistence, Active Directory, and internet exfiltration. A separate harness action never becomes exploit-derived capability by association. Shared hosted CI does not execute the Windows payloads.

Evidence is not infallible: a compromised host can lie before collection; a SHA-256 hash only detects later changes. A time-only match is weak, PID reuse can mislead, and missing telemetry means unknown. File creation is not proof of a read; a connection is not proof of transferred content. Native transfer claims need receiver content and matching hashes.

Containment is a dry-run-first action against the verified dedicated pool. Collect before cleanup. Never modify a generic process or service merely because its name appears in an alert.
