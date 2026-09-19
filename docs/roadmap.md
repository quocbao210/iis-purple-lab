# Later extensions — not part of this preview

1. **Native validation first:** complete the existing Windows gates and publish only permitted sanitized derivatives with provenance.
2. **One SIEM integration:** choose Wazuh or Sentinel, implement collection/mappings/execution and an evidence-backed case. Wazuh's server needs a supported separate host; the Windows endpoint is an agent. Optional cost/licensing; no untested KQL/SPL is advertised as working.
3. **Independent dataset validation:** select a licensed public Windows dataset, map schema/domain differences, evaluate selected rules and state population limits.
4. **Hosting model comparison:** observe both in-process and out-of-process worker ancestry; then test rule/correlation portability.
5. **Persistence study:** a harmless removable scheduled task with observed task-creation evidence and explicit permission requirements. A separately elevated setup step is not privilege escalation.
6. **Separate identity lab:** small synthetic Active Directory environment with a new threat model. It is not a prerequisite for this core.
