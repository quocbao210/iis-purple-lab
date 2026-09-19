"""Executable detections. No scenario labels, fixture identifiers or mode flags are read."""
from __future__ import annotations

import hashlib
import json
import ntpath
import re
import sqlite3
from pathlib import Path

from sigma.backends.sqlite.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[2]
RULES = {
    "IPL-001": ("Cross-tenant policy violation", {"application"}),
    "IPL-002": ("Interpreter child of IIS", {"sysmon"}),
    "IPL-003": ("Discovery in IIS descendants", {"sysmon"}),
    "IPL-004": ("Unexpected write by IIS interpreter chain", {"sysmon"}),
    "IPL-005": ("Unexpected connection from IIS descendants", {"sysmon"}),
    "IPL-006": ("Request and endpoint execution incident", {"application", "sysmon"}),
}


def basename(value):
    return ntpath.basename(str(value or "")).casefold()


def process_key(event):
    return str(event.get("host", "")).casefold(), str(event.get("process_guid", "")).casefold()


def sigma_matches(events, filename):
    """Convert real Sigma and execute on a strictly mapped process-creation table.

    SQL is generated only from repository-owned rules; event values are parameters.
    Filtering logsource here is necessary: the backend doesn't infer Sysmon EventID.
    """
    rule = ROOT / "detections" / "sigma" / filename
    collection = SigmaCollection.from_yaml(rule.read_text(encoding="utf-8"))
    queries = sqliteBackend().convert(collection)
    matched = set()
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE events (evidence_id TEXT, Image TEXT, ParentImage TEXT, CommandLine TEXT)")
        db.executemany("INSERT INTO events VALUES (?, ?, ?, ?)", [
            (e["evidence_id"], e.get("image"), e.get("parent_image"), e.get("command_line"))
            for e in events if e.get("source") == "sysmon" and e.get("event_id") == 1
        ])
        for query in queries:
            # Fixed identifier, never a value from a log or CLI argument.
            query = query.replace("<TABLE_NAME>", "events")
            matched.update(row[0] for row in db.execute(query))
    return matched


def ancestry(event, processes):
    """Return an observed GUID chain to a worker, never follow a reused numeric PID."""
    result, seen = [], set()
    current = event
    for _ in range(64):
        key = process_key(current)
        if not key[1] or key in seen:
            return []
        seen.add(key)
        result.append(current)
        if basename(current.get("image")) == "w3wp.exe":
            return result
        parent_key = (key[0], str(current.get("parent_process_guid", "")).casefold())
        parent = processes.get(parent_key)
        if parent is None or parent.get("timestamp", "") > current.get("timestamp", ""):
            return []
        current = parent
    return []


def _within(path, roots):
    value = ntpath.normcase(ntpath.normpath(str(path or "")))
    for root in roots:
        root = ntpath.normcase(ntpath.normpath(root))
        if value.startswith(root.rstrip("\\") + "\\"):
            return True
    return False


def prerequisites(events):
    """Distinguish missing fields/events from a predicate that ran without matching.

    Availability is evidence-level eligibility, not assurance of continuous collection.
    Each stage must have at least one complete record; per-stage counts expose gaps.
    """
    process = ("sysmon", 1, None, ("host", "timestamp", "image", "process_guid", "parent_process_guid"))
    stages = {
        "IPL-001": [("application", None, {"ticket_access", "attachment_access", "export_access"},
                     ("actor", "actor_tenant", "resource_tenant", "resource_id", "role", "shared_with", "outcome"))],
        "IPL-002": [("sysmon", 1, None, ("image", "parent_image"))],
        "IPL-003": [process],
        "IPL-004": [process, ("sysmon", 11, None, ("host", "timestamp", "process_guid", "target_filename"))],
        "IPL-005": [process, ("sysmon", 3, None, ("host", "timestamp", "process_guid", "destination_ip", "destination_port"))],
        "IPL-006": [process, ("application", None, {"report_request"}, ("request_id", "report_title", "outcome")),
                     ("application", None, {"process_launch"}, ("host", "request_id", "parent_pid", "child_pid", "parent_start", "launch_start", "launch_end", "outcome"))],
    }
    sources = {e.get("source") for e in events}
    result = {}
    for rule, roles in stages.items():
        counts, incomplete, absent = [], [], []
        for source, event_id, actions, fields in roles:
            candidates = [e for e in events if e.get("source") == source and (event_id is None or e.get("event_id") == event_id)
                          and (actions is None or e.get("action") in actions)]
            complete = sum(all(k in e and e[k] is not None and e[k] != "" for k in fields) for e in candidates)
            counts.append(complete)
            incomplete.append(len(candidates) - complete)
            absent.append(sorted({k for e in candidates for k in fields if k not in e or e[k] is None or e[k] == ""}))
        result[rule] = {"available": all(counts), "required_sources": sorted(RULES[rule][1]),
                        "missing_sources": sorted(RULES[rule][1] - sources),
                        "eligible_records_by_stage": counts, "incomplete_records_by_stage": incomplete,
                        "missing_fields_by_stage": absent,
                        "note": "Zero eligible records means prerequisites unavailable in this evidence. Presence does not establish continuous collection or a valid correlation."}
    return result


def detect(events: list[dict], links: list[dict], policy: dict | None = None) -> dict:
    if policy is None:
        policy = json.loads((ROOT / "detections/policy.json").read_text(encoding="utf-8"))
    processes = {}
    duplicates = set()
    for e in events:
        if e.get("source") == "sysmon" and e.get("event_id") == 1 and e.get("process_guid"):
            key = process_key(e)
            if key in processes and processes[key] != e:
                duplicates.add(key)
            processes[key] = e
    for key in duplicates:
        processes.pop(key, None)  # Conflicting identities cannot establish ancestry.
    by_id = {e["evidence_id"]: e for e in events}
    request_links = {}
    for link in links:
        if link.get("confidence") == "high" and link.get("request_id"):
            key = (str(link.get("host", "")).casefold(), str(link.get("process_guid", "")).casefold())
            if all(key):
                request_links.setdefault(key, set()).add(link["request_id"])

    def request_for(event):
        candidates = set()
        for parent in ancestry(event, processes) or [event]:
            candidates.update(request_links.get(process_key(parent), set()))
        return next(iter(candidates)) if len(candidates) == 1 else None

    alerts = []

    def add(rule, evidence, reason, severity="medium", kind="hunting-lead", request=None):
        ids = sorted(set(e["evidence_id"] for e in evidence))
        hosts = {str(e.get("host", "")).casefold() for e in evidence}
        alerts.append({"alert_id": hashlib.sha256((rule + ":" + ",".join(ids)).encode()).hexdigest()[:20],
                       "rule_id": rule, "title": RULES[rule][0], "severity": severity,
                       "kind": kind, "evidence_ids": ids, "request_id": request, "reason": reason,
                       "host": next(iter(hosts)) if len(hosts) == 1 and "" not in hosts else None})

    for e in events:
        # Recompute policy from server-side actor/resource fields. A denied request is an attempt, not data access.
        if e.get("source") == "application" and e.get("action") in {"ticket_access", "attachment_access", "export_access"}:
            required = ("actor", "actor_tenant", "resource_tenant", "resource_id", "role", "shared_with")
            if all(k in e and e[k] is not None for k in required) and isinstance(e["shared_with"], list):
                allowed = (e["actor_tenant"] == e["resource_tenant"] or e["role"] == "admin"
                           or e["actor_tenant"] in e["shared_with"])
                if not allowed and e.get("outcome") == "allowed":
                    add("IPL-001", [e], "Successful access violates tenant, sharing and administrator policy.",
                        "high", "policy-violation", e.get("request_id"))

    shell_ids = sigma_matches(events, "web_worker_interpreter.yml")
    discovery_ids = sigma_matches(events, "discovery_process.yml")
    interpreters = {"cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe"}
    for e in events:
        if e["evidence_id"] in shell_ids:
            add("IPL-002", [e], "An IIS worker launched an interpreter. Legitimate legacy exports remain an alternative.", request=request_for(e))
        chain = ancestry(e, processes) if e.get("event_id") == 1 else []
        if e["evidence_id"] in discovery_ids and len(chain) >= 2:
            add("IPL-003", chain, "Observed ProcessGuid ancestry connects identity/host discovery to IIS; intent is inferred.", request=request_for(e))
        if e.get("source") != "sysmon" or e.get("event_id") not in {3, 11}:
            continue
        process = processes.get(process_key(e))
        if not process or process.get("timestamp", "") > e.get("timestamp", ""):
            continue
        chain = ancestry(process, processes)
        if len(chain) < 2:
            continue
        if e["event_id"] == 11 and _within(e.get("target_filename"), policy.get("protected_roots", [])):
            if any(basename(p.get("image")) in interpreters for p in chain[:-1]):
                add("IPL-004", [e] + chain, "An interpreter descendant wrote under a protected application data root; no read is established.", request=request_for(process))
        if e["event_id"] == 3 and e.get("destination_ip") and e.get("destination_port") is not None:
            destination = {"ip": e["destination_ip"], "port": int(e["destination_port"])}
            if destination not in policy.get("approved_destinations", []):
                add("IPL-005", [e] + chain, "Connection outside the configured report destination policy; connection alone does not establish transfer.", request=request_for(process))

    # Independent input anomaly + endpoint execution + supported attribution. This is an incident grouping.
    for e in events:
        if (e.get("source") == "application" and e.get("action") == "report_request"
                and e.get("outcome") == "allowed" and re.search(r"[&|<>\r\n]", str(e.get("report_title", "")))):
            req = e.get("request_id")
            host = str(e.get("host", "")).casefold()
            components = [a for a in alerts if req and host and a["request_id"] == req
                          and a["host"] == host and a["rule_id"] in {"IPL-002", "IPL-003"}]
            if components:
                ids = {eid for a in components for eid in a["evidence_ids"]}
                launch_links = [l for l in links if l.get("request_id") == req and l.get("confidence") == "high"
                                and str(l.get("host", "")).casefold() == host]
                ids.update(eid for l in launch_links for eid in l.get("evidence_ids", []))
                add("IPL-006", [e] + [by_id[eid] for eid in ids if eid in by_id],
                    "Shell-control syntax in an accepted report request and independently observed endpoint execution share a high-confidence launch link.",
                    "high", "correlated-incident", req)

    availability = prerequisites(events)
    rule_paths = [Path(__file__)] + sorted((ROOT / "detections/sigma").glob("*.yml"))
    return {"alerts": sorted(alerts, key=lambda a: (a["rule_id"], a["alert_id"])), "availability": availability,
            "rule_versions": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in rule_paths},
            "policy": policy}


def baseline_process_alerts(events):
    """Untuned baseline for comparison only: every observed direct worker child."""
    return [e["evidence_id"] for e in events if e.get("source") == "sysmon" and e.get("event_id") == 1
            and basename(e.get("parent_image")) == "w3wp.exe"]
