"""Deterministic HANDCRAFTED fixtures, never Windows captures.

This generator is a dataset authoring tool. Analysis never imports it or the labels.
Run from repository root: python datasets/build_fixtures.py
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent / "fixtures"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build(split, seed):
    rng = random.Random(seed)
    target = ROOT / split
    target.mkdir(parents=True, exist_ok=True)
    application, windows, requests, cases = [], [], [], []
    start = datetime(2026, 8, 11 if split == "development" else 21, 10, tzinfo=timezone.utc)
    def stamp(seconds):
        return (start + timedelta(seconds=seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    def guid():
        return "{" + str(uuid.UUID(int=rng.getrandbits(128))) + "}"
    def win(host, seconds, event_id, **data):
        index = len(windows) + 1
        windows.append({"host": host, "timestamp": stamp(seconds), "record_id": index + 12000, "event_id": event_id, "data": data})
        return {"path": "sysmon.xml", "record": index}
    def app(host, seconds, **data):
        application.append({"host": host, "timestamp": stamp(seconds), **data})
        return {"path": "application.jsonl", "record": len(application)}

    definitions = [
        ("A", True, "cross-tenant", ["IPL-001"]),
        ("A", True, "attachment", ["IPL-001"]),
        ("A", False, "same-tenant", []), ("A", False, "sharing", []),
        ("A", False, "admin", []), ("A", False, "denied", []),
        ("B", True, "injection", ["IPL-002", "IPL-006"]),
        ("C", True, "follow-on", ["IPL-002", "IPL-003", "IPL-004", "IPL-005", "IPL-006"]),
        ("C", True, "follow-on", ["IPL-002", "IPL-003", "IPL-004", "IPL-005", "IPL-006"]),
        ("B", False, "helper", []), ("B", False, "helper", []),
        ("B", False, "concurrent-helper", []), ("B", False, "concurrent-helper", []),
        ("B", False, "recycled-helper", []),
        ("B", False, "maintenance-shell", []),
        ("A", False, "same-tenant", []), ("A", False, "same-tenant", []),
        ("B", True, "uninstrumented", ["IPL-002"]),
        ("A", True, "unlogged-policy", ["IPL-001"]),
    ]
    if split == "heldout":
        rng.shuffle(definitions)
    concurrent_worker = None
    for i, (family, malicious, behaviour, expected_rules) in enumerate(definitions):
        seconds = 20 * i + 10
        host = f"web-{rng.randrange(20,90)}.lab"
        req, job = guid().strip("{}"), guid().strip("{}")
        tenant = "tenant-" + str(rng.randrange(20, 40))
        other = "tenant-" + str(rng.randrange(60, 80))
        actor = "user-" + str(rng.randrange(100, 999))
        resource = "ticket-" + str(rng.randrange(2000, 9000))
        if behaviour == "concurrent-helper" and concurrent_worker:
            host, seconds = concurrent_worker[0], concurrent_worker[1]
        refs = []
        path = f"/api/tickets/{resource}" if family == "A" else "/api/reports"
        method = "GET" if family == "A" else "POST"
        requests.append(f"{stamp(seconds)[:10]} {stamp(seconds)[11:19]} {host} {method} {path} - 200 127.0.0.1 5")
        refs.append({"path": "iis.log", "record": len(requests) + 2})
        if family == "A" and behaviour != "unlogged-policy":
            rt = tenant if behaviour == "same-tenant" else other
            shared = [tenant] if behaviour == "sharing" else []
            role = "admin" if behaviour == "admin" else "user"
            allowed = rt == tenant or bool(shared) or role == "admin"
            refs.append(app(host, seconds, action="attachment_access" if behaviour == "attachment" else "ticket_access",
                            outcome="denied" if behaviour == "denied" else "allowed", request_id=req,
                            actor=actor, actor_tenant=tenant, resource_tenant=rt, resource_id=resource,
                            role=role, shared_with=shared, policy_allowed=allowed))
        if family in {"B", "C"}:
            worker, child = guid(), guid()
            parent_pid = rng.randrange(1000, 5000)
            child_pid = rng.randrange(5100, 9000)
            worker_start = seconds - rng.randrange(3, 9)
            worker_image = r"C:\Windows\System32\inetsrv\w3wp.exe"
            is_shell = behaviour in {"injection", "follow-on", "maintenance-shell", "uninstrumented"}
            image = r"C:\Windows\System32\cmd.exe" if is_shell else r"C:\IISPurpleLab\app\IisPurpleLab.exe"
            title = "Monthly support report"
            if malicious:
                title += " & whoami"
            if behaviour == "concurrent-helper" and concurrent_worker:
                host, seconds, worker, parent_pid, worker_start = concurrent_worker
            else:
                # Background worker events are deliberately outside case labels; shared ancestry
                # must not make an alert on one concurrent job count against its neighbour.
                win(host, worker_start, 1, ProcessGuid=worker, ProcessId=parent_pid,
                    ParentProcessGuid=guid(), ParentProcessId=720, Image=worker_image,
                    ParentImage=r"C:\Windows\System32\svchost.exe", CommandLine=worker_image)
                if behaviour == "concurrent-helper":
                    concurrent_worker = host, seconds, worker, parent_pid, worker_start
            if behaviour != "uninstrumented":
                refs.append(app(host, seconds, action="report_request", outcome="allowed", request_id=req,
                                actor=actor, actor_tenant=tenant, report_title=title, job_id=job))
                refs.append(app(host, seconds + .08, action="process_launch", outcome="started", request_id=req,
                                job_id=job, parent_pid=parent_pid, child_pid=child_pid,
                                parent_start=stamp(worker_start), launch_start=stamp(seconds), launch_end=stamp(seconds + .1),
                                image=image, command_line=image + " " + title))
            refs.append(win(host, seconds + .02, 1, ProcessGuid=child, ProcessId=child_pid,
                            ParentProcessGuid=worker, ParentProcessId=parent_pid, Image=image,
                            ParentImage=worker_image, CommandLine=image + " " + title))
            if behaviour == "follow-on":
                discovery = guid()
                refs.append(win(host, seconds + .3, 1, ProcessGuid=discovery, ProcessId=child_pid + 4,
                                ParentProcessGuid=child, ParentProcessId=child_pid,
                                Image=r"C:\Windows\System32\whoami.exe", ParentImage=image, CommandLine="whoami"))
                refs.append(win(host, seconds + .4, 11, ProcessGuid=child, ProcessId=child_pid, Image=image,
                                TargetFilename=rf"C:\IISPurpleLab\data\work\{job}\stage.txt"))
                refs.append(win(host, seconds + .5, 3, ProcessGuid=child, ProcessId=child_pid, Image=image,
                                DestinationIp="127.0.0.1", DestinationPort=5091, Protocol="tcp", Initiated="true"))
        cases.append({"case_id": f"{split}-{i+1:02d}", "family": family, "malicious": malicious,
                      "behaviour": behaviour, "request_id": req, "refs": refs, "expected_rules": expected_rules,
                      "limitation": "No application context exists" if behaviour == "unlogged-policy" else "Handcrafted fixture"})

    # Actual on-disk formats exercise parsers, but provenance stays handcrafted.
    (target / "application.jsonl").write_text("".join(json.dumps(x) + "\n" for x in application), encoding="utf-8")
    (target / "iis.log").write_text("#Software: IIS Purple Lab handcrafted fixture\n#Fields: date time s-computername cs-method cs-uri-stem cs-uri-query sc-status c-ip time-taken\n" + "\n".join(requests) + "\n", encoding="utf-8")
    ET.register_namespace("", NS)
    root = ET.Element("Events")
    for event in windows:
        element = ET.SubElement(root, f"{{{NS}}}Event")
        system = ET.SubElement(element, f"{{{NS}}}System")
        ET.SubElement(system, f"{{{NS}}}Provider", Name="Microsoft-Windows-Sysmon")
        for field, value in [("EventID", event["event_id"]), ("Version", 5 if event["event_id"] == 1 else 3),
                             ("EventRecordID", event["record_id"]), ("Channel", "Microsoft-Windows-Sysmon/Operational"), ("Computer", event["host"])]:
            ET.SubElement(system, f"{{{NS}}}{field}").text = str(value)
        ET.SubElement(system, f"{{{NS}}}TimeCreated", SystemTime=event["timestamp"])
        data = ET.SubElement(element, f"{{{NS}}}EventData")
        ET.SubElement(data, f"{{{NS}}}Data", Name="UtcTime").text = event["timestamp"]
        for name, value in event["data"].items():
            ET.SubElement(data, f"{{{NS}}}Data", Name=name).text = str(value)
    ET.indent(root)
    (target / "sysmon.xml").write_text(ET.tostring(root, encoding="unicode") + "\n", encoding="utf-8")
    files = [{"path": name, "source": source, "format": fmt,
              "sha256": hashlib.sha256((target / name).read_bytes()).hexdigest()}
             for name, source, fmt in [("application.jsonl", "application", "jsonl"), ("iis.log", "iis", "w3c"), ("sysmon.xml", "sysmon", "event_xml")]]
    write_json(target / "manifest.json", {"schema_version": 1, "origin": "handcrafted-fixture", "split": split,
        "description": "Synthetic parser/rule test data. NOT observed Windows activity. No tool generated native events.",
        "collected_at": stamp(999), "collection_conditions": "Not collected; deterministic fixture authoring timestamp",
        "generator": "datasets/build_fixtures.py", "generator_seed": seed,
        "tool_versions": {"IIS": "not executed", "Sysmon": "not executed", "Windows": "not executed"},
        "sanitisation": "Generated synthetic values; no real customer or host records", "files": files})
    write_json(target / "ground_truth.json", {"unit": "scenario-run", "origin": "evaluation-only labels for handcrafted fixtures",
        "cases": cases, "notes": "Not used by normalisation, correlation or detection. Expected rules define positives for conditional rule metrics; incident coverage includes all malicious cases."})


if __name__ == "__main__":
    build("development", 741)
    build("heldout", 1909)
