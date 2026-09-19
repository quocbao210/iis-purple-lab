"""Synthetic format tests; these do not claim native Windows validation."""
import hashlib
import json

import pytest

from iis_purple.normalize import EvidenceError, normalize_dataset, utc


def dataset(tmp_path, text, *, source="application", fmt="jsonl", extra=None):
    path = tmp_path / "input.log"
    path.write_text(text, encoding="utf-8")
    manifest = {"origin": "handcrafted-test-fixture", "collected_at": "2026-09-19T02:00:00Z", "files": [
        {"path": "input.log", "source": source, "format": fmt,
         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}]}
    if extra:
        manifest["files"].append(extra)
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    return tmp_path


def event_xml(data="", *, event_id=1, provider="Microsoft-Windows-Sysmon", channel="Microsoft-Windows-Sysmon/Operational"):
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="{provider}"/><EventID>{event_id}</EventID><Version>5</Version>
<TimeCreated SystemTime="2026-09-19T01:00:00.1234567Z"/><EventRecordID>83</EventRecordID>
<Channel>{channel}</Channel><Computer>LAB-01</Computer></System><EventData>{data}</EventData></Event>'''


def test_jsonl_order_dedup_offsets_refs_and_collection_time(tmp_path):
    one = {"timestamp": "2026-09-19T12:00:00+10:00", "action": "ticket_access", "host": "LAB"}
    two = {"timestamp": "2026-09-19T00:00:00Z", "action": "login", "host": "LAB"}
    root = dataset(tmp_path, "\n".join(json.dumps(item) for item in [one, two, one]))
    result = normalize_dataset(root)
    assert [event["action"] for event in result] == ["login", "ticket_access"]
    assert result[1]["timestamp"] == "2026-09-19T02:00:00.000000Z"
    assert result[0]["collected_at"] == "2026-09-19T02:00:00.000000Z"
    assert [ref["record"] for ref in result[1]["source_refs"]] == [1, 3]
    assert result[1]["source_ref"]["sha256"]


def test_dynamic_w3c_headers_and_query_secrets(tmp_path):
    text = """#Software: Microsoft Internet Information Services
#Fields: date time cs-method cs-uri-stem cs-uri-query sc-status
2026-09-19 01:00:00 GET /ticket id=7&token=secret 200
#Fields: sc-status cs-uri-stem time date cs-method
403 /ticket 01:00:01 2026-09-19 POST
"""
    events = normalize_dataset(dataset(tmp_path, text, source="iis", fmt="w3c"))
    assert [event["status"] for event in events] == [200, 403]
    assert events[1]["method"] == "POST"
    assert "secret" not in events[0]["uri_query"]
    assert "id=7" in events[0]["uri_query"]
    assert events[1]["source_ref"]["record"] == 5


def test_identical_w3c_lines_are_distinct_requests_without_event_identity(tmp_path):
    row = "2026-09-19 01:00:00 GET /tickets 200\n"
    events = normalize_dataset(dataset(tmp_path, "#Fields: date time cs-method cs-uri-stem sc-status\n" + row + row,
                                      source="iis", fmt="w3c"))
    assert len(events) == 2
    assert {event["source_ref"]["record"] for event in events} == {2, 3}


def test_structured_native_event_shape(tmp_path):
    xml = event_xml('<Data Name="ProcessGuid">{ABC}</Data><Data Name="ProcessId">124</Data>'
                    '<Data Name="ParentProcessId">64</Data><Data Name="ParentProcessGuid">{DEF}</Data>'
                    '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>'
                    '<Data Name="CommandLine">cmd.exe /c echo harmless</Data>')
    event = normalize_dataset(dataset(tmp_path, "<Events>" + xml + "</Events>", source="sysmon", fmt="event_xml"))[0]
    assert (event["event_id"], event["event_version"], event["record_id"]) == (1, 5, 83)
    assert event["provider"] == "Microsoft-Windows-Sysmon"
    assert event["host"] == "LAB-01"
    assert event["process_guid"] == "{abc}"
    assert (event["pid"], event["parent_pid"]) == (124, 64)


def test_security_4688_creator_and_new_pid_are_not_confused(tmp_path):
    xml = event_xml('<Data Name="NewProcessId">0x100</Data><Data Name="ProcessId">0x40</Data>'
                    '<Data Name="NewProcessName">C:\\app.exe</Data><Data Name="ProcessName">C:\\parent.exe</Data>',
                    event_id=4688, provider="Microsoft-Windows-Security-Auditing", channel="Security")
    event = normalize_dataset(dataset(tmp_path, xml, source="security", fmt="event_xml"))[0]
    assert (event["pid"], event["parent_pid"]) == (256, 64)
    assert event["parent_image"] == "C:\\parent.exe"


def test_source_removed_before_path_validation_and_parse(tmp_path):
    root = dataset(tmp_path, json.dumps({"timestamp": "2026-09-19T00:00:00Z", "action": "ticket_access"}),
                   extra={"path": "../../missing.xml", "source": "sysmon", "format": "event_xml"})
    assert len(normalize_dataset(root, {"application"})) == 1
    with pytest.raises(EvidenceError):
        normalize_dataset(root)


@pytest.mark.parametrize("name", ["../outside.json", "/etc/passwd", "C:\\Windows\\file", "folder/../../file"])
def test_path_escape_rejected(tmp_path, name):
    root = dataset(tmp_path, "{}")
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["files"][0]["path"] = name
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(EvidenceError):
        normalize_dataset(root)


def test_hash_tampering_rejected(tmp_path):
    root = dataset(tmp_path, json.dumps({"timestamp": "2026-09-19T00:00:00Z"}))
    (root / "input.log").write_text("changed")
    with pytest.raises(EvidenceError, match="SHA-256"):
        normalize_dataset(root)


@pytest.mark.parametrize("text,fmt", [
    ('<!DOCTYPE x [<!ENTITY payload "x">]><Event>&payload;</Event>', "event_xml"),
    ('{"timestamp":"2026-09-19T00:00:00Z","timestamp":"2026-09-19T00:00:01Z"}', "jsonl"),
    ('{"timestamp":"2026-09-19T00:00:00Z","policy_allowed":"false"}', "jsonl"),
    ("2026-09-19 01:00:00 GET / 200", "w3c"),
    ("#Fields: date time status\n2026-09-19 01:00:00", "w3c"),
])
def test_malformed_and_hostile_inputs_fail_explicitly(tmp_path, text, fmt):
    root = dataset(tmp_path, text, fmt=fmt)
    with pytest.raises(EvidenceError):
        normalize_dataset(root)


def test_untrusted_labels_and_credentials_not_normalized(tmp_path):
    raw = {"timestamp": "2026-09-19T00:00:00Z", "scenario_id": "attack", "expected": True,
           "password": "secret", "token": "secret", "vulnerable_mode": True, "actor": "analyst"}
    event = normalize_dataset(dataset(tmp_path, json.dumps(raw)))[0]
    assert not set(raw).difference({"timestamp", "actor"}).intersection(event)


def test_powershell_fragment_completeness_without_fabricated_content(tmp_path):
    parts = [{"timestamp": "2026-09-19T00:00:00Z", "host": "LAB", "event_id": 4104,
              "ScriptBlockId": "block", "MessageNumber": n, "MessageTotal": 2,
              "ScriptBlockText": text} for n, text in [(2, "Output 'lab'"), (1, "Write-")]]
    events = normalize_dataset(dataset(tmp_path, "\n".join(map(json.dumps, parts)), source="powershell"))
    assert all(event["script_block_complete"] for event in events)
    assert all(len(event["script_block_evidence_ids"]) == 2 for event in events)
    (tmp_path / "input.log").write_text(json.dumps(parts[0]))
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    manifest["files"][0].pop("sha256")
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    assert normalize_dataset(tmp_path)[0]["script_block_complete"] is False


def test_naive_application_time_rejected():
    with pytest.raises(EvidenceError, match="offset"):
        utc("2026-09-19T01:00:00")


def test_deep_xml_rejected_before_recursive_serialization(tmp_path):
    root = dataset(tmp_path, "<Events>" + "<x>" * 50 + "</x>" * 50 + "</Events>", fmt="event_xml")
    with pytest.raises(EvidenceError, match="nesting"):
        normalize_dataset(root)


def test_event_system_time_and_sysmon_observation_time_both_retained(tmp_path):
    xml = event_xml('<Data Name="UtcTime">2026-09-19 01:00:00.100</Data><Data Name="ProcessId">12</Data>')
    event = normalize_dataset(dataset(tmp_path, xml, source="sysmon", fmt="event_xml"))[0]
    assert event["timestamp"] == "2026-09-19T01:00:00.100000Z"
    assert event["system_timestamp"] == "2026-09-19T01:00:00.123456Z"


def test_duplicate_sysmon_payload_timestamps_are_rejected(tmp_path):
    xml = event_xml('<Data Name="UtcTime">2026-09-19 01:00:00.100</Data>'
                    '<Data Name="UtcTime">2026-09-19 01:00:00.200</Data>')
    root = dataset(tmp_path, xml, source="sysmon", fmt="event_xml")
    with pytest.raises(EvidenceError, match="duplicate field"):
        normalize_dataset(root)


def test_powershell_engine_pid_preserved_without_confusing_sysmon_emitter(tmp_path):
    xml = event_xml('<Data Name="ScriptBlockId">a</Data>', event_id=4104,
                    provider="Microsoft-Windows-PowerShell", channel="Microsoft-Windows-PowerShell/Operational")
    xml = xml.replace("</System>", '<Execution ProcessID="333" ThreadID="444"/></System>')
    event = normalize_dataset(dataset(tmp_path, xml, source="powershell", fmt="event_xml"))[0]
    assert event["pid"] == event["emitter_pid"] == 333
    assert event["emitter_tid"] == 444
    xml = event_xml('<Data Name="ProcessId">123</Data>').replace("</System>", '<Execution ProcessID="333"/></System>')
    event = normalize_dataset(dataset(tmp_path, xml, source="sysmon", fmt="event_xml"))[0]
    assert event["pid"] == 123 and event["emitter_pid"] == 333
