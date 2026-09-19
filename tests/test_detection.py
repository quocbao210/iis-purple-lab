from copy import deepcopy
from pathlib import Path

import pytest

from iis_purple.normalize import normalize_dataset
from iis_purple.correlate import correlate
from iis_purple.detection import detect, sigma_matches

DATA = Path(__file__).resolve().parents[1] / "datasets/fixtures/heldout"


def run(events, policy=None):
    return detect(events, correlate(events), policy)["alerts"]


def test_real_sigma_sql_executes_positive_and_near_miss():
    rows = [{"evidence_id": str(i), "source": "sysmon", "event_id": 1, "image": image, "parent_image": parent}
            for i, (image, parent) in enumerate([
                (r"C:\Windows\System32\CMD.EXE", r"C:\Windows\System32\inetsrv\w3wp.exe"),
                (r"C:\IISPurpleLab\app\IisPurpleLab.exe", r"C:\Windows\System32\inetsrv\w3wp.exe"),
                (r"C:\Windows\cmd.exe.bak", r"C:\Windows\inetsrv\w3wp.exe"),
                (r"C:\Windows\cmd.exe", r"C:\Windows\explorer.exe"),
                (r"C:\Windows\cmd.exe' OR 1=1 --", r"C:\Windows\w3wp.exe"),
            ])]
    assert sigma_matches(rows, "web_worker_interpreter.yml") == {"0"}
    rows[0]["event_id"] = 11
    assert not sigma_matches(rows, "web_worker_interpreter.yml")


def test_every_rule_has_an_executed_positive():
    events = normalize_dataset(DATA)
    assert {a["rule_id"] for a in run(events)} == {f"IPL-{i:03}" for i in range(1, 7)}


@pytest.mark.parametrize("change", [
    {"role": "admin"}, {"shared_with": ["a"]}, {"resource_tenant": "a"}, {"outcome": "denied"},
])
def test_access_policy_near_misses(change):
    event = {"evidence_id": "a", "source": "application", "action": "ticket_access", "outcome": "allowed",
             "actor": "user", "actor_tenant": "a", "resource_tenant": "b", "resource_id": "5", "role": "user", "shared_with": []}
    assert len(run([event])) == 1
    assert not run([{**event, **change}])


def test_policy_recomputed_and_mode_labels_do_not_control_detection():
    events = normalize_dataset(DATA)
    before = run(events)
    for e in events:
        e.update(scenario_id="benign", malicious=False, vulnerable=False, policy_allowed=True)
    assert run(events) == before


def test_contextual_write_and_connection_benign_exclusions():
    events = normalize_dataset(DATA)
    assert any(a["rule_id"] == "IPL-004" for a in run(events))
    policy = {"protected_roots": [r"C:\Unrelated"], "approved_destinations": [{"ip": "127.0.0.1", "port": 5091}]}
    assert not {"IPL-004", "IPL-005"}.intersection(a["rule_id"] for a in run(events, policy))
    for e in events:
        if e.get("event_id") == 11:
            e["target_filename"] = r"C:\IISPurpleLab\data-other\stage.txt"
    assert not any(a["rule_id"] == "IPL-004" for a in run(events))


def test_guid_host_boundary_prevents_false_descendant_scope():
    events = normalize_dataset(DATA)
    for e in events:
        if e.get("event_id") in {3, 11} or str(e.get("image", "")).endswith("whoami.exe"):
            e["host"] = "unrelated-host"
    assert not {"IPL-003", "IPL-004", "IPL-005"}.intersection(a["rule_id"] for a in run(events))


def test_combined_rule_needs_independent_input_and_strong_attribution():
    events = normalize_dataset(DATA)
    assert any(a["rule_id"] == "IPL-006" for a in run(events))
    missing_parent = deepcopy(events)
    for e in missing_parent:
        if e.get("action") == "process_launch":
            e.pop("parent_start", None)
    assert not any(a["rule_id"] == "IPL-006" for a in run(missing_parent))
    for e in events:
        if e.get("action") == "report_request":
            e["report_title"] = "Quarterly report"
    assert not any(a["rule_id"] == "IPL-006" for a in run(events))


def test_missing_required_source_is_unavailable_not_clean():
    events = normalize_dataset(DATA, {"iis"})
    result = detect(events, correlate(events))
    assert not result["alerts"]
    assert all(not x["available"] for x in result["availability"].values())


def test_source_presence_without_required_fields_is_unavailable():
    events = [{"evidence_id": "x", "source": "sysmon", "event_id": 1, "image": "cmd.exe"}]
    result = detect(events, [])
    assert not result["availability"]["IPL-002"]["available"]
    assert "parent_image" in result["availability"]["IPL-002"]["missing_fields_by_stage"][0]


@pytest.mark.parametrize("request_host", ["UNRELATED-HOST", ""])
def test_reused_request_id_on_another_or_missing_host_cannot_form_incident(request_host):
    events = normalize_dataset(DATA)
    for event in events:
        if event.get("action") == "report_request":
            event["host"] = request_host
    alerts = run(events)
    assert any(alert["rule_id"] == "IPL-002" for alert in alerts)
    assert not any(alert["rule_id"] == "IPL-006" for alert in alerts)


def test_incident_evidence_stays_on_its_host_when_request_ids_are_reused():
    events = normalize_dataset(DATA)
    other_host = deepcopy(events)
    for event in other_host:
        event["host"] = "ANOTHER-HOST"
        event["evidence_id"] += "-other"
        if event.get("action") == "report_request":
            event["report_title"] = "Routine report"
    # Windows host identity is case insensitive.
    for event in events:
        if event.get("action") == "report_request":
            event["host"] = event["host"].swapcase()
    combined = events + other_host
    by_id = {event["evidence_id"]: event for event in combined}
    incidents = [alert for alert in run(combined) if alert["rule_id"] == "IPL-006"]
    assert incidents
    for incident in incidents:
        assert {by_id[eid]["host"].casefold() for eid in incident["evidence_ids"]} == {incident["host"]}
