from copy import deepcopy

from iis_purple.correlate import correlate


def workload():
    parent = {"evidence_id": "parent", "source": "sysmon", "event_id": 1, "host": "LAB", "timestamp": "2026-09-19T00:00:00Z",
              "process_guid": "worker", "parent_process_guid": "services", "pid": 100, "parent_pid": 4, "image": "C:\\Windows\\System32\\inetsrv\\w3wp.exe"}
    launch = {"evidence_id": "launch", "source": "application", "host": "LAB", "timestamp": "2026-09-19T00:01:00Z",
              "request_id": "req", "action": "process_launch", "outcome": "started", "child_pid": 200, "parent_pid": 100,
              "parent_start": "2026-09-19T00:00:00Z", "launch_start": "2026-09-19T00:01:00Z", "launch_end": "2026-09-19T00:01:00.100Z"}
    child = {"evidence_id": "child", "source": "sysmon", "event_id": 1, "host": "LAB", "timestamp": "2026-09-19T00:01:00.050Z",
             "process_guid": "child-guid", "parent_process_guid": "worker", "pid": 200, "parent_pid": 100, "image": "C:\\Windows\\System32\\cmd.exe"}
    descendant = {"evidence_id": "descendant", "source": "sysmon", "event_id": 1, "host": "LAB", "timestamp": "2026-09-19T00:10:00Z",
                  "process_guid": "desc-guid", "parent_process_guid": "child-guid", "pid": 201, "parent_pid": 200, "image": "C:\\Windows\\System32\\whoami.exe"}
    return [parent, launch, child, descendant]


def link_for(links, guid):
    return next(link for link in links if link["process_guid"] == guid)


def test_unique_bounded_worker_identity_high_and_long_running_guid_descendant():
    events = workload()
    links = correlate(list(reversed(events)))
    child = link_for(links, "child-guid")
    assert child["confidence"] == "high"
    assert child["request_id"] == "req"
    assert set(child["evidence_ids"]) == {"parent", "child", "launch"}
    descendant = link_for(links, "desc-guid")
    assert descendant["confidence"] == "high"
    assert descendant["relation"] == "descendant"
    assert descendant["request_id"] == "req"


def test_missing_parent_is_low_not_exact_attribution():
    child = link_for(correlate(workload()[1:]), "child-guid")
    assert child["confidence"] == "low"
    assert "incomplete" in child["reason"]


def test_pid_reuse_with_different_worker_start_disproves_link():
    events = workload()
    events[0]["timestamp"] = "2026-09-19T00:00:30Z"
    links = correlate(events)
    assert link_for(links, "child-guid")["confidence"] == "unattributed"
    assert any(link["request_id"] == "req" and link["process_guid"] is None for link in links)


def test_concurrent_launches_are_ambiguous():
    events = workload()
    duplicate = deepcopy(events[1])
    duplicate.update(request_id="other", evidence_id="launch-other")
    links = correlate(events + [duplicate])
    assert link_for(links, "child-guid")["confidence"] == "ambiguous"
    assert link_for(links, "child-guid")["request_id"] is None
    assert link_for(links, "desc-guid")["confidence"] == "ambiguous"


def test_two_child_guids_for_reused_pid_within_window_ambiguous():
    events = workload()
    reused = {**events[2], "evidence_id": "reuse", "process_guid": "reuse-guid", "timestamp": "2026-09-19T00:01:01Z"}
    links = correlate(events + [reused])
    assert link_for(links, "child-guid")["confidence"] == "ambiguous"
    assert link_for(links, "reuse-guid")["confidence"] == "ambiguous"


def test_host_boundaries_and_time_skew_do_not_create_high_links():
    events = workload()
    events[2]["host"] = "OTHER"
    assert link_for(correlate(events), "child-guid")["confidence"] == "unattributed"
    events = workload()
    events[2]["timestamp"] = "2026-09-19T00:01:03Z"
    assert link_for(correlate(events), "child-guid")["confidence"] == "unattributed"


def test_time_only_association_explained_and_never_high():
    events = workload()
    events[1].pop("child_pid")
    events[1].pop("parent_pid")
    link = link_for(correlate(events), "child-guid")
    assert link["confidence"] == "low"
    assert "Time-only" in link["reason"]


def test_missing_or_unbounded_launch_times_preserve_unattributed_process():
    for replacement in (None, "2026-09-19T10:00:00Z"):
        events = workload()
        events[1]["launch_end"] = replacement
        links = correlate(events)
        assert link_for(links, "child-guid")["confidence"] == "unattributed"
        assert any("invalid bounded" in link["reason"] for link in links)


def test_file_network_events_use_guid_and_never_precede_process_creation():
    events = workload()
    for identifier, guid, timestamp in [("file", "desc-guid", "2026-09-19T00:11:00Z"),
                                        ("before", "desc-guid", "2026-09-19T00:00:00Z"),
                                        ("other", "unrelated", "2026-09-19T00:11:00Z")]:
        events.append({"evidence_id": identifier, "source": "sysmon", "event_id": 11,
                       "host": "LAB", "process_guid": guid, "timestamp": timestamp})
    ids = link_for(correlate(events), "desc-guid")["evidence_ids"]
    assert "file" in ids and "before" not in ids and "other" not in ids


def test_labels_and_payload_names_cannot_manufacture_correlation():
    events = workload()
    expected = correlate(events)
    for event in events:
        event.update(scenario_id="malicious", expected=True, vulnerable_mode=True, ground_truth="attack")
    assert correlate(events) == expected


def test_no_app_source_preserves_endpoint_processes_without_request():
    events = [event for event in workload() if event["source"] != "application"]
    assert all(link["confidence"] == "unattributed" and link["request_id"] is None for link in correlate(events))


def test_failed_launch_cannot_receive_high_confidence_from_pid_coincidence():
    events = workload()
    events[1]["outcome"] = "failed"
    link = link_for(correlate(events), "child-guid")
    assert link["confidence"] == "low"
    assert "outcome" in link["reason"]
