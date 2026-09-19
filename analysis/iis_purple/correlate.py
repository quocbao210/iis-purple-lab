"""Conservative request-to-process attribution with explicit failure paths."""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import deque
from datetime import datetime

SKEW_SECONDS = 2.0
MAX_LAUNCH_SECONDS = 120.0


def _time(value: str | None) -> float | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo else None
    except (AttributeError, ValueError, TypeError):
        return None


def _host(event: dict) -> str:
    return str(event.get("host", "")).casefold()


def _key(event: dict, field: str = "process_guid") -> tuple[str, str]:
    return _host(event), str(event.get(field, "")).lower()


def _link(evidence: list[dict], request_id: str | None, guid: str | None,
          confidence: str, reason: str, **extra) -> dict:
    return {"evidence_ids": sorted({item["evidence_id"] for item in evidence}),
            "request_id": request_id, "process_guid": guid,
            "confidence": confidence, "reason": reason, **extra}


def correlate(events: list[dict]) -> list[dict]:
    """Use instrumentation + bounded identities; labels are never consulted.

    A high link requires a unique launch, host, both PIDs, a bounded interval,
    an observed matching worker ProcessGuid and its matching start time.
    Descendants inherit only GUID-backed attribution, never a nearby timestamp.
    """
    processes = [event for event in events if event.get("source") == "sysmon"
                 and event.get("event_id") == 1 and event.get("process_guid")]
    by_guid = {}
    time_indexes = {}
    children = {}
    for process in processes:
        by_guid.setdefault(_key(process), []).append(process)
        children.setdefault(_key(process, "parent_process_guid"), []).append(process)
        created = _time(process.get("timestamp"))
        if created is not None:
            for index in ((_host(process), None, None), (_host(process), process.get("pid"), None),
                          (_host(process), None, process.get("parent_pid")),
                          (_host(process), process.get("pid"), process.get("parent_pid"))):
                time_indexes.setdefault(index, {})[process["evidence_id"]] = (created, process)
    for index, values in time_indexes.items():
        ordered = sorted(values.values(), key=lambda pair: (pair[0], pair[1]["evidence_id"]))
        time_indexes[index] = ([pair[0] for pair in ordered], [pair[1] for pair in ordered])
    launches = [event for event in events if event.get("source") == "application"
                and event.get("request_id") and (event.get("action") == "process_launch"
                or (event.get("child_pid") is not None and event.get("launch_start")))]
    # Ignore report completion records repeating the same launch instrumentation.
    launches = [event for event in launches if event.get("action") != "report_completed"]
    candidates = {}
    process_launches = {}
    for launch in launches:
        start, end = _time(launch.get("launch_start")), _time(launch.get("launch_end"))
        matches = []
        valid_interval = start is not None and end is not None and 0 <= end - start <= MAX_LAUNCH_SECONDS
        if valid_interval and _host(launch):
            child_pid, parent_pid = launch.get("child_pid"), launch.get("parent_pid", launch.get("pid"))
            times, possible = time_indexes.get((_host(launch), child_pid, parent_pid), ([], []))
            begin, finish = bisect_left(times, start - SKEW_SECONDS), bisect_right(times, end + SKEW_SECONDS)
            for process in possible[begin:finish]:
                created = _time(process.get("timestamp"))
                if _host(process) != _host(launch) or created is None or not start - SKEW_SECONDS <= created <= end + SKEW_SECONDS:
                    continue
                if child_pid is not None and child_pid != process.get("pid"):
                    continue
                if parent_pid is not None and parent_pid != process.get("parent_pid"):
                    continue
                parents = by_guid.get(_key(process, "parent_process_guid"), [])
                parent_start = _time(launch.get("parent_start"))
                # A captured contradictory worker identity disproves a PID-only association.
                if len(parents) == 1 and parent_start is not None:
                    observed_start = _time(parents[0].get("timestamp"))
                    if observed_start is not None and abs(observed_start - parent_start) > SKEW_SECONDS:
                        continue
                strong_parent = (len(parents) == 1 and parent_start is not None
                                 and parents[0].get("pid") == parent_pid
                                 and _time(parents[0].get("timestamp")) is not None
                                 and _time(parents[0]["timestamp"]) <= created + SKEW_SECONDS
                                 and abs(_time(parents[0]["timestamp"]) - parent_start) <= SKEW_SECONDS)
                strong = (child_pid is not None and parent_pid is not None and strong_parent
                          and len(by_guid[_key(process)]) == 1 and launch.get("action") == "process_launch"
                          and launch.get("outcome") == "started")
                matches.append((process, parents if strong else [], strong))
                process_launches.setdefault(_key(process), []).append(launch)
        candidates[launch["evidence_id"]] = (matches, valid_interval)
    links = []
    direct = {}
    for launch in launches:
        matches, valid_interval = candidates[launch["evidence_id"]]
        if not matches:
            reason = ("No matching Sysmon process creation: endpoint evidence missing or identities disagree"
                      if valid_interval else "Missing or invalid bounded launch interval; no process attribution")
            links.append(_link([launch], launch["request_id"], None, "low", reason, host=launch.get("host")))
            continue
        for process, parents, strong in matches:
            owners = process_launches[_key(process)]
            ambiguous = len(matches) > 1 or len(owners) > 1 or len(by_guid[_key(process)]) > 1
            if ambiguous:
                confidence = "ambiguous"
                reason = "Multiple viable launch/process identities; concurrency or PID reuse prevents exact attribution"
            elif strong:
                confidence = "high"
                reason = "Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree"
            else:
                confidence = "low"
                reason = ("Time-only association: launch lacks parent or child PID"
                          if launch.get("child_pid") is None or launch.get("parent_pid", launch.get("pid")) is None
                          else "Bounded PID match, but parent ProcessGuid/start identity or confirmed launch outcome is incomplete")
            link = _link([launch, process, *parents, *owners],
                         None if ambiguous else launch["request_id"], process["process_guid"],
                         confidence, reason, host=process.get("host"),
                         candidate_request_ids=sorted({owner["request_id"] for owner in owners}),
                         relation="launch")
            direct.setdefault(_key(process), []).append(link)
    # Combine duplicate candidate links into one process attribution verdict.
    attributed = {}
    for key, entries in direct.items():
        combined = dict(entries[0])
        combined["evidence_ids"] = sorted({value for entry in entries for value in entry["evidence_ids"]})
        combined["candidate_request_ids"] = sorted({value for entry in entries for value in entry["candidate_request_ids"]})
        if len(combined["candidate_request_ids"]) > 1:
            combined.update(confidence="ambiguous", request_id=None)
        attributed[key] = combined
    pending = deque(attributed)
    # GUID adjacency handles unordered records without a quadratic full-tree scan.
    while pending:
        ancestor = pending.popleft()
        for process in children.get(ancestor, []):
            key = _key(process)
            parent_key = _key(process, "parent_process_guid")
            if key in attributed or key == parent_key or parent_key not in attributed:
                continue
            parent_events = by_guid.get(parent_key, [])
            if len(parent_events) != 1 or len(by_guid[key]) != 1:
                continue
            child_time, parent_time = _time(process.get("timestamp")), _time(parent_events[0].get("timestamp"))
            if child_time is None or parent_time is None or child_time < parent_time - SKEW_SECONDS:
                continue
            parent = attributed[parent_key]
            attributed[key] = {**parent, "process_guid": process["process_guid"],
                               "evidence_ids": sorted(set(parent["evidence_ids"] + [process["evidence_id"]])),
                               "reason": "Observed ParentProcessGuid chain; " + parent["reason"],
                               "relation": "descendant"}
            pending.append(key)
    # Attach associated Sysmon file/network records by GUID, not by their proximity in time.
    for event in events:
        key = _key(event)
        if event.get("source") == "sysmon" and key in attributed and event.get("event_id") != 1:
            created = _time(by_guid[key][0].get("timestamp"))
            observed = _time(event.get("timestamp"))
            if created is None or observed is None or observed < created:
                continue
            link = attributed[key]
            link["evidence_ids"] = sorted(set(link["evidence_ids"] + [event["evidence_id"]]))
    links.extend(attributed.values())
    for key, group in by_guid.items():
        if key not in attributed:
            links.append(_link(group, None, group[0]["process_guid"], "unattributed",
                               "No unique instrumented request link; process remains independently observable",
                               host=group[0].get("host"), relation="unattributed"))
    return sorted(links, key=lambda link: (str(link.get("host")), str(link.get("process_guid")), str(link.get("request_id"))))
