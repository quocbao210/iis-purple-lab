"""Evaluation reads ground truth only AFTER running the production detector."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import time

from .normalize import normalize_dataset, read_manifest, safe_path
from .correlate import correlate
from .detection import RULES, baseline_process_alerts, detect, prerequisites
from .report import _write

VIEWS = {
    "iis-only": {"iis"},
    "iis-application": {"iis", "application"},
    "windows-only": {"sysmon", "security", "powershell"},
    "combined": {"iis", "application", "sysmon", "security", "powershell", "sink"},
}


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def metrics(tp, fp, fn, tn):
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "false_positive_case_rate": ratio(fp, fp + tn)}


def references(event):
    return {(x["path"], x["record"]) for x in event.get("source_refs", [event["source_ref"]])}


def evaluate_dataset(dataset: Path, output: Path) -> dict:
    dataset, output = Path(dataset).resolve(), Path(output).resolve()
    if output == dataset or output.is_relative_to(dataset) or dataset.is_relative_to(output):
        raise ValueError("Evaluation output must be separate from the input dataset")
    manifest = read_manifest(dataset)
    # Detector outputs depend only on evidence and configuration, never on the label file.
    runs = {}
    for name, sources in VIEWS.items():
        started = time.perf_counter()
        events = normalize_dataset(dataset, sources)
        links = correlate(events)
        detection = detect(events, links)
        elapsed = time.perf_counter() - started
        runs[name] = (events, links, detection, elapsed)
    truth_path = safe_path(dataset, "ground_truth.json")
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    if truth.get("unit") != "scenario-run" or not isinstance(truth.get("cases"), list):
        raise ValueError("Evaluation requires declared scenario-run cases")
    cases = truth["cases"]
    if len({c["case_id"] for c in cases}) != len(cases):
        raise ValueError("Duplicate ground-truth case identity")
    all_events = runs["combined"][0]
    valid_refs = set().union(*(references(e) for e in all_events)) if all_events else set()
    ownership = {}
    for case in cases:
        if type(case.get("malicious")) is not bool:
            raise ValueError("malicious label must be boolean")
        for ref in case["refs"]:
            key = (ref["path"], ref["record"])
            if key not in valid_refs:
                raise ValueError(f"Ground truth refers to absent evidence: {key}")
            if key in ownership:
                raise ValueError("Evaluation cases must have disjoint source records")
            ownership[key] = case["case_id"]
    for event in all_events:
        owners = {ownership[key] for key in references(event) if key in ownership}
        if len(owners) > 1:
            raise ValueError("Evaluation cases must not share a deduplicated evidence event")
    result = {"origin": manifest.get("origin", "unknown"), "split": manifest.get("split", "unspecified"),
              "unit": "scenario-run", "case_count": len(cases),
              "malicious_cases": sum(c["malicious"] for c in cases),
              "benign_cases": sum(not c["malicious"] for c in cases),
              "ground_truth_sha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
              "live_detection_latency": None,
              "timing_definition": "Offline evidence parsing + correlation + Sigma conversion/query execution; excludes collection/export/report rendering.",
              "limitations": ["Handcrafted fixtures are not empirical native Windows coverage.",
                  "Ground-truth case identifiers are used only for scoring, never attribution.",
                  "Undefined denominators are null. False alerts and false-positive cases are distinct.",
                  "Conditional rule recall excludes unavailable prerequisites; overall coverage includes every planned malicious case.",
                  "No analyst-time, collection CPU overhead, financial benefit or real-time latency study."], "views": {}}
    output.mkdir(parents=True, exist_ok=True)
    for name, (events, links, detection, elapsed) in runs.items():
        by_case = {c["case_id"]: set() for c in cases}
        case_events = {c["case_id"]: [] for c in cases}
        for event in events:
            for key in references(event):
                if key in ownership:
                    case_id = ownership[key]
                    by_case[case_id].add(event["evidence_id"])
                    if event not in case_events[case_id]:
                        case_events[case_id].append(event)
        verdicts, tp, fp, fn, tn, false_alerts = [], 0, 0, 0, 0, 0
        for case in cases:
            ids = by_case[case["case_id"]]
            alerts = [a for a in detection["alerts"] if ids.intersection(a["evidence_ids"])]
            detected = bool(alerts)
            if case["malicious"]:
                tp += detected
                fn += not detected
            else:
                fp += detected
                tn += not detected
                false_alerts += len(alerts)
            high = [l for l in links if l.get("confidence") == "high" and l.get("request_id") == case["request_id"]
                    and ids.intersection(l.get("evidence_ids", []))]
            affected_ids = {eid for a in alerts if a["rule_id"] == "IPL-001" for eid in a["evidence_ids"]}
            verdicts.append({"case_id": case["case_id"], "malicious": case["malicious"], "detected": detected,
                             "rules": sorted({a["rule_id"] for a in alerts}), "alert_count": len(alerts),
                             "high_confidence_process_links": len(high),
                             "observed_resource_ids": sorted({e["resource_id"] for e in case_events[case["case_id"]] if e.get("resource_id")}),
                             "affected_resource_ids": sorted({e["resource_id"] for e in case_events[case["case_id"]] if e.get("resource_id") and e["evidence_id"] in affected_ids})})
        conditional = {}
        case_prerequisites = {key: prerequisites(value) for key, value in case_events.items()}
        for rule in RULES:
            positive, negative, hits, false, unavailable_positive, missed_available = 0, 0, 0, 0, 0, 0
            for case, verdict in zip(cases, verdicts):
                available = case_prerequisites[case["case_id"]][rule]["available"]
                expected = rule in case["expected_rules"]
                if not available:
                    unavailable_positive += expected
                    continue
                positive += expected
                negative += not expected
                matched = rule in verdict["rules"]
                hits += expected and matched
                false += not expected and matched
                missed_available += expected and not matched
            conditional[rule] = {"available_positive_cases": positive, "available_negative_cases": negative,
                                 "unavailable_positive_cases": unavailable_positive,
                                 **metrics(hits, false, missed_available, negative - false)}
        sizes = {source: sum(safe_path(dataset, f["path"]).stat().st_size for f in manifest["files"] if f["source"] == source)
                 for source in VIEWS[name] if any(f["source"] == source for f in manifest["files"])}
        result["views"][name] = {**metrics(tp, fp, fn, tn), "alert_count": len(detection["alerts"]),
            "false_alerts": false_alerts, "false_alerts_per_100_benign_runs": 100 * false_alerts / result["benign_cases"] if result["benign_cases"] else None,
            "processing_seconds": elapsed, "event_counts": dict(Counter(e["source"] for e in events)),
            "source_bytes": sizes, "total_source_bytes": sum(sizes.values()),
            "rule_prerequisites": detection["availability"], "conditional_rules": conditional, "cases": verdicts,
            "attribution": dict(Counter(l["confidence"] for l in links))}
        _write(output, name + "/detector-output.json", json.dumps(detection, indent=2) + "\n")
    events, _, detection, _ = runs["combined"]
    baseline = set(baseline_process_alerts(events))
    tuned = {eid for alert in detection["alerts"] if alert["rule_id"] == "IPL-002" for eid in alert["evidence_ids"]}
    comparison = {}
    for method, matched in [("basic-any-worker-child", baseline), ("tuned-interpreter-child", tuned)]:
        tp = fp = fn = tn = 0
        for case in cases:
            # Same defined population: report cases, including separate uninstrumented path.
            if case["family"] not in {"B", "C"}:
                continue
            ids = {e["evidence_id"] for e in events if references(e).intersection({(r["path"], r["record"]) for r in case["refs"]})}
            hit = bool(ids & matched)
            if case["malicious"]:
                tp += hit; fn += not hit
            else:
                fp += hit; tn += not hit
        comparison[method] = metrics(tp, fp, fn, tn)
    result["process_rule_comparison"] = comparison
    _write(output, "evaluation.json", json.dumps(result, indent=2) + "\n")
    lines = ["# Telemetry comparison", "", f"Origin: **{result['origin']}**; split: {result['split']}. NOT a native Windows benchmark.", "",
             f"Unit: one scenario run. {result['malicious_cases']} malicious and {result['benign_cases']} benign runs. Components and combined incidents count once for case coverage.", "",
             "| View | TP | FP cases | FN | TN | Precision | Recall | False alerts | Source bytes | Replay seconds |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    def fmt(value):
        return "undefined" if value is None else f"{value:.3f}"
    for name, view in result["views"].items():
        lines.append(f"| {name} | {view['tp']} | {view['fp']} | {view['fn']} | {view['tn']} | {fmt(view['precision'])} | {fmt(view['recall'])} | {view['false_alerts']} | {view['total_source_bytes']} | {view['processing_seconds']:.6f} |")
    lines += ["", "The same files are filtered before parsing for each view. IIS-only establishes request metadata, not tenant policy or host consequences. Application context reveals policy decisions and resource identity. Windows-only reveals process activity but cannot recover application actor/resource context. Combined attribution requires independently matching launch identities.", "",
              "## Detection improvement", "", "Same report-run cases; baseline alerts on every worker child, tuned rule requires an interpreter. Benign maintenance that actually uses a shell still alerts.", "",
              "| Method | TP | FP | FN | TN |", "| --- | ---: | ---: | ---: | ---: |"]
    for name, value in comparison.items():
        lines.append(f"| {name} | {value['tp']} | {value['fp']} | {value['fn']} | {value['tn']} |")
    lines += ["", "See [machine-readable metrics](evaluation.json) for per-rule prerequisite availability, conditional performance, case verdicts, links and source counts. Offline processing excludes export and rendering; live detection latency is not measured.", "",
              "Blind spots: the unlogged policy case is missed even in the combined view; uninstrumented execution stays unattributed. Synthetic hosts, paths, users, identifiers and order differ between development and held-out splits, but both use one handcrafted behavioural model. These are held-out fixture checks, not independent external validation.", ""]
    _write(output, "evaluation.md", "\n".join(lines))
    return result
