import json
from pathlib import Path
import shutil

import pytest

from iis_purple.evaluation import evaluate_dataset

DATA = Path(__file__).resolve().parents[1] / "datasets/fixtures/heldout"


def test_same_population_source_ablation_and_no_double_count(tmp_path):
    result = evaluate_dataset(DATA, tmp_path / "result")
    assert result["case_count"] == 19
    assert result["malicious_cases"] == 7
    views = result["views"]
    assert views["iis-only"]["tp"] == 0
    assert views["iis-application"]["tp"] == 2
    assert views["windows-only"]["tp"] == 4
    assert views["combined"]["tp"] == 6
    assert views["combined"]["fn"] == 1
    assert views["combined"]["fp"] == 1
    assert views["combined"]["alert_count"] > views["combined"]["tp"]
    assert views["iis-only"]["precision"] is None
    assert set(views["windows-only"]["event_counts"]) == {"sysmon"}
    assert all(not c["affected_resource_ids"] for c in views["windows-only"]["cases"])
    conditional = views["combined"]["conditional_rules"]["IPL-001"]
    assert conditional["unavailable_positive_cases"] == 1
    assert conditional["recall"] == 1
    baseline, tuned = result["process_rule_comparison"].values()
    assert baseline["tp"] == tuned["tp"] == 4
    assert baseline["fp"] > tuned["fp"] == 1


def test_labels_change_scoring_never_detector_output(tmp_path):
    data = tmp_path / "data"
    shutil.copytree(DATA, data)
    evaluate_dataset(data, tmp_path / "before")
    truth = json.loads((data / "ground_truth.json").read_text())
    for case in truth["cases"]:
        case["malicious"] = not case["malicious"]
        case["expected_rules"] = []
    (data / "ground_truth.json").write_text(json.dumps(truth))
    evaluate_dataset(data, tmp_path / "after")
    for view in ("iis-only", "iis-application", "windows-only", "combined"):
        assert (tmp_path / "before" / view / "detector-output.json").read_bytes() == (tmp_path / "after" / view / "detector-output.json").read_bytes()


def test_same_deduplicated_event_cannot_be_scored_as_two_cases(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    event = json.dumps({"timestamp": "2026-09-19T01:00:00Z", "action": "ticket_access"})
    (data / "application.jsonl").write_text(event + "\n" + event + "\n", encoding="utf-8")
    (data / "manifest.json").write_text(json.dumps({"files": [
        {"path": "application.jsonl", "source": "application", "format": "jsonl"}
    ]}), encoding="utf-8")
    (data / "ground_truth.json").write_text(json.dumps({"unit": "scenario-run", "cases": [
        {"case_id": str(index), "malicious": False,
         "refs": [{"path": "application.jsonl", "record": index}]}
        for index in (1, 2)
    ]}), encoding="utf-8")
    with pytest.raises(ValueError, match="deduplicated evidence"):
        evaluate_dataset(data, tmp_path / "result")
