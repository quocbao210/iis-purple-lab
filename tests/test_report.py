import hashlib
import json
import re

import pytest

from iis_purple.normalize import EvidenceError, normalize_dataset
from iis_purple.report import write_report


def setup_dataset(tmp_path):
    root = tmp_path / "dataset"
    root.mkdir()
    raw = {"timestamp": "2026-09-19T01:00:00Z", "source": "application", "host": "LAB",
           "action": '<script>alert("x")</script>', "request_id": "request", "actor": "[user](javascript:alert(1))"}
    (root / "app.jsonl").write_text(json.dumps(raw))
    (root / "manifest.json").write_text(json.dumps({"origin": "handcrafted-fixture", "files": [
        {"path": "app.jsonl", "source": "application", "format": "jsonl"}]}))
    events = normalize_dataset(root)
    detection = {"alerts": [{"rule_id": "test", "severity": "medium", "kind": "policy",
                             "reason": '<img src=x onerror="alert(1)">', "request_id": "request",
                             "evidence_ids": [events[0]["evidence_id"]]}], "availability": {"test": {"available": True}}}
    return root, events, detection


def test_html_escapes_untrusted_values_links_resolve_and_hashes_verify(tmp_path):
    root, events, detection = setup_dataset(tmp_path)
    out = tmp_path / "report"
    bundle = write_report(events, [], detection, out, root)
    report = (out / "report.html").read_text()
    assert '<script>alert("x")</script>' not in report
    assert '<img src=x onerror="alert(1)">' not in report
    assert "&lt;script&gt;" in report
    ids = set(re.findall(r'id="(e-[a-f0-9]+)"', report))
    targets = set(re.findall(r'href="#(e-[a-f0-9]+)"', report))
    assert targets and targets <= ids
    assert 'href="original/app.jsonl"' in report
    assert (out / "original/app.jsonl").read_bytes() == (root / "app.jsonl").read_bytes()
    for entry in bundle["originals"] + bundle["generated"] + bundle["rules"]:
        assert hashlib.sha256((out / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    assert bundle["origin"] == "handcrafted-fixture"
    assert "not proof of native Windows" in report


def test_missing_evidence_rejected_instead_of_broken_conclusion_link(tmp_path):
    root, events, detection = setup_dataset(tmp_path)
    detection["alerts"][0]["evidence_ids"] = ["e-" + "0" * 24]
    with pytest.raises(EvidenceError, match="absent"):
        write_report(events, [], detection, tmp_path / "out", root)


def test_evidence_change_between_analysis_and_bundle_rejected(tmp_path):
    root, events, detection = setup_dataset(tmp_path)
    (root / "app.jsonl").write_text("tampered")
    with pytest.raises(EvidenceError, match="changed"):
        write_report(events, [], detection, tmp_path / "out", root)


def test_rule_change_between_detection_and_bundle_rejected(tmp_path):
    root, events, detection = setup_dataset(tmp_path)
    detection["rule_versions"] = {"analysis/iis_purple/detection.py": "0" * 64}
    with pytest.raises(EvidenceError, match="rule changed"):
        write_report(events, [], detection, tmp_path / "out", root)


def test_output_cannot_overwrite_dataset(tmp_path):
    root, events, detection = setup_dataset(tmp_path)
    with pytest.raises(EvidenceError, match="separate"):
        write_report(events, [], detection, root, root)


def test_markdown_escapes_injected_links(tmp_path):
    root, events, detection = setup_dataset(tmp_path)
    detection["alerts"][0]["reason"] = "[click](javascript:alert(1)) | forged\n# heading"
    out = tmp_path / "out"
    write_report(events, [], detection, out, root)
    md = (out / "report.md").read_text()
    assert "[click](javascript:alert(1))" not in md
    assert r"\[click\]" in md
    assert "\n# heading" not in md


def test_existing_report_symlink_cannot_overwrite_external_file(tmp_path):
    root, events, detection = setup_dataset(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    outside = tmp_path / "reviewer-notes.html"
    outside.write_text("preserve user work")
    (out / "report.html").symlink_to(outside)
    with pytest.raises(EvidenceError, match="symlink"):
        write_report(events, [], detection, out, root)
    assert outside.read_text() == "preserve user work"
