"""Generate self-contained, escaped investigations and integrity manifests."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import platform
import re
from urllib.parse import quote

from . import __version__
from .normalize import EvidenceError, read_manifest, safe_path


def _json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _md(value: object) -> str:
    text = _escape(value).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_{\}\[\]()#+.!|>~-])", r"\\\1", text)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(output: Path, name: str, data: bytes | str) -> None:
    """Constrain every write, including an existing report symlink, to the bundle."""
    target = output / name
    if not target.resolve().is_relative_to(output):
        raise EvidenceError("Report destination symlink escapes output")
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        target.write_bytes(data)
    else:
        target.write_text(data, encoding="utf-8")


def _evidence_links(ids: list[str], *, markdown: bool = False) -> str:
    if markdown:
        return ", ".join(f"[{value}](report.html#{value})" for value in ids)
    return " ".join(f'<a class="evidence-link" href="#{value}">{value}</a>' for value in ids)


def _original_url(ref: dict) -> str:
    return "original/" + quote(ref["path"], safe="/")


def write_report(events: list[dict], links: list[dict], detection: dict,
                 output: Path, dataset: Path | None = None) -> dict:
    """Write a review bundle; conclusions link only to records actually present.

    The bundle retains originals. Their hashes establish subsequent integrity,
    not the truthfulness or completeness of the original event producer.
    """
    output = Path(output).resolve()
    if dataset is not None:
        dataset = Path(dataset).resolve()
        if output == dataset or output.is_relative_to(dataset) or dataset.is_relative_to(output):
            raise EvidenceError("Report output must be separate from the input dataset")
    ids = {event["evidence_id"] for event in events}
    if len(ids) != len(events) or any(not re.fullmatch(r"e-[a-f0-9]{24}", value) for value in ids):
        raise EvidenceError("Invalid or duplicate normalized evidence IDs")
    for item in [*links, *detection.get("alerts", [])]:
        if any(evidence_id not in ids for evidence_id in item.get("evidence_ids", [])):
            raise EvidenceError("Report conclusion references an absent evidence record")
    output.mkdir(parents=True, exist_ok=True)
    source_manifest = read_manifest(dataset) if dataset else {}
    originals = []
    used = {ref["path"]: ref for event in events for ref in event.get("source_refs", [event["source_ref"]])}
    if dataset:
        # Include available declared empty sources too, while omitting excluded sources.
        included_sources = {event["source"] for event in events}
        for entry in source_manifest["files"]:
            if entry.get("source") in included_sources and entry["path"] not in used:
                used[entry["path"]] = {"path": entry["path"], "sha256": entry.get("sha256")}
        for name, ref in sorted(used.items()):
            data = safe_path(dataset, name).read_bytes()
            digest = _hash(data)
            if ref.get("sha256") and ref["sha256"] != digest:
                raise EvidenceError("Original evidence changed after normalization")
            _write(output, "original/" + name, data)
            originals.append({"path": "original/" + name, "sha256": digest, "bytes": len(data)})
        _write(output, "source-manifest.json", _json(source_manifest))
    alerts = detection.get("alerts", [])
    for name, value in {"events.json": events, "alerts.json": alerts,
                        "correlation.json": links, "availability.json": detection.get("availability", {}),
                        "detection-policy.json": detection.get("policy", {})}.items():
        _write(output, name, _json(value))
    rule_files = []
    repo = Path(__file__).resolve().parents[2]
    candidates = [repo / "analysis/iis_purple/detection.py", repo / "analysis/iis_purple/correlate.py"]
    for folder in (repo / "detections/sigma", repo / "detections/correlation"):
        if folder.is_dir():
            candidates.extend(path for path in folder.rglob("*") if path.is_file() and path.suffix in {".yml", ".yaml", ".json", ".sql", ".py"})
    for path in sorted(set(candidates)):
        if path.is_file():
            data = path.read_bytes()
            relative = path.relative_to(repo).as_posix()
            expected_hash = detection.get("rule_versions", {}).get(relative)
            if expected_hash is not None and expected_hash != _hash(data):
                raise EvidenceError("Detection rule changed after analysis")
            name = "rules/" + relative
            _write(output, name, data)
            rule_files.append({"path": name, "sha256": _hash(data)})
    origin = source_manifest.get("origin", "unspecified — no capture provenance supplied")
    title = "IIS Purple Lab · Evidence investigation"
    affected = {field: sorted({str(event[field]) for event in events if event.get(field) is not None})
                for field in ("actor", "actor_tenant", "resource_id", "resource_tenant", "process_guid")}
    counts = {level: sum(link["confidence"] == level for link in links)
              for level in ("high", "ambiguous", "low", "unattributed")}
    timeline = []
    evidence_blocks = []
    for event in events:
        identity = event.get("action") or event.get("image") or event.get("uri_stem") or f"Event {event.get('event_id', '?')}"
        ref = event["source_ref"]
        original = (f'<a href="{_escape(_original_url(ref))}">original: {_escape(ref["path"])} · record {_escape(ref["record"])}</a>'
                    if dataset else "Original source not bundled")
        timeline.append(f'<tr data-source="{_escape(event["source"])}"><td>{_escape(event["timestamp"])}</td>'
                        f'<td>{_escape(event["source"])}</td><td>{_escape(identity)}</td>'
                        f'<td>{_evidence_links([event["evidence_id"]])}</td></tr>')
        evidence_blocks.append(f'<details class="record" id="{event["evidence_id"]}"><summary>'
                               f'{event["evidence_id"]} · {_escape(event["source"])} · {_escape(identity)}</summary>'
                               f'<p>{original}</p><pre>{_escape(_json(event))}</pre></details>')
    alert_blocks = []
    for alert in alerts:
        alert_blocks.append('<article class="alert"><p class="eyebrow">' + _escape(alert.get("severity", "unknown"))
                            + " · " + _escape(alert.get("kind", "finding")) + '</p><h3>'
                            + _escape(alert.get("rule_id", "unknown")) + '</h3><p>'
                            + _escape(alert.get("reason", "")) + '</p><p>Request: '
                            + _escape(alert.get("request_id") or "not attributed") + '</p>'
                            + _evidence_links(alert.get("evidence_ids", [])) + '</article>')
    link_rows = []
    for link in links:
        link_rows.append('<tr><td>' + _escape(link.get("process_guid") or "no process observed")
                         + '</td><td>' + _escape(link.get("request_id") or "not attributed")
                         + '</td><td>' + _escape(link["confidence"]) + '</td><td>'
                         + _escape(link["reason"]) + '<br>' + _evidence_links(link["evidence_ids"]) + '</td></tr>')
    process_rows = []
    for event in events:
        if event.get("source") == "sysmon" and event.get("event_id") == 1:
            process_rows.append('<tr><td>' + _escape(event.get("host", "unknown")) + '</td><td>'
                                + _escape(event.get("parent_process_guid", "missing")) + '</td><td>'
                                + _escape(event.get("process_guid", "missing")) + '</td><td>'
                                + _escape(event.get("image", "unknown")) + '</td><td>'
                                + _evidence_links([event["evidence_id"]]) + '</td></tr>')
    html_report = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>''' + title + '''</title><style>
:root{color-scheme:light dark;--bg:#f7f6fc;--panel:#fff;--ink:#24213a;--sub:#625c78;--line:#d9d3eb;--accent:#6339ad}
@media(prefers-color-scheme:dark){:root{--bg:#14111d;--panel:#211c2c;--ink:#f0edf6;--sub:#b6afc8;--line:#443952;--accent:#bd9bed}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}main{max-width:1220px;margin:auto;padding:36px 24px}h1{font-size:clamp(2rem,5vw,3.8rem);letter-spacing:-.04em;line-height:1.1}h2{margin-top:40px}a{color:var(--accent);overflow-wrap:anywhere}.eyebrow{color:var(--accent);font-size:.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}.muted{color:var(--sub)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}.card,.alert,.record{border:1px solid var(--line);background:var(--panel);border-radius:12px;padding:18px}.card b{display:block;font-size:2rem}.alert{margin:14px 0}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:.88rem}th,td{text-align:left;vertical-align:top;padding:11px;border-bottom:1px solid var(--line)}th{color:var(--sub)}pre{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8rem}summary{cursor:pointer;font-weight:600;overflow-wrap:anywhere}.record{margin:10px 0}.record:target{outline:2px solid var(--accent)}.evidence-link{display:inline-block;font-family:monospace;font-size:.75rem;margin-right:8px}select{padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink)}nav{display:flex;gap:18px;flex-wrap:wrap}footer{margin-top:36px;color:var(--sub);font-size:.85rem}
</style></head><body><main><header><p class="eyebrow">Portable investigation · Quoc Bao Huynh</p><h1>Requests, processes,<br>and the evidence between.</h1><p class="muted">''' + _escape(origin) + '''</p><nav><a href="#findings">Findings</a><a href="#timeline">Timeline</a><a href="#attribution">Attribution</a><a href="#evidence">Evidence</a><a href="bundle-manifest.json">Integrity manifest</a></nav></header>
<p>This report describes supplied records. Fixture results are not proof of native Windows execution. Missing telemetry is unknown, and absence of an alert does not prove absence of exploitation.</p>
<div class="cards"><div class="card"><b>''' + str(len(events)) + '''</b>normalized records</div><div class="card"><b>''' + str(len(alerts)) + '''</b>alerts, including components</div><div class="card"><b>''' + str(counts["high"]) + '''</b>high confidence process links</div><div class="card"><b>''' + str(counts["ambiguous"]) + '''</b>ambiguous process links</div></div>
<h2 id="findings">Observed findings</h2>''' + ("".join(alert_blocks) or '<p>No rules produced an alert. Inspect prerequisite availability before interpreting this result.</p>') + '''
<details><summary>Rule prerequisite availability</summary><pre>''' + _escape(_json(detection.get("availability", {}))) + '''</pre></details>
<h2>Scope and analyst decisions</h2><p>Listed identities and resources are observed in the supplied dataset; they are not all confirmed affected assets. Each finding has its own supporting records. A process association is an inference with the stated confidence. File creation is not file-read evidence; a connection is not proof of data transfer.</p><details><summary>Observed identities and resources</summary><pre>''' + _escape(_json(affected)) + '''</pre></details>
<p>Preserve original events and relevant application artefacts before cleanup. Check legitimate export or maintenance explanations against the documented policy. Confirm the affected request and process before considering the dedicated lab application-pool containment action; containment is not performed by this report. Review the scenario case reports for remediation and retest evidence.</p>
<h2 id="timeline">UTC event timeline</h2><label for="source-filter">Source </label><select id="source-filter"><option value="">All available sources</option>''' + "".join(f'<option value="{_escape(source)}">{_escape(source)}</option>' for source in sorted({event["source"] for event in events})) + '''</select><div class="table-wrap"><table id="timeline-table"><thead><tr><th>Event time (UTC)</th><th>Source</th><th>Observation</th><th>Evidence</th></tr></thead><tbody>''' + "".join(timeline) + '''</tbody></table></div>
<h2 id="attribution">Request-to-process confidence</h2><div class="table-wrap"><table><thead><tr><th>ProcessGuid</th><th>Request</th><th>Confidence</th><th>Basis / limitation</th></tr></thead><tbody>''' + "".join(link_rows) + '''</tbody></table></div>
<h2>Observed process ancestry</h2><p>Edges below are recorded GUID relationships. Missing parents are not invented.</p><div class="table-wrap"><table><thead><tr><th>Host</th><th>ParentProcessGuid</th><th>ProcessGuid</th><th>Image</th><th>Evidence</th></tr></thead><tbody>''' + "".join(process_rows) + '''</tbody></table></div>
<h2 id="evidence">Evidence records and original sources</h2>''' + "".join(evidence_blocks) + '''
<footer>Hashing detects later changes; it does not establish that a compromised host originally reported the truth. Collection time is retained separately from event time in each normalized record. No commands contained in event data are executed by this pipeline.</footer></main><script>
document.getElementById('source-filter').addEventListener('change',function(){const source=this.value;document.querySelectorAll('#timeline-table tbody tr').forEach(row=>{row.hidden=!!source&&row.dataset.source!==source;});});
function openEvidence(){const id=location.hash.slice(1);const node=document.getElementById(id);if(node&&node.tagName==='DETAILS')node.open=true;}window.addEventListener('hashchange',openEvidence);openEvidence();
</script></body></html>'''
    markdown = ["# IIS Purple Lab investigation", "", f"Dataset origin: {_md(origin)}.", "",
                f"Observed {len(events)} records and {len(alerts)} alerts (including component alerts, not independent attack counts).",
                "Fixture replay does not establish native Windows execution. Missing sources remain unknown.", "",
                "## Findings", ""]
    for alert in alerts:
        markdown.extend([f"- {_md(alert.get('rule_id'))} ({_md(alert.get('severity'))}): {_md(alert.get('reason'))}. "
                         + _evidence_links(alert.get("evidence_ids", []), markdown=True)])
    if not alerts:
        markdown.append("No alerts; review prerequisite availability in [availability.json](availability.json).")
    markdown.extend(["", "## UTC timeline", "", "| Event time | Source | Observation | Evidence |", "| --- | --- | --- | --- |"])
    for event in events:
        identity = event.get("action") or event.get("image") or event.get("uri_stem") or f"Event {event.get('event_id', '?')}"
        markdown.append(f"| {_md(event['timestamp'])} | {_md(event['source'])} | {_md(identity)} | {_evidence_links([event['evidence_id']], markdown=True)} |")
    markdown.extend(["", "## Attribution and uncertainty", ""])
    for link in links:
        markdown.append(f"- {_md(link.get('process_guid') or 'No process observed')}: {_md(link['confidence'])}; {_md(link['reason'])}. " + _evidence_links(link["evidence_ids"], markdown=True))
    markdown.extend(["", "## Preservation and response", "", "Preserve originals before cleanup. Confirm policy and legitimate maintenance explanations. Use only the project-scoped, dry-run containment workflow after verifying the affected application pool. A file-create event does not prove a file read; a network event does not prove data transfer.", "", "[Normalized records](events.json) · [Observed alerts](alerts.json) · [Correlation](correlation.json) · [Integrity manifest](bundle-manifest.json)", "", "Hashes protect subsequent integrity, not the original producer's truthfulness. See scenario case reports for verified remediation and retest findings.", ""])
    _write(output, "report.html", html_report)
    _write(output, "report.md", "\n".join(markdown))
    generated = []
    for name in ("report.html", "report.md", "events.json", "alerts.json", "correlation.json", "availability.json", "source-manifest.json", "detection-policy.json"):
        path = output / name
        if path.exists():
            generated.append({"path": name, "sha256": _hash(path.read_bytes()), "bytes": path.stat().st_size})
    bundle = {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
              "pipeline_version": __version__, "python_version": platform.python_version(),
              "origin": origin, "collection_metadata": source_manifest,
              "counts": {"events": len(events), "alerts": len(alerts), "links": counts},
              "originals": originals, "rules": rule_files, "rule_versions_at_detection": detection.get("rule_versions", {}), "generated": generated,
              "integrity_limit": "Hashes do not prove the original event producer reported truthfully."}
    _write(output, "bundle-manifest.json", _json(bundle))
    return bundle
