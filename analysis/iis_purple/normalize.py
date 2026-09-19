"""Read declared evidence only; never execute strings found in an event.

XML fixtures exercise the Windows Event schema; they are not native captures.
Limits are deliberate and failures are explicit rather than silently losing evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import parse_qsl, urlencode
import xml.etree.ElementTree as ET

SOURCES = frozenset({"application", "iis", "sysmon", "security", "powershell", "sink"})
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_EVENTS = 250_000
SECRET_KEYS = frozenset({"password", "passwd", "token", "access_token", "refresh_token", "authorization", "cookie", "session", "sessionid", "api_key", "secret"})


class EvidenceError(ValueError):
    """A dataset is malformed, exceeds a bound, or fails an integrity check."""


def utc(value: object, *, allow_naive: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError("Event timestamp must be a nonempty ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"Invalid ISO timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        if not allow_naive:
            raise EvidenceError("Timestamp has no UTC offset")
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def safe_path(dataset: Path, name: str) -> Path:
    """Reject traversal, Windows drives, absolute paths, and escaping symlinks."""
    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        raise EvidenceError("Evidence path must be a relative POSIX path")
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise EvidenceError("Evidence path escapes the dataset")
    root = dataset.resolve()
    target = (root / str(relative)).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise EvidenceError(f"Evidence file missing or outside dataset: {name}")
    return target


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"Duplicate JSON property: {key}")
        result[key] = value
    return result


def _json(text: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(EvidenceError(f"Invalid JSON constant {value}")))
    except (ValueError, RecursionError) as exc:
        raise EvidenceError(f"Invalid evidence JSON: {exc}") from exc


def read_manifest(dataset: Path) -> dict:
    path = safe_path(dataset, "manifest.json")
    if path.stat().st_size > MAX_RECORD_BYTES:
        raise EvidenceError("Manifest exceeds 1 MiB")
    manifest = _json(path.read_text(encoding="utf-8-sig"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise EvidenceError("Manifest must contain a files array")
    return manifest


def _snake(name: str) -> str:
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).replace("-", "_").lower()


ALIASES = {
    "utc_time": "timestamp", "time_created": "timestamp", "computer": "host",
    "process_id": "pid", "parent_process_id": "parent_pid", "new_process_id": "pid",
    "new_process_name": "image", "creator_process_id": "parent_pid",
    "event_record_id": "record_id", "version": "event_version",
    "process_command_line": "command_line", "target_file_name": "target_filename",
    "child_process_id": "child_pid", "application_process_id": "parent_pid",
    "script_block_text": "script_text", "message_number": "fragment_number",
    "message_total": "fragment_count", "subject_user_name": "user",
}
FIELDS = frozenset("""timestamp system_timestamp host provider channel event_id event_version record_id emitter_pid emitter_tid
process_guid parent_process_guid pid parent_pid image parent_image command_line
parent_command_line target_filename destination_ip destination_port destination_hostname
source_ip source_port protocol initiated user integrity_level hashes current_directory
actor actor_tenant resource_id resource_tenant attachment_id role shared_with policy_allowed request_id
client_request_id job_id action outcome child_pid launch_start launch_end parent_start
app_root data_root method uri_stem uri_query status substatus win32_status client_ip
server_ip server_port time_taken script_block_id script_text fragment_number fragment_count
sha256 content_sha256 artifact_sha256 bytes length name filename artifact_path expected_sha256
received_sha256 sink_url path authentication_type exit_code executable arguments report_title peer artifact
""".split())
INT_FIELDS = frozenset({"pid", "parent_pid", "child_pid", "event_id", "event_version", "record_id", "emitter_pid", "emitter_tid", "destination_port", "source_port", "server_port", "status", "substatus", "win32_status", "time_taken", "fragment_number", "fragment_count", "bytes", "length", "exit_code"})


def _integer(value: object) -> int:
    if isinstance(value, bool):
        raise EvidenceError("Boolean supplied as an integer")
    try:
        if isinstance(value, int):
            return value
        if not isinstance(value, str) or not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", value):
            raise ValueError()
        return int(value, 16 if value.lower().startswith("0x") else 10)
    except (ValueError, TypeError) as exc:
        raise EvidenceError(f"Invalid numeric event field: {value!r}") from exc


def _redact_query(value: str) -> str:
    return urlencode([(key, "[REDACTED]" if key.lower() in SECRET_KEYS else val)
                      for key, val in parse_qsl(value, keep_blank_values=True)])


def _normal(raw: dict, source: str, collected_at: str | None, ref: dict) -> dict:
    event = {"source": source, "collected_at": collected_at, "source_ref": ref}
    for key, value in raw.items():
        name = ALIASES.get(_snake(key), _snake(key))
        if source == "security" and any(_snake(field) == "new_process_id" for field in raw):
            if _snake(key) == "process_id":
                name = "parent_pid"
            elif _snake(key) == "process_name":
                name = "parent_image"
        if name not in FIELDS or value is None or value == "-":
            continue
        if name in event and event[name] != value:
            raise EvidenceError(f"Conflicting aliases for {name}")
        if name in INT_FIELDS:
            value = _integer(value)
        elif name == "policy_allowed":
            if not isinstance(value, bool):
                raise EvidenceError("policy_allowed must be a JSON boolean")
        elif name == "shared_with":
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise EvidenceError("shared_with must be a list of tenant identifiers")
        elif isinstance(value, (dict, list, bool)):
            raise EvidenceError(f"Expected scalar event field: {name}")
        elif not isinstance(value, (str, int, float)):
            raise EvidenceError(f"Unsupported event field type: {name}")
        if name in {"process_guid", "parent_process_guid"}:
            value = str(value).lower()
        if name in {"timestamp", "system_timestamp", "launch_start", "launch_end", "parent_start"}:
            value = utc(value, allow_naive=source == "sysmon")
        if name == "uri_query":
            value = _redact_query(str(value))
        event[name] = value
    if "timestamp" not in event:
        raise EvidenceError(f"Missing event timestamp in {ref}")
    if source == "powershell" and "emitter_pid" in event:
        event.setdefault("pid", event["emitter_pid"])
    canonical = {key: val for key, val in event.items() if key not in {"source_ref", "collected_at"}}
    if source == "iis":
        # W3C has no event identity and second-resolution timestamps. Identical
        # adjacent lines may represent separate legitimate requests, not duplicates.
        canonical["w3c_record_identity"] = {"path": ref["path"], "record": ref["record"]}
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    event["evidence_id"] = "e-" + digest[:24]
    return event


def _xml_records(text: str) -> list[dict]:
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.IGNORECASE):
        raise EvidenceError("DTD/entity declarations are forbidden in event XML")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, RecursionError) as exc:
        raise EvidenceError(f"Malformed event XML: {exc}") from exc
    pending = [(root, 0)]
    while pending:
        element, depth = pending.pop()
        if depth > 32:
            raise EvidenceError("Event XML nesting exceeds 32 levels")
        pending.extend((child, depth + 1) for child in element)
    local = lambda tag: tag.rsplit("}", 1)[-1]
    nodes = [root] if local(root.tag) == "Event" else list(root)
    if local(root.tag) not in {"Event", "Events"} or any(local(node.tag) != "Event" for node in nodes):
        raise EvidenceError("Expected Event or Events XML root")
    records = []
    for node in nodes:
        if len(ET.tostring(node)) > MAX_RECORD_BYTES:
            raise EvidenceError("XML event exceeds 1 MiB")
        parts = {local(child.tag): child for child in node}
        system = parts.get("System")
        if system is None:
            raise EvidenceError("Event XML has no System section")
        record = {}
        for child in system:
            tag = local(child.tag)
            if tag == "Provider":
                record["provider"] = child.attrib.get("Name")
            elif tag == "TimeCreated":
                record["timestamp"] = child.attrib.get("SystemTime")
                record["system_timestamp"] = child.attrib.get("SystemTime")
            elif tag == "Execution":
                record["emitter_pid"] = child.attrib.get("ProcessID")
                record["emitter_tid"] = child.attrib.get("ThreadID")
            elif tag in {"EventID", "Version", "EventRecordID", "Channel", "Computer"}:
                record[tag] = child.text
        event_data = parts.get("EventData")
        if event_data is not None:
            seen_fields = set()
            for child in event_data:
                name = child.attrib.get("Name")
                if not name or name in record or name in seen_fields:
                    raise EvidenceError("EventData contains missing/duplicate field name")
                seen_fields.add(name)
                # System timestamps remain event time; Sysmon's UtcTime is checked separately.
                if name == "UtcTime":
                    if utc(child.text, allow_naive=True) != utc(record.get("timestamp")):
                        record["timestamp"] = utc(child.text, allow_naive=True)
                    continue
                record[name] = child.text
        records.append(record)
    return records


def _w3c_records(text: str):
    fields = None
    mapping = {"cs-method": "method", "cs-uri-stem": "uri_stem", "cs-uri-query": "uri_query",
               "sc-status": "status", "sc-substatus": "substatus", "sc-win32-status": "win32_status",
               "c-ip": "client_ip", "s-ip": "server_ip", "s-port": "server_port",
               "s-computername": "host", "time-taken": "time_taken",
               "cs(X-Request-ID)": "client_request_id", "sc(X-Request-ID)": "request_id"}
    for line_no, line in enumerate(text.splitlines(), 1):
        if len(line.encode()) > MAX_RECORD_BYTES:
            raise EvidenceError("W3C record exceeds 1 MiB")
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:"):].split()
            if len(fields) != len(set(fields)) or not {"date", "time"}.issubset(fields):
                raise EvidenceError("W3C #Fields must contain unique fields including date and time")
        elif line.strip() and not line.startswith("#"):
            if fields is None:
                raise EvidenceError("W3C data before #Fields header")
            values = line.split()
            if len(values) != len(fields):
                raise EvidenceError(f"W3C field count mismatch at line {line_no}")
            raw = dict(zip(fields, values))
            event = {mapping[key]: value for key, value in raw.items() if key in mapping}
            event["timestamp"] = raw["date"] + "T" + raw["time"] + "Z"
            yield line_no, event


def normalize_dataset(dataset: Path, sources: set[str] | None = None) -> list[dict]:
    """Normalise declared sources; remove excluded sources before opening their files."""
    dataset = Path(dataset)
    if sources is not None and not set(sources).issubset(SOURCES):
        raise EvidenceError("Unknown requested source")
    manifest = read_manifest(dataset)
    collected_at = utc(manifest["collected_at"]) if manifest.get("collected_at") else None
    events = {}
    for entry in manifest["files"]:
        if not isinstance(entry, dict):
            raise EvidenceError("Manifest file entries must be objects")
        source = entry.get("source")
        if not isinstance(source, str):
            raise EvidenceError("Manifest source must be a string")
        if sources is not None and source not in sources:
            continue
        if source not in SOURCES:
            raise EvidenceError(f"Unknown evidence source: {source}")
        path = safe_path(dataset, entry.get("path"))
        if path.stat().st_size > MAX_FILE_BYTES:
            raise EvidenceError("Evidence file exceeds 64 MiB; split it before replay")
        data = path.read_bytes()
        actual_hash = hashlib.sha256(data).hexdigest()
        if entry.get("sha256") is not None and (not isinstance(entry["sha256"], str) or not re.fullmatch(r"[a-fA-F0-9]{64}", entry["sha256"])):
            raise EvidenceError("Manifest SHA-256 must contain 64 hexadecimal digits")
        if entry.get("sha256") and entry["sha256"].lower() != actual_hash:
            raise EvidenceError(f"Evidence SHA-256 mismatch: {entry['path']}")
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise EvidenceError("Evidence must be exported as UTF-8") from exc
        fmt = entry.get("format")
        if fmt == "jsonl":
            records = []
            for number, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                if len(line.encode()) > MAX_RECORD_BYTES:
                    raise EvidenceError("JSONL record exceeds 1 MiB")
                raw = _json(line)
                if not isinstance(raw, dict):
                    raise EvidenceError("JSONL event must be an object")
                records.append((number, raw))
        elif fmt == "w3c":
            records = _w3c_records(text)
        elif fmt == "event_xml":
            records = enumerate(_xml_records(text), 1)
        else:
            raise EvidenceError(f"Unsupported evidence format: {fmt}")
        for number, raw in records:
            event = _normal(raw, source, collected_at, {"path": entry["path"], "record": number, "sha256": actual_hash})
            key = event["evidence_id"]
            if key in events:
                previous = events[key]
                refs = previous.setdefault("source_refs", [previous["source_ref"]])
                if event["source_ref"] not in refs:
                    refs.append(event["source_ref"])
            else:
                events[key] = event
            if len(events) > MAX_EVENTS:
                raise EvidenceError("Dataset exceeds 250,000 unique events")
    result = sorted(events.values(), key=lambda event: (event["timestamp"], event["evidence_id"]))
    _mark_script_fragments(result)
    return result


def _mark_script_fragments(events: list[dict]) -> None:
    """Mark completeness without silently concatenating conflicting script fragments."""
    groups = {}
    for event in events:
        if event["source"] == "powershell" and event.get("script_block_id"):
            groups.setdefault((event.get("host"), event.get("provider"), event.get("channel"),
                               event.get("pid"), event["script_block_id"]), []).append(event)
    for fragments in groups.values():
        totals = {item.get("fragment_count") for item in fragments}
        by_number = {}
        conflict = False
        for item in fragments:
            number = item.get("fragment_number")
            if number in by_number and by_number[number] != item.get("script_text"):
                conflict = True
            by_number[number] = item.get("script_text")
        total = next(iter(totals)) if len(totals) == 1 else None
        complete = isinstance(total, int) and 0 < total <= MAX_EVENTS and set(by_number) == set(range(1, total + 1)) and not conflict
        for item in fragments:
            item["script_block_complete"] = complete
            item["script_block_evidence_ids"] = [fragment["evidence_id"] for fragment in fragments]
