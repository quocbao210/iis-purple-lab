"""Shared entry points for fixture replay and exported Windows evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from .correlate import correlate
from .normalize import EvidenceError, SOURCES, normalize_dataset
from .report import write_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IIS Purple Lab portable evidence analysis (never executes event command lines)")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("demo", "analyze", "evaluate"):
        command = commands.add_parser(name)
        command.add_argument("--dataset", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        if name != "evaluate":
            command.add_argument("--sources", nargs="+", choices=sorted(SOURCES), help="Remove all other sources before parsing")
            command.add_argument("--policy", type=Path, help="Reviewed deployment-specific detection policy JSON")
    args = parser.parse_args(argv)
    try:
        if args.command == "evaluate":
            from .evaluation import evaluate_dataset
            result = evaluate_dataset(args.dataset, args.output)
        else:
            from .detection import detect
            start = time.perf_counter()
            events = normalize_dataset(args.dataset, set(args.sources) if args.sources else None)
            links = correlate(events)
            policy = json.loads(args.policy.read_text(encoding="utf-8")) if args.policy else None
            if policy is not None and not isinstance(policy, dict):
                raise EvidenceError("Detection policy must be a JSON object")
            detections = detect(events, links, policy=policy)
            result = write_report(events, links, detections, args.output, args.dataset)
            result = {"output": str(args.output.resolve()), "origin": result["origin"],
                      "counts": result["counts"], "offline_processing_seconds": round(time.perf_counter() - start, 6),
                      "measurement": "Offline normalization, detection, correlation and report writing; not live detection latency."}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (EvidenceError, OSError, ValueError) as exc:
        print(f"Evidence analysis failed: {exc}", file=sys.stderr)
        return 2
