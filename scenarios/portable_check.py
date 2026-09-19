"""Exercise real local HTTP policy + managed exports, without executing host payloads.

Starts two ephemeral Kestrel processes. Native interpreter/helper execution is not tested.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from run import Session, run


def check(dotnet: str, dll: Path, output: Path):
    results = []
    for mode in ("vulnerable", "hardened"):
        with tempfile.TemporaryDirectory(prefix="iis-purple-http-") as directory:
            root = Path(directory)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            base = f"http://127.0.0.1:{port}"
            environment = {**os.environ, "ASPNETCORE_URLS": base, "PurpleLab__DataRoot": str(root / "state"),
                           "PurpleLab__Vulnerable": str(mode == "vulnerable"),
                           "PurpleLab__Acknowledgement": "I_ACCEPT_DISPOSABLE_LOCAL_LAB",
                           "DOTNET_ENVIRONMENT": "Production"}
            with (root / "server.log").open("w", encoding="utf-8") as log:
                server = subprocess.Popen([dotnet, str(dll.resolve()), "--urls", base], cwd=dll.resolve().parent,
                                          env=environment, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 30
                    while True:
                        try:
                            if Session(base).request("/health")["status"] == 200:
                                break
                        except OSError:
                            pass
                        if server.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("Portable app failed readiness: " + (root / "server.log").read_text())
                        time.sleep(.2)
                    families = ["A", "benign"] if mode == "hardened" else ["A"]
                    for family in families:
                        args = argparse.Namespace(password_file=str(root / "state/bootstrap-password.txt"),
                            base_url=base, scenario=family, mode=mode, disposable_vm=False, portable_only=True, output=str(root / "result.json"))
                        observed = run(args)
                        results.append({"mode": mode, "family": family, "passed": observed["passed"],
                                        "checks": [{"name": c["name"], "status": c["response"]["status"],
                                                    "expected_status": c["expected_status"], "passed": c["passed"]}
                                                   for c in observed["checks"]]})
                    events = [json.loads(line) for line in (root / "state/events/application.jsonl").read_text().splitlines()]
                    if any(e.get("action") == "process_launch" for e in events):
                        raise AssertionError("Portable check must not invoke process-launch workflows")
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()
    result = {"origin": "executed-portable-http", "hosting": "Kestrel on development platform, not IIS",
              "native_windows_validated": False, "process_payloads_executed": False,
              "passed": all(r["passed"] for r in results), "runs": results}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": result["passed"], "checks": sum(len(r["checks"]) for r in results), "output": str(output)}))
    return result["passed"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default="dotnet")
    parser.add_argument("--dll", type=Path, default=Path("app/IisPurpleLab/bin/Debug/net10.0/IisPurpleLab.dll"))
    parser.add_argument("--output", type=Path, default=Path("reports/validation/portable-http.json"))
    options = parser.parse_args()
    raise SystemExit(0 if check(options.dotnet, options.dll, options.output) else 1)
