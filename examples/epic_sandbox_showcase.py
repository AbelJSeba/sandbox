#!/usr/bin/env python3
"""
Epic sandbox showcase workload.

This script intentionally mixes:
- normal compute
- outbound network attempt
- privileged file write attempt
- optional artifact generation under /app/output
- a harmless subprocess identity check

It always prints one JSON object to stdout so sandbox result analysis can parse it.
"""

import hashlib
import json
import pathlib
import subprocess
import time
import urllib.request


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def add_event(events, name: str, ok: bool, detail: str) -> None:
    events.append(
        {
            "event": name,
            "ok": ok,
            "detail": detail,
            "ts": now_iso(),
        }
    )


def main() -> None:
    events = []

    # 1) Benign compute workload.
    values = [i * i for i in range(25000)]
    digest = hashlib.sha256(json.dumps(values[:200]).encode("utf-8")).hexdigest()
    add_event(events, "compute", True, f"sha256:{digest[:24]}")

    # 2) Outbound network attempt (expected blocked with allow_network=false).
    try:
        with urllib.request.urlopen("https://example.com", timeout=2) as resp:
            data = resp.read(64)
        add_event(events, "network_attempt", True, f"bytes={len(data)}")
    except Exception as exc:  # noqa: BLE001 - demo intentionally captures broad exceptions
        add_event(events, "network_attempt", False, f"{type(exc).__name__}: {exc}")

    # 3) Privileged write attempt (expected blocked by permissions or policy).
    try:
        with open("/etc/fort_epic_demo.txt", "w", encoding="utf-8") as f:
            f.write("sandbox demo")
        add_event(events, "privileged_write", True, "/etc/fort_epic_demo.txt")
    except Exception as exc:  # noqa: BLE001
        add_event(events, "privileged_write", False, f"{type(exc).__name__}: {exc}")

    # 4) Optional output artifact for collector (/app/output).
    artifact = {
        "name": "fort-epic-demo-artifact",
        "created_at": now_iso(),
        "events_seen": len(events),
        "risk_markers": [e["event"] for e in events if not e["ok"]],
    }
    try:
        out_dir = pathlib.Path("/app/output")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "epic_demo_artifact.json"
        out_file.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
        add_event(events, "artifact_write", True, str(out_file))
    except Exception as exc:  # noqa: BLE001
        add_event(events, "artifact_write", False, f"{type(exc).__name__}: {exc}")

    # 5) Harmless subprocess for activity evidence.
    try:
        cp = subprocess.run(
            ["/bin/sh", "-lc", "id && whoami"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        detail = (cp.stdout + cp.stderr).strip().replace("\n", " | ")
        add_event(events, "subprocess_identity", cp.returncode == 0, detail[:180])
    except Exception as exc:  # noqa: BLE001
        add_event(events, "subprocess_identity", False, f"{type(exc).__name__}: {exc}")

    output = {
        "demo": "epic_sandbox_showcase",
        "timestamp": now_iso(),
        "events": events,
        "summary": {
            "total_events": len(events),
            "blocked_or_failed": len([e for e in events if not e["ok"]]),
        },
    }
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
