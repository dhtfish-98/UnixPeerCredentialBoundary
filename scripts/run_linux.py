# SPDX-License-Identifier: MIT
# Copyright (c) 2026 dhtfish98
"""Build and run the real Linux UID/AF_UNIX probe outside the source tree."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import sys

CASES = (
    "weak_spoof_uid1001", "strong_spoof_uid1001", "strong_legit_uid1000",
    "strong_replay_uid1000", "strong_claim_mismatch_uid1000",
    "strong_replay_spoof_uid1001", "strong_second_legit_uid1000",
    "strong_slow_drip_uid1001",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_log(log: str) -> dict[str, bool]:
    checks = {
        name: log.count(f"CASE_CHECK={name} PASS\n") == 1 and
        log.count(f"FILE_CHECK={name} PASS ") == 1
        for name in CASES
    }
    checks.update({
        "kernel": bool(re.search(r"^KERNEL_RELEASE=\S+$", log, re.M)),
        "weak_real_uid": "CASE=weak_spoof_uid1001 process_uid=1001 direct_file_errno=13 connected=1" in log,
        "strong_real_uid": "CASE=strong_spoof_uid1001 process_uid=1001 direct_file_errno=13 connected=1" in log,
        "kernel_credential_1001": bool(re.search(
            r"^SERVER_EVENT mode=SO_PEERCRED slot=0 observed_pid=[1-9][0-9]* observed_uid=1001 observed_gid=1001 declared_uid=1000 nonce=attack001 response=ERR UID_DENIED$", log, re.M)),
        "kernel_credential_1000": bool(re.search(
            r"^SERVER_EVENT mode=SO_PEERCRED slot=1 observed_pid=[1-9][0-9]* observed_uid=1000 observed_gid=1000 declared_uid=1000 nonce=valid001 response=OK WRITE$", log, re.M)),
        "weak_server": "SERVER_CHECK=weak_lab PASS status=0 socket_removed=1" in log,
        "strong_server": "SERVER_CHECK=strong PASS status=0 socket_removed=1" in log,
        "cleanup": "CLEANUP=PASS\nTEST_EXIT=0\n" in log,
        "untrusted_ancestor": "PATH_CHECK=uid1001_ancestor PASS status=65 socket_absent=1" in log and
                              "FILE_CHECK=uid1001_ancestor PASS " in log,
        "symlink_ancestor": "PATH_CHECK=symlink_ancestor PASS status=65 socket_absent=1" in log and
                            "FILE_CHECK=symlink_ancestor PASS " in log,
    })
    return checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path,
                        help="new build/evidence directory outside the project source tree")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.out.resolve()
    try:
        output.relative_to(project)
    except ValueError:
        pass
    else:
        parser.error("--out must be outside the project source tree")
    output.mkdir(parents=True, exist_ok=False)
    receipt: dict[str, object] = {
        "status": "OPEN", "created_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "source_root": str(project), "out": str(output),
    }
    try:
        if sys.platform != "linux":
            raise RuntimeError("Linux required for SO_PEERCRED")
        cc = os.environ.get("CC", "cc")
        common = [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                  "-I", str(project / "include")]
        gate = project / "src/peer_gate.c"
        server = project / "cmd/managed_write_server.c"
        probe = project / "tests/live_probe.c"
        specs = (
            ("managed-write-server", [gate, server], []),
            ("weak-lab-server", [gate, server], ["-DPEER_GATE_WEAK_LAB=1"]),
            ("live-probe", [probe], []),
        )
        binaries = {}
        for name, sources, extra in specs:
            path = output / name
            with (output / (name + ".compile.log")).open("w") as log:
                subprocess.run(common + extra + [str(s) for s in sources] +
                               ["-o", str(path)], check=True, stdout=log,
                               stderr=subprocess.STDOUT)
            binaries[name] = digest(path)
        receipt["binary_sha256"] = binaries
        receipt["source_sha256"] = {
            str(path.relative_to(project)): digest(path)
            for path in (project / "include/peer_gate.h", gate, server, probe, Path(__file__))
        }
        fixture = f"/tmp/upcb-{secrets.token_hex(5)}"
        command = [str(output / "live-probe"), str(output / "weak-lab-server"),
                   str(output / "managed-write-server"), fixture]
        if os.geteuid() != 0:
            command = ["sudo", "-n"] + command
        result = subprocess.run(command, capture_output=True, timeout=30,
                                env=dict(os.environ, LC_ALL="C"))
        raw = result.stdout + result.stderr
        log_path = output / "linux-probe.log"
        log_path.write_bytes(raw)
        receipt["probe_exit"] = result.returncode
        receipt["probe_log_sha256"] = digest(log_path)
        log = raw.decode("utf-8", errors="replace")
        checks = check_log(log)
        receipt["checks"] = checks
        if result.returncode != 0 or not all(checks.values()):
            raise AssertionError("Linux probe checks failed")
        receipt["status"] = "PASS"
    except Exception as error:
        receipt["status"] = "FAIL" if isinstance(error, AssertionError) else "OPEN"
        receipt["error"] = f"{type(error).__name__}: {error}"
    path = output / "receipt.json"
    path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(f"{receipt['status']} {path}")
    if receipt["status"] != "PASS":
        print(receipt.get("error", "unknown error"), file=sys.stderr)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
