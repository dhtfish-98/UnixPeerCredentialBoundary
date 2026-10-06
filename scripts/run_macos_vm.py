# SPDX-License-Identifier: MIT
# Copyright (c) 2026 dhtfish98
"""Compile and run the source in a pinned disposable ARM64 Linux VM."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import time

PINS = {
    "Image-6.18.52-0-virt": "8dfe2ce7e5bfe4d0efcf2fed0a01a692b5a5d5217e9a55587a17d92203ab7b0d",
    "initramfs-virt": "b0be51c9de43d582da897df3583114192933872a7e219218752b18082d75b6cb",
    "zig": "90b31f6630e0489bc4f6fd41b70dcfde8fce434636cff15a61d57061b10a4abb",
}
COMMANDS = (
    "/bin/busybox stat -c ROOT_BEFORE=%u:%a /\n"
    "/bin/busybox chown 0:0 /\n"
    "/bin/busybox chmod 755 /\n"
    "/bin/busybox stat -c ROOT_AFTER=%u:%a /\n"
    "/bin/busybox mkdir -p /tmp\n"
    "echo VM_PROBE_START\n"
    "/usr/bin/live-probe /usr/bin/weak-lab-server /usr/bin/managed-write-server /tmp/peercred\n"
    "echo VM_PROBE_RC=$?\n"
    "/bin/busybox poweroff -f\n"
)
EXPECTED_CASES = (
    "weak_spoof_uid1001", "strong_spoof_uid1001", "strong_legit_uid1000",
    "strong_replay_uid1000", "strong_claim_mismatch_uid1000",
    "strong_replay_spoof_uid1001", "strong_second_legit_uid1000",
    "strong_slow_drip_uid1001",
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_elf(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"{path.name}: not little-endian ELF64")
    if struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError(f"{path.name}: not AArch64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize < 56 or phoff + phentsize * phnum > len(data):
        raise ValueError(f"{path.name}: invalid program table")
    if any(struct.unpack_from("<I", data, phoff + i * phentsize)[0] == 3
           for i in range(phnum)):
        raise ValueError(f"{path.name}: dynamic interpreter found")
    return {"sha256": sha(path), "machine": "AArch64", "dynamic_interpreter": False}


def vm_run(host: Path, kernel: Path, initramfs: Path, serial_path: Path) -> tuple[int, str]:
    master, slave = pty.openpty()
    process = subprocess.Popen([str(host), str(kernel), str(initramfs)],
                               stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    captured = bytearray()
    sent = False
    deadline = time.monotonic() + 60
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    data = os.read(master, 16384)
                except OSError:
                    break
                if not data:
                    break
                captured.extend(data)
                if not sent and b"~ #" in captured:
                    os.write(master, COMMANDS.encode())
                    sent = True
            if process.poll() is not None and not ready:
                break
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    finally:
        os.close(master)
        serial_path.write_bytes(captured)
    if not sent:
        raise RuntimeError("guest shell not reached")
    return process.returncode, captured.decode(errors="replace").replace("\r", "")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    build_root = args.build_root.resolve()
    if build_root.name != "Build":
        parser.error("build root must be the workspace Build directory")
    run_id = args.run_id or datetime.now(timezone.utc).strftime("vm-%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", run_id):
        parser.error("invalid run ID")
    output = build_root / "验证/UnixPeerCredentialBoundary-20261006" / run_id
    output.mkdir(parents=True, exist_ok=False)
    receipt: dict[str, object] = {
        "status": "OPEN", "created_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id, "source_root": str(project), "output": str(output),
        "host_platform": platform.platform(),
    }
    serial_path = output / "vm-serial.log"
    try:
        if sys.platform != "darwin" or platform.machine() != "arm64":
            raise RuntimeError("Apple Silicon macOS required for this VM harness")
        environment = build_root / "环境/LandlockFilesystemGate-20261006"
        kernel = environment / "Image-6.18.52-0-virt"
        base = environment / "initramfs-virt"
        zig = environment / "zig-macos-aarch64-0.13.0/zig"
        for path, name in ((kernel, kernel.name), (base, base.name), (zig, "zig")):
            if not path.is_file() or sha(path) != PINS[name]:
                raise RuntimeError(f"missing or changed pinned input: {name}")
        receipt["environment_sha256"] = dict(PINS)
        build_env = dict(os.environ,
                         ZIG_GLOBAL_CACHE_DIR=str(output / "zig-global"),
                         ZIG_LOCAL_CACHE_DIR=str(output / "zig-local"))
        include = project / "include"
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
            command = ([str(zig), "cc", "-target", "aarch64-linux-musl", "-static",
                        "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(include)]
                       + extra + [str(s) for s in sources] + ["-o", str(path)])
            with (output / (name + ".compile.log")).open("w") as log:
                subprocess.run(command, check=True, env=build_env,
                               stdout=log, stderr=subprocess.STDOUT)
            binaries[name] = verify_elf(path)
        receipt["binaries"] = binaries
        receipt["source_sha256"] = {
            str(path.relative_to(project)): sha(path)
            for path in (project / "include/peer_gate.h", gate, server, probe,
                         project / "tests/guest_vm.swift",
                         project / "tests/virtualization.entitlements", Path(__file__))
        }
        overlay = output / "overlay/usr/bin"
        overlay.mkdir(parents=True)
        for name in binaries:
            shutil.copy2(output / name, overlay / name)
        entries = b".\n./usr\n./usr/bin\n" + b"".join(
            f"./usr/bin/{name}\n".encode() for name in binaries)
        archive = subprocess.run(["cpio", "-o", "-H", "newc"], input=entries,
                                 cwd=output / "overlay", check=True,
                                 capture_output=True).stdout
        initramfs = output / "initramfs-with-probe.gz"
        initramfs.write_bytes(gzip.compress(gzip.decompress(base.read_bytes()) + archive,
                                            compresslevel=9, mtime=0))
        receipt["initramfs_sha256"] = sha(initramfs)
        host = output / "guest_vm"
        with (output / "swift.compile.log").open("w") as log:
            subprocess.run(["swiftc", "-parse-as-library", "-framework", "Virtualization",
                            str(project / "tests/guest_vm.swift"), "-o", str(host)],
                           check=True, stdout=log, stderr=subprocess.STDOUT)
        subprocess.run(["codesign", "--force", "--sign", "-", "--entitlements",
                        str(project / "tests/virtualization.entitlements"), str(host)],
                       check=True, capture_output=True)
        receipt["host_binary_sha256"] = sha(host)
        vm_exit, serial = vm_run(host, kernel, initramfs, serial_path)
        receipt["vm_exit"] = vm_exit
        receipt["serial_sha256"] = sha(serial_path)
        checks = {name: serial.count(f"CASE_CHECK={name} PASS\n") == 1 and
                  serial.count(f"FILE_CHECK={name} PASS ") == 1
                  for name in EXPECTED_CASES}
        checks.update({
            "weak_server": "SERVER_CHECK=weak_lab PASS status=0 socket_removed=1" in serial,
            "strong_server": "SERVER_CHECK=strong PASS status=0 socket_removed=1" in serial,
            "cleanup": "CLEANUP=PASS\nTEST_EXIT=0" in serial,
            "untrusted_ancestor": "PATH_CHECK=uid1001_ancestor PASS status=65 socket_absent=1" in serial and
                                  "FILE_CHECK=uid1001_ancestor PASS " in serial,
            "symlink_ancestor": "PATH_CHECK=symlink_ancestor PASS status=65 socket_absent=1" in serial and
                                "FILE_CHECK=symlink_ancestor PASS " in serial,
            "guest_exit": "VM_PROBE_RC=0" in serial,
            "kernel": "KERNEL_RELEASE=6.18.52-0-virt" in serial,
            "root_mode": "ROOT_AFTER=0:755" in serial,
            "weak_spoof": "CASE=weak_spoof_uid1001 process_uid=1001 direct_file_errno=13 connected=1" in serial,
            "strong_reject": "CASE=strong_spoof_uid1001 process_uid=1001 direct_file_errno=13 connected=1" in serial,
        })
        receipt["checks"] = checks
        if vm_exit != 0 or not all(checks.values()):
            raise AssertionError("VM/probe did not satisfy every check")
        receipt["status"] = "PASS"
    except Exception as error:
        receipt["status"] = "FAIL" if isinstance(error, AssertionError) else "OPEN"
        receipt["error"] = f"{type(error).__name__}: {error}"
    if serial_path.exists() and "serial_sha256" not in receipt:
        receipt["serial_sha256"] = sha(serial_path)
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n")
    print(f"{receipt['status']} {output / 'receipt.json'}")
    if receipt["status"] != "PASS":
        print(receipt.get("error", "unknown error"), file=sys.stderr)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
