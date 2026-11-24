#!/usr/bin/env python3
"""Measure the comparison image on a switch using the web console."""

import argparse
import csv
from functools import lru_cache
import getpass
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from fwupdate import FirmwareUpdater

IMPLEMENTATIONS = ("ref", "direct", "asm", "sparse", "inline", "regs")


@lru_cache(maxsize=16)
def expected_digests(data, count):
    blake3 = blake2s = sha256 = data
    for _ in range(count):
        blake3 = subprocess.check_output(["b3sum", "--raw"], input=blake3)
        blake2s = hashlib.blake2s(blake2s).digest()
        sha256 = hashlib.sha256(sha256).digest()
    return {"BLAKE3": blake3.hex(), "BLAKE2s-256": blake2s.hex(), "SHA-256": sha256.hex()}


def run_hashcheck(switch, args, data, count):
    cmd = ("hashcheck " + args).rstrip()
    status, _, body = switch._request("POST", "/cmd", cmd.encode(), content_type="text/plain")
    rows = body.decode("ascii").splitlines()
    expected = expected_digests(bytes(range(36)) if data is None else data, count)
    paths = [(impl, algo) for impl in IMPLEMENTATIONS for algo in ("BLAKE3", "BLAKE2s-256")]
    paths.extend((impl, "SHA-256") for impl in ("full", "ring", "asm"))
    if status != 200 or len(rows) != len(paths):
        raise ValueError(f"{cmd}: HTTP {status}, expected {len(paths)} rows, got {rows!r}")
    results = []
    for (impl, algo), row in zip(paths, rows):
        match = re.fullmatch(r"(\S+) (\S+) (<?)(\d+) ms / (\d+), (>?)(\d+) hashes/s ([0-9a-f]{64})( OK)?", row.strip())
        if not match or (match[1], match[2], int(match[5]), match[8]) != (impl, algo, count, expected[algo]):
            raise ValueError(f"{cmd}: wrong result: {row}")
        ms = int(match[4])
        if (bool(match[9]) != (data is None) or bool(match[3]) != bool(match[6])
                or ms < 5 or ms % 5 or (match[3] and ms != 5) or int(match[7]) != count * 1000 // ms):
            raise ValueError(f"{cmd}: wrong timing or self-test: {row}")
        results.append((impl, algo, count, ms))
    return results


def measure_all(switch, output):
    writer = csv.writer(output)
    writer.writerow(("sample", "implementation", "algorithm", "iterations", "ms"))
    for args, data, count in (("", None, 32), ('"" 1', b"", 1),
                              ('"hello world" 2', b"hello world", 2),
                              ('"12345678901234567890" 64', b"12345678901234567890", 64)):
        run_hashcheck(switch, args, data, count)
    for sample in range(13):
        for count in ((15, 64) if sample % 2 == 0 else (64, 15)):
            for result in run_hashcheck(switch, str(count), None, count):
                if sample:
                    writer.writerow((sample, *result))
            output.flush()


def measure(switch, output):
    writer = csv.writer(output)
    writer.writerow(("sample", "implementation", "algorithm", "iterations", "ms"))
    for count in (15, 64):
        references = expected_digests(bytes(range(36)), count)
        expected = [(name, references[name]) for name in ("BLAKE3", "BLAKE2s-256")]
        for sample in range(1 + 2 * len(IMPLEMENTATIONS)):
            # Sample zero warms each path. Rotate the order through two full cycles.
            offset = sample % len(IMPLEMENTATIONS)
            for impl in IMPLEMENTATIONS[offset:] + IMPLEMENTATIONS[:offset]:
                cmd = f"hashbench --{impl} {count}"
                status, _, body = switch._request("POST", "/cmd", cmd.encode(), content_type="text/plain")
                rows = body.decode("ascii").strip().splitlines()
                if status != 200 or len(rows) != 3 or rows[0] != impl:
                    raise ValueError(f"{cmd}: expected implementation and two results, got HTTP {status}, {rows!r}")
                for row, (algo, digest) in zip(rows[1:], expected):
                    match = re.fullmatch(r"(\S+) (\d+) ms / (\d+), (\d+) hashes/s ([0-9a-f]{64}) OK", row.strip())
                    if not match or (match[1], int(match[3]), match[5]) != (algo, count, digest):
                        raise ValueError(f"{cmd}: wrong result: {row}")
                    ms = int(match[2])
                    if ms <= 0 or int(match[4]) != count * 1000 // ms:
                        raise ValueError(f"{cmd}: invalid timing: {row}")
                    if sample:
                        writer.writerow((sample, impl, algo, count, ms))
                output.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--hashcheck", action="store_true", help="measure all implementations together")
    args = parser.parse_args()
    password = os.environ.get("RTLP_PASSWORD") or getpass.getpass("Switch password: ")
    switch = FirmwareUpdater(args.host, password)
    print(switch.describe(switch.status()), file=sys.stderr)
    (measure_all if args.hashcheck else measure)(switch, sys.stdout)


if __name__ == "__main__":
    main()
