#!/usr/bin/env python3
"""Check linked 8051 hash objects in uCsim against b3sum and hashlib."""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SHA_IMPLEMENTATIONS = ("full", "ring", "asm")
IMPLEMENTATIONS = ("ref", "direct", "asm", "sparse", "inline", "regs")

# Use a nonzero tail to catch reads of unpadded message words. Stop on return from main()
# to dump the 65 complete digests from a single simulator invocation.
DRIVER = """
#include "crypto/hashbench.h"
__xdata uint8_t results[65][32], algorithm;
void main(void) {
    for (uint8_t n = 0; n <= 64; n++) {
        for (uint8_t i = 0; i < 64; i++)
            blake_block.bytes[i] = 37 * i + 19 * n + 11;
        if (algorithm == 2) {
            if (n > 55) break;
            sha256(n);
        } else if (algorithm)
            blake2s(n);
        else
            blake3(n);
        for (uint8_t i = 0; i < 32; i++)
            results[n][i] = blake_block.bytes[i];
    }
}
"""


def reference(name, length):
    data = bytes((37 * i + 19 * length + 11) & 255 for i in range(length))
    if name == "sha256":
        return hashlib.sha256(data).digest()
    if name == "blake2s":
        return hashlib.blake2s(data).digest()
    return subprocess.check_output(["b3sum", "--raw"], input=data)


def addresses(directory):
    symbols = (directory / "sim.map").read_text()
    return {name: int(value, 16) for value, name in
            re.findall(r"^.:\s+([0-9A-F]+)\s+_(\w+)\s", symbols, re.M)}


def simulate(simulator, directory, addr, impl_id, algorithm, expected):
    commands = [f"run 0 {addr['main']}"]
    if impl_id:
        symbol = "sha256_impl" if algorithm == "sha256" else "blake_impl"
        commands.append(f"set memory xram {addr[symbol]} {impl_id}")
    commands += [f"set memory xram {addr['algorithm']} {('blake3', 'blake2s', 'sha256').index(algorithm)}",
                 f"run {addr['main']} {addr[algorithm]}",
                 f"run {addr[algorithm]} {addr['_sdcc_program_startup'] + 3}", "state"]
    start = addr["results"]
    commands += [f"dump xram {start} {start + len(expected) - 1} 8", "quit"]
    log = subprocess.check_output([simulator, "-q", "-t", "8051", "-c", "-", "sim.ihx"],
                                  input="\n".join(commands) + "\n", text=True, cwd=directory,
                                  timeout=30)
    rows = re.findall(r"^0x[0-9a-f]+\s+((?:[0-9a-f]{2} ){8})", log, re.M)
    actual = bytes.fromhex(" ".join(rows))
    if actual != expected:
        bad = next((i for i in range(65) if actual[32*i:32*i+32] != expected[32*i:32*i+32]), 0)
        raise AssertionError(f"{algorithm} length {bad}, got {actual[32*bad:32*bad+32].hex()}")
    # Second stop is at digest entry, after the caller pushed the return PC.
    entry = int(re.findall(r"^SP 0x([0-9a-f]+)", log, re.M)[1], 16)
    peak = int(re.search(r"Most value of stack pointer= 0x([0-9a-f]+)", log)[1], 16)
    return peak - entry + 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("builddir", type=Path)
    parser.add_argument("--simulator", default="s51")
    args = parser.parse_args()
    builddir = args.builddir.resolve()
    flags = (builddir / ".ccflags").read_text()
    impl = re.search(r"-DBLAKE_BUILD=BLAKE_(\w+)", flags)[1]
    sha_impl = re.search(r"-DSHA256_BUILD=SHA256_(\w+)", flags)[1]
    objects = [builddir / "crypto/blake.rel", builddir / "crypto/sha256.rel"]
    if sha_impl in ("all", "asm"):
        objects.append(builddir / "crypto/sha256_sigma.rel")
    if impl in ("all", "asm", "sparse"):
        objects.append(builddir / "crypto/blake_8051.rel")
    if impl in ("all", "inline"):
        objects.append(builddir / "crypto/blake_inline.rel")
    if impl in ("all", "regs"):
        objects.append(builddir / "crypto/blake_regs.rel")
    expected = {name: b"".join(reference(name, n) for n in range(56 if name == "sha256" else 65))
                for name in ("blake3", "blake2s", "sha256")}
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        (directory / "driver.c").write_text(DRIVER)
        state_layout = 0x1b0 if sha_impl in ("all", "full") else 0x70
        for xram, crossing in ((0xb0, "blake_block"), (state_layout, "blake_state")):
            subprocess.run(["sdcc", "-mmcs51", "-I" + str(ROOT), f"-DBLAKE_BUILD=BLAKE_{impl}",
                            f"-DSHA256_BUILD=SHA256_{sha_impl}", "--xram-loc", hex(xram), "-Wl-bBANK4=0x4000", "driver.c",
                            *objects, "-o", "sim.ihx"], check=True, cwd=directory)
            addr = addresses(directory)
            assert addr[crossing] // 256 != (addr[crossing] + 63) // 256
            for algorithm, digests in expected.items():
                variants, build = (SHA_IMPLEMENTATIONS, sha_impl) if algorithm == "sha256" else (IMPLEMENTATIONS, impl)
                for name in variants if build == "all" else (build,):
                    selector = variants.index(name) + 1 if build == "all" else 0
                    stack = simulate(args.simulator, directory, addr, selector, algorithm, digests)
                    print(f"{xram:#04x} {name} {algorithm}: {len(digests) // 32} digests passed, peak stack {stack} bytes")


if __name__ == "__main__":
    main()
