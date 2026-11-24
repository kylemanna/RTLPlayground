# Choosing a password hash for the Horaco HC-SWTG124AS

## Executive summary

**Use BLAKE3 with the register-cached 8051 mixer. Target about 100 ms for a password login.** Start with **42 iterations** when integrating the mixer. On `sw-horaco`, 42 chained BLAKE3 digests took 100 ms in each of five runs. The optimized core fits in 1,048 bytes of flash, the smallest of the three candidates. Measure a complete HTTP login after integration to confirm the user-visible delay.

**For the existing C verifier on the `passwd-hash` branch, keep 15 iterations and share the HTTP request buffer.** That version took 105.58 ms per verification and saved 146 bytes of permanently allocated XRAM. A request carrying a valid session cookie skips the hash.

## Recommended implementation

| Source on the `hashbench` branch | What it does |
| --- | --- |
| [BLAKE3 digest in C](../crypto/blake.c#L198) | `blake3()` initializes one block, runs seven compression rounds and writes the 32-byte digest. |
| [Register-cached mixer in 8051 assembly](../crypto/blake_regs.asm#L142) | `_blake_regs_round` implements one round. The [`BLAKE_regs` case](../crypto/blake.c#L150) calls it. |
| [Work factor in the benchmark](../crypto/hashbench.c#L84) | At 42 iterations, the loop hashes the input once and rehashes the preceding digest 41 times. |

To reproduce the 100 ms measurement on a benchmark image, run **`hashbench --regs 42`** in the switch console and read the `BLAKE3` row.

## Motivation and goals

Someone who copies the switch configuration can test password guesses on a GPU without contacting the switch. Each extra iteration makes a guess more expensive, but the switch has to do the same work at login. Its 125 MHz, 8-bit management CPU also runs the web interface. We set a budget of about 100 ms so one password submission can afford multiple iterations.

We wanted the smallest flash implementation that made good use of that budget, kept the hash workspace available to HTTP between logins, and made offline guessing as slow as practical. A faster mixer on the switch lets us require more iterations in the same login time.

## Approach and results

We tested six implementations each of BLAKE3 and BLAKE2s, and three of SHA-256. For each algorithm we timed a chain on the physical Horaco, selected the fastest implementation, and found the iteration count closest to 100 ms. We linked each selected core separately to measure flash and RAM. We then compared complete password guesses per second at those work factors. A lower GPU rate is better.

| Algorithm | Core flash | Static XRAM | Peak digest stack | Iterations at 100 ms | RX 5700 XT measured guesses/s | RTX 5090 estimated guesses/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| **BLAKE3** | **1,048 B** | 129 B | 9 B | 42 | 149.8 million | ~1.1 billion |
| BLAKE2s-256 | 1,192 B | 129 B | 9 B | 30 | **145.5 million** | ~1.1 billion |
| SHA-256 | 2,169 B | **105 B** | 17 B | 11 | 209.5 million | ~2.3–2.6 billion |

BLAKE2s slowed guessing by 2.8% on the measured Radeon but cost 144 more flash bytes than BLAKE3. The RTX 5090 estimates are too close to rank those two. SHA-256 used the least XRAM in the benchmark, but took more than twice the flash of BLAKE3 and allowed more guesses. With flash the priority, we selected BLAKE3.

### What the GPU figures mean

The Radeon measurements used a fixed 16-byte salt and a generated 20-byte password. Each guess hashed these together, then hashed the previous 32-byte digest for every remaining iteration. The figures are medians of nine samples after warm-up. All 24 sampled outputs matched independent host digests.

On **one RTX 5090**, the estimate for 42-iteration BLAKE3 is **about 12 years on average** to find a uniformly random 10-character password drawn from `A–Z`, `a–z` and `0–9`. At 1.13 billion guesses per second, exhausting all `62^10` possibilities would take about 24 years. Human-chosen passwords can be guessed much earlier.

The 5090 figure is an extrapolation. A published benchmark measured 33.59 billion raw BLAKE2s digests per second. On our Radeon, single-digest BLAKE3 was 1.41 times as fast as BLAKE2s. Applying that ratio gives `33.59 × 1.41 / 42 ≈ 1.13` billion BLAKE3 guesses per second. For BLAKE2s we used `33.59 / 30`. The SHA-256 range scales the published single- and double-hash rates to 11 digests. Exact salted-chain throughput on a 5090 is unmeasured. [RTX 5090 benchmark, modes 1400, 21400 and 31000](https://gist.github.com/Chick3nman/09bac0775e6393468c2925c1e1363d5c)

## What stays in RAM between logins?

The switch has 256 bytes of internal RAM for registers, small variables and the hardware stack. Larger buffers go in on-chip XRAM, also called XMEM or `__xdata`. RTLPlayground documents 64 KiB of XRAM. The Horaco linker budgets 49,151 bytes. Both C verifier builds leave 133 bytes for the entire stack, including interrupts. [Hardware layout](hardware.md) · [Linker settings](../Makefile) · [Stack usage](internal-ram.md)

The **129 bytes** in the algorithm table cover the optimized benchmark core’s 64-byte input block, 64-byte working state and one-byte round index. Its 9-byte peak stack use is separate. The C login verifier also needs 16 bytes for four working words and one for the remaining iterations, bringing its workspace to **146 bytes**.

HTTP already owns a 4,480-byte XRAM buffer. The C verifier borrows part of it for the duration of a login. The first 65 bytes hold the encoded form and its terminator, so a fragmented request can still be decoded while the verifier writes its state immediately after it. A compile-time check requires a single TCP connection. Completion or cancellation wipes the workspace. Only the configured verifier and its settings need to survive between logins.

| C verifier at 15 iterations | Dedicated workspace | Shared HTTP buffer |
| --- | ---: | ---: |
| Whole-image XRAM | 17,025 B | 16,879 B |
| Whole-image linked flash | 148,550 B | 148,599 B |
| Correct password | 101.91 ms | 105.58 ms |
| Wrong final byte | 101.91 ms | 105.58 ms |

Sharing saved 146 bytes of permanent XRAM, added 49 bytes of flash and cost 3.67 ms per verification. Sizes came from matched Horaco health builds. Times are medians of 20 samples per cell on `sw-horaco` with firmware `xram-ab1`, the same salt and a 20-byte password. Timer 2 measured form decoding through digest comparison and cleanup. The timing command used the real verifier objects and a separate workspace of the same layout so HTTP could carry the command. All 80 verdicts were correct. The timings exclude network latency and main-loop scheduling between rounds.

## Reproduce the benchmarks

Build with `make MACHINE=HORACO_HC_SWTG124AS HASH_BENCH=1`. The default image contains all 15 implementations. Each output row gives elapsed time, iteration count, digests per second and the full digest.

| Console command | What it measures |
| --- | --- |
| `hashcheck` | All 15 implementations on the built-in fixture, 32 iterations each |
| `hashcheck "hello world" 64` | All 15 on the same custom input and work factor |
| `hashbench --regs 42` | Both register-cached BLAKE chains, including the recommended BLAKE3 work factor |
| `hashcheck 11` | All paths at 11 iterations, including the 100 ms assembly SHA-256 row |

Both commands accept up to 20 bytes of text and 1–64 iterations. Quote spaces, empty text, numeric text or text beginning with `--`. A lone number selects the iteration count for the built-in fixture. Its 36 bytes (values 0 through 35) model the maximum first input of a 16-byte salt plus a 20-byte password. Subsequent iterations hash the previous 32-byte digest. Printing and checking the digest happen outside the timed interval.

For repeated measurements, run `python3 test/bench_hashmix.py sw-horaco.home --hashcheck > samples.csv` with `b3sum` on PATH. All 360 timed rows on `f07357a` matched host references. For size comparisons we used patched SDCC 4.6.0. Core flash includes code, constants and each BLAKE core’s own schedule and mixer. The benchmark console and login parser are outside those figures. The isolated cores passed simulator checks at every supported input length, 0–64 bytes for BLAKE and 0–55 for SHA-256. [Simulator tests](../test/test_hashmix.py) · [Hardware benchmark runner](../test/bench_hashmix.py)

## Detailed measurements

### BLAKE mixers

Timings are medians of 12 runs of 64 digests on `65b0d78`. The flash column covers **both BLAKE algorithms** sharing one mixer. Select an implementation with `hashbench --regs 64` or the corresponding selector. Set `HASH_IMPL=regs` at build time to include only that mixer.

| Mixer | Implementation | BLAKE3 | BLAKE2s | Combined core flash |
| --- | --- | ---: | ---: | ---: |
| `ref` | C with scratch words | 435 ms | 620 ms | 2,029 B |
| `direct` | In-place C | 375 ms | 535 ms | 2,181 B |
| `asm` | Assembly word helpers | 290 ms | 410 ms | 1,530 B |
| `sparse` | Skip additions of known zero words | 280 ms | 400 ms | 1,536 B |
| `inline` | Inline the sparse word helpers | 185 ms | 260 ms | 1,717 B |
| `regs` | Cache a working word in registers | 155 ms | 215 ms | 1,641 B |

The smallest two-algorithm mixer saved 111 flash bytes over `regs` and took nearly twice as long for BLAKE3. Register caching, byte-wise rotations and a packed message schedule improved throughput. With a 5 ms timer tick, BLAKE3 measured 100 ms at both 41 and 42 iterations. BLAKE2s measured 100 ms at 29 and 30. Each count was tested five times. We chose the higher count in each pair.

### SHA-256 experiment

Timings are medians of 12 runs of 64 digests on `f07357a`. Set `SHA_IMPL=full`, `ring` or `asm` to build one implementation.

| SHA-256 implementation | 64 digests | Core flash | Static XRAM | Peak digest stack |
| --- | ---: | ---: | ---: | ---: |
| Full 64-word schedule, C | 690 ms | 2,897 B | 297 B | 17 B |
| Rolling 16-word schedule, C | 680 ms | 2,894 B | 105 B | 17 B |
| Rolling schedule, assembly sigma functions | 585 ms | 2,169 B | 105 B | 17 B |

The rolling schedule saved 192 bytes of XRAM. Assembly rotations saved another 725 bytes of flash. At 10, 11 and 12 iterations the assembly version took 90, 100 and 110 ms respectively in all five runs per count. [SHA-256 core](../crypto/sha256.c) · [Assembly rotations](../crypto/sha256_sigma.asm) · [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4)

## Final on-device verification

On 2026-11-23, the default `hashcheck` on `sw-horaco` (HC-SWTG124AS, firmware `v0.1.0-xram-ab1`) passed all 15 implementations at 32 iterations. Every digest matched the on-device vector and an independent host calculation with `b3sum` or Python’s `hashlib`. This transcript records one run. The work factors above come from repeated measurements.

<details>
<summary>Full switch output</summary>

```text
> hashcheck
ref BLAKE3 215 ms / 32, 148 hashes/s 1ca0dcee789a3de990d4946f6524acbe7375e9b58cd98a41412aab722247b8de OK
ref BLAKE2s-256 310 ms / 32, 103 hashes/s 63cc90a2e677e122e8c613c9d84032f777d15e898e81793899a1bd3d3da0daf6 OK
direct BLAKE3 185 ms / 32, 172 hashes/s 1ca0dcee789a3de990d4946f6524acbe7375e9b58cd98a41412aab722247b8de OK
direct BLAKE2s-256 270 ms / 32, 118 hashes/s 63cc90a2e677e122e8c613c9d84032f777d15e898e81793899a1bd3d3da0daf6 OK
asm BLAKE3 145 ms / 32, 220 hashes/s 1ca0dcee789a3de990d4946f6524acbe7375e9b58cd98a41412aab722247b8de OK
asm BLAKE2s-256 205 ms / 32, 156 hashes/s 63cc90a2e677e122e8c613c9d84032f777d15e898e81793899a1bd3d3da0daf6 OK
sparse BLAKE3 140 ms / 32, 228 hashes/s 1ca0dcee789a3de990d4946f6524acbe7375e9b58cd98a41412aab722247b8de OK
sparse BLAKE2s-256 200 ms / 32, 160 hashes/s 63cc90a2e677e122e8c613c9d84032f777d15e898e81793899a1bd3d3da0daf6 OK
inline BLAKE3 90 ms / 32, 355 hashes/s 1ca0dcee789a3de990d4946f6524acbe7375e9b58cd98a41412aab722247b8de OK
inline BLAKE2s-256 135 ms / 32, 237 hashes/s 63cc90a2e677e122e8c613c9d84032f777d15e898e81793899a1bd3d3da0daf6 OK
regs BLAKE3 80 ms / 32, 400 hashes/s 1ca0dcee789a3de990d4946f6524acbe7375e9b58cd98a41412aab722247b8de OK
regs BLAKE2s-256 105 ms / 32, 304 hashes/s 63cc90a2e677e122e8c613c9d84032f777d15e898e81793899a1bd3d3da0daf6 OK
full SHA-256 345 ms / 32, 92 hashes/s 99514f338d4abee4b2c1f538c01f4e965d93322dd3b69e24afb5c9d7ea9e98ca OK
ring SHA-256 340 ms / 32, 94 hashes/s 99514f338d4abee4b2c1f538c01f4e965d93322dd3b69e24afb5c9d7ea9e98ca OK
asm SHA-256 305 ms / 32, 104 hashes/s 99514f338d4abee4b2c1f538c01f4e965d93322dd3b69e24afb5c9d7ea9e98ca OK
```

</details>
