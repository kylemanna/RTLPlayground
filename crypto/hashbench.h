#ifndef HASHBENCH_H
#define HASHBENCH_H

#include <stdint.h>

#define BLAKE_all 0
#define BLAKE_ref 1
#define BLAKE_direct 2
#define BLAKE_asm 3
#define BLAKE_sparse 4
#define BLAKE_inline 5
#define BLAKE_regs 6
#ifndef BLAKE_BUILD
#define BLAKE_BUILD BLAKE_ref
#endif
#if BLAKE_BUILD == BLAKE_all
extern __xdata uint8_t blake_impl;
#else
#define blake_impl BLAKE_BUILD
#endif

#define SHA256_all 0
#define SHA256_full 1
#define SHA256_ring 2
#define SHA256_asm 3
#ifndef SHA256_BUILD
#define SHA256_BUILD SHA256_ring
#endif
#if SHA256_BUILD == SHA256_all
extern __xdata uint8_t sha256_impl;
#else
#define sha256_impl SHA256_BUILD
#endif

// Single final block, unkeyed BLAKE3 or BLAKE2s with a 32-byte output. SDCC MCS-51 is little-endian.
union blake_block {
	uint8_t bytes[64];
	uint32_t words[16];
#if SHA256_BUILD == SHA256_full || SHA256_BUILD == SHA256_all
	uint32_t sha_schedule[64];
#endif
};
extern __xdata union blake_block blake_block;

// Supply at most 64 input bytes. Both functions finish the digest in place.
void blake3(uint8_t len);
void blake2s(uint8_t len);
// SHA-256 of 0..55 bytes in blake_block, with the 32-byte result in place.
void sha256(uint8_t len);
uint8_t hashbench(const __xdata uint8_t *args, uint8_t all) __banked;

#endif
