#include "hashbench.h"

#pragma codeseg BANK4
#pragma constseg BANK4

static const __code uint32_t iv[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
// Each byte selects the two message words for one G, first word in the high nibble.
static const __code uint8_t schedule[][8] = {
	{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
	{0x26,0x3a,0x70,0x4d,0x1b,0xc5,0x9e,0xf8},
	{0x34,0xac,0xd2,0x7e,0x65,0x90,0xbf,0x81},
	{0xa7,0xc9,0xe3,0xdf,0x40,0xb2,0x58,0x16},
	{0xcd,0x9b,0xfa,0xe8,0x72,0x53,0x01,0x64},
	{0x9e,0xb5,0x8c,0xf1,0xd3,0x0a,0x26,0x47},
	{0xbf,0x50,0x19,0x86,0xea,0x2c,0x34,0x7d},
	// BLAKE2s message permutations, RFC 7693 section 2.7.
	{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
	{0xea,0x48,0x9f,0xd6,0x1c,0x02,0xb7,0x53},
	{0xb8,0xc0,0x52,0xfd,0xae,0x36,0x71,0x94},
	{0x79,0x31,0xdc,0xbe,0x26,0x5a,0x40,0xf8},
	{0x90,0x57,0x24,0xaf,0xe1,0xbc,0x68,0x3d},
	{0x2c,0x6a,0x0b,0x83,0x4d,0x75,0xfe,0x19},
	{0xc5,0x1f,0xed,0x4a,0x07,0x63,0x92,0x8b},
	{0xdb,0x7e,0xc1,0x39,0x50,0xf4,0x86,0x2a},
	{0x6f,0xe9,0xb3,0x08,0xc2,0xd7,0x14,0xa5},
	{0xa2,0x84,0x76,0x15,0xfb,0x9e,0x3c,0xd0},
};
#if BLAKE_BUILD != BLAKE_regs
const __code uint8_t blake_lanes[8][4] = {
	{0,4,8,12}, {1,5,9,13}, {2,6,10,14}, {3,7,11,15},
	{0,5,10,15}, {1,6,11,12}, {2,7,8,13}, {3,4,9,14}
};

#endif

__xdata union blake_block blake_block;
__xdata uint32_t blake_state[16];
#if BLAKE_BUILD == BLAKE_all
__xdata uint8_t blake_impl;
#endif
static __xdata uint8_t round_index;
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#if BLAKE_BUILD == BLAKE_all || BLAKE_BUILD == BLAKE_ref
static __xdata uint32_t lane[4];

// Separate leaf functions let SDCC overlay spills in the limited direct RAM.
static void mix(uint8_t mix_index)
{
	enum { A, B, C, D };
	const __code uint8_t *indices = blake_lanes[mix_index];
	uint8_t pair = schedule[round_index][mix_index];

	for (uint8_t i = 0; i < 4; i++)
		lane[i] = blake_state[indices[i]];

	lane[A] += lane[B] + blake_block.words[pair >> 4];
	lane[D] ^= lane[A];
	lane[D] = ROTR(lane[D], 16);
	lane[C] += lane[D];
	lane[B] ^= lane[C];
	lane[B] = ROTR(lane[B], 12);
	lane[A] += lane[B] + blake_block.words[pair & 15];
	lane[D] ^= lane[A];
	lane[D] = ROTR(lane[D], 8);
	lane[C] += lane[D];
	lane[B] ^= lane[C];
	lane[B] = ROTR(lane[B], 7);

	for (uint8_t i = 0; i < 4; i++)
		blake_state[indices[i]] = lane[i];
}

#endif

#if BLAKE_BUILD == BLAKE_all || BLAKE_BUILD == BLAKE_direct
// Operate on the state in place. Small leaf functions let SDCC overlay spills.
static __xdata uint32_t * __xdata a, * __xdata b, * __xdata c, * __xdata d;

static void add_message(uint8_t word)
{
	*a += *b;
	*a += blake_block.words[word];
}

static __xdata uint32_t rotated;

static void first_rotations(void)
{
	rotated = *d ^ *a;
	*d = ROTR(rotated, 16);
	*c += *d;
	rotated = *b ^ *c;
	*b = ROTR(rotated, 12);
}

static void last_rotations(void)
{
	rotated = *d ^ *a;
	*d = ROTR(rotated, 8);
	*c += *d;
	rotated = *b ^ *c;
	*b = ROTR(rotated, 7);
}

static void direct_mix(uint8_t group)
{
	const __code uint8_t *indices = blake_lanes[group];
	static __xdata uint8_t pair;
	pair = schedule[round_index][group];
	a = &blake_state[indices[0]];
	b = &blake_state[indices[1]];
	c = &blake_state[indices[2]];
	d = &blake_state[indices[3]];
	add_message(pair >> 4);
	first_rotations();
	add_message(pair & 15);
	last_rotations();
}
#endif

#if BLAKE_BUILD == BLAKE_all || BLAKE_BUILD >= BLAKE_asm
__bit blake_skip_high_words;
void blake_regs_round(const __code uint8_t *schedule);
void blake_inline_round(const __code uint8_t *schedule);
void blake_asm_round(const __code uint8_t *schedule);
#endif

static void pad_block(uint8_t len)
{
#if BLAKE_BUILD == BLAKE_all
	blake_skip_high_words = blake_impl >= BLAKE_sparse && len <= 32;
#elif BLAKE_BUILD == BLAKE_asm
	blake_skip_high_words = 0;
#elif BLAKE_BUILD >= BLAKE_sparse
	blake_skip_high_words = len <= 32;
#endif
	for (uint8_t i = len; i < 64; i++)
		blake_block.bytes[i] = 0;
}

static void rounds(uint8_t end)
{
	for (round_index = end == 7 ? 0 : 7; round_index < end; round_index++) {
		switch (blake_impl) {
#if BLAKE_BUILD == BLAKE_all || BLAKE_BUILD == BLAKE_regs
		case BLAKE_regs:
			blake_regs_round(schedule[round_index]);
			break;
#endif
#if BLAKE_BUILD == BLAKE_all || BLAKE_BUILD == BLAKE_inline
		case BLAKE_inline:
			blake_inline_round(schedule[round_index]);
			break;
#endif
#if BLAKE_BUILD == BLAKE_all || BLAKE_BUILD == BLAKE_asm || BLAKE_BUILD == BLAKE_sparse
		case BLAKE_asm:
		case BLAKE_sparse:
			blake_asm_round(schedule[round_index]);
			break;
#endif
#if BLAKE_BUILD == BLAKE_all || BLAKE_BUILD == BLAKE_direct
		case BLAKE_direct:
			for (uint8_t i = 0; i < 8; i++)
				direct_mix(i);
			break;
#endif
#if BLAKE_BUILD == BLAKE_all || BLAKE_BUILD == BLAKE_ref
		default:
			for (uint8_t i = 0; i < 8; i++)
				mix(i);
#endif
		}
	}
}

static void blake3_begin(uint8_t len)
{
	pad_block(len);
	for (uint8_t i = 0; i < 8; i++)
		blake_state[i] = iv[i];
	for (uint8_t i = 0; i < 4; i++)
		blake_state[8 + i] = iv[i];
	blake_state[12] = blake_state[13] = 0;
	blake_state[14] = len;
	blake_state[15] = 1 | 2 | 8; // CHUNK_START | CHUNK_END | ROOT
}

static void finish_digest(void)
{
	for (uint8_t i = 0; i < 8; i++)
		blake_block.words[i] = blake_state[i] ^ blake_state[i + 8];
}

void blake3(uint8_t len)
{
	blake3_begin(len);
	rounds(7);
	finish_digest();
}

static void blake2s_begin(uint8_t len)
{
	pad_block(len);
	for (uint8_t i = 0; i < 8; i++)
		blake_state[i] = blake_state[8 + i] = iv[i];
	blake_state[0] ^= 0x01010020UL; // Unkeyed, 32-byte output, fanout and depth 1.
	blake_state[12] ^= len;
	blake_state[14] = ~blake_state[14];
}

static void blake2s_finish(void)
{
	for (uint8_t i = 0; i < 8; i++)
		blake_block.words[i] = blake_state[i] ^ blake_state[i + 8] ^ iv[i];
	blake_block.words[0] ^= 0x01010020UL;
}

void blake2s(uint8_t len)
{
	blake2s_begin(len);
	rounds(17);
	blake2s_finish();
}
