#include "hashbench.h"

#pragma codeseg BANK4
#pragma constseg BANK4

static const __code uint32_t iv[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const __code uint32_t k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#if SHA256_BUILD == SHA256_all
__xdata uint8_t sha256_impl;
#endif
#if SHA256_BUILD == SHA256_all || SHA256_BUILD == SHA256_full
#define w blake_block.sha_schedule
#else
#define w blake_block.words
#endif
static __xdata uint32_t state[8];
static volatile __xdata uint32_t t1, t2;
static __xdata uint8_t round_no;
#if SHA256_BUILD == SHA256_all
static __xdata uint8_t mask;
#elif SHA256_BUILD == SHA256_full
#define mask 63
#else
#define mask 15
#endif

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#if SHA256_BUILD != SHA256_asm
static uint32_t big0(uint32_t x) { return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22); }
static uint32_t big1(uint32_t x) { return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25); }
static uint32_t small0(uint32_t x) { return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3); }
static uint32_t small1(uint32_t x) { return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10); }
#endif
#if SHA256_BUILD == SHA256_asm || SHA256_BUILD == SHA256_all
uint32_t sha256_big0(uint32_t x);
uint32_t sha256_big1(uint32_t x);
uint32_t sha256_small0(uint32_t x);
uint32_t sha256_small1(uint32_t x);
#endif
#if SHA256_BUILD == SHA256_all
#define SIGMA(f, x) (sha256_impl == SHA256_asm ? sha256_##f(x) : f(x))
#elif SHA256_BUILD == SHA256_asm
#define SIGMA(f, x) sha256_##f(x)
#else
#define SIGMA(f, x) f(x)
#endif

static void expand(void) __reentrant
{
	t1 = SIGMA(small1, w[(round_no - 2) & mask]);
	t1 += SIGMA(small0, w[(round_no - 15) & mask]);
	t1 += w[(round_no - 7) & mask];
	w[round_no & mask] = t1 + w[(round_no - 16) & mask];
}

static void add_choice(void)
{
	t1 += state[6] ^ (state[4] & (state[5] ^ state[6]));
	t1 += state[7];
	t1 += k[round_no];
	t1 += w[round_no & mask];
}

static void advance(void)
{
	t2 += (state[0] & state[1]) ^ (state[2] & (state[0] ^ state[1]));
	state[7] = state[6];
	state[6] = state[5];
	state[5] = state[4];
	state[4] = state[3] + t1;
	state[3] = state[2];
	state[2] = state[1];
	state[1] = state[0];
	state[0] = t1 + t2;
}

static void prepare(uint8_t len)
{
	blake_block.bytes[len] = 0x80;
	for (uint8_t i = len + 1; i < 62; i++)
		blake_block.bytes[i] = 0;
	blake_block.bytes[62] = len >> 5;
	blake_block.bytes[63] = len << 3;
	// Convert the padded block from wire order into the schedule in place.
	for (uint8_t i = 0; i < 64; i += 4) {
		uint8_t a = blake_block.bytes[i], b = blake_block.bytes[i + 1];
		blake_block.bytes[i] = blake_block.bytes[i + 3];
		blake_block.bytes[i + 1] = blake_block.bytes[i + 2];
		blake_block.bytes[i + 2] = b;
		blake_block.bytes[i + 3] = a;
	}
	for (uint8_t i = 0; i < 8; i++)
		state[i] = iv[i];
}

static void finish(void)
{
	for (uint8_t i = 0; i < 8; i++)
		state[i] += iv[i];
	for (uint8_t i = 0; i < 32; i++)
		blake_block.bytes[i] = ((__xdata uint8_t *)state)[i ^ 3];
}

void sha256(uint8_t len)
{
	prepare(len);
#if SHA256_BUILD == SHA256_all
	mask = sha256_impl == SHA256_full ? 63 : 15;
#endif
#if SHA256_BUILD == SHA256_full || SHA256_BUILD == SHA256_all
	if (sha256_impl == SHA256_full)
		for (round_no = 16; round_no < 64; round_no++)
			expand();
#endif
	for (round_no = 0; round_no < 64; round_no++) {
#if SHA256_BUILD != SHA256_full
		if (sha256_impl != SHA256_full && round_no >= 16)
			expand();
#endif
		t1 = SIGMA(big1, state[4]);
		add_choice();
		t2 = SIGMA(big0, state[0]);
		advance();
	}
	finish();
}
