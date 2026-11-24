#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "crypto/hashbench.h"
#include "timer.h"

static char output[512], digest[3][65];
static unsigned stamps;
static bool corrupt;
static unsigned ticks = 2;

void print_string(const char *s)
{
	assert(strlen(output) + strlen(s) < sizeof(output));
	strcat(output, s);
}

void write_char(char c)
{
	char s[] = {c, 0};
	print_string(s);
}

void print_byte(uint8_t byte)
{
	char s[3];
	snprintf(s, sizeof(s), "%02x", (unsigned)byte);
	print_string(s);
}

void itoa_short(uint16_t n)
{
	char s[6];
	snprintf(s, sizeof(s), "%u", (unsigned)n);
	print_string(s);
}

void itoa(uint8_t n)
{
	itoa_short(n);
}

void timer_set(struct timer *t, clock_time_t interval)
{
	assert(!interval && stamps < 6);
	t->start = (stamps % 2) ? (uint16_t)(UINT16_MAX + ticks) : UINT16_MAX;
	if (stamps % 2) {
		if (corrupt)
			blake_block.bytes[31] ^= 1;
		for (unsigned i = 0; i < 32; i++)
			snprintf(digest[stamps / 2] + 2 * i, 3, "%02x", blake_block.bytes[i]);
	}
	stamps++;
}

static void run(const char *args, unsigned count, const char *status)
{
	char expected[sizeof(output)];
	stamps = 0;
	output[0] = 0;
	assert(hashbench((const uint8_t *)args, 0));
	assert(stamps == 4);
	const char *time = ticks ? "10" : "<5";
	const char *bound = ticks ? "" : ">";
	unsigned rate = count * 200 / (ticks ? ticks : 1);
	snprintf(expected, sizeof(expected),
	         "BLAKE3 %s ms / %u, %s%u hashes/s %s%s\n"
	         "BLAKE2s-256 %s ms / %u, %s%u hashes/s %s%s\n",
	         time, count, bound, rate, digest[0], status,
	         time, count, bound, rate, digest[1], status);
	assert(strcmp(output, expected) == 0);
}

// Reference digests from b3sum --raw and hashlib.blake2s. The built-in vector starts with bytes 0..35.
static void check(const char *args, unsigned count, const char *status, const char *blake3, const char *blake2s)
{
	run(args, count, status);
	assert(strcmp(digest[0], blake3) == 0);
	assert(strcmp(digest[1], blake2s) == 0);
}

int main(void)
{
	for (unsigned n = 1; n <= 64; n++) {
		char arg[4];
		snprintf(arg, sizeof(arg), "%u", n);
		run(arg, n, " OK");
	}
	check("1", 1, " OK", "02b34dc75e6e7dfb3b020188c7a5c277c7171417b75f91540f34e112b7f3552c",
	      "e48d0ecfaf497d5b27c25d99e156cb0579d440d6e31fb62473696dbf95e010e4");
	check("15", 15, " OK", "f6433c949e7552c3f3c42d42dbc579b2c10df7532971844bb46a1efc6a2bb261",
	      "cc3ef59af7fbc23aa5997a820b8084e98c87ca77eebe15afed336a6c9fb1dc0d");
	check("", 32, " OK", "1ca0dcee789a3de990d4946f6524acbe7375e9b58cd98a41412aab722247b8de",
	      "63cc90a2e677e122e8c613c9d84032f777d15e898e81793899a1bd3d3da0daf6");
	check("64", 64, " OK", "f691182a3febd233b4f2451a3b6b2bb0768d2fcd691369733f0232348bcf4dcc",
	      "00413c4367f0ae79ec1ed1a369dd22e4153feb8d45540838107f552debb6c392");
	check(" \"hello world\" 1", 1, "", "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24",
	      "9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b");
	check("hello", 32, "", "d6450fb5721dc5b0b69eaaf71f31909e8a79bb8460f9aaa580d63595db9d6d36",
	      "28e7eab19334e921a54965adae8d1f01b3c3affc704f9d761e5145e740f35c6b");
	check("\"\" 1", 1, "", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
	      "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
	check("\"15\"", 32, "", "9747d7adcd7c0a5d43e9ed1dc47788bd8dded0816f76bae1640434e9b3a14c08",
	      "ff92b71cbb3a6c6f55b6028178da3ad4fe9a004ec78e1420dc9f03f53c8d7ff8");
	check(" 12345678901234567890  64 ", 64, "", "61eb418dd054a4dd98d7dffae154b74a24bbc58a34bae3d11366641fc390d0df",
	      "364da23f056d0ee6e009836296228427fd7ac774b530d562fe0de04dcc5b4e25");
	stamps = 0;
	output[0] = 0;
	assert(hashbench((const uint8_t *)"abc 1", 1));
	assert(stamps == 6);
	assert(strstr(output, "ring SHA-256 10 ms / 1, 100 hashes/s "
	              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"));
	const char *bad[] = {"0", "65", "hello 0", "hello 256", "a 1x", "a 1 2",
	                     "123456789012345678901 1", "\"unfinished", "\"text\"1"};
	stamps = 0;
	for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		assert(!hashbench((const uint8_t *)bad[i], 0));
	assert(!stamps);
	ticks = 0;
	run("test 1", 1, "");
	ticks = 2;
	// Corrupt the timed digest both before and at a known answer.
	corrupt = true;
	run("15", 15, " FAIL");
	run("32", 32, " FAIL");
	return 0;
}
