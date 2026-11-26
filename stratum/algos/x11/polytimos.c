#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <third_party/sph/sph_skein.h>
#include <third_party/sph/sph_shabal.h>
#include <third_party/sph/sph_echo.h>
#include <third_party/sph/sph_luffa.h>
#include <third_party/sph/sph_fugue.h>
#include "algos/misc/gost.h"

#include "algos/common/common.h"

void polytimos_hash(const char *input, char* output, uint32_t len)
{
	uint32_t _ALIGN(64) hash[16];

	sph_skein512_context ctx_skein;
	sph_shabal512_context ctx_shabal;
	sph_echo512_context ctx_echo;
	sph_luffa512_context ctx_luffa;
	sph_fugue512_context ctx_fugue;
	sph_gost512_context ctx_gost;

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, (void*) hash);

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, hash, 64);
	sph_shabal512_close(&ctx_shabal, hash);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hash, 64);
	sph_echo512_close(&ctx_echo, hash);

	sph_luffa512_init(&ctx_luffa);
	sph_luffa512(&ctx_luffa, hash, 64);
	sph_luffa512_close(&ctx_luffa, hash);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, hash, 64);
	sph_fugue512_close(&ctx_fugue, hash);

	sph_gost512_init(&ctx_gost);
	sph_gost512(&ctx_gost, (const void*) hash, 64);
	sph_gost512_close(&ctx_gost, (void*) hash);

	memcpy(output, hash, 32);
}

