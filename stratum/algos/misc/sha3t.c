#include <stdint.h>
#include <string.h>

#include "third_party/sph/sph_sha3d.h"
#include "sha3t.h"

// SHA3-256 (FIPS 202 padding) applied three times; merkle root stays sha256d
void sha3t_hash(const char *input, char *output, uint32_t len)
{
	uint32_t buffer[8];
	sph_sha3d256_context ctx;

	sph_sha3d256_init(&ctx);
	sph_sha3d256(&ctx, input, len);
	sph_sha3d256_close(&ctx, buffer);

	sph_sha3d256_init(&ctx);
	sph_sha3d256(&ctx, buffer, 32);
	sph_sha3d256_close(&ctx, buffer);

	sph_sha3d256_init(&ctx);
	sph_sha3d256(&ctx, buffer, 32);
	sph_sha3d256_close(&ctx, output);
}
