// Verthash (Vertcoin). Algorithm as in cpuminer-opt algo/verthash (GPLv2).

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "third_party/sph/sph_sha3d.h"
#include "verthash.h"

#define VH_DATA_SIZE 1283457024UL
#define VH_HEADER_SIZE 80

static const uint8_t vh_data_sha256[32] = {
	0xa5, 0x55, 0x31, 0xe8, 0x43, 0xcd, 0x56, 0xb0, 0x10, 0x11, 0x4a, 0xaf, 0x63, 0x25, 0xb0, 0xd5,
	0x29, 0xec, 0xf8, 0x8f, 0x8a, 0xd4, 0x76, 0x39, 0xb6, 0xed, 0xed, 0xaf, 0xd7, 0x21, 0xaa, 0x48
};

static const uint32_t *vh_data = NULL;
static uint32_t vh_mdiv = 0;

int verthash_data_loaded(void)
{
	return vh_data != NULL;
}

int verthash_data_open(const char *path, char *err, int errlen)
{
	struct stat st;
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		snprintf(err, errlen, "%s: %s", path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) < 0) {
		snprintf(err, errlen, "%s: %s", path, strerror(errno));
		close(fd);
		return -1;
	}
	if ((uint64_t) st.st_size != VH_DATA_SIZE) {
		snprintf(err, errlen, "%s: size %lld, expected %lu", path,
			(long long) st.st_size, VH_DATA_SIZE);
		close(fd);
		return -1;
	}
	void *p = mmap(NULL, VH_DATA_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		snprintf(err, errlen, "%s: mmap: %s", path, strerror(errno));
		return -1;
	}

	// the checksum pass also pulls the file into the page cache; no
	// MADV_SEQUENTIAL, it would let the kernel drop the pages behind it
	uint8_t digest[32];
	SHA256((const unsigned char *) p, VH_DATA_SIZE, digest);
	if (memcmp(digest, vh_data_sha256, 32)) {
		snprintf(err, errlen, "%s: SHA-256 mismatch, not the Vertcoin data file", path);
		munmap(p, VH_DATA_SIZE);
		return -1;
	}
	madvise(p, VH_DATA_SIZE, MADV_RANDOM);

	vh_mdiv = (uint32_t) ((VH_DATA_SIZE - 32) / 16 + 1);
	vh_data = (const uint32_t *) p;
	return 0;
}

#define fnv1a(a, b) (((a) ^ (b)) * 0x1000193U)

static inline uint32_t rol32(uint32_t x, uint32_t n)
{
	return n ? (x << n) | (x >> (32 - n)) : x;
}

void verthash_hash(const char *input, char *output, uint32_t len)
{
	uint32_t hash[8], subset[128];
	uint8_t in[VH_HEADER_SIZE];
	sph_sha3d256_context c256;
	sph_sha3d512_context c512;

	if (!vh_data || len != VH_HEADER_SIZE) {
		memset(output, 0xff, 32);
		return;
	}

	sph_sha3d256_init(&c256);
	sph_sha3d256(&c256, input, VH_HEADER_SIZE);
	sph_sha3d256_close(&c256, hash);

	// 8 x SHA3-512 over the header, byte 0 incremented each time
	memcpy(in, input, VH_HEADER_SIZE);
	for (int i = 0; i < 8; i++) {
		in[0] += 1;
		sph_sha3d512_init(&c512);
		sph_sha3d512(&c512, in, VH_HEADER_SIZE);
		sph_sha3d512_close(&c512, (uint8_t *) subset + i * 64);
	}

	uint32_t acc = 0x811c9dc5U;
	for (uint32_t r = 0; r < 32; r++) {
		for (uint32_t i = 0; i < 128; i++) {
			const uint32_t *p = vh_data + (fnv1a(rol32(subset[i], r), acc) % vh_mdiv) * 4;
			for (int j = 0; j < 8; j++)
				acc = fnv1a(acc, p[j]);
			for (int j = 0; j < 8; j++)
				hash[j] = fnv1a(hash[j], p[j]);
		}
	}

	memcpy(output, hash, 32);
}
