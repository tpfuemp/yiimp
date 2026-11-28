// BC3Hash (Bitcoin III, from block 64360): the coin's own crypto/bc3 sources
// (MIT, ref/COPYING, vendored by ref/vendor.py) as one translation unit.

// the .cpp files share one unit, so their anonymous-namespace types meet
#pragma GCC diagnostic ignored "-Wsubobject-linkage"
#include "ref/mix.cpp"
#include "ref/hash.cpp"
#include "ref/standard_hashes.cpp"

#include <cstring>

#include "bc3hash.h"

extern "C" int bc3hash_init(void)
{
	try {
		bc3::initialize();
		return 0;
	} catch (...) {
		return -1;
	}
}

extern "C" void bc3hash_hash(const char *input, char *output, uint32_t len)
{
	try {
		const auto d = bc3::bc3hash(input, len);
		std::memcpy(output, d.data(), 32);
	} catch (...) {
		std::memset(output, 0xff, 32);
	}
}
