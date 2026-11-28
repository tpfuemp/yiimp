#ifndef BC3HASH_H
#define BC3HASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Build the shared tables now instead of on the first share. 0 on success.
int bc3hash_init(void);

// On any failure the output is all 0xff (never a valid share).
void bc3hash_hash(const char *input, char *output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
