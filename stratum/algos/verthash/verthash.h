#ifndef VERTHASH_H
#define VERTHASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Map verthash.dat read-only and check its size and SHA-256.
// Returns 0 on success, otherwise a message is in err.
int verthash_data_open(const char *path, char *err, int errlen);
int verthash_data_loaded(void);

// Without a loaded data file the output is all 0xff (never a valid share).
void verthash_hash(const char *input, char *output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
