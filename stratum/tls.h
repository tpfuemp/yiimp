
// Interface to the OpenSSL code in tls.cpp. <openssl/ssl.h> is kept out of
// here: its openssl/sha.h clashes with algos/sha256.h (SHA256_CTX, SHA256_Init).
#ifndef YAAMP_TLS_H
#define YAAMP_TLS_H

#include <stddef.h>

// one TLS connection; opaque outside tls.cpp
typedef struct stratum_tls STRATUM_TLS;

// loads certificate and key once; on failure errbuf gets the reason
bool stratum_tls_init(const char *cert, const char *key, char *errbuf, size_t errlen);
void stratum_tls_free();

// server handshake on an accepted socket; release the result with stratum_tls_close()
bool stratum_tls_accept(int fd, STRATUM_TLS **out, char *errbuf, size_t errlen);

// The client thread reads while other threads (job broadcast) write, so both
// are serialized per connection. They keep the socket's SO_RCVTIMEO and
// SO_SNDTIMEO as deadlines like recv()/send(), and return <= 0 on error.
int  stratum_tls_read(STRATUM_TLS *tls, void *buf, int num);
int  stratum_tls_write(STRATUM_TLS *tls, const void *buf, int num);
void stratum_tls_close(STRATUM_TLS *tls);

#endif
