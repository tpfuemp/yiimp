
// OpenSSL implementation for stratum's optional TLS listeners.
//
// This file intentionally does not include stratum.h. OpenSSL's sha.h defines
// SHA256_CTX / SHA256_Init / SHA256_Final, which collide with the copy in
// algos/sha256.h used by the rest of the stratum sources.
#include "tls.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// An SSL object must not be used by two threads at once: ssl_lock guards every
// SSL call. The socket is non-blocking, so the lock is only held for the call
// itself and a waiting reader does not hold up the job broadcast. write_lock
// keeps writers in one piece (a write retry must repeat the same data).
struct stratum_tls
{
	SSL *ssl;
	int fd;
	bool broken;
	pthread_mutex_t ssl_lock;
	pthread_mutex_t write_lock;
};

static SSL_CTX *g_ctx = NULL;

static void tls_errors(char *buf, size_t len)
{
	unsigned long err;
	char msg[256];

	buf[0] = 0;
	while ((err = ERR_get_error()))
	{
		ERR_error_string_n(err, msg, sizeof(msg));
		if (buf[0]) strncat(buf, "; ", len - strlen(buf) - 1);
		strncat(buf, msg, len - strlen(buf) - 1);
	}
	if (!buf[0]) snprintf(buf, len, "unknown OpenSSL error");
}

static long long tls_now_ms()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// deadline from the socket's SO_RCVTIMEO/SO_SNDTIMEO (0: none)
static long long tls_deadline(int fd, int opt)
{
	struct timeval tv = { 0, 0 };
	socklen_t len = sizeof(tv);
	if (getsockopt(fd, SOL_SOCKET, opt, &tv, &len) != 0) return 0;
	long long ms = (long long) tv.tv_sec * 1000 + tv.tv_usec / 1000;
	return ms > 0 ? tls_now_ms() + ms : 0;
}

// wait until the socket can do what OpenSSL asked for; false on error or timeout
static bool tls_wait(int fd, int ssl_error, long long deadline)
{
	struct pollfd pfd;
	pfd.fd = fd;
	if (ssl_error == SSL_ERROR_WANT_READ) pfd.events = POLLIN;
	else if (ssl_error == SSL_ERROR_WANT_WRITE) pfd.events = POLLOUT;
	else return false;

	while (true)
	{
		int timeout = -1;
		if (deadline)
		{
			long long left = deadline - tls_now_ms();
			if (left <= 0) return false;
			timeout = (int) left;
		}

		pfd.revents = 0;
		int pr = poll(&pfd, 1, timeout);
		if (pr > 0) return true;	// readable, writable or closed: the next SSL call tells
		if (pr == 0) return false;
		if (errno != EINTR) return false;
	}
}

// one SSL call under the lock; *err gets SSL_get_error() when it did not succeed
template <typename F>
static int tls_call(STRATUM_TLS *t, F call, int *err)
{
	pthread_mutex_lock(&t->ssl_lock);
	if (t->broken)
	{
		pthread_mutex_unlock(&t->ssl_lock);
		*err = SSL_ERROR_SSL;
		return -1;
	}
	ERR_clear_error();
	int n = call();
	*err = n > 0 ? SSL_ERROR_NONE : SSL_get_error(t->ssl, n);
	pthread_mutex_unlock(&t->ssl_lock);
	return n;
}

// the stream can't be used any more (e.g. a write timed out mid-record):
// fail all later calls and wake up a waiting reader
static void tls_break(STRATUM_TLS *t)
{
	pthread_mutex_lock(&t->ssl_lock);
	t->broken = true;
	pthread_mutex_unlock(&t->ssl_lock);
	shutdown(t->fd, SHUT_RDWR);
}

bool stratum_tls_init(const char *cert, const char *key, char *errbuf, size_t errlen)
{
	errbuf[0] = 0;
	if (!cert || !*cert)
	{
		snprintf(errbuf, errlen, "no certificate configured");
		return false;
	}

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	g_ctx = SSL_CTX_new(TLS_server_method());
#else
	g_ctx = SSL_CTX_new(SSLv23_server_method());
#endif
	if (!g_ctx)
	{
		tls_errors(errbuf, errlen);
		return false;
	}

	// Modern TLS only. SSL_OP_ALL keeps compatibility with a few miner stacks
	// that depend on OpenSSL negotiation workarounds.
	SSL_CTX_set_options(g_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv3 |
		SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

	if (SSL_CTX_use_certificate_chain_file(g_ctx, cert) != 1)
	{
		tls_errors(errbuf, errlen);
		SSL_CTX_free(g_ctx);
		g_ctx = NULL;
		return false;
	}

	// When only a combined fullchain+key PEM is configured, load the key from
	// the same file.
	const char *keyfile = (key && *key) ? key : cert;
	int rc = SSL_CTX_use_PrivateKey_file(g_ctx, keyfile, SSL_FILETYPE_PEM);
	if (rc == 1)
	{
		rc = SSL_CTX_check_private_key(g_ctx);
		if (rc != 1)
			snprintf(errbuf, errlen, "certificate and private key do not match");
	}

	if (rc != 1)
	{
		if (!errbuf[0]) tls_errors(errbuf, errlen);
		SSL_CTX_free(g_ctx);
		g_ctx = NULL;
		return false;
	}

	// SSL_write to a closed peer raises SIGPIPE (plain sockets use MSG_NOSIGNAL)
	signal(SIGPIPE, SIG_IGN);
	return true;
}

void stratum_tls_free()
{
	if (g_ctx)
	{
		SSL_CTX_free(g_ctx);
		g_ctx = NULL;
	}
}

bool stratum_tls_accept(int fd, STRATUM_TLS **out, char *errbuf, size_t errlen)
{
	errbuf[0] = 0;
	*out = NULL;

	if (!g_ctx)
	{
		snprintf(errbuf, errlen, "TLS is not initialized");
		return false;
	}

	SSL *ssl = SSL_new(g_ctx);
	if (!ssl)
	{
		tls_errors(errbuf, errlen);
		return false;
	}
	int flags = fcntl(fd, F_GETFL, 0);
	if (SSL_set_fd(ssl, fd) != 1 || flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
		tls_errors(errbuf, errlen);
		SSL_free(ssl);
		return false;
	}

	// a short deadline: a client that never sends a ClientHello must not
	// pin a worker thread for the whole receive timeout
	long long deadline = tls_now_ms() + 10000;
	int res;
	while ((res = SSL_accept(ssl)) != 1)
	{
		int err = SSL_get_error(ssl, res);
		if (!tls_wait(fd, err, deadline))
		{
			if (!errbuf[0]) tls_errors(errbuf, errlen);
			SSL_free(ssl);
			return false;
		}
	}

	STRATUM_TLS *t = new STRATUM_TLS;
	t->ssl = ssl;
	t->fd = fd;
	t->broken = false;
	pthread_mutex_init(&t->ssl_lock, NULL);
	pthread_mutex_init(&t->write_lock, NULL);

	*out = t;
	return true;
}

int stratum_tls_read(STRATUM_TLS *t, void *buf, int num)
{
	long long deadline = tls_deadline(t->fd, SO_RCVTIMEO);
	while (true)
	{
		int err;
		int n = tls_call(t, [&] { return SSL_read(t->ssl, buf, num); }, &err);
		if (n > 0) return n;
		if (!tls_wait(t->fd, err, deadline)) return -1;
	}
}

// writes all of buf or fails (returns -1)
int stratum_tls_write(STRATUM_TLS *t, const void *buf, int num)
{
	if (num <= 0) return 0;

	pthread_mutex_lock(&t->write_lock);
	long long deadline = tls_deadline(t->fd, SO_SNDTIMEO);
	int n, err;
	while ((n = tls_call(t, [&] { return SSL_write(t->ssl, buf, num); }, &err)) <= 0)
	{
		if (!tls_wait(t->fd, err, deadline))
		{
			// a pending record can't be abandoned: the stream is lost
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) tls_break(t);
			n = -1;
			break;
		}
	}
	pthread_mutex_unlock(&t->write_lock);
	return n;
}

void stratum_tls_close(STRATUM_TLS *t)
{
	if (!t) return;

	pthread_mutex_lock(&t->write_lock);
	pthread_mutex_lock(&t->ssl_lock);
	if (!t->broken) SSL_shutdown(t->ssl);	// best effort, non-blocking
	SSL_free(t->ssl);
	pthread_mutex_unlock(&t->ssl_lock);
	pthread_mutex_unlock(&t->write_lock);

	pthread_mutex_destroy(&t->ssl_lock);
	pthread_mutex_destroy(&t->write_lock);
	delete t;
}
