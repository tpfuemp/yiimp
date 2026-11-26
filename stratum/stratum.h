
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <math.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <mysql.h>
#include <errmsg.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <algorithm>

#include <iostream>
#include <vector>

using namespace std;

#include "iniparser/src/iniparser.h"

#include "json.h"
#include "utilstrencodings.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "util.h"

#define YAAMP_RESTARTDELAY		(24*60*60)
#define YAAMP_MAXJOBDELAY		(2*60)
#define CURL_RPC_TIMEOUT		(30)

#define YAAMP_MS				1000
#define YAAMP_SEC				1000000

#define YAAMP_MAXALGOS			32

typedef void (*YAAMP_HASH_FUNCTION)(const char *, char *, uint32_t);


#define YAAMP_MINDIFF			0x0000000080000000
#define YAAMP_MAXDIFF			0x4000000000000000

#define YAAMP_SMALLBUFSIZE		(32*1024)

#define YAAMP_NONCE_SIZE		4
#define YAAMP_KAWPOW_NONCE_SIZE	8
#define YAAMP_RES_NONCE_SIZE	(32 - YAAMP_NONCE_SIZE)
#define YAAMP_EQUIHASH_NONCE_SIZE   28
#define YAAMP_EXTRANONCE2_SIZE	4

#define YAAMP_HASHLEN_STR		65
#define YAAMP_HASHLEN_BIN		32

extern CommonList g_list_coind;
extern CommonList g_list_client;
extern CommonList g_list_job;
extern CommonList g_list_remote;
extern CommonList g_list_renter;
extern CommonList g_list_share;
extern CommonList g_list_worker;
extern CommonList g_list_block;
extern CommonList g_list_submit;
extern CommonList g_list_source;

extern bool is_kawpow;
extern bool is_firopow;
extern bool is_phihash;
extern bool is_meowpow;
extern bool is_evrprogpow;
extern bool is_meraki;
extern bool is_homescrypt;
extern bool is_randomscash;
extern bool is_ethash;
extern bool is_etchash;
extern bool is_nebhash;
// protocol families (algos/registry.def); the names above are single algos
extern bool is_progpow;
extern bool is_eth;
extern bool is_equihash;

extern int g_tcp_port;

// Optional TLS listeners. tls_port = 0 disables the dedicated TLS port; the
// main port still accepts TLS when a certificate is configured and
// tls_autodetect is enabled.
extern int g_tcp_tls_port;
extern char g_tcp_tls_cert[1024];
extern char g_tcp_tls_key[1024];
extern bool g_tcp_tls_autodetect;
extern bool g_tls_enabled;

extern char g_tcp_server[1024];
extern char g_tcp_password[1024];

extern char g_sql_host[1024];
extern char g_sql_database[1024];
extern char g_sql_username[1024];
extern char g_sql_password[1024];
extern int g_sql_port;

extern char g_stratum_coin_include[256];
extern char g_stratum_coin_exclude[256];

extern char g_stratum_algo[256];
extern double g_stratum_difficulty;
extern double g_stratum_min_diff;
extern double g_stratum_max_diff;
extern double g_stratum_spm_min;
extern double g_stratum_spm_max;
extern double g_stratum_spm_spam;
extern int g_stratum_share_timeout;
extern int g_stratum_speed_slot_secs;
extern int g_stratum_idle_timeout;
extern bool g_stratum_allow_static_diff;

extern char g_nebhash_work_host[256];
extern int g_nebhash_work_port;
extern char g_nebhash_dataset[1024];
extern char g_nebhash_chain_id[65];
extern uint32_t g_nebhash_start_k;

extern double g_stratum_nicehash_difficulty;
extern double g_stratum_nicehash_min_diff;
extern double g_stratum_nicehash_max_diff;

extern int g_stratum_max_cons;
extern int g_stratum_max_ttf;
extern bool g_stratum_reconnect;
extern bool g_stratum_renting;
extern bool g_stratum_segwit;
extern bool g_stratum_mweb;
extern int g_limit_txs_per_block;

extern bool g_handle_haproxy_ips;
extern int g_socket_recv_timeout;

extern char g_log_directory[1024];
extern bool g_debuglog_client;
extern bool g_debuglog_hash;
extern bool g_debuglog_socket;
extern bool g_debuglog_rpc;
extern bool g_debuglog_list;
extern bool g_debuglog_remote;

extern uint64_t g_max_shares;
extern uint64_t g_shares_counter;

extern uint32_t g_equihash_wk;
extern uint32_t g_equihash_wn;

extern bool g_allow_rolltime;
extern time_t g_last_broadcasted;

extern struct ifaddrs *g_ifaddr;

extern pthread_mutex_t g_db_mutex;
extern pthread_mutex_t g_nonce1_mutex;
extern pthread_mutex_t g_context_mutex;
extern pthread_mutex_t g_job_create_mutex;

extern volatile bool g_exiting;

#include "db.h"
#include "object.h"
#include "socket.h"
#include "job.h"
#include "client.h"
#include "rpc.h"
#include "coind.h"
#include "remote.h"
#include "share.h"
#include "kawpow/hash.h"
#include "kawpow/kawpow.h"
#include "firopow/hash.h"
#include "firopow/overrides.h"
#include "phihash/hash.h"
#include "meraki/hash.h"
#include "meraki/meraki.h"
#include "homescrypt/homescrypt.h"
#include "ethash/params.h"
#include "ethash/context.h"
#include "ethash/work.h"
#include "nebhash/work.h"

extern YAAMP_DB *g_db;
extern YAAMP_ALGO g_algos[];
extern YAAMP_ALGO *g_current_algo;

extern bool g_autoexchange;

/////////////////////////////////////////////////////////////////////////////////////////

YAAMP_ALGO *stratum_find_algo(const char *name);
void stratum_set_algo_flags(const YAAMP_ALGO *algo);

extern "C"
{
void sha256_hash(const char *input, char *output, unsigned int len);
void sha256_double_hash(const char *input, char *output, unsigned int len);

void scrypt_1024_1_1_256(const unsigned char *input, unsigned char *output);
void scrypt_N_R_1_256(const char* input, char* output, uint32_t N, uint32_t R, uint32_t len);
}

void sha256_hash_hex(const char *input, char *output, unsigned int len);
void sha256_double_hash_hex(const char *input, char *output, unsigned int len);
void sha3d_hash_hex(const char *input, char *output, unsigned int len);

#include "algos/algos.h"

