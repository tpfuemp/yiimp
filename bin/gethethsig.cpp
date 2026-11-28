// gethethsig - sign an Ethereum-style legacy (type 0) transfer from a V3 keystore.
//
// Built against OpenSSL 1.1/3 and the sph keccak implementation shipped with
// yiimp's stratum tree. It never talks to the network and never prints the
// private key; it only prints the signed raw transaction (or the derived
// address with --check-only).
//
// Usage:
//   gethethsig --keystore FILE --password-file FILE [--expected-address 0x..]
//              --to 0x.. --value-wei DECIMAL --nonce N
//              --gas-price DECIMAL --gas-limit N --chain-id N [--check-only]
//
// Exit status: 0 on success, 1 on any error. Errors go to stderr.

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "sph_keccak.h"
}

namespace {

void keccak256(const unsigned char *data, size_t len, unsigned char out[32])
{
    sph_keccak256_context ctx;
    sph_keccak256_init(&ctx);
    sph_keccak256(&ctx, data, len);
    sph_keccak256_close(&ctx, out);
}

std::string hex_encode(const unsigned char *data, size_t len)
{
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 15]);
    }
    return out;
}

bool hex_decode(const std::string &in, std::vector<unsigned char> &out)
{
    std::string s = in;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s.erase(0, 2);
    if (s.size() % 2) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        char a = (char) std::tolower((unsigned char) s[i]);
        char b = (char) std::tolower((unsigned char) s[i+1]);
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        int hi = nib(a), lo = nib(b);
        if (hi < 0 || lo < 0) return false;
        out.push_back((unsigned char) ((hi << 4) | lo));
    }
    return true;
}

std::string read_file(const std::string &path)
{
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) return std::string();
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Minimal JSON scanner: enough for the flat string/number values used by
// Ethereum V3 keystores. Returns npos when the key is absent.
size_t json_key(const std::string &s, const char *key, size_t from = 0)
{
    std::string needle = std::string("\"") + key + "\"";
    return s.find(needle, from);
}

bool json_string(const std::string &s, const char *key, std::string &value,
                 size_t from = 0)
{
    size_t p = json_key(s, key, from);
    if (p == std::string::npos) return false;
    p = s.find(':', p + strlen(key) + 2);
    if (p == std::string::npos) return false;
    p = s.find('"', p + 1);
    if (p == std::string::npos) return false;
    std::string out;
    for (size_t i = p + 1; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            out.push_back(s[++i]);
            continue;
        }
        if (s[i] == '"') { value = out; return true; }
        out.push_back(s[i]);
    }
    return false;
}

bool json_number(const std::string &s, const char *key, long long &value,
                 size_t from = 0)
{
    size_t p = json_key(s, key, from);
    if (p == std::string::npos) return false;
    p = s.find(':', p + strlen(key) + 2);
    if (p == std::string::npos) return false;
    ++p;
    while (p < s.size() && std::isspace((unsigned char) s[p])) ++p;
    size_t start = p;
    while (p < s.size() && std::isdigit((unsigned char) s[p])) ++p;
    if (p == start) return false;
    value = std::atoll(s.substr(start, p - start).c_str());
    return true;
}

// Locate the opening brace of an object value, e.g. "crypto": { ...
size_t json_object(const std::string &s, const char *key, size_t from = 0)
{
    size_t p = json_key(s, key, from);
    if (p == std::string::npos) return std::string::npos;
    p = s.find('{', p + strlen(key) + 2);
    return p;
}

bool bn_to_bytes(const char *decimal, std::vector<unsigned char> &out, bool minimal)
{
    BIGNUM *bn = NULL;
    if (!BN_dec2bn(&bn, decimal)) return false;
    if (BN_is_zero(bn)) {
        out.clear();
        if (!minimal) out.push_back(0);
        BN_free(bn);
        return true;
    }
    size_t len = (size_t) BN_num_bytes(bn);
    out.assign(len, 0);
    BN_bn2bin(bn, &out[0]);
    BN_free(bn);
    // For RLP integer fields leading zeros must be removed; the BN encoder
    // already emits the minimal big-endian form.
    (void) minimal;
    return true;
}

std::vector<unsigned char> rlp_string(const std::vector<unsigned char> &v)
{
    std::vector<unsigned char> out;
    size_t n = v.size();
    if (n == 1 && v[0] < 0x80) {
        out.push_back(v[0]);
        return out;
    }
    if (n <= 55) {
        out.push_back((unsigned char) (0x80 + n));
    } else {
        std::vector<unsigned char> l;
        size_t t = n;
        while (t) { l.insert(l.begin(), (unsigned char) (t & 0xff)); t >>= 8; }
        out.push_back((unsigned char) (0xb7 + l.size()));
        out.insert(out.end(), l.begin(), l.end());
    }
    out.insert(out.end(), v.begin(), v.end());
    return out;
}

std::vector<unsigned char> rlp_list(const std::vector<unsigned char> &payload)
{
    std::vector<unsigned char> out;
    size_t n = payload.size();
    if (n <= 55) {
        out.push_back((unsigned char) (0xc0 + n));
    } else {
        std::vector<unsigned char> l;
        size_t t = n;
        while (t) { l.insert(l.begin(), (unsigned char) (t & 0xff)); t >>= 8; }
        out.push_back((unsigned char) (0xf7 + l.size()));
        out.insert(out.end(), l.begin(), l.end());
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// RLP integers are big-endian without leading zero bytes
std::vector<unsigned char> rlp_uint(const BIGNUM *bn)
{
    std::vector<unsigned char> out(BN_num_bytes(bn));
    if (!out.empty()) BN_bn2bin(bn, &out[0]);
    return rlp_string(out);
}

void append(std::vector<unsigned char> &dst, const std::vector<unsigned char> &src)
{
    dst.insert(dst.end(), src.begin(), src.end());
}

bool parse_args(int argc, char **argv, std::string &keystore,
                std::string &password_file, std::string &expected,
                std::string &to, std::string &value, std::string &nonce,
                std::string &gas_price, std::string &gas_limit,
                std::string &chain_id, bool &check_only)
{
    keystore = password_file = expected = to = value = nonce = gas_price =
        gas_limit = chain_id = "";
    check_only = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](std::string &dst) -> bool {
            if (i + 1 >= argc) return false;
            dst = argv[++i];
            return true;
        };
        if (a == "--keystore") { if (!next(keystore)) return false; }
        else if (a == "--password-file") { if (!next(password_file)) return false; }
        else if (a == "--expected-address") { if (!next(expected)) return false; }
        else if (a == "--to") { if (!next(to)) return false; }
        else if (a == "--value-wei") { if (!next(value)) return false; }
        else if (a == "--nonce") { if (!next(nonce)) return false; }
        else if (a == "--gas-price") { if (!next(gas_price)) return false; }
        else if (a == "--gas-limit") { if (!next(gas_limit)) return false; }
        else if (a == "--chain-id") { if (!next(chain_id)) return false; }
        else if (a == "--check-only") { check_only = true; }
        else return false;
    }
    return !keystore.empty() && !password_file.empty();
}

} // namespace

int main(int argc, char **argv)
{
    std::string keystore_path, password_path, expected, to, value, nonce,
        gas_price, gas_limit, chain_id;
    bool check_only = false;
    if (!parse_args(argc, argv, keystore_path, password_path, expected, to,
                    value, nonce, gas_price, gas_limit, chain_id, check_only)) {
        std::cerr << "gethethsig: invalid arguments\n";
        return 1;
    }

    std::string json = read_file(keystore_path);
    std::string password = read_file(password_path);
    if (json.empty() || password.empty()) {
        std::cerr << "gethethsig: cannot read keystore or password file\n";
        return 1;
    }
    while (!password.empty() &&
           (password.back() == '\n' || password.back() == '\r'))
        password.erase(password.size() - 1);

    size_t crypto = json_object(json, "crypto");
    if (crypto == std::string::npos) crypto = json_object(json, "Crypto");
    if (crypto == std::string::npos) {
        std::cerr << "gethethsig: unsupported keystore format\n";
        return 1;
    }
    std::string cipher, ciphertext_hex, iv_hex, salt_hex, mac_hex, kdf;
    long long n = 0, r = 0, p = 0, dklen = 32;
    if (!json_string(json, "cipher", cipher, crypto) ||
        !json_string(json, "ciphertext", ciphertext_hex, crypto) ||
        !json_string(json, "mac", mac_hex, crypto) ||
        !json_string(json, "kdf", kdf, crypto)) {
        std::cerr << "gethethsig: incomplete keystore crypto section\n";
        return 1;
    }
    size_t cipherparams = json_object(json, "cipherparams", crypto);
    size_t kdfparams = json_object(json, "kdfparams", crypto);
    if (cipherparams == std::string::npos || kdfparams == std::string::npos ||
        !json_string(json, "iv", iv_hex, cipherparams) ||
        !json_string(json, "salt", salt_hex, kdfparams) ||
        !json_number(json, "n", n, kdfparams) ||
        !json_number(json, "r", r, kdfparams) ||
        !json_number(json, "p", p, kdfparams)) {
        std::cerr << "gethethsig: incomplete keystore parameters\n";
        return 1;
    }
    json_number(json, "dklen", dklen, kdfparams);

    std::vector<unsigned char> ciphertext, iv, salt, mac;
    if (cipher != "aes-128-ctr" || kdf != "scrypt" || dklen != 32 ||
        !hex_decode(ciphertext_hex, ciphertext) || ciphertext.empty() ||
        !hex_decode(iv_hex, iv) || iv.size() != 16 ||
        !hex_decode(salt_hex, salt) || !hex_decode(mac_hex, mac) || mac.size() != 32) {
        std::cerr << "gethethsig: unsupported cipher/kdf parameters\n";
        return 1;
    }

    unsigned char key[32];
    // scrypt N=262144,r=8,p=1 needs ~256 MiB.
    if (EVP_PBE_scrypt(password.data(), password.size(), salt.data(), salt.size(),
                       (uint64_t) n, (uint64_t) r, (uint64_t) p,
                       (uint64_t) 1 << 29, key, dklen) != 1) {
        std::cerr << "gethethsig: scrypt derivation failed\n";
        return 1;
    }
    std::vector<unsigned char> mac_input(key + 16, key + 32);
    mac_input.insert(mac_input.end(), ciphertext.begin(), ciphertext.end());
    unsigned char mac_hash[32];
    keccak256(mac_input.data(), mac_input.size(), mac_hash);
    if (std::memcmp(mac_hash, mac.data(), 32) != 0) {
        std::cerr << "gethethsig: wrong password or corrupt keystore (MAC mismatch)\n";
        return 1;
    }

    unsigned char privkey[32];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0;
    if (!ctx ||
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv.data()) != 1 ||
        EVP_DecryptUpdate(ctx, privkey, &outlen, ciphertext.data(),
                          (int) ciphertext.size()) != 1 ||
        outlen != 32 ||
        EVP_DecryptFinal_ex(ctx, privkey + outlen, &outlen) != 1) {
        std::cerr << "gethethsig: keystore decryption failed\n";
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(&password[0], password.size());

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *priv = BN_secure_new();
    BN_bin2bn(privkey, 32, priv);
    OPENSSL_cleanse(privkey, sizeof(privkey));
    EC_POINT *pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, NULL, NULL, bnctx);
    std::vector<unsigned char> pubbuf(65);
    EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                       &pubbuf[0], pubbuf.size(), bnctx);
    unsigned char pubhash[32];
    keccak256(&pubbuf[1], 64, pubhash);
    std::string address = "0x" + hex_encode(pubhash + 12, 20);

    if (!expected.empty()) {
        std::string want = expected;
        std::transform(want.begin(), want.end(), want.begin(),
                       [](unsigned char c) { return (char) std::tolower(c); });
        std::transform(address.begin(), address.end(), address.begin(),
                       [](unsigned char c) { return (char) std::tolower(c); });
        if (want.find("0x") == 0) want.erase(0, 2);
        if (address.find("0x") == 0) address.erase(0, 2);
        if (want != address) {
            std::cerr << "gethethsig: keystore address " << address
                      << " does not match expected " << want << "\n";
            return 1;
        }
    }
    if (check_only) {
        std::cout << "0x" << hex_encode(pubhash + 12, 20) << "\n";
        return 0;
    }

    if (to.empty() || value.empty() || nonce.empty() || gas_price.empty() ||
        gas_limit.empty() || chain_id.empty()) {
        std::cerr << "gethethsig: missing transaction arguments\n";
        return 1;
    }
    std::vector<unsigned char> to_bytes, value_bytes, nonce_bytes,
        gas_price_bytes, gas_limit_bytes, chain_bytes;
    std::vector<unsigned char> empty_data;
    if (!hex_decode(to, to_bytes) || to_bytes.size() != 20 ||
        !bn_to_bytes(value.c_str(), value_bytes, true) ||
        !bn_to_bytes(nonce.c_str(), nonce_bytes, true) ||
        !bn_to_bytes(gas_price.c_str(), gas_price_bytes, true) ||
        !bn_to_bytes(gas_limit.c_str(), gas_limit_bytes, true) ||
        !bn_to_bytes(chain_id.c_str(), chain_bytes, true)) {
        std::cerr << "gethethsig: invalid transaction arguments\n";
        return 1;
    }

    auto encode_unsigned = [&](const std::vector<unsigned char> &v) {
        return rlp_string(v);
    };

    std::vector<unsigned char> payload;
    append(payload, encode_unsigned(nonce_bytes));
    append(payload, encode_unsigned(gas_price_bytes));
    append(payload, encode_unsigned(gas_limit_bytes));
    append(payload, rlp_string(to_bytes));
    append(payload, encode_unsigned(value_bytes));
    append(payload, rlp_string(empty_data));
    append(payload, encode_unsigned(chain_bytes)); // v placeholder = chain id
    append(payload, rlp_string(empty_data)); // r placeholder = 0
    append(payload, rlp_string(empty_data)); // s placeholder = 0

    std::vector<unsigned char> unsigned_tx = rlp_list(payload);
    unsigned char msg[32];
    keccak256(unsigned_tx.data(), unsigned_tx.size(), msg);

    // ECDSA sign with OpenSSL's secp256k1 group; OpenSSL gives us r and s.
    BIGNUM *z = BN_bin2bn(msg, 32, NULL);
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_private_key(eckey, priv);
    EC_KEY_set_public_key(eckey, pub);
    ECDSA_SIG *sig = ECDSA_do_sign(msg, 32, eckey);
    if (!sig) {
        std::cerr << "gethethsig: ECDSA signing failed\n";
        return 1;
    }
    const BIGNUM *sr = NULL, *ss = NULL;
    ECDSA_SIG_get0(sig, &sr, &ss);

    // EIP-2: enforce low-s.
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BIGNUM *half = BN_new();
    BN_rshift1(half, order);
    BIGNUM *s = BN_dup(ss);
    if (BN_cmp(s, half) > 0) BN_sub(s, order, s);

    // Recovery id: try R.x = r and R.x = r + n, and both square roots of
    // y^2 = x^3 + 7; keep the candidate that reconstructs our public key.
    int recid = -1;
    BIGNUM *rx = BN_dup(sr);
    const BIGNUM *field = EC_GROUP_get0_field(group);
    BIGNUM *rinv = BN_mod_inverse(NULL, sr, order, bnctx);
    for (int candidate = 0; candidate < 2 && recid < 0; ++candidate) {
        if (candidate == 1) BN_add(rx, rx, order);
        BIGNUM *rhs = BN_new();
        BIGNUM *x2 = BN_new(), *x3 = BN_new(), *seven = BN_new();
        BN_mod_mul(x2, rx, rx, field, bnctx);
        BN_mod_mul(x3, x2, rx, field, bnctx);
        BN_set_word(seven, 7);
        BN_mod_add(rhs, x3, seven, field, bnctx);
        BIGNUM *y = BN_mod_sqrt(NULL, rhs, field, bnctx);
        for (int sign = 0; sign < 2 && y && recid < 0; ++sign) {
            BIGNUM *ry = BN_dup(y);
            if (sign == 1) BN_sub(ry, field, y);
            EC_POINT *R = EC_POINT_new(group);
            if (EC_POINT_set_affine_coordinates(group, R, rx, ry, bnctx) &&
                EC_POINT_is_on_curve(group, R, bnctx) == 1) {
                EC_POINT *sR = EC_POINT_new(group);
                EC_POINT *zG = EC_POINT_new(group);
                EC_POINT *neg = EC_POINT_new(group);
                EC_POINT *sum = EC_POINT_new(group);
                EC_POINT *Q = EC_POINT_new(group);
                EC_POINT_mul(group, sR, NULL, R, s, bnctx);
                EC_POINT_mul(group, zG, NULL,
                             EC_GROUP_get0_generator(group), z, bnctx);
                EC_POINT_copy(neg, zG);
                EC_POINT_invert(group, neg, bnctx);
                EC_POINT_add(group, sum, sR, neg, bnctx);
                EC_POINT_mul(group, Q, NULL, sum, rinv, bnctx);
                if (EC_POINT_cmp(group, Q, pub, bnctx) == 0) {
                    recid = BN_is_odd(ry) ? 1 : 0;
                    if (candidate == 1) recid += 2;
                }
                EC_POINT_free(Q); EC_POINT_free(sum); EC_POINT_free(neg);
                EC_POINT_free(zG); EC_POINT_free(sR);
            }
            EC_POINT_free(R);
            BN_free(ry);
        }
        if (y) BN_free(y);
        BN_free(x2); BN_free(x3); BN_free(seven); BN_free(rhs);
    }
    BN_free(rinv);
    if (recid < 0) {
        std::cerr << "gethethsig: cannot determine recovery id\n";
        return 1;
    }

    BIGNUM *vbn = BN_new();
    BIGNUM *chain_bn = NULL;
    BN_dec2bn(&chain_bn, chain_id.c_str());
    BN_add(vbn, chain_bn, chain_bn);
    BN_add_word(vbn, 35 + recid);


    std::vector<unsigned char> signed_payload;
    append(signed_payload, encode_unsigned(nonce_bytes));
    append(signed_payload, encode_unsigned(gas_price_bytes));
    append(signed_payload, encode_unsigned(gas_limit_bytes));
    append(signed_payload, rlp_string(to_bytes));
    append(signed_payload, encode_unsigned(value_bytes));
    append(signed_payload, rlp_string(empty_data));
    append(signed_payload, rlp_uint(vbn));
    append(signed_payload, rlp_uint(sr));
    append(signed_payload, rlp_uint(s));

    EC_KEY_free(eckey);
    BN_clear_free(priv);

    std::vector<unsigned char> raw = rlp_list(signed_payload);
    std::cout << "0x" << hex_encode(raw.data(), raw.size()) << "\n";
    return 0;
}
