#!/usr/bin/env python3
"""Independent check of bin/gethethsig: own keccak, secp256k1, RLP and keystore.

usage: bin/gethethsig-check.py bin/gethethsig <workdir>   (needs the openssl CLI)
"""
import hashlib, json, os, subprocess, sys

# ---- keccak-256 (pre-FIPS padding 0x01) -------------------------------------
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M = (1 << 64) - 1
def rol(x, n): return ((x << n) | (x >> (64 - n))) & M if n else x
def kf(A):
    for rc in RC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rol(A[x][y], ROT[x][y])
        A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= rc
    return A
def keccak256(data):
    rate = 136
    p = bytearray(data) + b'\x01'
    while len(p) % rate: p += b'\x00'
    p[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            A[x][y] ^= int.from_bytes(p[off + 8 * i: off + 8 * i + 8], 'little')
        A = kf(A)
    out = b''
    for i in range(4):
        out += A[i % 5][i // 5].to_bytes(8, 'little')
    return out
assert keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'

# ---- secp256k1 --------------------------------------------------------------
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    l = (3 * a[0] * a[0] * pow(2 * a[1], -1, P)) % P if a == b else ((b[1] - a[1]) * pow(b[0] - a[0], -1, P)) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)
def mul(k, pt):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r
def addr_of(pub): return keccak256(pub[0].to_bytes(32, 'big') + pub[1].to_bytes(32, 'big'))[12:]
def recover(z, r, s, recid):
    x = r + (N if recid & 2 else 0)
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    if (y & 1) != (recid & 1): y = P - y
    R = (x, y)
    rinv = pow(r, -1, N)
    zG = mul(z % N, G)
    return mul(rinv, add(mul(s, R), (zG[0], P - zG[1])))

# ---- strict RLP -------------------------------------------------------------
def rlp_dec(b, i=0):
    t = b[i]
    if t < 0x80: return b[i:i + 1], i + 1
    if t <= 0xb7:
        n = t - 0x80; v = b[i + 1:i + 1 + n]
        assert not (n == 1 and v[0] < 0x80), 'non-canonical single byte'
        return v, i + 1 + n
    if t <= 0xbf:
        ll = t - 0xb7; n = int.from_bytes(b[i + 1:i + 1 + ll], 'big'); assert n > 55
        return b[i + 1 + ll:i + 1 + ll + n], i + 1 + ll + n
    if t <= 0xf7: n = t - 0xc0; s = i + 1
    else:
        ll = t - 0xf7; n = int.from_bytes(b[i + 1:i + 1 + ll], 'big'); s = i + 1 + ll
    items, j = [], s
    while j < s + n:
        v, j = rlp_dec(b, j); items.append(v)
    assert j == s + n
    return items, j
def rlp_int(v):
    assert not (len(v) > 0 and v[0] == 0), 'leading zero in RLP integer'
    return int.from_bytes(v, 'big')
def rlp_enc(x):
    if isinstance(x, list):
        p = b''.join(rlp_enc(i) for i in x)
        return (bytes([0xc0 + len(p)]) if len(p) <= 55 else bytes([0xf7 + len(len(p).to_bytes(8, 'big').lstrip(b'\0'))]) + len(p).to_bytes(8, 'big').lstrip(b'\0')) + p
    if len(x) == 1 and x[0] < 0x80: return x
    return (bytes([0x80 + len(x)]) if len(x) <= 55 else bytes([0xb7 + len(len(x).to_bytes(8, 'big').lstrip(b'\0'))]) + len(x).to_bytes(8, 'big').lstrip(b'\0')) + x
def ib(n): return n.to_bytes((n.bit_length() + 7) // 8, 'big')

# ---- keystore ---------------------------------------------------------------
def make_keystore(priv, password, work):
    salt, iv = os.urandom(32), os.urandom(16)
    n, r, p = 1024, 8, 1
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    ct = subprocess.run(['openssl', 'enc', '-aes-128-ctr', '-K', dk[:16].hex(), '-iv', iv.hex(), '-nopad'],
                        input=priv.to_bytes(32, 'big'), capture_output=True, check=True).stdout
    ks = {'version': 3, 'id': '00000000-0000-0000-0000-000000000000',
          'address': addr_of(mul(priv, G)).hex(),
          'crypto': {'cipher': 'aes-128-ctr', 'ciphertext': ct.hex(), 'cipherparams': {'iv': iv.hex()},
                     'kdf': 'scrypt', 'kdfparams': {'dklen': 32, 'n': n, 'r': r, 'p': p, 'salt': salt.hex()},
                     'mac': keccak256(dk[16:] + ct).hex()}}
    path = os.path.join(work, 'UTC--test')
    open(path, 'w').write(json.dumps(ks))
    pw = os.path.join(work, 'password.txt'); open(pw, 'w').write(password + '\n')
    return path, pw

def main():
    signer, work = sys.argv[1], sys.argv[2]
    os.makedirs(work, exist_ok=True)
    fails = 0

    # EIP-155 example: key 0x46..46, nonce 9, 20 gwei, 21000, to 0x35..35, 1 ether, chain 1
    priv = int('46' * 32, 16)
    ks, pw = make_keystore(priv, 'test password', work)
    addr = '0x' + addr_of(mul(priv, G)).hex()
    assert addr == '0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f'

    def run(args):
        return subprocess.run([signer, '--keystore', ks, '--password-file', pw] + args, capture_output=True, text=True)

    r = run(['--check-only'])
    if r.stdout.strip() != addr: print('FAIL check-only', r.stdout, r.stderr); fails += 1
    r = run(['--expected-address', '0x' + '11' * 20, '--check-only'])
    if r.returncode == 0: print('FAIL wrong expected address accepted'); fails += 1
    open(pw + '.bad', 'w').write('wrong\n')
    r = subprocess.run([signer, '--keystore', ks, '--password-file', pw + '.bad', '--check-only'], capture_output=True, text=True)
    if r.returncode == 0 or 'MAC' not in r.stderr: print('FAIL wrong password', r.stderr); fails += 1

    zero_lead = 0
    count = 300
    for k in range(count):
        nonce, chain = (9, 1) if k == 0 else (k * 7919 % 100000, [1, 61, 2102, 1337][k % 4])
        value, gp = (10**18, 20 * 10**9) if k == 0 else (10**15 * (k + 1), 10**9 + k)
        to = bytes.fromhex('35' * 20)
        r = run(['--expected-address', addr, '--to', '0x' + to.hex(), '--value-wei', str(value), '--nonce', str(nonce),
                 '--gas-price', str(gp), '--gas-limit', '21000', '--chain-id', str(chain)])
        if r.returncode:
            print('FAIL sign', r.stderr); fails += 1; continue
        raw = bytes.fromhex(r.stdout.strip()[2:])
        try:
            items, end = rlp_dec(raw)
            assert end == len(raw) and len(items) == 9
            n_, gp_, gl_, to_, v_, d_, V, R, S = items
            n_, gp_, gl_, v_, V, R, S = map(rlp_int, (n_, gp_, gl_, v_, V, R, S))
        except AssertionError as e:
            print('FAIL rlp', e); fails += 1; continue
        if len(items[7]) < 32 or len(items[8]) < 32: zero_lead += 1
        unsigned = rlp_enc([ib(n_), ib(gp_), ib(gl_), to_, ib(v_), d_, ib(chain), b'', b''])
        z = int.from_bytes(keccak256(unsigned), 'big')
        if k == 0 and z != 0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53:
            print('FAIL EIP-155 signing hash'); fails += 1
        ok = (n_, gp_, gl_, to_, v_, d_) == (nonce, gp, 21000, to, value, b'')
        recid = V - (2 * chain + 35)
        ok = ok and recid in (0, 1) and S <= N // 2
        if ok:
            pub = recover(z, R, S, recid)
            ok = pub is not None and '0x' + addr_of(pub).hex() == addr
        if not ok: print('FAIL tx', k); fails += 1
    print('gethethsig: %d transactions, %d with short r/s, %d failures' % (count, zero_lead, fails))
    return 1 if fails else 0

sys.exit(main())
