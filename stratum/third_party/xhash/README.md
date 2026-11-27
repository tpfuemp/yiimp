# XHash (Parallax / LAX) for the yiimp stratum

`xhash` is an Ethereum-style algorithm: it uses the same work package,
EthereumStratum/1.0.0 protocol and `getWork`/`submitWork` RPC shape as
`ethash`, but a different PoW core. This directory vendors the canonical
C/C++ implementation; the stratum glue lives in `stratum/protocol/ethash/` and is selected
by `algo = xhash`.

## Provenance and license

Sources here (`include/`, `lib/`) come from `parallax-pool`
(<https://github.com/ParallaxProtocol/parallax-pool>), path
`src/Native/libxhash`, revision matching XHash revision 23 / library version
1.1.0. They are licensed under **Apache-2.0** (see `LICENSE`); the
original copyright notices are kept in every file.

Only the library core is vendored. The upstream `exports.cpp` (shared-object
`dlopen` shim) and `Makefile` are intentionally omitted: yiimp links the
objects directly, so no extra exported ABI is needed.

No Parallax node source is compiled here. The node is a separate process and
is reached over JSON-RPC (`xhash_getWork`, `xhash_submitWork`, plus the normal
`eth_*` block/height methods).

## Algorithm parameters (consensus, not tunable)

| Parameter | Value |
|---|---|
| Revision | 23 |
| Epoch length | 720 blocks |
| Seed hash | SHA3-256(`"PARALLAX\x01"` ++ previous seed) |
| Cache seed | SHA3-512(seed) |
| Final hash | SHA3-256(cache seed ++ mix) |
| Dataset accesses | 64 |
| Difficulty | `target = floor((2^256-1) / difficulty)`, `hash <= target` |

The pool uses the same 2^224 share scale as `ethash`
(`target = 2^224 / diff`), so Hashwarp's `d=0.1` means 0.1 * 2^32 expected
hashes per share. This matches the official pool and the other ETH-family
algos in yiimp.

## Files

- `include/`, `lib/` — vendored Apache-2.0 implementation (upstream layout).
- `protocol/ethash/engine.cpp` — selects ethash/etchash or xhash at startup and
  owns the light-cache context cache.
- `protocol/ethash/work.cpp` — shared work/template/submit/protocol code; the
  engine supplies the RPC method names, epoch derivation and hash function.

## Verification

`make -C stratum/tests check-xhash` runs known answers from parallax-pool's
tests (epoch seeds and light hash/mix vectors); `make check` includes it.
Setup notes: `stratum/protocol/ethash/README.xhash.md`.
