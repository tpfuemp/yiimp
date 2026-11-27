# XHash (Parallax / LAX) in the ethash work module

`algo = xhash` reuses the Ethash/Etchash work package, EthereumStratum/1.0.0
protocol and ethproxy compatibility layer. Only the chain-specific parts are
swapped in through `protocol/ethash/engine.cpp`:

| | Ethash / Etchash | XHash |
|---|---|---|
| Mining RPC | `eth_getWork`, `eth_submitWork` | `xhash_getWork`, `xhash_submitWork` |
| Work fields | `[sealHash, seed, target]` | `[sealHash, seed, target, blockNumber]` |
| Epoch | reverse-mapped from seed / height | `blockNumber / 720` |
| PoW core | ethash light library (Keccak-256) | `third_party/xhash` (SHA3-512/256) |
| Share scale | `target = 2^224 / diff` | same |

Block/height queries stay in the `eth_` namespace on Parallax; only the
mining methods change. The 4th `xhash_getWork` field is the candidate block
number, so it is used directly (no `+1` like classic `eth_blockNumber`).

## Share verification

`mining.notify` carries the advertised seed hash and seal hash. The stratum
derives the epoch from the `xhash_getWork` height and requires the advertised
seed to equal `xhash_calculate_epoch_seed(epoch)`; a mismatch is treated as a
failed work poll so miners are never handed jobs that cannot be verified.
Submitted nonces are verified against that same light cache.

The node boundary is `floor((2^256-1)/difficulty)`. Yiimp's `2^224/diff`
share target is the same scale Hashwarp uses (`2^256/(diff*2^32)`), so a
miner reporting `d=0.1` performs about `0.1 * 2^32` expected hashes per share.

## ccminer XHash protocol

ccminer forks (ccminer-kudaraidee) route XHash through their KawPoW-family
miner code. They subscribe with `[user_agent]`, expect `[null, extranonce1]`
back, and parse only a 7-field `mining.notify`
`[job_id, header_hash, seed_hash, target, clean, height, nbits]`.

When the subscribe user agent contains `ccminer-kudaraidee`, the xhash
listener switches that session to this wire format:

- subscribe result: `[null, "<nonce prefix>"]`
- `mining.notify`: 16-hex job id (8-digit prefix + 8-digit id), seal hash,
  seed hash, big-endian share target, clean flag, height and an 8-hex nbits
  value derived from the node boundary (ccminer treats zero nbits as "no job")
- no numeric `mining.set_difficulty`; the target travels with each job
- `mining.submit` accepts `[worker, job_id, nonce, header, mix, ...]` and
  normalizes it for the EthereumStratum verifier.

The miner strips the job id prefix, so a submit does not tell which resend of
a job it belongs to. As for ethproxy, the last resend of the job counts, and a
share in flight across a difficulty change may still meet the other (lower)
difficulty. All other miners keep the EthereumStratum/Rigel behaviour.

## Setup

1. Apply `sql/2026-11-27-add_algo_xhash.sql` and add the LAX coin row in the
   admin UI (`rpcencoding=GETH`, `rpccurl=1`, `mature_blocks=100`).
2. Run the official Parallax v2.x node with the pool beneficiary configured:
   - HTTP RPC on loopback, HTTP APIs `eth,net,web3,xhash,miner`
   - `--mine --miner.threads 0 --miner.coinbase <pool address>`
3. Leave `rpcuser`/`rpcpasswd` blank: Parallax HTTP RPC has no basic auth.
   The stratum reads host/port from the coin row.
4. Use `stratum/config.sample/xhash.conf` as the runtime config template.
   `coinid = <coins.id>` binds every login on the port to LAX, so a wallet
   already bound to another EVM chain keeps that binding.

## Tests

`make -C stratum/tests check-xhash` runs the vendored-library known-answer
tests from `parallax-pool` (seed hashes for epochs 0/1/171 and two light
hash/mix vectors). `make check` includes it.

`stratum/third_party/xhash/README.md` records the upstream provenance and
license.
