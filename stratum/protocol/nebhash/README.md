# NEB `nebhash` pool support

This directory adds a `neb-pool/1` stratum listener for NEB v1.0.9 mainnet.

## Files

- `stratum/algos/nebhash/`: `blake3_shared.c/.h` — one-shot BLAKE3 over the
  canonical `stratum/third_party/blake3/` (shared with xelisv2); `chacha8.c/.h`,
  `nebhash2.c/.h`, `shares.c/.h` — verbatim C reference PoW engine from the
  NEB node (Apache-2.0, see `LICENSE`).
- `work.cpp/.h` — work-service TCP client, template/job builder, submit
  verification, reference k-window vardiff and chain-share forwarding.
- `tests/test_neb_pool1.py` — protocol smoke test (subscribe/authorize/notify,
  multi-login, NEB error shapes). It does not mine a share.

## Runtime requirements

- NEB node v1.0.9 (1.0.2+ compatible), `neb-node` from
  <https://github.com/SilasEigen/neb>. The stratum uses two of its services:
  - work service, port `3441` (`[NEBHASH] work_host` / `work_port`): jobs,
    models and share results
  - JSON-RPC, port `8432` (coin row `rpchost` / `rpcport`): `getinfo` and
    `submitshares`
- The work service only serves miners when the node runs with
  `--miner-lock <64 hex>` (the pool wallet's lock, `neb-wallet lock`).
- Pinned dataset `neb-datasets.bin` of the node (`[NEBHASH] dataset`)
  (`NMDS||LE32(2)||NMD2 arch=1 N=13404||NMD2 arch=1 N=7089`). Slot is
  `height mod 2`. The stratum reads its own copy, so it must be the same
  file the node pins (the node refuses any other).
- Stratum config `stratum/config.sample/nebhash.conf`
  (port `3645`, TLS-only port `4645` intentionally commented).
- SQL migrations `sql/2026-11-23-add_algo_nebhash.sql` and
  `sql/2026-11-24-widen-workers-name.sql` (62-char neb1 addresses); add the
  NEB coin through admin with algo `nebhash`. Expire the web memcache keys.

### Node on the stratum host (default)

The upstream `neb-node` binds JSON-RPC and the work service to `127.0.0.1`
only, with no option to change it. Run it on the stratum host and keep the
defaults: `work_host = 127.0.0.1`, coin row `rpchost = 127.0.0.1`.

### Node on a dedicated host

The NEB template in
[yiimp-contrib](https://github.com/tpfuemp/yiimp-contrib)
(`Coin-Dockerfile-Templates/NEB-NeuralEngineByte`) builds a podman/docker
image of `neb-node` and `neb-wallet` v1.0.9 with the pinned dataset in
`/usr/share/neb/neb-datasets.bin`. Its `docker.patch` adds `--rpc-bind` and
`--work-bind` (default `127.0.0.1`); its Makefile sets both
(`rpc_bind` / `work_bind`) and `miner_lock`.

- Point the stratum at that host: `[NEBHASH] work_host` and the coin row
  `rpchost`, and copy the image's dataset file to the stratum host
  (`[NEBHASH] dataset`).
- Both services have no authentication: when binding `0.0.0.0`, firewall
  ports `3441` and `8432` to the stratum host only.

## Protocol notes

- Subscribe result is an object: `session`, `extranonce1`,
  `extranonce2_size`, `chain_id`, `dataset_hash`. `extranonce1` is 4 bytes and
  `extranonce2_size` comes from the current node job.
- Every subscribe must send `"neb-pool/1"` as parameter 2. The generic
  notify-id reconnect path is skipped for this protocol.
- Every job push sends `mining.set_target` (exact 256-bit little-endian target
  bytes), `mining.set_model` when the model changes, then `mining.notify`.
  There is no generic `mining.set_difficulty` or default Yiimp difficulty 16.
- `mining.submit` has five parameters:
  `[login, job_id, extranonce2, time, nonce]`. A session may authorize up to
  eight `neb1` logins; shares and solo mode are attributed per login.
- Chain shares are sent to the node with JSON-RPC `submitshares`. P2P share
  forwarding is intentionally not used. Block credit is applied only after
  the node returns an accepted two-byte `Result` frame.
- V1 model frames are not supported. The loader accepts only `NMD2` /
  `neb2_model` datasets from node v1.0.9.
- Password tokens `d=` and `sd=` select the session target before the first
  job. An integer `1..48` keeps the reference pool's `k` shift
  (`target = share_target << k`). Any other positive number is the miner's
  display difficulty (`d=0.1` means `10^9` expected hashes); it is clamped so
  the pool target is never harder than the node's `share_target`. `d=` pins
  the value (only with `allow_static_diff = true`, otherwise like `sd=`), `sd=` only seeds it and leaves vardiff active, and `d=` wins if
  both are present. Invalid tokens are ignored.

## Smoke test

With the node replay complete and the stratum unit running:

```sh
python3 stratum/protocol/nebhash/tests/test_neb_pool1.py --host 127.0.0.1 --port 3645
```
