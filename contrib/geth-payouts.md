# GETH payouts

GETH-family coins (`rpcencoding` `GETH` or `NIRO`: ethash, etchash, Parallax
XHash) have no Bitcoin-style `sendmany`/`sendtoaddress`, and a mining node
normally has no unlocked account. The payout is signed locally and sent as a
raw transaction.

## Flow

1. The payment cron (`BackendCoinPayments()`, yiimp2 `PaymentService`) uses
   the per-user `sendtoaddress` path for GETH coins.
2. `WalletRPC` reads `eth_chainId`, `eth_gasPrice` and the pending nonce of
   the pool address (`master_wallet`, or the coin's `account`).
3. `bin/gethethsig` decrypts the Ethereum V3 keystore (scrypt, AES-128-CTR),
   checks that it belongs to the pool address and prints a signed legacy
   EIP-155 transfer. It never prints the private key.
4. `eth_sendRawTransaction` broadcasts it. The payout row is written and the
   user debited only after a 32-byte txid comes back.

A missing signer, wrong password, invalid address or failed broadcast stops
the payout cycle before any debit. Failed GETH payouts are not retried in a
batch: a broadcast that timed out may already be on chain, check it by hand.
The pool pays the gas on top of the payout amount (21000 gas per transfer).

## Configuration (`serverconfig.php`)

| Define | Purpose |
|---|---|
| `YIIMP_GETH_SIGNER_BIN` | signer binary |
| `YIIMP_GETH_KEYSTORE_DIR` | directory scanned for `UTC*` keystore files |
| `YIIMP_GETH_KEYSTORE_FILE` | one keystore file instead of the directory (optional) |
| `YIIMP_GETH_PASSWORD_FILE` | keystore password file (required) |
| `YIIMP_GETH_GAS_LIMIT` | gas limit per transfer, default 21000 |
| `YIIMP_GETH_GAS_PRICE` | fixed gas price in wei instead of `eth_gasPrice` (optional) |

Keep the keystore and password file outside the web root, readable only by
the user that runs the payment cron.

## Build and check

```sh
./bin/build-gethethsig.sh
python3 bin/gethethsig-check.py bin/gethethsig /tmp/gethethsig-check
```

The check creates a throwaway keystore, signs 300 transfers on several chain
ids and verifies each with its own keccak, secp256k1 recovery and strict RLP
decoder (canonical integers, low-s, EIP-155 `v`), plus the EIP-155 example
signing hash. It needs the `openssl` command line tool.

Without broadcasting, a signed transaction for a given keystore:

```sh
bin/gethethsig --keystore /etc/yiimp/geth/keystore/UTC--... \
  --password-file /etc/yiimp/geth/password.txt \
  --expected-address <pool address> --to <payee address> \
  --value-wei 1000000000000000000 --nonce 0 \
  --gas-price 1000000000 --gas-limit 21000 --chain-id <chain id>
```
