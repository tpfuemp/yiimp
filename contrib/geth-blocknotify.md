# Block notify — usage

The yiimp stratum has a `mining.update_block` endpoint to announce new blocks
from a coin daemon. The `blocknotify` binary connects to the stratum port and
sends:

```json
{"id":1,"method":"mining.update_block","params":["tu8tu5",<coinid>,"<blockhash>"]}
```

The password must match `TCP:password` in that stratum's config (default
`tu8tu5`), and `coinid` must match `coins.id` in the `coins` table.

Examples below use:

| Coin | Symbol | Algo | coinid | stratum port |
|------|--------|------|--------|--------------|
| Larissa Coin | LRS | ethash | 7 | 3639 |
| Lumenite | LMT | homescrypt | 12 | 3644 |

---

## 1. Bitcoin Core style daemons (Lumenite, Scash, EVR, …)

A daemon with a `blocknotify=` option calls the binary directly:

```ini
blocknotify=/usr/bin/blocknotify 127.0.0.1:3644 12 %s
```

If the daemon runs in Docker, mount the binary into the container and use the
host gateway instead of `127.0.0.1`:

```yaml
services:
  lumenite:
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ./data:/data
      - /usr/bin/blocknotify:/yiimp/blocknotify:ro
```

Then in `lumenite.conf`:

```ini
blocknotify=/yiimp/blocknotify host.docker.internal:3644 12 %s
```

and restart the node:

```bash
cd /path/to/lumenite-node
docker compose up -d
```

---

## 2. geth (ethash / LRS)

**geth has no `blocknotify=` option**, so use one of these:

### 2.1 Polling (default, nothing to do)

The ethash stratum calls `eth_getWork` about every second and creates a new
job as soon as `eth_header` changes (see `stratum/ethash/work.cpp`,
`coind_template.cpp`). This works without blocknotify.

### 2.2 Push with `eth_subscribe("newHeads")` (recommended)

Enable WebSocket RPC on geth in `docker-compose.yml`:

```yaml
    command:
      - --http
      - --http.addr=0.0.0.0
      - --http.port=8545
      - --http.api=eth,net,web3,admin
      - --ws
      - --ws.addr=0.0.0.0
      - --ws.port=8546
      - --ws.api=eth
      - "--ws.origins=*"
    ports:
      - "${NODE_TS_IP}:8545:8545"
      - "${NODE_TS_IP}:8546:8546"
```

Install the dependency and the watcher:

```bash
sudo apt-get install -y python3-websocket
cp bin/geth-blocknotify.py /opt/yiimp/bin/geth-blocknotify.py
cp contrib/geth-blocknotify.service ~/.config/systemd/user/yiimp-geth-blocknotify.service
systemctl --user daemon-reload
systemctl --user enable --now yiimp-geth-blocknotify.service
```

Run it by hand to test (no root needed):

```bash
python3 bin/geth-blocknotify.py
```

Settings via environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `GETH_WS_URL` | `ws://127.0.0.1:8546` | geth WebSocket RPC |
| `BLOCKNOTIFY_BIN` | `/usr/bin/blocknotify` | blocknotify binary |
| `STRATUM_HOSTPORT` | `127.0.0.1:3639` | ethash stratum |
| `COIN_ID` | `7` | LRS coin id |
| `BLOCKNOTIFY_LOG` | `/var/log/yiimp/geth-blocknotify.log` | log file |

---

## 3. Check that it works

Temporarily enable debug logging in the stratum config:

```ini
[DEBUGLOG]
client = 1
```

Restart the stratum and watch the log on a new block:

```bash
systemctl --user restart yiimp-stratum@ethash.service
tail -f /var/log/yiimp/stratum/stratum-ethash.log | grep 'notify: new'
```

Expected:

```
client mining.update_block 1 null
notify: new LRS block 0x9a6a183b...
client terminate
```

and on the watcher side:

```bash
tail -f /var/log/yiimp/geth-blocknotify.log
```

```
subscribed newHeads id=0x...
new block 0x6a9bd2 0xec85c35a...
blocknotify 0xec85c35a... -> 0
```

Set `client = 0` again and restart the stratum when done.

---

## 4. Troubleshooting

- `error connect ...` from blocknotify: the stratum is not listening for a
  moment (restarting); the watcher retries 3 times.
- `bad password`: `TCP:password` in the stratum config does not match `tu8tu5`.
- No `notify: new ...`: check the WebSocket. `curl` can't do `eth_subscribe`;
  use `python3 -c "import websocket"` or check the watcher log for `subscribed`.
- If geth runs on another host (e.g. over Tailscale), set
  `GETH_WS_URL=ws://<host-ip>:8546` and publish port 8546 on that host.
