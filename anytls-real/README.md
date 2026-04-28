# anytls-real

This crate provides two binaries that together form a REALITY-wrapped
[AnyTLS](https://github.com/ssrlive/anytls-rs) proxy pair.

---

## `anytls-real-client`

Exposes a local SOCKS5 listener and forwards traffic over a REALITY/TLS
tunnel to `anytls-real-server` using the full AnyTLS session-multiplexing
protocol. Supports both `CONNECT` (TCP) and `UDP ASSOCIATE` (AnyTLS
UDP-over-TCP mode).

### Quick start

Use the sample config in [config/reality-client.toml](config/reality-client.toml)
together with the local test server (run from the repo root):

```powershell
cargo run -p anytls-real --bin anytls-real-client -- --config ./anytls-real/config/reality-client.toml
```

Both JSON and TOML config files are supported. An equivalent TOML sample is
available in [config/reality-client.toml](config/reality-client.toml).

The sample config includes the local-only `insecure = true` setting so the
bundled `bogo/keys/cert.pem` certificate can be used without extra setup.

### Config layout

The sample client config uses three top-level sections:

- `reality`: REALITY handshake material (`shortId`, `publicKey`,
  `serverName`, `version`)
- `anytls`: shared AnyTLS settings (`password`, plus the client-side
  session-pool knobs)
- `client`: client-only runtime defaults such as `listen`, `serverAddr`,
  `caFile`, and `insecure`

The binary now reads runtime values from the config file. The CLI only takes
`--config` and `--log`.

### AnyTLS settings

The `anytls` section carries the shared password and the client-side pool
knobs:

| Field | Default | Description |
|-------|---------|-------------|
| `password` | required | AnyTLS shared password |
| `idleCheckSecs` | 30 | How often to reap idle AnyTLS sessions |
| `idleTimeoutSecs` | 30 | Idle session lifetime before close |
| `minIdleSessions` | 5 | Minimum warm idle sessions to keep |

---

## `anytls-real-server`

Accepts REALITY/TLS connections from `anytls-real-client`, verifies the
shared-password AnyTLS auth header, then multiplexes streams using the
AnyTLS session protocol. Each stream carries a target `Address` in SOCKS5
wire format; the server opens a TCP (or UDP-over-TCP) connection to that
target and relays bytes in both directions.

Default listen address: `[::]:443`.

### Quick start

Use the sample config in [config/reality-server.toml](config/reality-server.toml)
with the local test certificate (run from the repo root):

```powershell
cargo run -p anytls-real --bin anytls-real-server -- --config ./anytls-real/config/reality-server.toml
```

Both TOML and JSON config files are supported. An equivalent JSON sample is
available in [config/reality-server.json](config/reality-server.json).

### Config layout

The sample server config uses three top-level sections:

- `reality`: REALITY handshake material (`shortId`, `privateKey`,
  `serverNames`, `version`)
- `anytls`: shared AnyTLS settings (`password`)
- `server`: server-only runtime defaults such as `listen`, `cert`, and
  `key`

The binary now reads runtime values from the config file. The CLI only takes
`--config` and `--log`.

---

## End-to-end smoke tests

The `admin/` directory contains automated smoke tests that start both
binaries together with a local target and verify the tunnel end-to-end.

### TCP CONNECT smoke test

```powershell
# Windows
pwsh -File admin/reality-smoke.ps1 -BuildWithCargo

# Linux / macOS
bash admin/reality-smoke.sh --build-with-cargo
```

This starts a tiny HTTP server on port `18080`, verifies that a `curl`
request routed through the SOCKS5 proxy returns `reality tunnel ok`.

### UDP ASSOCIATE smoke test

```powershell
# Windows
pwsh -File admin/reality-smoke-udp.ps1

# Linux / macOS
bash admin/reality-smoke-udp.sh
```

This starts a UDP echo server on port `19090`, sends a SOCKS5
`UDP ASSOCIATE` datagram through the AnyTLS UoT tunnel, and verifies the
echo payload and source port are correct.
