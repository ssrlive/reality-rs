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

Use the sample config in [client/reality-client.json](client/reality-client.json)
together with the local test server (run from the repo root):

```powershell
cargo run -p anytls-real --bin anytls-real-client -- `
  --listen 127.0.0.1:1081 `
  --server-addr 127.0.0.1:9445 `
  --reality-config .\anytls-real\client\reality-client.json `
  --ca-file .\bogo\keys\cert.pem `
  --insecure `
  --password YOUR_PASSWORD
```

Both JSON and TOML config files are supported. An equivalent TOML sample is
available in [client/reality-client.toml](client/reality-client.toml).

The `--insecure` flag is only for the local test path here, because the
bundled `bogo/keys/cert.pem` certificate is not provisioned to match the
sample REALITY `serverName` value.

### Config fields

- `reality.shortId`
- `reality.publicKey`
- `reality.serverName`
- `reality.version`

### Session-pool flags

| Flag | Default | Description |
|------|---------|-------------|
| `--idle-check-secs` | 30 | How often to reap idle AnyTLS sessions |
| `--idle-timeout-secs` | 30 | Idle session lifetime before close |
| `--min-idle-sessions` | 5 | Minimum warm idle sessions to keep |

---

## `anytls-real-server`

Accepts REALITY/TLS connections from `anytls-real-client`, verifies the
shared-password AnyTLS auth header, then multiplexes streams using the
AnyTLS session protocol. Each stream carries a target `Address` in SOCKS5
wire format; the server opens a TCP (or UDP-over-TCP) connection to that
target and relays bytes in both directions.

Default listen address: `[::]:443`.

### Quick start

Use the sample config in [server/reality-server.toml](server/reality-server.toml)
with the local test certificate (run from the repo root):

```powershell
cargo run -p anytls-real --bin anytls-real-server -- `
  --cert .\bogo\keys\cert.pem `
  --key .\bogo\keys\key.pem `
  --listen 127.0.0.1:9445 `
  --reality-config .\anytls-real\server\reality-server.toml `
  --password YOUR_PASSWORD
```

Both TOML and JSON config files are supported. An equivalent JSON sample is
available in [server/reality-server.json](server/reality-server.json).

### Config fields

- `reality.shortId`
- `reality.privateKey`
- `reality.serverNames` (array)
- `reality.version`

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
