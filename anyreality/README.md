# anyreality

This crate provides two binaries that together form a REALITY-wrapped
[AnyTLS](https://github.com/ssrlive/anytls-rs) proxy pair.

---

## `anyreality-client`

Exposes a local mixed SOCKS5 and HTTP CONNECT listener and forwards traffic over a REALITY/TLS
tunnel to `anyreality-server` using the full AnyTLS session-multiplexing
protocol. Supports both `CONNECT` (TCP) and `UDP ASSOCIATE` (AnyTLS
UDP-over-TCP mode).

### Quick start

Use the sample config in [config/reality-client.toml](config/reality-client.toml)
together with the local test server (run from the repo root):

```powershell
cargo run -p anyreality --bin anyreality-client -- --config ./anyreality/config/reality-client.toml
```

Both JSON and TOML config files are supported. An equivalent TOML sample is
available in [config/reality-client.toml](config/reality-client.toml).

The sample config uses the built-in REALITY certificate verification flow;
the server generates a temporary certificate and key for each connection.

### Config layout

The sample client config uses three top-level sections:

- `reality`: REALITY handshake material (`shortId`, `publicKey`,
  `serverName`, `version`)
- `anytls`: shared AnyTLS settings (`password`, plus the client-side
  session-pool knobs)
- `client`: client-only runtime defaults such as `listen`, `serverAddr`,
  and `probeProxy`

The binary now reads runtime values from the config file. The CLI only takes
`--config` and `--log`.

### AnyTLS settings

The `anytls` section carries the shared password and the client-side pool
knobs:

| Field                  | Default  | Description                                                             |
| ---------------------- | -------- | ----------------------------------------------------------------------- |
| `password`             | required | AnyTLS shared password                                                  |
| `clientId`             | omitted  | Reserved client identity value; not functionality yet                   |
| `idleCheckSecs`        | 30       | How often to reap idle AnyTLS sessions                                  |
| `idleTimeoutSecs`      | 30       | Idle session lifetime before close                                      |
| `minIdleSessions`      | 0        | Minimum warm idle sessions to keep                                      |
| `maxStreamsPerSession` | 8        | Maximum logical streams per session; set to `1` to disable multiplexing |

### Probe proxy

If your environment needs the client to reach the AnyTLS server through an
HTTP CONNECT probe proxy, set `client.probeProxy` to the proxy address.
The client will open the TLS carrier through that proxy before starting the
REALITY handshake.

Example:

```toml
[client]
probeProxy = "127.0.0.1:8080"
```

The repository also includes a standalone probe proxy example at
[examples/reality-cracker.rs](examples/reality-cracker.rs). Run it from the repo
root like this:

```powershell
cargo run -p anyreality --example reality-cracker -- 127.0.0.1:8080
```

By default, the example uses the built-in characteristic probe set. You can
override or extend that set from the CLI:

```powershell
# replace the built-in probe set with inline probes
cargo run -p anyreality --example reality-cracker -- 127.0.0.1:8080 --probe "14 03 03 00 01 01"

# append extra probes on top of the built-in set
cargo run -p anyreality --example reality-cracker -- 127.0.0.1:8080 --probe-mode append --probe "14 03 03 00 01 01"

# replace the built-in set from a file such as VLESS-cracker/characteristic.txt
cargo run -p anyreality --example reality-cracker -- 127.0.0.1:8080 --probe-file C:/VLESS-cracker/characteristic.txt
```

`--probe` and `--probe-file` can both be repeated. `--probe-mode replace`
is the default, and `--probe-mode append` keeps the built-in characteristic
probes and then adds the CLI/file probes after them. Blank lines plus `#` /
`//` comment lines in probe files are ignored.

Then point the anyreality client at that address with `client.probeProxy` in
`config/reality-client.toml` or `config/reality-client.json`. The client will
send its outbound carrier CONNECT request through the probe proxy, so the
proxy can parse the TLS ClientHello/ServerHello records, log the negotiated
SNI/ALPN/version fields, and launch a background replay probe using the same
record-level logic as the vless-cracker sample.

---

## `anyreality-server`

Accepts REALITY/TLS connections from `anyreality-client`, verifies the
shared-password AnyTLS auth header, then multiplexes streams using the
AnyTLS session protocol. Each stream carries a target `Address` in SOCKS5
wire format; the server opens a TCP (or UDP-over-TCP) connection to that
target and relays bytes in both directions.

Default listen address: `[::]:443`.

### Quick start

Use the sample config in [config/reality-server.toml](config/reality-server.toml)
(run from the repo root):

```powershell
cargo run -p anyreality --bin anyreality-server -- --config ./anyreality/config/reality-server.toml
```

Both TOML and JSON config files are supported. An equivalent JSON sample is
available in [config/reality-server.json](config/reality-server.json).

### Config layout

The sample server config uses three top-level sections:

- `reality`: REALITY handshake material (`shortId`, `privateKey`,
  `serverNames`, `version`)
- `anytls`: shared AnyTLS settings (`password`)
- `server`: server-only runtime defaults such as `listen`

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

This starts a tiny HTTP server on port `18080`, verifies that `curl`
requests routed through both the SOCKS5 and HTTP CONNECT proxies return
`reality tunnel ok`.

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
