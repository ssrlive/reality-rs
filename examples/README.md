# Rustls Examples

This directory contains a number of examples that use Rustls.

We recommend new users start by looking at `simpleclient.rs` and `simpleserver.rs`. Once those are understood, `tlsclient-mio.rs` and `tlsserver-mio.rs` provide more advanced examples.

## Client examples

* `simpleclient.rs` - shows a simple client configuration that uses sensible defaults. It demonstrates using the `Stream` helper to treat a Rustls connection as you would a bi-directional TCP stream.
* `tlsclient-mio.rs` - shows a more complete client example that handles command line flags for customizing TLS options, and uses MIO to handle asynchronous I/O.
* `limitedclient.rs` - shows how to configure Rustls so that unused cryptography is discarded by the linker. This client only supports TLS 1.3 and a single cipher suite.
* `simple_0rtt_client.rs` - shows how to make a TLS 1.3 client connection that sends early 0RTT data.
* `ech-client.rs` - shows how to configure Rustls to use encrypted client hello (ECH), including fetching an ECH config list with DNS-over-HTTPS.

## Server examples

* `simpleserver.rs` - shows a very minimal server example that accepts a single TLS connection. See `tlsserver-mio.rs` or `server_acceptor.rs` for a more realistic example.
* `tlsserver-mio.rs` - shows a more complete server example that handles command line flags for customizing TLS options, and uses MIO to handle asynchronous I/O.
* `simple_0rtt_server.rs` - shows how to make a TLS1.3 that accepts multiple connections and prints early 0RTT data.
* `server_acceptor.rs` - shows how to use the `Acceptor` API to create a server that generates a unique `ServerConfig` for each client. This example also shows how to use client authentication, CRL revocation checking, and uses `rcgen` to generate its own certificates.

## Client-Server examples

* A client-server example using Raw Public Keys (RFC 7250) can be found in [`raw_key_openssl_interop`](../openssl-tests/src/raw_key_openssl_interop.rs).

## REALITY Mapping

The REALITY-capable example programs now support both CLI flags and `--reality-config` files in JSON or TOML.

`tlsserver-mio.rs` also supports `--reality-fallback-address <addr>` plus `--reality-fallback-port <port>`, or `reality.fallbackAddress` plus `reality.fallbackPort` in the config file, to raw-forward connections whose pre-read `ClientHello` SNI falls outside the configured `serverNames` allowlist to `addr:port`. The address defaults to `localhost` if only a port is set. CLI wins if both are set. The config file can also define ordered `reality.fallbackRules` entries to route specific SNI values, optional ALPN offerings, and optional key-exchange group offerings via `namedGroups`, to alternate decoy targets before the global fallback target is used. Each rule must include at least one matcher (`serverNames`, `alpns`, or `namedGroups`), and all fallback ports must be non-zero so invalid decoy targets fail at startup instead of later at connect time. This is an initial probe-diversion step for decoy handling, not a full Xray-equivalent cryptographic discriminator.

### Xray field mapping

| Xray field | Rust client example | Rust server example | Config file field | Notes |
| --- | --- | --- | --- | --- |
| `shortId` | `--reality-short-id` | `--reality-short-id` | `reality.shortId` | Same hex value on both sides. |
| `publicKey` | `--reality-public-key` | n/a | `reality.publicKey` | Client uses the server's X25519 public key. The config loader also accepts Xray's client-side alias `password`. |
| `privateKey` | n/a | `--reality-private-key` | `reality.privateKey` | Server uses the matching X25519 private key. |
| `serverName` | `--server-name` | `--reality-server-name` (repeatable) | `reality.serverName` / `reality.serverNames` | Client-side TLS SNI and certificate verification name. Both `tlsserver-mio.rs` and `simpleserver.rs` can enforce an allowlist via `serverNames`. |
| decoy fallback target | n/a | `--reality-fallback-address` + `--reality-fallback-port` | `reality.fallbackAddress` + `reality.fallbackPort` | `tlsserver-mio.rs` only. Reject-path raw TCP forwarding target. Address defaults to `localhost` when omitted. CLI overrides config. |
| decoy fallback rules | n/a | n/a | `reality.fallbackRules` | `tlsserver-mio.rs` only. Ordered decoy targets matched by SNI, optional `alpns`, and optional `namedGroups`, evaluated before the default fallback target. Each rule must set at least one matcher. |
| version tag | `--reality-version` | `--reality-version` | `reality.version` | Rust examples currently require an explicit 3-byte version tag encoded as 6 hex digits. |

### Config file examples

Client JSON example: [examples/config/reality-client.json](c:/Users/Administrator/Desktop/mytests/rustls/examples/config/reality-client.json)

Server TOML example: [examples/config/reality-server.toml](c:/Users/Administrator/Desktop/mytests/rustls/examples/config/reality-server.toml)

Example client invocation using a config file:

```powershell
cargo run -p rustls-examples --bin tlsclient-mio -- --port 9445 --protover 1.3 --cafile .\bogo\keys\cert.pem --reality-config .\examples\config\reality-client.json localhost
```

Example server invocation using a config file:

```powershell
cargo run -p rustls-examples --bin simpleserver -- --cert .\bogo\keys\cert.pem --key .\bogo\keys\key.pem --port 9445 --reality-config .\examples\config\reality-server.toml
```

### REALITY server implementation status

This workspace now has a usable example-level REALITY server path centered on `tlsserver-mio.rs`. It is best understood as a constrained probe-routing implementation built on top of Rustls TLS 1.3 handling, not as a full reimplementation of Xray's production REALITY server semantics.

#### Completion boundary

The current implementation should be treated as complete for the following scope:

* REALITY server configuration can be loaded from CLI flags or JSON/TOML config files.
* REALITY handshakes are constrained to the example provider path already wired into Rustls examples.
* `tlsserver-mio.rs` can pre-read `ClientHello`, decide whether traffic should stay on the REALITY/TLS path or be diverted to a decoy backend, and then either continue the handshake or raw-forward bytes.
* Decoy selection is configurable through one default fallback target plus ordered `reality.fallbackRules`.
* Rule matching now supports `serverNames`, `alpns`, and `namedGroups`, with startup validation for obviously bad configs.
* The example binaries and focused tests currently exercise this behavior successfully.

Outside that boundary, further work should be treated as new feature development rather than completion work.

#### Supported capabilities

* REALITY client and server examples support Xray-style `shortId`, `publicKey` or `privateKey`, `serverName`, and `version` fields through config loading.
* The server side enforces REALITY mode as TLS 1.3 only.
* `tlsserver-mio.rs` uses `Acceptor` to inspect the incoming `ClientHello` before the full handshake completes.
* The server can reject probes by SNI allowlist and can additionally inspect the raw `session_id` prefix to distinguish expected REALITY traffic from plain TLS probes.
* Rejected traffic can be forwarded to a configured decoy backend using nonblocking passthrough I/O.
* Ordered decoy routing rules can match on SNI, ALPN, and named groups before falling back to the default decoy target.
* Sample config, config parsing, and focused tests exist for this ruleset.

#### Unsupported capabilities

* This is not a complete Xray-compatible REALITY server implementation.
* It does not claim wire-level parity with all Xray probe discrimination behavior, fallback heuristics, or deployment semantics.
* The current rule engine does not yet match on every `ClientHello` dimension Rustls exposes, such as cipher suites or signature schemes.
* The current implementation lives in example binaries rather than a stabilized library API intended for downstream integration.
* Operational concerns such as metrics, admin controls, hot reload, policy isolation, and production-grade observability are not part of this example implementation.
* The decoy path is raw TCP passthrough chosen from pre-handshake inspection; it is not a comprehensive traffic camouflage system.

#### Deployment risks

* The code lives under examples and should be treated as example-grade integration code, not production-hardened server infrastructure.
* Behavior is intentionally scoped around the currently wired Rustls REALITY provider path; changing providers or protocol assumptions may require extra verification.
* Decoy routing decisions depend on early `ClientHello` observations and simple configured matchers; a mismatch between expected probe patterns and real traffic can send traffic to the wrong backend.
* A bad fallback target or bad matcher configuration can still create routing surprises even though startup validation now rejects empty rules and zero ports.
* The implementation has focused tests and some live validation, but it has not been presented here as having broad interoperability or adversarial hardening coverage.
* If you need production deployment, you should treat this code as a reference prototype and perform a separate hardening pass instead of assuming the example layer is deployment-ready.

#### Minimum checklist before practical deployment

If the goal is to move from the current prototype into a realistically usable deployment, the minimum engineering checklist is:

* Move the REALITY server path out of the example binary and into a dedicated crate or service entrypoint with a narrower public surface.
* Freeze one provider and one protocol profile, then rerun interoperability checks against the exact client population you expect to serve.
* Add structured connection logs and counters for at least: REALITY handshake accepted, fallback by default target, fallback by named rule, fallback connect failure, and client hello parse failure.
* Exercise the server under longer-running and concurrent traffic instead of only focused unit tests and short manual probes.
* Validate fallback behavior with your real decoy backends, including address family, failure handling, and wrong-rule recovery.
* Add an operational rollback path so REALITY routing can be disabled or bypassed quickly without editing code.
* Lock down configuration management so `shortId`, keys, `serverNames`, and fallback targets are deployed from controlled config rather than ad hoc command lines.
* Perform one explicit security review of the rule assumptions, key handling, logging contents, and probe-misclassification impact before exposing the service to public traffic.

If those items are not done yet, the safest description is still: usable prototype, not deployment-finished server.
