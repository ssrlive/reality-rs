# server

This binary accepts REALITY/TLS connections from the formal `client` binary, reads a small `RLY1` target header from the tunnel, then opens a TCP connection to the requested upstream target and relays bytes in both directions.

## Quick start

Use the sample config in [config/reality-server.toml](config/reality-server.toml) with the local test certificate:

```powershell
cargo run -p server -- --cert .\bogo\keys\cert.pem --key .\bogo\keys\key.pem --listen 127.0.0.1:9445 --reality-config .\server\config\reality-server.toml
```

## Local tunnel smoke test

One simple local target is a tiny HTTP listener on port `18080`. Once that target is up and the formal client is also running, the request path is:

`curl.exe -> SOCKS5 client -> REALITY server -> local target`

## Config fields

The config file currently uses:

- `reality.shortId`
- `reality.privateKey`
- `reality.serverNames`
- `reality.version`

Extra example-only fallback keys from the older example server config are ignored by this formal server.