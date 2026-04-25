# client

This binary exposes a local SOCKS5 listener and forwards `CONNECT` traffic over a REALITY/TLS tunnel to the formal `server` binary.

## Quick start

Use the sample config in [config/reality-client.json](config/reality-client.json) together with the local test server:

```powershell
cargo run -p client -- --listen 127.0.0.1:1081 --server-addr 127.0.0.1:9445 --reality-config .\client\config\reality-client.json --ca-file .\bogo\keys\cert.pem --insecure
```

The `--insecure` flag is only for the local test path here, because the bundled `bogo/keys/cert.pem` certificate is not provisioned to match the sample REALITY `serverName` value.

## End-to-end smoke test

After starting the formal server and a local target service, you can verify the tunnel through SOCKS5:

```powershell
curl.exe --socks5-hostname 127.0.0.1:1081 http://127.0.0.1:18080/
```

## Config fields

The config file matches the existing REALITY example conventions:

- `reality.shortId`
- `reality.publicKey`
- `reality.serverName`
- `reality.version`