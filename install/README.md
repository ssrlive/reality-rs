install/ — helper scripts for deploying anyreality

This folder contains helper scripts to install the anyreality server binary, generate REALITY keys,
produce an anytls password, create a self-signed CA and server certificate (for testing),
write server and client configuration files, install a systemd service unit,
and print the client configuration and CA to the terminal for easy copy/paste.

Files of interest:

- `installer.sh` — all-in-one installer and configurator.
  It performs the full flow described below and inlines the previous example templates.

Quick usage (run as root):

1) Prepare server config and install everything (interactive by default):

```sh
sudo ./installer.sh install
```

You may provide the target site and port as arguments to run non-interactively:

```sh
sudo ./installer.sh install example.com 443
```

This will (summary):
- install prerequisites (`curl`, `unzip`, `openssl`) where supported
- download and install the server binary to `/usr/local/bin/anyreality-server` (default `BIN_DIR`)
- generate (or reuse) a self-signed CA and a server certificate for the chosen site and write them to
  `/etc/anyreality/` (`ca.crt`, `ca.key`, `server.crt`, `server.key`)
- write the server configuration to `/etc/anyreality/config.toml`
- write a client config to `/etc/anyreality/client-config.toml`
- write a systemd unit to `/etc/systemd/system/anyreality.service` and attempt to enable/start it (best-effort)
- finally, print the client config and CA to the terminal so you can copy them to a client machine

Notes and recommendations (accurate to the current script):

- The script must be run as root (it enforces this).
- The installer is interactive by default: it will prompt for a domain name and listen port if they are not
  provided on the command line. To run in automation, pass the `install <site> <port>` arguments.
- Certificate/CA handling: if an existing `ca.crt` and `ca.key` are present under `/etc/anyreality/`, the script
  will verify they match (modulus comparison) and reuse them if they do. If they don't match, the script
  regenerates the CA and overwrites related artifacts.
- The script will overwrite generated artifacts (certs, keys, configs) as part of its flow; re-run cautiously
  or add your own `--force`/`--no-clobber` wrapper if you need idempotency.
- The anytls password is generated in-memory and is not written to a standalone password file by the script.
- Permissions: the script sets conservative permissions for certs and keys (server key is 600, certs 644), but it
  does not automatically tighten `config.toml`. For production, run after install:

```sh
chmod 600 /etc/anyreality/config.toml
chown root:root /etc/anyreality/config.toml
```

- systemd: if `systemctl` is available and systemd is running, the installer will write the unit and attempt to
  `enable --now` the service. If systemd is not present, the unit file is still written but the script prints the
  command you can use to start the server manually: `/usr/local/bin/anyreality-server --config /etc/anyreality/config.toml`.

Compatibility and behavior notes:

- The script generates REALITY keys by invoking the installed `anyreality-server --gen-reality-keys` command.
  Ensure the binary is present (the installer downloads and installs it by default).
- The script writes a few temporary OpenSSL helper files during certificate creation; these live in the install
  directory by default. Consider running the script in an environment where `/etc/anyreality` is writable only
  by root and cleaning temporary files if you need to keep the directory minimal.

Examples — after running the installer, copy client config and CA to a client and run the client using the provided client config.
