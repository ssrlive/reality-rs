install/ — helper scripts for deploying anyreality

This folder contains helper scripts to install the anyreality server binary, generate REALITY keys,
and produce an anytls password,
write server and client configuration files, install a systemd service unit,
and print the client configuration to the terminal for easy copy/paste.

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
- generate REALITY's per-connection temporary certificates and keys at runtime
- write the server configuration to `/etc/anyreality/config.toml`
- write a client config to `/etc/anyreality/client-config.toml`
- write a systemd unit to `/etc/systemd/system/anyreality.service` and attempt to enable/start it (best-effort)
- finally, print the client config to the terminal so you can copy it to a client machine

Notes and recommendations (accurate to the current script):

- The script must be run as root (it enforces this).
- The installer is interactive by default: it will prompt for a domain name and listen port if they are not
  provided on the command line. To run in automation, pass the `install <site> <port>` arguments.
- The script will overwrite generated configuration files as part of its flow; re-run cautiously
  or add your own `--force`/`--no-clobber` wrapper if you need idempotency.
- The anytls password is generated in-memory and is not written to a standalone password file by the script.
- Permissions: the script does not automatically tighten `config.toml`. For production, run after install:

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
- The server does not require static certificate or private-key files. Its REALITY certificate and private key are
  generated per connection and are never written to disk.

Examples — after running the installer, copy the client config to a client and run the client using the provided client config.
