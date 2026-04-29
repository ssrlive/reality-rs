#!/usr/bin/env bash
set -euo pipefail

#fonts color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

# Require root to run this script. The install uses system paths and
# writes files into system locations; enforce root to avoid sudo misuse.
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${Red}This script must be run as root (use sudo)${Font}" >&2
  exit 1
fi

anytls_real_bin_url="https://github.com/ssrlive/reality-rs/releases/latest/download/anytls-real-x86_64-unknown-linux-musl.zip"

# some foreign sites likely accessible from China (common CDNs, developer sites)
STOCK_SITES=(cdn.jsdelivr.net jsdelivr.com stackoverflow.com developer.mozilla.org python.org pypi.org crates.io golang.org nodejs.org npmjs.com cloudflare.com nginx.org rust-lang.org debian.org ubuntu.com)

BIN_DIR=${BIN_DIR:-/usr/local/bin}
BIN_FILE="anytls-real-server"
INSTALL_DIR=${INSTALL_DIR:-/etc/anytls-real}
SERVER_CONFIG="${INSTALL_DIR}/config.toml"
TARGET_SITE=""
LISTEN_PORT=""
SERVICE_UNIT_NAME="anytls-real.service"

select_random_site() {
  # choose a random site and generate certificate
  local site_index=$((RANDOM % ${#STOCK_SITES[@]}))
  echo "${STOCK_SITES[$site_index]}"
}

install_prereqs() {
  echo -e "${Green}Installing prerequisites: curl unzip openssl${Font}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y curl unzip openssl ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl unzip openssl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl unzip openssl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl unzip openssl ca-certificates
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm curl unzip openssl ca-certificates
  else
    echo -e "${Red}No supported package manager found. Please install: curl unzip openssl${Font}" >&2
    exit 1
  fi
}

install_server_binary() {
  TMPDIR=$(mktemp -d)
  cleanup() { rm -rf "$TMPDIR"; }
  trap cleanup EXIT

  echo -e "${Green}Downloading anytls-real from: $anytls_real_bin_url${Font}"
  curl -L "$anytls_real_bin_url" -o "$TMPDIR/anytls.zip"

  echo -e "${Green}Extracting...${Font}"
  unzip -o "$TMPDIR/anytls.zip" -d "$TMPDIR" >/dev/null

  # Prefer the server binary; avoid installing the client
  binfile=$(find "$TMPDIR" -type f -name "$BIN_FILE" -print -quit || true)
  if [ -z "$binfile" ]; then
    echo -e "${Red}Could not locate $BIN_FILE binary in archive${Font}"
    return 1
  fi

  echo -e "${Green}Installing binary to $BIN_DIR${Font}"
  mkdir -p "$BIN_DIR"
  install -m 0755 "$binfile" "$BIN_DIR/$BIN_FILE"
}

generate_anytls_password() {
  openssl rand -base64 32 | tr '/+' '_-' | tr -d '='
}

generate_reality_keys() {
  printf 'Generating REALITY keys (using %s)\n' "$BIN_DIR/$BIN_FILE"
  keys_out=$("$BIN_DIR/$BIN_FILE" --gen-reality-keys 2>/dev/null || true)
  priv=$(echo "$keys_out" | sed -n 's/^privateKey:[[:space:]]*//p' | tr -d '\r')
  pub=$(echo "$keys_out" | sed -n 's/^publicKey:[[:space:]]*//p' | tr -d '\r')
  shortid=$(echo "$keys_out" | sed -n 's/^shortId:[[:space:]]*//p' | tr -d '\r')
  if [ -z "$priv" ] || [ -z "$shortid" ]; then
    printf 'Failed to generate REALITY keys; output:\n%s\n' "$keys_out" >&2
    return 1
  fi
}

generate_cert_for_target_site() {
  local the_site="$1"
  local install_dir="$2"
  if [ -z "$the_site" ]; then
    echo -e "${Red}generate_cert_for_target_site requires a site argument${Font}" >&2
    return 1
  fi
  mkdir -p "$install_dir"
  echo -e "${Green}Generating CA and server certificate for $the_site${Font}"

  # If a CA cert/key already exist, ensure they match. If they don't, remove them so
  # we create a fresh CA (this prevents "CA certificate and CA private key do not match").
  if [ -f "$install_dir/ca.crt" ] && [ -f "$install_dir/ca.key" ]; then
    can_read_mods=true
    cert_mod=$(openssl x509 -noout -modulus -in "$install_dir/ca.crt" 2>/dev/null | openssl md5 2>/dev/null) || can_read_mods=false
    key_mod=$(openssl rsa -noout -modulus -in "$install_dir/ca.key" 2>/dev/null | openssl md5 2>/dev/null) || can_read_mods=false
    if [ "$can_read_mods" = false ]; then
      echo -e "${Yellow}Warning: existing CA files present but could not compute modulus; regenerating CA${Font}" >&2
      rm -f "$install_dir/ca.crt" "$install_dir/ca.key" "$install_dir/ca.srl" || true
    elif [ "$cert_mod" != "$key_mod" ]; then
      echo -e "${Yellow}Warning: existing CA cert and key do not match; regenerating CA${Font}" >&2
      rm -f "$install_dir/ca.crt" "$install_dir/ca.key" "$install_dir/ca.srl" || true
    else
      echo -e "${Green}Found matching existing CA cert/key; reusing${Font}"
    fi
  fi
  openssl genrsa -out "$install_dir/ca.key" 4096 || { echo -e "${Red}Failed to generate CA private key${Font}" >&2; return 1; }

  # Create CA extensions for a v3 CA cert
  cat > "$install_dir/ca.ext" <<CAEXT
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=CA:TRUE
keyUsage = cRLSign, keyCertSign
CAEXT

  # Build a minimal openssl config referencing the v3_ca extensions (more compatible)
  cat > "$install_dir/ca.conf" <<CAREQ
[ req ]
default_bits = 4096
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
CN = anytls-local-CA

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=CA:TRUE
keyUsage = cRLSign, keyCertSign
CAREQ

  if ! openssl req -x509 -new -nodes -key "$install_dir/ca.key" -sha256 -days 3650 \
    -config "$install_dir/ca.conf" -out "$install_dir/ca.crt" 2>"$install_dir/ca_gen.err"; then
    echo -e "${Red}Failed to generate CA certificate; openssl stderr:${Font}" >&2
    sed -n '1,200p' "$install_dir/ca_gen.err" >&2 || true
    rm -f "$install_dir/ca_gen.err"
    return 1
  fi

  # Verify CA cert exists
  if [ ! -s "$install_dir/ca.crt" ]; then
    echo -e "${Red}CA certificate missing after creation: $install_dir/ca.crt${Font}" >&2
    return 1
  fi

  openssl genrsa -out "$install_dir/server.key" 2048 || { echo -e "${Red}Failed to generate server private key${Font}" >&2; return 1; }
  if ! openssl req -new -key "$install_dir/server.key" -subj "/CN=$the_site" -out "$install_dir/server.csr" 2>"$install_dir/server_csr.err"; then
    echo -e "${Red}Failed to generate server CSR; openssl stderr:${Font}" >&2
    sed -n '1,200p' "$install_dir/server_csr.err" >&2 || true
    rm -f "$install_dir/server_csr.err"
    return 1
  fi

  # Create server certificate extensions (v3) including SAN
  cat > "$install_dir/server.ext" <<SRVEXT
[ v3_req ]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$the_site
SRVEXT

  if ! openssl x509 -req -in "$install_dir/server.csr" -CA "$install_dir/ca.crt" -CAkey "$install_dir/ca.key" -CAcreateserial -out "$install_dir/server.crt" -days 365 -sha256 -extfile "$install_dir/server.ext" -extensions v3_req 2>"$install_dir/server_sign.err"; then
    echo -e "${Red}Failed to sign server certificate; openssl stderr:${Font}" >&2
    sed -n '1,200p' "$install_dir/server_sign.err" >&2 || true
    rm -f "$install_dir/server_sign.err"
    return 1
  fi
  rm -f "$install_dir/ca.srl" || true

  # Ensure server cert was created and is non-empty
  if [ ! -s "$install_dir/server.crt" ]; then
    echo -e "${Red}Error: server certificate not created or empty: $install_dir/server.crt${Font}" >&2
    return 1
  fi

  # Many TLS stacks expect the cert file to contain the full chain (server cert followed by CA cert)
  # Append CA cert to server.crt to produce a chain file.
  if [ -s "$install_dir/ca.crt" ]; then
    cat "$install_dir/ca.crt" >> "$install_dir/server.crt" || true
  else
    echo -e "${Yellow}Warning: CA cert missing: $install_dir/ca.crt${Font}" >&2
  fi

  chmod 0644 "$install_dir/server.crt" || true
  chmod 0600 "$install_dir/server.key" || true
  chmod 0644 "$install_dir/ca.crt" || true

  echo -e "${Green}Wrote CA and server cert/key to $install_dir${Font}"
}

write_server_config() {
  local the_site="$1"
  local listen_port="$2"
  cat > "$SERVER_CONFIG" <<EOF
[reality]
# shortId: 8-byte hex string (16 hex chars)
shortId = "$shortid"
# privateKey: base64url no-padding X25519 private key (32 bytes encoded)
privateKey = "$priv"
version = "010203"
serverNames = ["$the_site"]

[anytls]
# anytls password used by server
password = "$anytls_password"

[server]
listen = "0.0.0.0:${listen_port}"
cert = "$INSTALL_DIR/server.crt"
key = "$INSTALL_DIR/server.key"
EOF
  echo -e "${Green}Wrote server config: $SERVER_CONFIG${Font}"
}

write_client_config() {
  local the_site="$1"
  local the_port="$2"
  CLIENT_OUT="$INSTALL_DIR/client-config.toml"
  hostaddr=$(curl -sS https://ip.sb || hostname -f 2>/dev/null || hostname)
  cat > "$CLIENT_OUT" <<EOF
[reality]
# shortId: 8-byte hex string (16 hex chars)
shortId = "$shortid"
# publicKey (base64url no-padding) — client may need server public for some flows
publicKey = "$pub"
version = "010203"
serverName = "$the_site"

[anytls]
password = "$anytls_password"
idleCheckSecs = 30
idleTimeoutSecs = 30
minIdleSessions = 0

[client]
listen = "127.0.0.1:2080"
serverAddr = "${hostaddr}:${the_port}"
caFile = "$INSTALL_DIR/ca.crt"
insecure = true
EOF
  echo -e "${Green}Wrote client config: $CLIENT_OUT${Font}"
}

install_systemd_service() {
  local service_path="/etc/systemd/system/$SERVICE_UNIT_NAME"
  cat > "$service_path" <<EOF
[Unit]
Description=anytls-real server
After=network.target

[Service]
# Running as root by default; create and switch to a dedicated user manually if desired
ExecStart=$BIN_DIR/$BIN_FILE --config $SERVER_CONFIG
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  # Do NOT create a system user or change ownership (user requested no user creation)
  # Only attempt to enable/start the unit if systemctl exists and systemd is running.
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    if ! systemctl enable --now "$SERVICE_UNIT_NAME"; then
      echo -e "${Red}Warning: failed to enable/start $SERVICE_UNIT_NAME; showing status and recent journal entries:${Font}" >&2
      systemctl status $SERVICE_UNIT_NAME --no-pager || true
      journalctl -u $SERVICE_UNIT_NAME -n 200 --no-pager || true
    else
      echo -e "${Green}Installed and started systemd service: $SERVICE_UNIT_NAME${Font}"
    fi
  else
    echo -e "${Yellow}systemctl not found or systemd not running; created $service_path. Start the service manually:${Font}" >&2
    echo -e "  ${Yellow}$BIN_DIR/$BIN_FILE --config $SERVER_CONFIG${Font}" >&2
  fi
}

install_anytls_real_all() {
  # Begin main flow
  install_prereqs
  install_server_binary || { echo -e "${Red}Binary installation failed${Font}" >&2; exit 1; }

  if [ -n "$TARGET_SITE" ]; then
    echo -e "${Green}Using provided site: $TARGET_SITE${Font}"
  else
    echo "请输入 你的网站域名 (形如 mygooodsite.com) 并敲回车, 如果不输入（只敲回车）将随机选择一个常见的站点名:"
    stty erase '^H' && read -p "Enter your domain name (for example: mygooodsite.com), or press Enter only to select a random common site: " TARGET_SITE

    if [ -z "$TARGET_SITE" ]; then
      echo -e "${Yellow}No site provided; selecting a random site from the stock list${Font}"
      TARGET_SITE=$(select_random_site)
    fi
  fi

  if [ -n "$LISTEN_PORT" ]; then
    echo -e "${Green}Using provided listen port: $LISTEN_PORT${Font}"
  else
    echo "请输入服务器监听端口 (默认为 443) 并敲回车:"
    stty erase '^H' && read -p "Enter the listen port for the server (default 443): " LISTEN_PORT
    if [ -z "$LISTEN_PORT" ]; then
      LISTEN_PORT=443
    fi
  fi

  # generate or reuse REALITY keys
  generate_reality_keys || { echo -e "${Red}REALITY key generation failed${Font}" >&2; exit 1; }

  # generate anytls password (kept in-memory only; do not create a password file)
  anytls_password=$(generate_anytls_password)
  mkdir -p "$INSTALL_DIR"

  # generate certs
  generate_cert_for_target_site "$TARGET_SITE" "$INSTALL_DIR" || { echo -e "${Red}Certificate generation failed${Font}" >&2; exit 1; }

  # write configs
  write_server_config "$TARGET_SITE" "$LISTEN_PORT"
  write_client_config "$TARGET_SITE" "$LISTEN_PORT"

  # install and start systemd service (best-effort)
  if command -v systemctl >/dev/null 2>&1; then
    install_systemd_service
  else
    echo -e "${Yellow}systemctl not found; skipping service install. Start $BIN_DIR/$BIN_FILE manually:${Font}" >&2
    echo -e "  ${Yellow}$BIN_DIR/$BIN_FILE --config $SERVER_CONFIG${Font}" >&2
  fi

  # Print client config and CA to terminal for easy copy/paste
  echo -e "${Green}\n==== CA CERT ($INSTALL_DIR/ca.crt) ====\n${Font}"
  cat "$INSTALL_DIR/ca.crt" || true
  CLIENT_OUT="$INSTALL_DIR/client-config.toml"
  echo -e "${Green}\n==== Client config ($CLIENT_OUT) ====\n${Font}"
  cat "$CLIENT_OUT" || true

  echo -e "${Green}Install complete. Server config: $SERVER_CONFIG; client config and CA printed above.${Font}"
}

uninstall_all() {
  printf "Are you sure uninstall ${SERVICE_UNIT_NAME}? (y/n)\n"
  read -p "(Default: n):" answer
  # Default to 'n' when empty, normalize to lowercase and accept y/yes in any case
  answer=${answer:-n}
  lc_answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]')
  case "$lc_answer" in
    y|yes)
      do_uninstall_service_action
      ;;
    *)
      echo
      echo "Uninstall cancelled, nothing to do..."
      echo
      ;;
  esac
}

do_uninstall_service_action() {
  echo -e "${Yellow}Uninstalling anytls-real...${Font}"

  # Stop and disable service if systemd is present
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    echo -e "${Green}Stopping and disabling systemd service $SERVICE_UNIT_NAME${Font}"
    systemctl stop $SERVICE_UNIT_NAME 2>/dev/null || true
    systemctl disable --now $SERVICE_UNIT_NAME 2>/dev/null || true
    # Remove unit file
    if [ -f /etc/systemd/system/$SERVICE_UNIT_NAME ]; then
      rm -f /etc/systemd/system/$SERVICE_UNIT_NAME || true
      systemctl daemon-reload || true
    fi
  else
    echo -e "${Yellow}systemd not present or not running; skipping service stop${Font}"
  fi

  # Remove binary
  if [ -f "$BIN_DIR/$BIN_FILE" ]; then
    echo -e "${Green}Removing binary: $BIN_DIR/$BIN_FILE${Font}"
    rm -f "$BIN_DIR/$BIN_FILE" || true
  else
    echo -e "${Yellow}Binary not found: $BIN_DIR/$BIN_FILE${Font}"
  fi

  # Remove installation directory (configs, certs, keys)
  if [ -d "$INSTALL_DIR" ]; then
    echo -e "${Green}Removing install directory and all contents: $INSTALL_DIR${Font}"
    rm -rf "$INSTALL_DIR" || true
  else
    echo -e "${Yellow}Install directory not found: $INSTALL_DIR${Font}"
  fi

  echo -e "${Green}Uninstall complete.${Font}"
}

case "${1:-}" in
  install)
    TARGET_SITE="${2:-}"
    LISTEN_PORT="${3:-}"
    install_anytls_real_all
    exit 0
    ;;
  uninstall)
    uninstall_all
    exit 0
    ;;
  *)
    echo -e "${Yellow}Usage: $0 <install|uninstall> [site] [port]${Font}" >&2
    exit 1    
    ;;
esac
