#!/usr/bin/env bash
set -euo pipefail

#fonts color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
ColorOff="\033[0m"

# Require root to run this script. The install uses system paths and
# writes files into system locations; enforce root to avoid sudo misuse.
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${Red}This script must be run as root (use sudo)${ColorOff}" >&2
  exit 1
fi

anyreality_bin_url="https://github.com/ssrlive/reality-rs/releases/latest/download/anyreality-x86_64-unknown-linux-musl.zip"

# some foreign sites likely accessible from China (common CDNs, developer sites)
STOCK_SITES=(cdn.jsdelivr.net jsdelivr.com stackoverflow.com developer.mozilla.org python.org pypi.org crates.io golang.org nodejs.org npmjs.com cloudflare.com nginx.org rust-lang.org debian.org ubuntu.com)

BIN_DIR=${BIN_DIR:-/usr/local/bin}
BIN_FILE="anyreality-server"
INSTALL_DIR=${INSTALL_DIR:-/etc/anyreality}
SERVER_CONFIG="${INSTALL_DIR}/config.toml"
TARGET_SITE=""
LISTEN_PORT=""
SERVICE_UNIT_NAME="anyreality.service"

select_random_site() {
  # choose a random site and generate certificate
  local site_index=$((RANDOM % ${#STOCK_SITES[@]}))
  echo "${STOCK_SITES[$site_index]}"
}

install_prereqs() {
  local prereq_tools=(curl unzip openssl ca-certificates)

  echo -e "${Green}Installing prerequisites: ${prereq_tools[*]}${ColorOff}"

  for tool in "${prereq_tools[@]}"; do
    install_tool "$tool"
  done
}

apt_checked_flag=false

install_tool() {
  local tool="$1"
  if tool_is_installed "$tool"; then
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    if [ "$apt_checked_flag" = false ]; then
       apt_checked_flag=true
      # Some systems ship with a broken third-party APT source; do not abort on
      # update failures because the base distro repositories may still be usable.
      if ! apt-get update; then
        echo -e "${Yellow}apt-get update failed; continuing to package install${ColorOff}" >&2
      fi
    fi

    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${tool}
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache ${tool}
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ${tool}
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ${tool}
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ${tool}
  else
    echo -e "${Red}No supported package manager found. Please install: ${tool} manually${ColorOff}" >&2
    exit 1
  fi
}

tool_is_installed() {
  local tool="$1"

  if command -v apt-get >/dev/null 2>&1; then
    dpkg -s "$tool" >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then
    apk info -e "$tool" >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    rpm -q "$tool" >/dev/null 2>&1
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Q "$tool" >/dev/null 2>&1
  else
    command -v "$tool" >/dev/null 2>&1
  fi
}

install_server_binary() {
  TMPDIR=$(mktemp -d)
  cleanup() { rm -rf "$TMPDIR"; }
  trap cleanup EXIT

  echo -e "${Green}Downloading anyreality from: $anyreality_bin_url${ColorOff}"
  curl -L "$anyreality_bin_url" -o "$TMPDIR/anytls.zip"

  echo -e "${Green}Extracting...${ColorOff}"
  unzip -o "$TMPDIR/anytls.zip" -d "$TMPDIR" >/dev/null

  # Prefer the server binary; avoid installing the client
  binfile=$(find "$TMPDIR" -type f -name "$BIN_FILE" -print -quit || true)
  if [ -z "$binfile" ]; then
    echo -e "${Red}Could not locate $BIN_FILE binary in archive${ColorOff}"
    return 1
  fi

  echo -e "${Green}Installing binary to $BIN_DIR${ColorOff}"
  mkdir -p "$BIN_DIR"
  install -m 0755 "$binfile" "$BIN_DIR/$BIN_FILE"
}

resolve_hostaddr() {
  local hostaddr

  hostaddr=$(curl -4 -sS https://ip.sb 2>/dev/null || true)
  if [ -n "$hostaddr" ]; then
    printf '%s\n' "$hostaddr"
    return 0
  fi

  hostaddr=$(curl -6 -sS https://ip.sb 2>/dev/null || true)
  if [ -n "$hostaddr" ]; then
    printf '%s\n' "$hostaddr"
    return 0
  fi

  hostname -f 2>/dev/null || hostname
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
EOF
  echo -e "${Green}Wrote server config: $SERVER_CONFIG${ColorOff}"
}

write_client_config() {
  local the_site="$1"
  local the_port="$2"
  CLIENT_OUT="$INSTALL_DIR/client-config.toml"
  hostaddr=$(resolve_hostaddr)
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
minIdleSessions = 5

[client]
listen = "127.0.0.1:2080"
serverAddr = "${hostaddr}:${the_port}"
EOF
  echo -e "${Green}Wrote client config: $CLIENT_OUT${ColorOff}"
}

install_systemd_service() {
  local service_path="/etc/systemd/system/$SERVICE_UNIT_NAME"
  cat > "$service_path" <<EOF
[Unit]
Description=anyreality server
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
      echo -e "${Red}Warning: failed to enable/start $SERVICE_UNIT_NAME; showing status and recent journal entries:${ColorOff}" >&2
      systemctl status $SERVICE_UNIT_NAME --no-pager || true
      journalctl -u $SERVICE_UNIT_NAME -n 200 --no-pager || true
    else
      echo -e "${Green}Installed and started systemd service: $SERVICE_UNIT_NAME${ColorOff}"
    fi
  else
    echo -e "${Yellow}systemctl not found or systemd not running; created $service_path. Start the service manually:${ColorOff}" >&2
    echo -e "  ${Yellow}$BIN_DIR/$BIN_FILE --config $SERVER_CONFIG${ColorOff}" >&2
  fi
}

install_anyreality_all() {
  # Begin main flow
  install_prereqs
  install_server_binary || { echo -e "${Red}Binary installation failed${ColorOff}" >&2; exit 1; }

  if [ -n "$TARGET_SITE" ]; then
    echo -e "${Green}Using provided site: $TARGET_SITE${ColorOff}"
  else
    echo "请输入 你的网站域名 (形如 mygooodsite.com) 并敲回车, 如果不输入（只敲回车）将随机选择一个常见的站点名:"
    stty erase '^H' && read -p "Enter your domain name (for example: mygooodsite.com), or press Enter only to select a random common site: " TARGET_SITE

    if [ -z "$TARGET_SITE" ]; then
      echo -e "${Yellow}No site provided; selecting a random site from the stock list${ColorOff}"
      TARGET_SITE=$(select_random_site)
    fi
  fi

  if [ -n "$LISTEN_PORT" ]; then
    echo -e "${Green}Using provided listen port: $LISTEN_PORT${ColorOff}"
  else
    echo "请输入服务器监听端口 (默认为 443) 并敲回车:"
    stty erase '^H' && read -p "Enter the listen port for the server (default 443): " LISTEN_PORT
    if [ -z "$LISTEN_PORT" ]; then
      LISTEN_PORT=443
    fi
  fi

  # generate or reuse REALITY keys
  generate_reality_keys || { echo -e "${Red}REALITY key generation failed${ColorOff}" >&2; exit 1; }

  # generate anytls password (kept in-memory only; do not create a password file)
  anytls_password=$(generate_anytls_password)
  mkdir -p "$INSTALL_DIR"

  # write configs
  write_server_config "$TARGET_SITE" "$LISTEN_PORT"
  write_client_config "$TARGET_SITE" "$LISTEN_PORT"

  # install and start systemd service (best-effort)
  if command -v systemctl >/dev/null 2>&1; then
    install_systemd_service
  else
    echo -e "${Yellow}systemctl not found; skipping service install. Start $BIN_DIR/$BIN_FILE manually:${ColorOff}" >&2
    echo -e "  ${Yellow}$BIN_DIR/$BIN_FILE --config $SERVER_CONFIG${ColorOff}" >&2
  fi

  # Print client config to terminal for easy copy/paste
  CLIENT_OUT="$INSTALL_DIR/client-config.toml"
  echo -e "${Green}\n==== Client config ($CLIENT_OUT) ====\n${ColorOff}"
  cat "$CLIENT_OUT" || true

  echo -e "${Green}\nInstall complete. Server config: $SERVER_CONFIG; client config printed above.\n${ColorOff}"
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
  echo -e "${Yellow}Uninstalling anyreality...${ColorOff}"

  # Stop and disable service if systemd is present
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    echo -e "${Green}Stopping and disabling systemd service $SERVICE_UNIT_NAME${ColorOff}"
    systemctl stop $SERVICE_UNIT_NAME 2>/dev/null || true
    systemctl disable --now $SERVICE_UNIT_NAME 2>/dev/null || true
    # Remove unit file
    if [ -f /etc/systemd/system/$SERVICE_UNIT_NAME ]; then
      rm -f /etc/systemd/system/$SERVICE_UNIT_NAME || true
      systemctl daemon-reload || true
    fi
  else
    echo -e "${Yellow}systemd not present or not running; skipping service stop${ColorOff}"
  fi

  # Remove binary
  if [ -f "$BIN_DIR/$BIN_FILE" ]; then
    echo -e "${Green}Removing binary: $BIN_DIR/$BIN_FILE${ColorOff}"
    rm -f "$BIN_DIR/$BIN_FILE" || true
  else
    echo -e "${Yellow}Binary not found: $BIN_DIR/$BIN_FILE${ColorOff}"
  fi

  # Remove installation directory (configs, certs, keys)
  if [ -d "$INSTALL_DIR" ]; then
    echo -e "${Green}Removing install directory and all contents: $INSTALL_DIR${ColorOff}"
    rm -rf "$INSTALL_DIR" || true
  else
    echo -e "${Yellow}Install directory not found: $INSTALL_DIR${ColorOff}"
  fi

  echo -e "${Green}Uninstall complete.${ColorOff}"
}

case "${1:-}" in
  install)
    TARGET_SITE="${2:-}"
    LISTEN_PORT="${3:-}"
    install_anyreality_all
    exit 0
    ;;
  uninstall)
    uninstall_all
    exit 0
    ;;
  *)
    echo -e "${Yellow}Usage: $0 <install|uninstall> [site] [port]${ColorOff}" >&2
    exit 1    
    ;;
esac
