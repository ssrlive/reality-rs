#!/usr/bin/env bash

set -uo pipefail

# UDP ASSOCIATE end-to-end smoke test for anytls-real.
#
# Topology:
#   Python UDP client
#     -> SOCKS5 UDP relay (anytls-real-client on $client_listen)
#     -> REALITY tunnel
#     -> anytls-real-server (on $server_listen)
#     -> UDP echo server (on $udp_echo_listen)
#     -> back the same way
#
# Run from the repo root:
#   bash admin/reality-smoke-udp.sh
#   bash admin/reality-smoke-udp.sh --build-with-cargo

server_listen='127.0.0.1:9445'
client_listen='127.0.0.1:1081'
udp_echo_listen='127.0.0.1:19090'
keep_running=0
build_with_cargo=0
cleanup_message=0

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

echo_pid=''
server_pid=''
client_pid=''
udp_echo_script=''
server_config_path=''
client_config_path=''

declare -a entry_logs=()
declare -a entry_errors=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

usage() {
    cat <<'EOF'
Usage: ./admin/reality-smoke-udp.sh [options]

Options:
  --server-listen HOST:PORT   Server listen endpoint (default: 127.0.0.1:9445)
  --client-listen HOST:PORT   Client listen endpoint (default: 127.0.0.1:1081)
  --udp-echo-listen HOST:PORT UDP echo server endpoint (default: 127.0.0.1:19090)
  --keep-running              Keep background processes alive after a successful smoke test
  --build-with-cargo          Build anytls-real with Cargo before running
  -h, --help                  Show this help text
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

assert_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        die "Required command not found: $1"
    fi
}

split_endpoint() {
    local endpoint="$1"
    if [[ "$endpoint" != *:* ]]; then
        die "Invalid endpoint: $endpoint"
    fi
    SPLIT_HOSTNAME="${endpoint%:*}"
    SPLIT_PORT="${endpoint##*:}"
    if [[ -z "$SPLIT_HOSTNAME" || -z "$SPLIT_PORT" ]]; then
        die "Invalid endpoint: $endpoint"
    fi
}

test_tcp_endpoint_available() {
    local endpoint="$1"
    split_endpoint "$endpoint"
    python3 - "$SPLIT_HOSTNAME" "$SPLIT_PORT" <<'PY' >/dev/null 2>&1
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.bind((sys.argv[1], int(sys.argv[2])))
except OSError:
    sys.exit(1)
finally:
    sock.close()
PY
}

get_free_loopback_endpoint() {
    local bind_host="$1"
    python3 - "$bind_host" <<'PY'
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((sys.argv[1], 0))
try:
    print(f"{sys.argv[1]}:{sock.getsockname()[1]}")
finally:
    sock.close()
PY
}

resolve_endpoint() {
    local preferred="$1"
    local label="$2"
    if test_tcp_endpoint_available "$preferred"; then
        printf '%s\n' "$preferred"
        return
    fi
    split_endpoint "$preferred"
    local fallback
    fallback="$(get_free_loopback_endpoint "$SPLIT_HOSTNAME")"
    echo "warning: $label endpoint $preferred is already in use. Falling back to $fallback" >&2
    printf '%s\n' "$fallback"
}

wait_tcp_endpoint() {
    local endpoint="$1"
    local timeout_seconds="${2:-30}"
    split_endpoint "$endpoint"
    local hostname="$SPLIT_HOSTNAME"
    local port="$SPLIT_PORT"
    local deadline=$(( SECONDS + timeout_seconds ))
    while (( SECONDS < deadline )); do
        if python3 - "$hostname" "$port" <<'PY' >/dev/null 2>&1
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.5)
try:
    sock.connect((sys.argv[1], int(sys.argv[2])))
except OSError:
    sys.exit(1)
finally:
    sock.close()
PY
        then
            return
        fi
        sleep 0.25
    done
    die "Timed out waiting for $endpoint"
}

prepare_log_paths() {
    local log_name="$1"
    LOG_PATH="$repo_root/target/tmp/${log_name}.log"
    ERROR_PATH="$repo_root/target/tmp/${log_name}.err.log"
    mkdir -p "$(dirname -- "$LOG_PATH")"
    : > "$LOG_PATH"
    : > "$ERROR_PATH"
}

show_log_pair() {
    if [[ -f "$1" ]]; then echo "===== $1 ====="; cat "$1"; fi
    if [[ -f "$2" ]]; then echo "===== $2 ====="; cat "$2"; fi
}

show_logs() {
    local i
    for i in "${!entry_logs[@]}"; do
        show_log_pair "${entry_logs[$i]}" "${entry_errors[$i]}"
    done
}

start_binary_process() {
    local file_path="$1"
    local log_name="$2"
    shift 2
    prepare_log_paths "$log_name"
    (
        cd -- "$repo_root"
        "$file_path" "$@"
    ) >"$LOG_PATH" 2>"$ERROR_PATH" &
    START_PID=$!
    START_LOG_PATH="$LOG_PATH"
    START_ERROR_PATH="$ERROR_PATH"
    entry_logs+=("$START_LOG_PATH")
    entry_errors+=("$START_ERROR_PATH")
}

assert_process_running() {
    local pid="$1"
    local label="$2"
    local log_path="$3"
    local error_path="$4"
    if ! kill -0 "$pid" >/dev/null 2>&1; then
        local exit_code=0
        wait "$pid" || exit_code=$?
        show_log_pair "$log_path" "$error_path"
        die "$label exited early with code $exit_code"
    fi
}

run_cargo_build() {
    prepare_log_paths 'reality-build'
    if ! (
        cd -- "$repo_root"
        cargo build -p anytls-real
    ) >"$LOG_PATH" 2>"$ERROR_PATH"; then
        show_log_pair "$LOG_PATH" "$ERROR_PATH"
        die "Cargo build failed. See logs above."
    fi
}

cleanup() {
    local exit_code=$?
    for pid_var in client_pid server_pid echo_pid; do
        local pid="${!pid_var}"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -f -- "$server_config_path" "$client_config_path"
    if [[ -n "$udp_echo_script" && -f "$udp_echo_script" ]]; then
        rm -f -- "$udp_echo_script"
    fi
    if (( cleanup_message == 1 )) && (( keep_running == 0 )); then
        echo 'Cleaning up background processes'
        if (( exit_code == 0 )); then echo 'Done.'; fi
    fi
    exit "$exit_code"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while (( $# > 0 )); do
    case "$1" in
        --server-listen)   [[ $# -ge 2 ]] || die "Missing value for $1"; server_listen="$2"; shift 2 ;;
        --client-listen)   [[ $# -ge 2 ]] || die "Missing value for $1"; client_listen="$2"; shift 2 ;;
        --udp-echo-listen) [[ $# -ge 2 ]] || die "Missing value for $1"; udp_echo_listen="$2"; shift 2 ;;
        --keep-running)    keep_running=1; shift ;;
        --build-with-cargo) build_with_cargo=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

assert_command python3

server_binary="$repo_root/target/debug/anytls-real-server"
client_binary="$repo_root/target/debug/anytls-real-client"
smoke_password='reality-smoke-password'
server_config_path="$repo_root/target/tmp/reality-server.smoke.toml"
client_config_path="$repo_root/target/tmp/reality-client.smoke.toml"

server_listen="$(resolve_endpoint "$server_listen" 'Server')"
client_listen="$(resolve_endpoint "$client_listen" 'Client')"

split_endpoint "$udp_echo_listen"
echo_host="$SPLIT_HOSTNAME"
echo_port="$SPLIT_PORT"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (( build_with_cargo == 1 )); then
    assert_command cargo
    echo 'Building anytls-real binaries with Cargo'
    run_cargo_build
fi

[[ -f "$server_binary" ]] || die "Server binary not found at '$server_binary'. Build first with '--build-with-cargo' or 'cargo build -p anytls-real'."
[[ -f "$client_binary" ]] || die "Client binary not found at '$client_binary'. Build first with '--build-with-cargo' or 'cargo build -p anytls-real'."

cat > "$server_config_path" <<EOF
[reality]
shortId = "aabbcc"
privateKey = "SMGC8zRkH_w4ZggVwiEJOdkeY1jWMZLCet5Qf2i-SmM"
version = "010203"
serverNames = ["test"]

[anytls]
password = "$smoke_password"

[server]
listen = "$server_listen"
cert = './bogo/keys/cert.pem'
key = './bogo/keys/key.pem'
EOF

cat > "$client_config_path" <<EOF
[reality]
shortId = "aabbcc"
publicKey = "h72QTtr2UAYmGeblfKYIUsN3q4kOJQZPxq556g6eIhg"
serverName = "test"
version = "010203"

[anytls]
password = "$smoke_password"
idleCheckSecs = 30
idleTimeoutSecs = 30
minIdleSessions = 5

[client]
listen = "$client_listen"
serverAddr = "$server_listen"
caFile = './bogo/keys/cert.pem'
insecure = true
EOF

cleanup_message=1

# Start UDP echo server (Python)
udp_echo_script="$repo_root/target/tmp/udp-echo-helper.py"
mkdir -p "$(dirname -- "$udp_echo_script")"
cat > "$udp_echo_script" <<'PY'
import socket, sys
bind_host = sys.argv[1]
bind_port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((bind_host, bind_port))
try:
    while True:
        data, addr = sock.recvfrom(65535)
        sock.sendto(data, addr)
finally:
    sock.close()
PY

echo "Starting UDP echo server on ${echo_host}:${echo_port}"
prepare_log_paths 'udp-echo'
(
    cd -- "$repo_root"
    python3 "$udp_echo_script" "$echo_host" "$echo_port"
) >"$LOG_PATH" 2>"$ERROR_PATH" &
echo_pid=$!
entry_logs+=("$LOG_PATH")
entry_errors+=("$ERROR_PATH")
sleep 0.25

echo "Starting anytls-real-server on $server_listen"
start_binary_process "$server_binary" 'reality-server' \
    --config "$server_config_path"
server_pid="$START_PID"
sleep 0.5
assert_process_running "$server_pid" 'anytls-real-server' "$START_LOG_PATH" "$START_ERROR_PATH"
wait_tcp_endpoint "$server_listen"

echo "Starting anytls-real-client on $client_listen"
start_binary_process "$client_binary" 'reality-client' \
    --config "$client_config_path"
client_pid="$START_PID"
sleep 0.5
assert_process_running "$client_pid" 'anytls-real-client' "$START_LOG_PATH" "$START_ERROR_PATH"
wait_tcp_endpoint "$client_listen"

# Run the SOCKS5 UDP ASSOCIATE handshake and echo round-trip via Python
echo 'Running SOCKS5 UDP ASSOCIATE smoke request'

split_endpoint "$client_listen"
socks_host="$SPLIT_HOSTNAME"
socks_port="$SPLIT_PORT"

if ! response="$(python3 - "$socks_host" "$socks_port" "$echo_host" "$echo_port" <<'PY'
import socket
import struct
import sys

socks_host  = sys.argv[1]
socks_port  = int(sys.argv[2])
echo_host   = sys.argv[3]
echo_port   = int(sys.argv[4])
payload_str = 'reality-uot-ok'

# ---- SOCKS5 control connection for UDP ASSOCIATE ----
ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctrl.settimeout(10)
ctrl.connect((socks_host, socks_port))

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f'EOF after {len(buf)} of {n} bytes')
        buf += chunk
    return buf

# Auth negotiation
ctrl.sendall(b'\x05\x01\x00')
resp = recv_exact(ctrl, 2)
if resp != b'\x05\x00':
    raise RuntimeError(f'Auth negotiation failed: {resp.hex()}')

# UDP ASSOCIATE request (bind addr/port all-zeros = client decides)
ctrl.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
head = recv_exact(ctrl, 4)
if head[0] != 0x05 or head[1] != 0x00:
    raise RuntimeError(f'UDP ASSOCIATE failed, REP={head[1]:#04x}: {head.hex()}')

atyp = head[3]
if atyp == 1:
    raw = recv_exact(ctrl, 6)
    relay_ip   = socket.inet_ntoa(raw[:4])
    relay_port = struct.unpack('!H', raw[4:6])[0]
elif atyp == 4:
    raw = recv_exact(ctrl, 18)
    relay_ip   = socket.inet_ntop(socket.AF_INET6, raw[:16])
    relay_port = struct.unpack('!H', raw[16:18])[0]
elif atyp == 3:
    nlen = recv_exact(ctrl, 1)[0]
    raw  = recv_exact(ctrl, nlen + 2)
    relay_ip   = raw[:nlen].decode()
    relay_port = struct.unpack('!H', raw[nlen:nlen+2])[0]
else:
    raise RuntimeError(f'Unsupported ATYP {atyp}')

relay_addr = (relay_ip, relay_port)

# ---- Build SOCKS5 UDP packet ----
echo_ip_bytes = socket.inet_aton(echo_host)
port_bytes    = struct.pack('!H', echo_port)
udp_payload   = payload_str.encode()
packet = b'\x00\x00\x00\x01' + echo_ip_bytes + port_bytes + udp_payload

# ---- Send via UDP, receive echo ----
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
udp.sendto(packet, relay_addr)
response, _ = udp.recvfrom(65535)
udp.close()
ctrl.close()

# ---- Parse SOCKS5 UDP response ----
if len(response) < 4:
    raise RuntimeError('UDP response too short')
ratyp = response[3]
off = 4
if ratyp == 1:
    src_ip   = socket.inet_ntoa(response[off:off+4]); off += 4
    src_port = struct.unpack('!H', response[off:off+2])[0]; off += 2
elif ratyp == 4:
    src_ip   = socket.inet_ntop(socket.AF_INET6, response[off:off+16]); off += 16
    src_port = struct.unpack('!H', response[off:off+2])[0]; off += 2
elif ratyp == 3:
    nlen     = response[off]; off += 1
    src_ip   = response[off:off+nlen].decode(); off += nlen
    src_port = struct.unpack('!H', response[off:off+2])[0]; off += 2
else:
    raise RuntimeError(f'Unsupported response ATYP {ratyp}')

text = response[off:].decode()

if text != payload_str:
    raise RuntimeError(f"Unexpected payload: '{text}'")
if src_port != echo_port:
    raise RuntimeError(f"Unexpected source port {src_port}, expected {echo_port}")

print(f"UDP echo: '{text}' from {src_ip}:{src_port}")
PY
    )"; then
    show_logs
    die "UDP ASSOCIATE smoke request failed"
fi

echo "Smoke response: $response"
echo 'UDP ASSOCIATE end-to-end smoke test passed'

if (( keep_running == 1 )); then
    echo 'Tunnel is up. Press Ctrl+C to stop background processes.'
    while true; do sleep 1; done
fi
