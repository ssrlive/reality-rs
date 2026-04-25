#!/usr/bin/env bash

set -uo pipefail

server_listen='127.0.0.1:9445'
client_listen='127.0.0.1:1081'
target_listen='127.0.0.1:18080'
keep_running=0
build_with_cargo=0
cleanup_message=0

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

http_target_pid=''
server_pid=''
client_pid=''
http_target_script=''

declare -a entry_logs=()
declare -a entry_errors=()

usage() {
    cat <<'EOF'
Usage: ./admin/reality-smoke.sh [options]

Options:
  --server-listen HOST:PORT   Server listen endpoint (default: 127.0.0.1:9445)
  --client-listen HOST:PORT   Client listen endpoint (default: 127.0.0.1:1081)
  --target-listen HOST:PORT   HTTP target endpoint (default: 127.0.0.1:18080)
  --keep-running              Keep background processes alive after a successful smoke test
  --build-with-cargo          Build server and client with Cargo before running
  -h, --help                  Show this help text
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

assert_command() {
    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        die "Required command not found: $command_name"
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
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.bind((host, port))
except OSError:
    sys.exit(1)
finally:
    sock.close()
PY
}

get_free_loopback_endpoint() {
    local bind_host="$1"

    python3 - "$bind_host" <<'PY'
import socket
import sys

host = sys.argv[1]
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((host, 0))
try:
    print(f"{host}:{sock.getsockname()[1]}")
finally:
    sock.close()
PY
}

resolve_endpoint() {
    local preferred_endpoint="$1"
    local label="$2"

    if test_tcp_endpoint_available "$preferred_endpoint"; then
        printf '%s\n' "$preferred_endpoint"
        return
    fi

    split_endpoint "$preferred_endpoint"
    local fallback
    fallback="$(get_free_loopback_endpoint "$SPLIT_HOSTNAME")"
    echo "warning: $label endpoint $preferred_endpoint is already in use. Falling back to $fallback" >&2
    printf '%s\n' "$fallback"
}

wait_tcp_endpoint() {
    local endpoint="$1"
    local timeout_seconds="${2:-30}"
    split_endpoint "$endpoint"

    local hostname="$SPLIT_HOSTNAME"
    local port="$SPLIT_PORT"
    local deadline=$((SECONDS + timeout_seconds))

    while (( SECONDS < deadline )); do
        if python3 - "$hostname" "$port" <<'PY' >/dev/null 2>&1
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.5)
try:
    sock.connect((host, port))
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
    local log_path="$1"
    local error_path="$2"

    if [[ -f "$log_path" ]]; then
        echo "===== $log_path ====="
        cat "$log_path"
    fi

    if [[ -f "$error_path" ]]; then
        echo "===== $error_path ====="
        cat "$error_path"
    fi
}

show_logs() {
    local index

    for index in "${!entry_logs[@]}"; do
        show_log_pair "${entry_logs[$index]}" "${entry_errors[$index]}"
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

run_cargo_build() {
    prepare_log_paths 'reality-build'

    if ! (
        cd -- "$repo_root"
        cargo build -p server -p client
    ) >"$LOG_PATH" 2>"$ERROR_PATH"
    then
        show_log_pair "$LOG_PATH" "$ERROR_PATH"
        die "Cargo build failed. See logs above."
    fi
}

start_http_target_process() {
    local listen_uri="$1"
    local log_name="$2"

    prepare_log_paths "$log_name"
    http_target_script="$repo_root/target/tmp/${log_name}.py"

    cat > "$http_target_script" <<'PY'
import http.server
import socketserver
import sys

host = sys.argv[1]
port = int(sys.argv[2])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'reality tunnel ok'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

class Server(socketserver.TCPServer):
    allow_reuse_address = True

with Server((host, port), Handler) as httpd:
    httpd.serve_forever()
PY

    split_endpoint "$target_listen"
    (
        cd -- "$repo_root"
        python3 "$http_target_script" "$SPLIT_HOSTNAME" "$SPLIT_PORT"
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

assert_file_exists() {
    local file_path="$1"
    local label="$2"

    if [[ ! -f "$file_path" ]]; then
        die "$label binary not found at '$file_path'. Build it first with './admin/reality-smoke.sh --build-with-cargo' or 'cargo build -p server -p client'."
    fi
}

cleanup() {
    local exit_code=$?

    if [[ -n "$client_pid" ]] && kill -0 "$client_pid" >/dev/null 2>&1; then
        kill "$client_pid" >/dev/null 2>&1 || true
        wait "$client_pid" 2>/dev/null || true
    fi

    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" >/dev/null 2>&1; then
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" 2>/dev/null || true
    fi

    if [[ -n "$http_target_pid" ]] && kill -0 "$http_target_pid" >/dev/null 2>&1; then
        kill "$http_target_pid" >/dev/null 2>&1 || true
        wait "$http_target_pid" 2>/dev/null || true
    fi

    if [[ -n "$http_target_script" && -f "$http_target_script" ]]; then
        rm -f -- "$http_target_script"
    fi

    if (( cleanup_message == 1 )) && (( keep_running == 0 )); then
        echo 'Cleaning up background processes'
        if (( exit_code == 0 )); then
            echo 'Done.'
        fi
    fi

    exit "$exit_code"
}

trap cleanup EXIT

while (( $# > 0 )); do
    case "$1" in
        --server-listen)
            [[ $# -ge 2 ]] || die "Missing value for $1"
            server_listen="$2"
            shift 2
            ;;
        --client-listen)
            [[ $# -ge 2 ]] || die "Missing value for $1"
            client_listen="$2"
            shift 2
            ;;
        --target-listen)
            [[ $# -ge 2 ]] || die "Missing value for $1"
            target_listen="$2"
            shift 2
            ;;
        --keep-running)
            keep_running=1
            shift
            ;;
        --build-with-cargo)
            build_with_cargo=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
done

assert_command python3
assert_command curl

server_binary="$repo_root/target/debug/server"
client_binary="$repo_root/target/debug/client"

server_listen="$(resolve_endpoint "$server_listen" 'Server')"
client_listen="$(resolve_endpoint "$client_listen" 'Client')"
target_listen="$(resolve_endpoint "$target_listen" 'Target')"
target_uri="http://${target_listen}/"

smoke_password='reality-smoke-password'

server_args=(
    '--cert' './bogo/keys/cert.pem'
    '--key' './bogo/keys/key.pem'
    '--listen' "$server_listen"
    '--reality-config' './server/config/reality-server.toml'
    '--password' "$smoke_password"
)

client_args=(
    '--listen' "$client_listen"
    '--server-addr' "$server_listen"
    '--reality-config' './client/config/reality-client.json'
    '--ca-file' './bogo/keys/cert.pem'
    '--insecure'
    '--password' "$smoke_password"
)

if (( build_with_cargo == 1 )); then
    assert_command cargo
    echo 'Building formal server and client binaries with Cargo'
    run_cargo_build
fi

assert_file_exists "$server_binary" 'Formal server'
assert_file_exists "$client_binary" 'Formal client'

cleanup_message=1

echo "Starting local HTTP target on $target_uri"
start_http_target_process "$target_uri" 'reality-target'
http_target_pid="$START_PID"
sleep 0.25
assert_process_running "$http_target_pid" 'HTTP target' "$START_LOG_PATH" "$START_ERROR_PATH"
wait_tcp_endpoint "$target_listen"

echo "Starting formal server on $server_listen"
start_binary_process "$server_binary" 'reality-server' "${server_args[@]}"
server_pid="$START_PID"
sleep 0.5
assert_process_running "$server_pid" 'Formal server' "$START_LOG_PATH" "$START_ERROR_PATH"
wait_tcp_endpoint "$server_listen"

echo "Starting formal client on $client_listen"
start_binary_process "$client_binary" 'reality-client' "${client_args[@]}"
client_pid="$START_PID"
sleep 0.5
assert_process_running "$client_pid" 'Formal client' "$START_LOG_PATH" "$START_ERROR_PATH"
wait_tcp_endpoint "$client_listen"

echo 'Running SOCKS5 smoke request'
if ! response="$(curl --silent --show-error --socks5-hostname "$client_listen" "$target_uri")"; then
    show_logs
    die "curl exited with a non-zero status"
fi

echo "Smoke response: $response"

if [[ "$response" != 'reality tunnel ok' ]]; then
    show_logs
    die "Unexpected response body: $response"
fi

if (( keep_running == 1 )); then
    echo 'Tunnel is up. Press Ctrl+C to stop background processes.'
    while true; do
        sleep 1
    done
fi