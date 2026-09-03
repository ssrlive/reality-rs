#!/usr/bin/env python3
"""TCP smoke test for anyreality with SOCKS5 CONNECT and SNI fallback coverage."""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time


def binary_path(repo_root, name):
    exe = name + ('.exe' if os.name == 'nt' else '')
    return os.path.join(repo_root, 'target', 'debug', exe)


def wait_tcp(host, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def split_endpoint(endpoint):
    if ':' not in endpoint:
        raise ValueError(f'Invalid endpoint: {endpoint}')
    host, port_text = endpoint.rsplit(':', 1)
    if not host or not port_text:
        raise ValueError(f'Invalid endpoint: {endpoint}')
    return host, int(port_text)


def test_tcp_endpoint_available(endpoint):
    host, port = split_endpoint(endpoint)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def get_free_loopback_endpoint(bind_host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((bind_host, 0))
    try:
        return f'{bind_host}:{sock.getsockname()[1]}'
    finally:
        sock.close()


def resolve_endpoint(preferred_endpoint, label):
    if test_tcp_endpoint_available(preferred_endpoint):
        return preferred_endpoint
    host, _ = split_endpoint(preferred_endpoint)
    fallback = get_free_loopback_endpoint(host)
    print(f'warning: {label} endpoint {preferred_endpoint} is already in use. Falling back to {fallback}', file=sys.stderr)
    return fallback


def prepare_log_paths(repo_root, log_name):
    log_path = os.path.join(repo_root, 'target', 'tmp', f'{log_name}.log')
    error_path = os.path.join(repo_root, 'target', 'tmp', f'{log_name}.err.log')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    for path in (log_path, error_path):
        with open(path, 'w', encoding='utf-8'):
            pass
    return log_path, error_path


def show_log_pair(log_path, error_path):
    for path in (log_path, error_path):
        if os.path.isfile(path):
            print(f'===== {path} =====')
            with open(path, 'r', encoding='utf-8', errors='replace') as handle:
                print(handle.read(), end='')


def show_logs(entries):
    for entry in entries:
        show_log_pair(entry['log_path'], entry['error_path'])


def start_process(repo_root, command, log_name):
    log_path, error_path = prepare_log_paths(repo_root, log_name)
    stdout = open(log_path, 'w', encoding='utf-8')
    stderr = open(error_path, 'w', encoding='utf-8')
    process = subprocess.Popen(command, cwd=repo_root, stdout=stdout, stderr=stderr)
    return {
        'process': process,
        'log_path': log_path,
        'error_path': error_path,
        'stdout': stdout,
        'stderr': stderr,
    }


def start_http_target_process(repo_root, listen_endpoint, log_name):
    host, port = split_endpoint(listen_endpoint)
    script_path = os.path.join(repo_root, 'target', 'tmp', f'{log_name}.py')
    log_path, error_path = prepare_log_paths(repo_root, log_name)
    script = """import http.server
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
"""
    with open(script_path, 'w', encoding='utf-8') as handle:
        handle.write(script)
    stdout = open(log_path, 'w', encoding='utf-8')
    stderr = open(error_path, 'w', encoding='utf-8')
    process = subprocess.Popen(
        [sys.executable, script_path, host, str(port)],
        cwd=repo_root,
        stdout=stdout,
        stderr=stderr,
    )
    return {
        'process': process,
        'script_path': script_path,
        'log_path': log_path,
        'error_path': error_path,
        'stdout': stdout,
        'stderr': stderr,
    }


def assert_process_running(entry, label):
    if entry['process'].poll() is not None:
        show_log_pair(entry['log_path'], entry['error_path'])
        raise RuntimeError(f"{label} exited early with code {entry['process'].returncode}")


def cleanup_entries(entries):
    for entry in entries:
        process = entry['process']
        if process.poll() is None:
            process.terminate()
    for entry in entries:
        process = entry['process']
        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        for key in ('stdout', 'stderr'):
            handle = entry.get(key)
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass


def main():
    parser = argparse.ArgumentParser(
        description='Run the TCP REALITY smoke test end to end.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python admin/reality_smoke.py --build-with-cargo
  python admin/reality_smoke.py --server-listen 127.0.0.1:9445 --client-listen 127.0.0.1:1081 --target-listen 127.0.0.1:18080
        '''.strip(),
    )
    parser.add_argument('--build-with-cargo', action='store_true')
    parser.add_argument('--keep-running', action='store_true')
    parser.add_argument('--server-listen', default='127.0.0.1:9445')
    parser.add_argument('--client-listen', default='127.0.0.1:1081')
    parser.add_argument('--target-listen', default='127.0.0.1:18080')
    args = parser.parse_args()

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if shutil.which('curl') is None:
        print('Required command not found: curl', file=sys.stderr)
        return 1

    server_listen = resolve_endpoint(args.server_listen, 'Server')
    client_listen = resolve_endpoint(args.client_listen, 'Client')
    target_listen = resolve_endpoint(args.target_listen, 'Target')
    target_uri = f'http://{target_listen}/'

    if args.build_with_cargo:
        print('Building formal server and client binaries with Cargo')
        build_log, build_err = prepare_log_paths(repo_root, 'reality-build')
        with open(build_log, 'w', encoding='utf-8') as stdout, open(build_err, 'w', encoding='utf-8') as stderr:
            completed = subprocess.run(['cargo', 'build', '-p', 'anyreality'], cwd=repo_root, stdout=stdout, stderr=stderr)
        if completed.returncode != 0:
            show_log_pair(build_log, build_err)
            print('Cargo build failed. See logs above.', file=sys.stderr)
            return 2

    server_binary = binary_path(repo_root, 'anyreality-server')
    client_binary = binary_path(repo_root, 'anyreality-client')
    if not os.path.isfile(server_binary):
        print(f"Formal server binary not found at '{server_binary}'. Build first with '--build-with-cargo' or 'cargo build -p anyreality'.", file=sys.stderr)
        return 3
    if not os.path.isfile(client_binary):
        print(f"Formal client binary not found at '{client_binary}'. Build first with '--build-with-cargo' or 'cargo build -p anyreality'.", file=sys.stderr)
        return 3

    server_config_path = os.path.join(repo_root, 'target', 'tmp', 'reality-server.smoke.toml')
    client_config_path = os.path.join(repo_root, 'target', 'tmp', 'reality-client.smoke.toml')
    os.makedirs(os.path.dirname(server_config_path), exist_ok=True)

    with open(server_config_path, 'w', encoding='utf-8') as handle:
        handle.write(
            '[reality]\n'
            'shortId = "aabbcc"\n'
            'privateKey = "SMGC8zRkH_w4ZggVwiEJOdkeY1jWMZLCet5Qf2i-SmM"\n'
            'version = "010203"\n'
            'serverNames = ["test", "example.com", "baidu.com", "www.baidu.com"]\n\n'
            '[anytls]\n'
            'password = "reality-smoke-password"\n\n'
            '[server]\n'
            f'listen = "{server_listen}"\n'
        )

    with open(client_config_path, 'w', encoding='utf-8') as handle:
        handle.write(
            '[reality]\n'
            'shortId = "aabbcc"\n'
            'publicKey = "h72QTtr2UAYmGeblfKYIUsN3q4kOJQZPxq556g6eIhg"\n'
            'serverName = "test"\n'
            'version = "010203"\n\n'
            '[anytls]\n'
            'password = "reality-smoke-password"\n'
            'idleCheckSecs = 30\n'
            'idleTimeoutSecs = 30\n'
            'minIdleSessions = 5\n\n'
            '[client]\n'
            f'listen = "{client_listen}"\n'
            f'serverAddr = "{server_listen}"\n'
        )

    entries = []
    cleanup_message = False
    http_target_script_path = None

    try:
        print(f'Starting local HTTP target on {target_uri}')
        http_target = start_http_target_process(repo_root, target_listen, 'reality-target')
        http_target_script_path = http_target['script_path']
        entries.append(http_target)
        time.sleep(0.25)
        assert_process_running(http_target, 'HTTP target')
        if not wait_tcp(*split_endpoint(target_listen), timeout=5.0):
            raise RuntimeError('Timed out waiting for HTTP target')

        print(f'Starting formal server on {server_listen}')
        server_entry = start_process(repo_root, [server_binary, '--config', server_config_path], 'reality-server')
        entries.append(server_entry)
        time.sleep(0.5)
        assert_process_running(server_entry, 'Formal server')
        if not wait_tcp(*split_endpoint(server_listen), timeout=5.0):
            raise RuntimeError('Timed out waiting for formal server')

        print(f'Starting formal client on {client_listen}')
        client_entry = start_process(repo_root, [client_binary, '--config', client_config_path], 'reality-client')
        entries.append(client_entry)
        time.sleep(0.5)
        assert_process_running(client_entry, 'Formal client')
        if not wait_tcp(*split_endpoint(client_listen), timeout=5.0):
            raise RuntimeError('Timed out waiting for formal client')

        print('Running SOCKS5 smoke request')
        response = subprocess.run(
            ['curl', '--silent', '--show-error', '--socks5-hostname', client_listen, target_uri],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if response.returncode != 0:
            show_logs(entries)
            raise RuntimeError('curl exited with a non-zero status')

        smoke_response = response.stdout
        print(f'Smoke response: {smoke_response.rstrip()}')

        print('Running HTTP CONNECT smoke request')
        http_response = subprocess.run(
            [
                'curl', '--silent', '--show-error', '--fail', '--proxytunnel',
                '--proxy', f'http://{client_listen}', '--noproxy', '', target_uri,
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if http_response.returncode != 0:
            show_logs(entries)
            raise RuntimeError('HTTP CONNECT curl probe exited with a non-zero status')

        http_smoke_response = http_response.stdout
        print(f'HTTP CONNECT response: {http_smoke_response.rstrip()}')

        server_host, server_port = split_endpoint(server_listen)
        print(f'Running direct SNI fallback probe to baidu.com on {server_listen}')
        fallback = subprocess.run(
            ['curl', '--silent', '--show-error', '--fail', '--resolve', f'baidu.com:{server_port}:{server_host}', f'https://baidu.com:{server_port}/'],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if fallback.returncode != 0:
            show_logs(entries)
            raise RuntimeError('Fallback curl probe exited with a non-zero status')

        print(f'Fallback probe response: {fallback.stdout.rstrip()}')

        if smoke_response != 'reality tunnel ok':
            show_logs(entries)
            raise RuntimeError(f'Unexpected response body: {smoke_response}')
        if http_smoke_response != 'reality tunnel ok':
            show_logs(entries)
            raise RuntimeError(f'Unexpected HTTP response body: {http_smoke_response}')

        cleanup_message = True
        print('Smoke test passed')
        if args.keep_running:
            print('Tunnel is up. Press Ctrl+C to stop background processes.')
            while True:
                time.sleep(1)
        return 0
    except Exception:
        show_logs(entries)
        raise
    finally:
        cleanup_entries(entries)
        for path in (server_config_path, client_config_path, http_target_script_path):
            if path and os.path.isfile(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
        if cleanup_message and not args.keep_running:
            print('Cleaning up background processes')
            print('Done.')


if __name__ == '__main__':
    raise SystemExit(main())
