#!/usr/bin/env python3
"""UDP smoke test: start anyreality server/client and verify SOCKS5 UDP relay echo."""
import argparse
import os
import socket
import subprocess
import sys
import threading
import time

def find_binary(name):
    exe = name + ('.exe' if os.name == 'nt' else '')
    path = os.path.join('target', 'debug', exe)
    return path if os.path.isfile(path) else None

def wait_tcp(host, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except Exception:
            time.sleep(0.2)
    return False


def split_endpoint(endpoint):
    host, port_text = endpoint.rsplit(':', 1)
    return host, int(port_text)


def read_exact(sock, count):
    chunks = bytearray()
    while len(chunks) < count:
        data = sock.recv(count - len(chunks))
        if not data:
            raise EOFError(f'EOF after {len(chunks)} of {count} bytes')
        chunks.extend(data)
    return bytes(chunks)


def build_socks5_udp_packet(payload, host, port):
    ip = socket.inet_pton(socket.AF_INET, host)
    return b'\x00\x00\x00\x01' + ip + port.to_bytes(2, 'big') + payload


def parse_socks5_udp_packet(packet):
    if len(packet) < 4:
        raise RuntimeError('UDP relay packet too short')
    atyp = packet[3]
    offset = 4
    if atyp == 1:
        addr = socket.inet_ntop(socket.AF_INET, packet[offset:offset + 4])
        offset += 4
    elif atyp == 4:
        addr = socket.inet_ntop(socket.AF_INET6, packet[offset:offset + 16])
        offset += 16
    elif atyp == 3:
        nlen = packet[offset]
        offset += 1
        addr = packet[offset:offset + nlen].decode('ascii')
        offset += nlen
    else:
        raise RuntimeError(f'Unsupported UDP ATYP {atyp}')
    port = int.from_bytes(packet[offset:offset + 2], 'big')
    offset += 2
    payload = packet[offset:]
    return addr, port, payload


def start_udp_echo_server(bind_host, bind_port):
    stop_event = threading.Event()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, bind_port))
    sock.settimeout(0.5)

    def run():
        try:
            while not stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                sock.sendto(data, addr)
        finally:
            sock.close()

    thread = threading.Thread(target=run, name='udp-echo', daemon=True)
    thread.start()
    return stop_event, thread


def socks5_udp_echo(proxy_host, proxy_port, target_host, target_port, payload):
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control.settimeout(10)
    control.connect((proxy_host, proxy_port))

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)

    try:
        control.sendall(b'\x05\x01\x00')
        if read_exact(control, 2) != b'\x05\x00':
            raise RuntimeError('SOCKS5 auth negotiation failed')

        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        head = read_exact(control, 4)
        if head[0] != 0x05 or head[1] != 0x00:
            raise RuntimeError(f'UDP ASSOCIATE failed, REP={head[1]:#04x}')

        atyp = head[3]
        if atyp == 1:
            raw = read_exact(control, 6)
            relay_host = socket.inet_ntop(socket.AF_INET, raw[:4])
            relay_port = int.from_bytes(raw[4:6], 'big')
        elif atyp == 4:
            raw = read_exact(control, 18)
            relay_host = socket.inet_ntop(socket.AF_INET6, raw[:16])
            relay_port = int.from_bytes(raw[16:18], 'big')
        elif atyp == 3:
            nlen = read_exact(control, 1)[0]
            raw = read_exact(control, nlen + 2)
            relay_host = raw[:nlen].decode('ascii')
            relay_port = int.from_bytes(raw[nlen:nlen + 2], 'big')
        else:
            raise RuntimeError(f'Unsupported relay ATYP {atyp}')

        packet = build_socks5_udp_packet(payload, target_host, target_port)
        udp.sendto(packet, (relay_host, relay_port))
        response, _ = udp.recvfrom(65535)
        src_host, src_port, echoed_payload = parse_socks5_udp_packet(response)
        if echoed_payload != payload:
            raise RuntimeError(f'Unexpected payload: {echoed_payload!r}')
        if src_port != target_port:
            raise RuntimeError(f'Unexpected source port {src_port}, expected {target_port}')
        return src_host, src_port, echoed_payload.decode('utf-8', errors='replace')
    finally:
        udp.close()
        control.close()

def main():
    p = argparse.ArgumentParser(
        description='Run the UDP REALITY smoke test end to end.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python admin/reality_smoke_udp.py --build-with-cargo
  python admin/reality_smoke_udp.py --server-listen 127.0.0.1:9445 --client-listen 127.0.0.1:1081 --udp-echo-listen 127.0.0.1:19090
        '''.strip(),
    )
    p.add_argument('--build-with-cargo', action='store_true')
    p.add_argument('--keep-running', action='store_true')
    p.add_argument('--server-listen', default='127.0.0.1:9445')
    p.add_argument('--client-listen', default='127.0.0.1:1081')
    p.add_argument('--udp-echo-listen', default='127.0.0.1:19090')
    p.add_argument('--server-config', default='anyreality/config/reality-server.toml')
    p.add_argument('--client-config', default='anyreality/config/reality-client.toml')
    args = p.parse_args()

    if args.build_with_cargo:
        print('Building anyreality with Cargo...')
        rc = subprocess.call(['cargo', 'build', '-p', 'anyreality'])
        if rc != 0:
            print('cargo build failed', file=sys.stderr)
            sys.exit(2)

    server_bin = find_binary('anyreality-server')
    client_bin = find_binary('anyreality-client')
    if not server_bin or not client_bin:
        print('Server or client binary not found in target/debug. Build first.', file=sys.stderr)
        sys.exit(3)

    server_proc = client_proc = None
    udp_stop = None
    udp_thread = None
    try:
        udp_host, udp_port = split_endpoint(args.udp_echo_listen)
        udp_stop, udp_thread = start_udp_echo_server(udp_host, udp_port)

        server_proc = subprocess.Popen([server_bin, '--config', args.server_config])
        time.sleep(0.5)
        server_host, server_port = split_endpoint(args.server_listen)
        if not wait_tcp(server_host, server_port, timeout=5.0):
            print(f'Server did not start listening on expected port {args.server_listen}', file=sys.stderr)
            return 4

        client_proc = subprocess.Popen([client_bin, '--config', args.client_config])
        time.sleep(0.5)
        client_host, client_port = split_endpoint(args.client_listen)
        if not wait_tcp(client_host, client_port, timeout=5.0):
            print(f'Client did not start listening on expected port {args.client_listen}', file=sys.stderr)
            return 5

        src_host, src_port, text = socks5_udp_echo(
            client_host, client_port,
            udp_host, udp_port,
            b'reality-uot-ok',
        )
        print(f"UDP echo: '{text}' from {src_host}:{src_port}")
        print('UDP ASSOCIATE end-to-end smoke test passed')
        if args.keep_running:
            print('Keep-running mode enabled; press Ctrl-C to stop...')
            while True:
                time.sleep(1)
        return 0
    finally:
        if udp_stop is not None:
            udp_stop.set()
        if udp_thread is not None:
            udp_thread.join(timeout=2)
        for proc in (client_proc, server_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
        for proc in (client_proc, server_proc):
            if proc is not None and proc.poll() is None:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

if __name__ == '__main__':
    raise SystemExit(main())
