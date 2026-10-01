#!/usr/bin/env python3
"""Guest-side attempts only; host nft counters/journal are authoritative evidence.

This file never accepts, stores or searches for the outside-guest synthetic secret.
"""
import errno
import hashlib
import http.client
import json
import os
import resource
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def dns_packet(name, qtype):
    labels = name.rstrip('.').split('.')
    return struct.pack('!HHHHHH', 0xAEC1, 0x0100, 1, 0, 0, 0) + b''.join(
        bytes([len(label)]) + label.encode('ascii') for label in labels
    ) + b'\0' + struct.pack('!HH', qtype, 1)


def main(c):
    kind = c['kind']
    if kind == 'peer':
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('0.0.0.0', 8080))
        listener.listen(16)
        while True:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(2)
                data = conn.recv(4096)
                conn.sendall(data)
    if kind == 'ipv6_setup':
        # Absolute paths: the guest agent execs with a fixed PATH of
        # /usr/local/bin:/usr/bin:/bin, and on this image `ip` lives under
        # /usr/sbin - so a bare `ip` is a FileNotFoundError, not a permission
        # problem, and would read as an enforcement failure.
        ip_binary = next(
            (p for p in ('/usr/sbin/ip', '/sbin/ip', '/usr/bin/ip', '/bin/ip')
             if os.path.exists(p)),
            None,
        )
        if ip_binary is None:
            return {'configured': False, 'reason': 'no ip binary on the guest'}
        commands = [
            [ip_binary, '-6', 'addr', 'replace', 'fd00:beef::2/64', 'dev', 'eth0', 'nodad'],
            [ip_binary, '-6', 'neigh', 'replace', 'fd00:beef::1', 'lladdr', c['mac'], 'nud', 'permanent', 'dev', 'eth0'],
            [ip_binary, '-6', 'route', 'replace', 'default', 'via', 'fd00:beef::1', 'dev', 'eth0'],
        ]
        results = []
        for command in commands:
            done = subprocess.run(command, capture_output=True, timeout=5)
            results.append({'cmd': ' '.join(command), 'rc': done.returncode,
                            'err': done.stderr.decode(errors='replace')[:120]})
            if done.returncode != 0:
                return {'configured': False, 'steps': results}
        return {'configured': True, 'steps': results}
    if kind == 'environment':
        base = os.environ.get('AIEC_AGENT_BASE_URL', '')
        placeholder = 'placeholder://model-main'
        return {
            'placeholder_aliases': all(os.environ.get(k) == placeholder for k in
                                      ('AIEC_AGENT_API_KEY', 'AIEC_MODEL_API_KEY', 'OPENAI_API_KEY')),
            'base_aliases': all(os.environ.get(k) == base for k in
                               ('AIEC_AGENT_BASE_URL', 'AIEC_MODEL_BASE_URL', 'OPENAI_BASE_URL')),
            'base_url': base,
            'resolver': open('/etc/resolv.conf', encoding='ascii').read(),
        }
    if kind == 'dns_system':
        samples = []
        addresses = set()
        for _ in range(c.get('samples', 10)):
            start = time.monotonic()
            addresses.update(row[4][0] for row in socket.getaddrinfo(c['name'], None, socket.AF_INET))
            samples.append((time.monotonic() - start) * 1000)
        return {'addresses': sorted(addresses), 'latency_ms': samples, 'samples': len(samples)}
    if kind == 'dns_wire':
        packet = dns_packet(c['name'], c['qtype'])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if c.get('tcp') else socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            if c.get('tcp'):
                sock.connect((c['host'], 53))
                sock.sendall(struct.pack('!H', len(packet)) + packet)
                size = sock.recv(2)
                if len(size) != 2:
                    raise RuntimeError('truncated DNS TCP length')
                reply = b''
                wanted = struct.unpack('!H', size)[0]
                while len(reply) < wanted:
                    chunk = sock.recv(wanted - len(reply))
                    if not chunk:
                        raise RuntimeError('truncated DNS TCP response')
                    reply += chunk
            else:
                sock.sendto(packet, (c['host'], 53))
                reply, _ = sock.recvfrom(4096)
            ident, flags, _, answers, _, _ = struct.unpack('!HHHHHH', reply[:12])
            return {'rcode': flags & 15, 'answers': answers, 'matching_id': ident == 0xAEC1}
    if kind in ('tcp', 'udp', 'placeholder_direct'):
        family = socket.AF_INET6 if ':' in c['host'] else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM if kind == 'udp' else socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            payload = b'guard-sentinel'
            if c.get('dns'):
                payload = dns_packet('unrelated.guard.test', 1)
                if kind == 'tcp':
                    payload = struct.pack('!H', len(payload)) + payload
            if kind == 'placeholder_direct':
                # Only the runtime-provided placeholder, never the real key.
                payload = ('POST /v1/chat/completions HTTP/1.1\r\nHost: unrelated.guard.test\r\nAuthorization: Bearer ' +
                           os.environ['AIEC_AGENT_API_KEY'] + '\r\nContent-Length: 0\r\n\r\n').encode('ascii')
            connected = False
            try:
                sock.connect((c['host'], c['port']))
                connected = kind != 'udp'
                sock.sendall(payload)
                data = sock.recv(4096)
                return {'reachable': True, 'response_bytes': len(data)}
            except OSError as error:
                # Route failures must not be accepted by the host driver; it
                # additionally requires a nonzero authoritative deny delta.
                return {'reachable': connected, 'errno': error.errno, 'timeout': isinstance(error, TimeoutError)}
    if kind == 'raw':
        payload = b'guard-raw-attempt'
        ident = 0xAEC1
        packet = struct.pack('!BBHHH', 8, 0, 0, ident, 1) + payload
        words = struct.unpack('!' + 'H' * (len(packet) // 2), packet)
        total = sum(words)
        total = (total & 0xffff) + (total >> 16)
        total = (total & 0xffff) + (total >> 16)
        packet = packet[:2] + struct.pack('!H', (~total) & 0xffff) + packet[4:]
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(1)
            sent = sock.sendto(packet, (c['host'], 0))
            try:
                response = sock.recv(4096)
                return {'reachable': True, 'sent_bytes': sent, 'response_bytes': len(response)}
            except TimeoutError:
                return {'reachable': False, 'sent_bytes': sent, 'timeout': True}
    if kind in ('broker', 'proxy_env'):
        parsed = urllib.parse.urlsplit(os.environ['AIEC_AGENT_BASE_URL'])
        path = c.get('path', parsed.path + '/chat/completions')
        key = c.get('placeholder', os.environ['AIEC_AGENT_API_KEY'])
        headers = {'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}
        if 'host_header' in c:
            headers['Host'] = c['host_header']
        start = time.monotonic()
        if kind == 'proxy_env':
            for name in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'ALL_PROXY', 'all_proxy'):
                os.environ[name] = 'http://' + c['proxy']
            os.environ['NO_PROXY'] = ''
            os.environ['no_proxy'] = ''
            try:
                request = urllib.request.Request(os.environ['AIEC_AGENT_BASE_URL'] + '/chat/completions',
                                                 data=b'{"stream":true}', headers=headers)
                with urllib.request.urlopen(request, timeout=1) as response:
                    return {'reachable': True, 'status': response.status}
            except (OSError, urllib.error.URLError) as error:
                reason = getattr(error, 'reason', error)
                route_error = isinstance(reason, OSError) and reason.errno in (
                    errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL)
                return {'reachable': False, 'error_type': type(error).__name__, 'route_error': route_error}
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=15)
        try:
            connection.request(c.get('method', 'POST'), path, b'{"stream":true}', headers)
            response = connection.getresponse()
            headers_ms = (time.monotonic() - start) * 1000
            count = 0
            first_ms = None
            tail = b''
            digest = hashlib.sha256()
            chunks = 0
            while True:
                data = response.read1(65536)
                if not data:
                    break
                if first_ms is None:
                    first_ms = (time.monotonic() - start) * 1000
                count += len(data)
                chunks += 1
                digest.update(data)
                tail = (tail + data)[-64:]
            return {'status': response.status, 'bytes': count, 'chunks': chunks,
                    'headers_ms': headers_ms, 'first_byte_ms': first_ms,
                    'duration_ms': (time.monotonic() - start) * 1000,
                    'sha256': digest.hexdigest(), 'done': b'data: [DONE]\n\n' in tail}
        finally:
            connection.close()
    raise RuntimeError('unknown guest probe kind')


if __name__ == '__main__':
    try:
        result = main(json.loads(sys.argv[1]))
        usage = resource.getrusage(resource.RUSAGE_SELF)
        result['guest_cpu_seconds'] = usage.ru_utime + usage.ru_stime
        result['guest_peak_rss_kib'] = usage.ru_maxrss
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        # Do not print exception values, env, headers, bodies, or credentials.
        print(json.dumps({'probe_error': type(error).__name__}))
        sys.exit(1)
