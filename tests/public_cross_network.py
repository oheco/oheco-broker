#!/usr/bin/env python3
"""Bounded client-to-independent-peer acceptance against explicit public targets."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time
from public_options import https_origin, turn_address


def terminate(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser()
    parser.add_argument('--api', required=True, type=https_origin)
    parser.add_argument('--turn-address', required=True, type=turn_address)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--peer-password-file', required=True, type=Path)
    parser.add_argument('--broker-id', required=True)
    parser.add_argument('--relay', choices=('never', 'force'), required=True)
    parser.add_argument('--tcp-timeout', type=int, default=20, help='Bounded WAN transfer deadline in seconds (1..120)')
    parser.add_argument('--udp-timeout', type=int, default=3, help='Per-packet receive deadline in seconds (1..15)')
    parser.add_argument('--tcp-only', action='store_true', help='Run scoped TCP and relay-accounting smoke; omit UDP payload trials')
    args = parser.parse_args()
    if not 1 <= args.tcp_timeout <= 120:
        parser.error('--tcp-timeout must be within 1..120')
    if not 1 <= args.udp_timeout <= 15:
        parser.error('--udp-timeout must be within 1..15')
    os.umask(0o077)
    binary = args.binary.resolve()
    profile = args.profile.resolve()
    unchanged = profile.read_bytes()
    if json.loads(unchanged).get('api') != args.api:
        parser.error('profile API must match the explicitly selected --api')
    peer_password = args.peer_password_file.read_bytes().strip()
    record = {'peer_topology': 'local client to explicitly selected independent peer',
              'api': args.api, 'turn_address': args.turn_address,
              'relay_mode': args.relay, 'broker_id': args.broker_id,
              'cli_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'tcp': {}, 'udp': {},
              'created_processes': [], 'profile_unchanged': False,
              'requested_protocols': ['tcp'] if args.tcp_only else ['tcp', 'udp']}
    result_file = args.output.resolve()
    result_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if result_file.exists():
        parser.error('--output must be a new evidence file')
    def cli(parts):
        result = subprocess.run([str(binary), '--api', args.api, '--config', str(profile)] + parts,
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError('control operation failed: ' + result.stderr)
        return json.loads(result.stdout)
    def save():
        data = json.dumps(record, indent=2)
        if peer_password.decode() in data:
            raise RuntimeError('credential redaction assertion failed')
        result_file.write_text(data + '\n')
        result_file.chmod(0o600)
    capabilities = cli(['tenant', 'capabilities'])
    if capabilities.get('turn_address') != args.turn_address:
        raise RuntimeError('selected server advertised a different TURN address')
    before = cli(['tenant', 'usage', '--broker', args.broker_id])
    record['usage_before'] = before
    error = None
    with tempfile.TemporaryDirectory(prefix='public-cross-', dir=os.environ['TMPDIR']) as directory:
        root = Path(directory)
        processes, outputs = [], []
        def start(protocol, target_port):
            path = root / (protocol + '.log')
            output = path.open('wb')
            outputs.append(output)
            command = [str(binary), '--api', args.api, '--config', str(profile), 'tenant', 'connect',
                       '--broker-id', args.broker_id, '--password-stdin', '--protocol', protocol,
                       '--target', '127.0.0.1:' + str(target_port), '--local', '0', '--relay', args.relay]
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output, stderr=output,
                                       cwd=root, start_new_session=True)
            processes.append(process)
            process.stdin.write(peer_password + b'\n')
            process.stdin.close()
            end = time.monotonic() + 45
            while time.monotonic() < end:
                if process.poll() is not None:
                    text = path.read_text().replace(peer_password.decode(), '[redacted]')
                    raise RuntimeError(protocol + ' peer setup failed: ' + text)
                for line in path.read_text().splitlines():
                    try:
                        value = json.loads(line)
                    except ValueError:
                        continue
                    if value.get('event') == 'mapping_ready':
                        record['created_processes'].append({'protocol': protocol, 'local': value['local']})
                        return value['local']
                time.sleep(.03)
            raise RuntimeError(protocol + ' mapping readiness timeout')
        try:
            record['stage'] = 'peer_setup_tcp'
            tcp_address = start('tcp', 41081)
            host, port = tcp_address.rsplit(':', 1)
            payload = bytes(range(256)) * 2048
            with socket.create_connection((host, int(port)), timeout=10) as client:
                client.settimeout(args.tcp_timeout)
                received = bytearray()
                failures = []
                def consume():
                    try:
                        while True:
                            data = client.recv(32768)
                            if not data:
                                return
                            received.extend(data)
                    except Exception as problem:
                        failures.append(str(problem))
                reader = threading.Thread(target=consume)
                reader.start()
                started = time.monotonic()
                record['stage'] = 'tcp_payload_and_fin'
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                reader.join(timeout=args.tcp_timeout+5)
                if reader.is_alive():
                    client.close()
                    reader.join(timeout=3)
                record['tcp_probe'] = {'expected_bytes': len(payload), 'received_bytes': len(received),
                                       'read_errors': failures, 'reader_joined': not reader.is_alive(),
                                       'deadline_seconds': args.tcp_timeout,
                                       'elapsed_ms': round((time.monotonic()-started)*1000, 3)}
                if reader.is_alive() or failures or bytes(received) != payload:
                    raise RuntimeError('cross-network TCP bytes/FIN did not match')
                record['tcp'] = {'bytes_each_direction': len(payload), 'fin_pass': True,
                                 'elapsed_ms': round((time.monotonic()-started)*1000, 3)}
            print('PASS cross-network TCP relay=' + args.relay, flush=True)
            address = None
            if not args.tcp_only:
                record['stage'] = 'peer_setup_udp'
                udp_address = start('udp', 41082)
                host, port = udp_address.rsplit(':', 1)
                address = (host, int(port))
                time.sleep(1)
            def exchange(client, data):
                client.sendto(data, address)
                deadline = time.monotonic()+args.udp_timeout
                unmatched = 0
                while time.monotonic() < deadline:
                    client.settimeout(max(.001, deadline-time.monotonic()))
                    try:
                        answer, source = client.recvfrom(65535)
                    except socket.timeout:
                        return False, unmatched
                    if source == address and answer == data:
                        return True, unmatched
                    # Ignore a previous nonempty trial's late echo while waiting.
                    unmatched += 1
                return False, unmatched
            for size in (() if args.tcp_only else (0, 513, 16384, 65507)):
                outcomes, warmups = [], []
                with ExitStack() as sockets:
                    shared = None
                    for trial in range(5):
                        if shared is None or size == 0:
                            client = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                            # Keep zero-length trials' sockets open until this size
                            # finishes. Distinct source flows prevent a late empty
                            # echo being credited to a later empty request.
                            warmed, ignored = exchange(client, secrets.token_bytes(513))
                            warmups.append({'received': warmed, 'unmatched_packets_ignored': ignored})
                            shared = client
                            time.sleep(.5)
                        client = shared
                        data = secrets.token_bytes(size)
                        started = time.monotonic()
                        received_ok, ignored = exchange(client, data)
                        outcomes.append({'received': received_ok,
                                         'unmatched_packets_ignored': ignored,
                                         'elapsed_ms': round((time.monotonic()-started)*1000,3)})
                        time.sleep(.5)
                record['udp'][str(size)] = {'warmup_received': all(x['received'] for x in warmups),
                                            'warmups': warmups,
                                            'independent_source_per_trial': size == 0,
                                            'receive_deadline_seconds': args.udp_timeout,
                                           'received': sum(x['received'] for x in outcomes),
                                           'sent': len(outcomes), 'trials': outcomes}
                save()
                print('UDP cross-network bytes=' + str(size) + ' delivered=' +
                      str(record['udp'][str(size)]['received']) + '/5 relay=' + args.relay, flush=True)
            if not args.tcp_only and any(record['udp'][str(size)]['received'] < 1 for size in (0,513,16384)):
                raise RuntimeError('small cross-network UDP traffic not established')
            record['stage'] = 'completed'
            record['functional_pass'] = True
            record['udp_delivery_not_guaranteed'] = True
        except BaseException as problem:
            record['functional_pass'] = False
            record['error'] = str(problem).replace(peer_password.decode(), '[redacted]')
            error = problem
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                record.setdefault('process_exit_codes', []).append(process.returncode)
            for output in outputs:
                output.close()
            record['profile_unchanged'] = profile.read_bytes() == unchanged
            try:
                after = cli(['tenant', 'usage', '--broker', args.broker_id])
                record['usage_after'] = after
                record['forwarded_bytes_delta'] = after['lifetime'] - before['lifetime']
                if args.relay == 'never' and record['forwarded_bytes_delta'] != 0:
                    record['functional_pass'] = False
                    record['error'] = 'NEVER path unexpectedly consumed relay bytes'
                if args.relay == 'force' and record['functional_pass'] and record['forwarded_bytes_delta'] <= 0:
                    record['functional_pass'] = False
                    record['error'] = 'FORCE path omitted actual relay usage'
            except Exception as problem:
                record['usage_error'] = str(problem)
            save()
    print('Evidence: ' + str(result_file), flush=True)
    if not record['functional_pass']:
        raise SystemExit(1)
    print('PASS independent Linux peer/public control cross-network relay=' + args.relay, flush=True)

if __name__ == '__main__':
    main()
