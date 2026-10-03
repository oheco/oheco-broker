#!/usr/bin/env python3
"""Explicit-target, bounded HTTPS/WSS and peer acceptance; never print credentials."""
import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import tarfile
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from public_options import https_origin, port_number, remote_path, service_unit, ssh_target, turn_address



def main():
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser()
    parser.add_argument('--admin-token-file', required=True, type=Path)
    parser.add_argument('--api', required=True, type=https_origin)
    parser.add_argument('--turn-address', required=True, type=turn_address)
    parser.add_argument('--ssh-target', required=True, type=ssh_target)
    parser.add_argument('--ssh-port', required=True, type=port_number)
    parser.add_argument('--remote-root', required=True, type=remote_path)
    parser.add_argument('--remote-peer', required=True, type=remote_path)
    parser.add_argument('--ca-file', required=True, type=Path)
    parser.add_argument('--remote-ca-file', required=True, type=remote_path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--service-unit', default='oheco-broker.service', type=service_unit)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--modes', nargs='+', choices=('never', 'force'), default=['never', 'force'])
    parser.add_argument('--tcp-only', action='store_true', help='Scope this smoke to TCP and actual relay accounting')
    args = parser.parse_args()
    os.umask(0o077)
    args.output = args.output.resolve()
    if args.output.exists():
        parser.error('--output must be a new evidence file')
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.ca_file = args.ca_file.resolve()
    api_origin = urlsplit(args.api)
    turn_endpoint = urlsplit('udp://' + args.turn_address)
    turn_socket = socket.getaddrinfo(turn_endpoint.hostname, turn_endpoint.port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    remote_user = args.ssh_target.rpartition('@')[0]
    q = shlex.quote
    admin = args.admin_token_file.read_text().strip()
    context = ssl.create_default_context(cafile=str(args.ca_file))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    record = {'api': args.api, 'turn_address': args.turn_address, 'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'modes': {},
              'requested_protocols': ['tcp'] if args.tcp_only else ['tcp', 'udp']}
    secrets_to_redact = [admin]

    def save():
        text = json.dumps(record, indent=2)
        assert not any(secret in text for secret in secrets_to_redact)
        args.output.write_text(text + '\n')

    def api(method, path, token='', body=None):
        data = None if body is None else json.dumps(body).encode()
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        attempts = 3 if method in ('GET', 'PATCH') else 1
        for attempt in range(attempts):
            req = urllib.request.Request(args.api + path, data=data, headers=headers, method=method)
            try:
                with opener.open(req, timeout=20) as response:
                    raw = response.read()
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError:
                raise
            except (urllib.error.URLError, http.client.RemoteDisconnected, OSError) as problem:
                if attempt+1 == attempts:
                    raise
                record.setdefault('idempotent_transport_retries', []).append(
                    {'method': method, 'path': path, 'attempt': attempt+1, 'error_type': type(problem).__name__})
                time.sleep(.25*(attempt+1))

    def ssh(command, check=True):
        return subprocess.run(['ssh', '-p', str(args.ssh_port), '-o', 'BatchMode=yes', args.ssh_target, command], capture_output=True, text=True, timeout=30, check=check)

    with socket.create_connection((api_origin.hostname, api_origin.port or 443), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=api_origin.hostname) as tls:
            cert = tls.getpeercert()
            record['tls'] = {'verified': True, 'version': tls.version(), 'issuer': cert['issuer'],
                             'subject': cert['subject'], 'serial': cert['serialNumber'],
                             'not_before': cert['notBefore'], 'not_after': cert['notAfter'],
                             'certificate_sha256': hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()}
    transaction = secrets.token_bytes(12)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        # Retransmit the same Binding transaction on the same socket, as STUN
        # clients do over UDP; record the attempts instead of assuming no loss.
        for stun_attempt in range(1, 6):
            udp.settimeout(2)
            udp.sendto(struct.pack('!HHI', 1, 0, 0x2112a442) + transaction, turn_socket)
            try:
                response, source = udp.recvfrom(2048)
                if source == turn_socket and response[8:20] == transaction:
                    break
            except TimeoutError:
                continue
        else:
            raise RuntimeError('public STUN Binding failed after five bounded attempts')
    kind, length, cookie = struct.unpack('!HHI', response[:8])
    assert kind == 0x0101 and response[8:20] == transaction and cookie == 0x2112a442
    mapped = None
    offset = 20
    while offset + 4 <= len(response):
        atype, alen = struct.unpack('!HH', response[offset:offset+4])
        value = response[offset+4:offset+4+alen]
        if atype == 0x20 and len(value) == 8 and value[1] == 1:
            port = struct.unpack('!H', value[2:4])[0] ^ (cookie >> 16)
            address = socket.inet_ntoa(bytes(a ^ b for a, b in zip(value[4:8], struct.pack('!I', cookie))))
            mapped = {'ip': address, 'port': port}
        offset += 4 + ((alen + 3) & ~3)
    assert mapped
    record['stun'] = {'server': list(source), 'mapped': mapped, 'verified': True, 'attempts': stun_attempt}
    settings = api('GET', '/v1/admin/settings', admin)
    assert settings['registration_policy'] == 'approval' and settings['registration_relay_enabled'] is False
    record['registration_policy'] = settings['registration_policy']
    record['registration_relay_enabled'] = settings['registration_relay_enabled']
    suffix = secrets.token_hex(8)
    runtime = args.remote_root + '/runtime-' + suffix
    unit = 'oheco-broker-acceptance-' + suffix + '.service'
    password = secrets.token_hex(32)
    account_password = secrets.token_hex(32)
    secrets_to_redact.extend([password, account_password])
    tenant_id = broker_id = None
    token = None
    unit_started = runtime_created = False
    try:
        registered = api('POST', '/v1/tenants/register', body={'name': 'acceptance-' + suffix, 'password': account_password})
        tenant_id = registered['tenant']['id']
        token = registered['token']
        secrets_to_redact.append(token)
        assert registered['tenant']['status'] == 'pending' and registered['tenant']['relay_enabled'] is False
        pending = api('GET', '/v1/capabilities', token)
        assert pending['status'] == 'pending' and pending['relay_enabled'] is False
        try:
            api('POST', '/v1/brokers', token, {'name': 'denied-before-approval'})
        except urllib.error.HTTPError as denied:
            assert denied.code == 403
            record['pending_broker_operation_denied'] = 403
        else:
            raise RuntimeError('pending account unexpectedly allowed broker registration')
        api('POST', '/v1/admin/tenants/' + tenant_id + '/approve', admin)
        approved = api('GET', '/v1/capabilities', token)
        assert approved['status'] == 'active' and approved['relay_enabled'] is False
        api('POST', '/v1/admin/tenants/' + tenant_id + '/relay', admin, {'enabled': True})
        record['registration_flow'] = {'initial_status': 'pending', 'initial_relay_enabled': False,
                                       'approved_status': 'active', 'relay_after_approval': False,
                                       'admin_relay_enable_performed': True}
        capabilities = api('GET', '/v1/capabilities', token)
        assert capabilities['status'] == 'active' and capabilities['relay_enabled'] is True and capabilities['turn_available'] is True
        assert capabilities['signaling'] == 'ob-signaling-v1'
        assert capabilities['stun_address'] == args.turn_address
        record['capabilities'] = capabilities
        with tempfile.TemporaryDirectory(prefix='production-acceptance-', dir=os.environ['TMPDIR']) as temp:
            directory = Path(temp)
            profile = directory / 'account.json'
            profile.write_text(json.dumps({'version': 1, 'api': args.api, 'ca_file': str(args.ca_file),
                                          'account': {'id': tenant_id, 'name': registered['tenant']['name'],
                                                      'password': account_password, 'token': token}}))
            profile.chmod(0o600)
            password_file = directory / 'peer.password'
            password_file.write_text(password + '\n'); password_file.chmod(0o600)
            token_file = directory / 'tenant.token'
            token_file.write_text(token + '\n'); token_file.chmod(0o600)
            ssh('set -eu; umask 077; mkdir -p ' + q(args.remote_root) + '; mkdir ' + q(runtime) + '; mkdir ' + q(runtime + '/tmp'))
            runtime_created = True
            # Transfer only test-owned credential files over the selected SSH link.
            # Shell arguments are quoted independently; no SCP path interpretation.
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w') as tar:
                tar.add(password_file, arcname='peer.password')
                tar.add(token_file, arcname='tenant.token')
            subprocess.run(['ssh', '-p', str(args.ssh_port), '-o', 'BatchMode=yes', args.ssh_target,
                            'umask 077; tar -xf - -C ' + q(runtime)], input=archive.getvalue(),
                           check=True, capture_output=True, timeout=30)
            command = shlex.join(['sudo', '-n', 'systemd-run', '--collect', '--unit=' + unit,
                '--property=User=' + remote_user, '--property=RuntimeMaxSec=20min',
                '--property=TimeoutStopSec=30s', '--property=KillMode=control-group',
                '--setenv=TMPDIR=' + runtime + '/tmp', args.remote_peer, 'serve', '--api', args.api,
                '--ca-file', args.remote_ca_file, '--tenant-token-file', runtime + '/tenant.token',
                '--peer-password-file', runtime + '/peer.password', '--broker', 'production-acceptance-' + suffix])
            ssh(command)
            unit_started = True
            deadline = time.monotonic() + 75
            while time.monotonic() < deadline:
                brokers = api('GET', '/v1/brokers', token)
                for broker in brokers['brokers']:
                    if broker['name'] == 'production-acceptance-' + suffix and broker['online']:
                        broker_id = broker['id']
                        break
                if broker_id:
                    break
                state = ssh('systemctl is-active ' + q(unit), check=False)
                if state.stdout.strip() not in ('active', 'activating'):
                    raise RuntimeError('acceptance peer exited before registration')
                time.sleep(.25)
            assert broker_id, 'native peer readiness timed out'
            record['broker_id'] = broker_id
            driver = Path(__file__).with_name('public_cross_network.py')
            artifacts = args.output.parent / ('cross-' + suffix)
            artifacts.mkdir(mode=0o700)
            for mode in args.modes:
                evidence = artifacts / ('cross-' + mode + '.json')
                process = subprocess.Popen(['python3', str(driver), '--api', args.api, '--turn-address', args.turn_address,
                                             '--binary', str(args.binary.resolve()), '--output', str(evidence),
                                             '--profile', str(profile), '--peer-password-file', str(password_file),
                                            '--broker-id', broker_id, '--relay', mode, '--tcp-timeout', '90', '--udp-timeout', '10'] + (['--tcp-only'] if args.tcp_only else []),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    stdout, stderr = process.communicate(timeout=540)
                except BaseException:
                    process.terminate()
                    try:
                        process.communicate(timeout=60)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.communicate(timeout=10)
                    raise
                result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
                assert not any(secret in result.stdout + result.stderr for secret in secrets_to_redact)
                print(result.stdout, end='', flush=True)
                matching = [json.loads(evidence.read_text())] if evidence.is_file() else []
                matching = [value for value in matching if value['broker_id'] == broker_id]
                if len(matching) == 1:
                    record['modes'][mode] = matching[0]
                    save()
                if result.returncode:
                    raise RuntimeError('native public acceptance failed: ' + mode + ' ' + result.stderr)
                assert len(matching) == 1
            record['functional_pass'] = True
    except BaseException as problem:
        record['functional_pass'] = False
        record['error_type'] = type(problem).__name__
        raise
    finally:
        cleanup = {}
        cleanup_errors = []
        def attempt(name, operation):
            try:
                operation()
                cleanup[name] = True
            except Exception as problem:
                cleanup[name] = False
                cleanup_errors.append({'step': name, 'error_type': type(problem).__name__})
        if unit_started:
            def stop_peer():
                ssh('sudo -n systemctl stop ' + q(unit), check=False)
                state = ssh('systemctl is-active ' + q(unit), check=False).stdout.strip()
                assert state not in ('active', 'activating', 'deactivating')
            attempt('peer_stopped', stop_peer)
        if broker_id and token:
            attempt('broker_deleted', lambda: api('DELETE', '/v1/brokers/' + broker_id, token))
        if tenant_id:
            attempt('acceptance_tenant_disabled', lambda: api('POST', '/v1/admin/tenants/' + tenant_id + '/disable', admin))
            attempt('acceptance_relay_disabled', lambda: api('PATCH', '/v1/admin/tenants/' + tenant_id, admin, {'relay_enabled': False}))
        if runtime_created:
            attempt('ephemeral_remote_credentials_removed', lambda: ssh('rm -rf -- ' + q(runtime)))
        record['cleanup'] = cleanup
        record['cleanup_errors'] = cleanup_errors
        def check_service():
            record['service_active'] = ssh('systemctl is-active ' + q(args.service_unit)).stdout.strip() == 'active'
            assert record['service_active']
            current = api('GET', '/v1/admin/settings', admin)
            assert current['registration_policy'] == 'approval' and current['registration_relay_enabled'] is False
        attempt('production_service_unchanged', check_service)
        save()
        if cleanup_errors:
            raise RuntimeError('acceptance cleanup failed; see redacted evidence')
    print('PASS explicit-target HTTPS/WSS, administrator approval/relay gates and ' + '/'.join(args.modes) + ' ' + '/'.join(record['requested_protocols']) + ' payloads', flush=True)


if __name__ == '__main__':
    main()
