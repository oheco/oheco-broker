#!/usr/bin/env python3
"""SSH ProxyCommand via explicit unauthenticated SOCKS5; never fall back direct."""
import os
import selectors
import socket
import struct
import sys


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise OSError('SOCKS proxy closed handshake')
        result.extend(part)
    return bytes(result)


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: socks-proxy-command.py target-host target-port')
    host, port = sys.argv[1], int(sys.argv[2])
    encoded = host.encode('idna')
    if not 1 <= len(encoded) <= 255 or not 1 <= port <= 65535:
        raise SystemExit('invalid SOCKS target')
    sock = socket.create_connection(('127.0.0.1', 10808), timeout=10)
    sock.sendall(b'\x05\x01\x00')
    if exact(sock, 2) != b'\x05\x00':
        raise OSError('SOCKS proxy does not permit unauthenticated connection')
    sock.sendall(b'\x05\x01\x00\x03' + bytes([len(encoded)]) + encoded + struct.pack('!H', port))
    reply = exact(sock, 4)
    if reply[0] != 5 or reply[1] != 0:
        raise OSError('SOCKS connection rejected, reply=' + str(reply[1]))
    address_length = {1: 4, 4: 16}.get(reply[3])
    if reply[3] == 3:
        address_length = exact(sock, 1)[0]
    if address_length is None:
        raise OSError('SOCKS response address invalid')
    exact(sock, address_length + 2)
    sock.setblocking(False)
    os.set_blocking(0, False)
    os.set_blocking(1, False)
    pending_out, pending_socket = bytearray(), bytearray()
    input_open, socket_open = True, True
    with selectors.DefaultSelector() as selector:
        while socket_open or pending_out:
            # Refresh readiness; bound buffering and propagate backpressure.
            for key in list(selector.get_map().values()):
                selector.unregister(key.fileobj)
            if input_open and len(pending_socket) < 1024 * 1024:
                selector.register(0, selectors.EVENT_READ, 'stdin')
            events = (selectors.EVENT_READ if socket_open and len(pending_out) < 1024 * 1024 else 0)
            if pending_socket:
                events |= selectors.EVENT_WRITE
            if events:
                selector.register(sock, events, 'socket')
            if pending_out:
                selector.register(1, selectors.EVENT_WRITE, 'stdout')
            for key, mask in selector.select():
                if key.data == 'stdin':
                    data = os.read(0, 65536)
                    if data:
                        pending_socket.extend(data)
                    else:
                        input_open = False
                        if not pending_socket:
                            sock.shutdown(socket.SHUT_WR)
                elif key.data == 'stdout':
                    count = os.write(1, pending_out)
                    del pending_out[:count]
                else:
                    if mask & selectors.EVENT_READ:
                        data = sock.recv(65536)
                        if data:
                            pending_out.extend(data)
                        else:
                            socket_open = False
                            input_open = False
                    if mask & selectors.EVENT_WRITE and pending_socket:
                        count = sock.send(pending_socket)
                        del pending_socket[:count]
                        if not input_open and not pending_socket:
                            sock.shutdown(socket.SHUT_WR)
    sock.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        print('SSH SOCKS proxy failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
