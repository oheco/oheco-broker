"""Shared explicit-target argument validation for opt-in public acceptance."""
import argparse
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit


def https_origin(value):
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as error:
        raise argparse.ArgumentTypeError('invalid HTTPS origin') from error
    if (url.scheme != 'https' or not url.hostname or url.username is not None or
            url.password is not None or url.path not in ('', '/') or url.query or url.fragment or
            any(ord(c) <= 32 for c in value) or (port is not None and not 1 <= port <= 65535)):
        raise argparse.ArgumentTypeError('use an HTTPS origin without credentials, path, query, or fragment')
    return value.rstrip('/')


def port_number(value):
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('port must be an integer from 1 to 65535') from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError('port must be from 1 to 65535')
    return port


def turn_address(value):
    try:
        url = urlsplit('udp://' + value)
        port = url.port
    except ValueError as error:
        raise argparse.ArgumentTypeError('TURN address must be host:port') from error
    if (not url.hostname or port is None or not 1 <= port <= 65535 or url.username is not None or
            url.password is not None or url.path or url.query or url.fragment or
            any(ord(c) <= 32 for c in value)):
        raise argparse.ArgumentTypeError('TURN address must be host:port (bracket an IPv6 address)')
    return value


def remote_path(value):
    path = PurePosixPath(value)
    if not path.is_absolute() or path == PurePosixPath('/') or '..' in path.parts or '\n' in value or '\r' in value:
        raise argparse.ArgumentTypeError('remote path must be absolute, non-root, and contain no traversal')
    return str(path)


def ssh_target(value):
    # A named non-root account is also the transient peer unit's service user.
    user, separator, host = value.rpartition('@')
    if (not separator or user == 'root' or not re.fullmatch(r'[a-z_][a-z0-9_-]*', user) or
            not host or host.startswith('-') or any(ord(c) <= 32 for c in host) or '@' in host):
        raise argparse.ArgumentTypeError('SSH target must be non-root-user@host')
    return value


def service_unit(value):
    if not re.fullmatch(r'[A-Za-z0-9_.@-]+[.]service', value) or value.startswith('-'):
        raise argparse.ArgumentTypeError('service unit must be a .service unit name')
    return value
