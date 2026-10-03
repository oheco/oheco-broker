#!/usr/bin/env python3
"""Offline SDK source audit; optionally include the repository's Go manifest."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent


def sdk_source(value):
    # Manifests retain repository-relative provenance paths. Stripping this
    # fixed prefix also resolves them after extracting only sdk/c elsewhere.
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts:
        raise SystemExit('Invalid manifest source path')
    if path.parts[:2] == ('sdk', 'c'):
        path = path.relative_to('sdk/c')
    if not path.parts or path.parts[0] != 'tpr':
        raise SystemExit('Native manifest source must be under SDK tpr/')
    return ROOT / path


def source_files(source):
    if not source.is_dir() or source.is_symlink():
        raise SystemExit('Missing or linked dependency directory: ' + str(source))
    paths = list(source.rglob('*'))
    if any(p.is_symlink() for p in paths):
        raise SystemExit('Dependency source symlinks are not permitted')
    return {p.relative_to(source).as_posix(): p for p in paths if p.is_file()}


def audit_files(name):
    manifest = json.loads((ROOT / 'tpr/manifests' / (name + '-files.json')).read_text())
    actual = source_files(sdk_source(manifest['source_directory']))
    expected = manifest['upstream_files_sha256']
    allowed = set(manifest['allowed_modifications'])
    if set(actual) != set(expected):
        raise SystemExit(f'{name}: missing/extra source paths: {sorted(set(actual) ^ set(expected))}')
    changed = set()
    for path, digest in expected.items():
        value = hashlib.sha256(actual[path].read_bytes()).hexdigest()
        if value != digest:
            changed.add(path)
            if path not in allowed or value != manifest['local_modified_sha256'].get(path):
                raise SystemExit(f'{name}: unrecorded source modification: {path}')
    if changed != allowed:
        raise SystemExit(f'{name}: recorded policy edits absent or changed: {sorted(changed ^ allowed)}')
    print(f'PASS {name}: {len(actual)} upstream paths, {len(changed)} declared modified files')


def audit_curl():
    manifest = json.loads((ROOT / 'tpr/manifests/curl.json').read_text())
    actual = source_files(sdk_source(manifest['source_directory']))
    h = hashlib.sha256()
    for relative, path in sorted(actual.items()):
        h.update((hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + relative + '\n').encode())
    if len(actual) != manifest['source_files'] or h.hexdigest() != manifest['source_tree_sha256']:
        raise SystemExit('curl: source tree differs from recorded exact official archive')
    if manifest['local_modifications']:
        raise SystemExit('curl: source modifications are not permitted')
    print(f'PASS curl: {len(actual)} exact upstream paths, zero modifications')


def audit_go_websocket(repository):
    manifest = json.loads((repository / 'vendor-manifests/gorilla-websocket.json').read_text())
    actual = source_files(repository / manifest['source_directory'])
    expected = manifest['files_sha256']
    if manifest['modifications'] or set(actual) != set(expected):
        raise SystemExit('Gorilla WebSocket: altered/missing/extra complete-source paths')
    for path, digest in expected.items():
        if hashlib.sha256(actual[path].read_bytes()).hexdigest() != digest:
            raise SystemExit('Gorilla WebSocket: upstream source differs: ' + path)
    print(f'PASS Gorilla WebSocket: {len(actual)} pinned upstream paths, zero modifications')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-go', action='store_true', help='Also audit the full repository Go input')
    parser.add_argument('--repository-root', type=Path, help='Repository containing vendor-manifests and vendor')
    parser.add_argument('--curl-only', action='store_true', help='Audit curl before its separate build')
    args = parser.parse_args()
    if args.curl_only and args.include_go:
        parser.error('--curl-only and --include-go are mutually exclusive')
    if not args.curl_only:
        for dependency in ('xquic', 'boringssl', 'cjson', 'libjuice'):
            audit_files(dependency)
    audit_curl()
    if args.include_go:
        repository = args.repository_root or ROOT.parents[1]
        if not (repository / 'vendor-manifests/gorilla-websocket.json').is_file():
            parser.error('--include-go requires the full repository or --repository-root')
        audit_go_websocket(repository)


if __name__ == '__main__':
    main()
