#!/usr/bin/env python3
"""Scan public source and reachable Git history without printing matched values."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from export_public import Scanner

MAX_BLOB = 32 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
ROLE_MAIL = {b'maintainers' + b'@' + b'users.noreply.github.com', b'noreply' + b'@' + b'github.com',
             b'googlebook-pad3' + b'@' + b'users.noreply.github.com', b'maintainers' + b'@' + b'googlebook-pad3.invalid',
             b'41898282+github-actions[bot]' + b'@' + b'users.noreply.github.com'}
EMAIL = rb'[A-Za-z0-9_.+%\[\]-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
URL_TEST = b'https://owner:' + b'token' + b'@' + b'github.com/ota'
URL_CREDENTIALS = re.compile(rb'https?://[^/\s:@]+:[^/\s@]+@')


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)


def check(data, path, scanner, *, metadata=False, oid=None):
    findings = scanner.scan(data, path)
    if metadata and b'\0' not in data:
        lines = data.splitlines()
        def role_address(f):
            if not 0 < f['line'] <= len(lines):
                return False
            addresses = set(re.findall(EMAIL, lines[f['line']-1]))
            return bool(addresses) and addresses <= ROLE_MAIL
        findings = [f for f in findings if f['classification'] != 'email' or not role_address(f)]
    # This exact historical negative-test fixture contains no real credential.
    url_data = data.replace(URL_TEST, b'') if path == 'components/updater/tests/UpdateCoreTest.java' else data
    if URL_CREDENTIALS.search(url_data):
        findings.append({'path':path,'classification':'url_credentials','line':1})
    if scanner.scan(path.encode(), 'name') or URL_CREDENTIALS.search(path.encode()):
        findings = [dict(f, path='<redacted-sensitive-name>') for f in findings]
        findings.append({'path':'<redacted-sensitive-name>','classification':'sensitive_filename','line':1})
    if oid:
        findings = [dict(f, object=oid) for f in findings]
    return findings


def audit(repo, scanner, history=False):
    repo = Path(repo).resolve(strict=True)
    if git(repo, 'rev-parse', '--is-inside-work-tree').strip() != b'true':
        raise ValueError('not a source checkout')
    findings, checked, total = [], 0, 0
    names = git(repo, 'ls-files', '-c', '-o', '--exclude-standard', '-z').split(b'\0')
    for raw in sorted(set(n for n in names if n)):
        name = raw.decode('utf-8', 'strict')
        path = repo / name
        if path.is_symlink():
            data = str(path.readlink()).encode()
        else:
            if not path.is_file() or path.stat().st_size > MAX_BLOB:
                raise ValueError('file exceeds audit bounds')
            data = path.read_bytes()
        total += len(data)
        if total > MAX_TOTAL:
            raise ValueError('audit exceeds total bound')
        findings.extend(check(data, name, scanner))
        checked += 1
    blobs = commits = tags = trees = 0
    if history:
        if git(repo, 'rev-parse', '--is-shallow-repository').strip() == b'true':
            raise ValueError('history scan requires a complete checkout')
        rows = git(repo, 'rev-list', '--objects', '--all').splitlines()
        if len(rows) > 100000:
            raise ValueError('history exceeds object bound')
        seen, seen_names = set(), set()
        for row in rows:
            parts = row.split(b' ', 1)
            oid = parts[0].decode()
            if oid in seen or not re.fullmatch('[0-9a-f]{40,64}', oid):
                continue
            seen.add(oid)
            kind = git(repo, 'cat-file', '-t', oid).strip()
            if kind == b'tree':
                names = git(repo, 'ls-tree', '-r', '-z', '--name-only', oid)
                total += len(names)
                if len(names) > MAX_BLOB or total > MAX_TOTAL:
                    raise ValueError('historical names exceed byte bound')
                for raw_name in names.split(b'\0'):
                    if raw_name and raw_name not in seen_names:
                        seen_names.add(raw_name)
                        if len(seen_names) > 100000:
                            raise ValueError('historical names exceed count bound')
                        findings.extend(check(b'', raw_name.decode('utf-8', 'strict'), scanner, oid=oid))
                trees += 1
                continue
            if kind not in (b'blob', b'commit', b'tag'):
                continue
            size = int(git(repo, 'cat-file', '-s', oid))
            total += size
            if size > MAX_BLOB or total > MAX_TOTAL:
                raise ValueError('history exceeds byte bound')
            data = git(repo, 'cat-file', kind.decode(), oid)
            path = parts[1].decode('utf-8', 'strict') if len(parts) == 2 else 'git-' + kind.decode()
            findings.extend(check(data, path, scanner, metadata=kind != b'blob', oid=oid))
            blobs += kind == b'blob'
            commits += kind == b'commit'
            tags += kind == b'tag'
        for raw in git(repo, 'for-each-ref', '--format=%(refname)').splitlines():
            findings.extend(check(raw, 'git-reference', scanner, metadata=True))
        findings.extend(check(git(repo, 'remote', '-v'), 'git-remotes', scanner, metadata=True))
    return {'schema':1, 'status':'blocked' if findings else 'passed', 'findings':findings,
            'working_files':checked, 'history_requested':history,
            'history_blobs':blobs, 'history_commits':commits, 'history_tags':tags, 'history_trees':trees,
            'known_private_patterns':len(scanner.patterns),
            'limits':['Heuristics and supplied exact patterns cannot prove absence of unknown or encoded private data.',
                      'Release binaries, GitHub issues, logs and assets require a separate publication audit.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path('.'))
    parser.add_argument('--history', action='store_true')
    parser.add_argument('--secret-file', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        scanner = Scanner()
        for path in args.secret_file:
            scanner.load_secrets(path)
        result = audit(args.repo, scanner, args.history)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
        print(json.dumps({k:result[k] for k in ['status','working_files','history_blobs','history_commits']}))
        return bool(result['findings'])
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        print('{"status":"blocked","reason":"audit incomplete; private diagnostics withheld"}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
