#!/usr/bin/env python3
"""Reconstruct locked source outside this component; never overwrite edited source."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import urllib.request

COMPONENT = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(work, archive=None):
    lock = json.loads((COMPONENT / 'source-lock.json').read_text())
    work = Path(work).resolve()
    if work == COMPONENT or COMPONENT in work.parents:
        raise ValueError('Use a separate local disposable workspace')
    work.mkdir(parents=True, exist_ok=True)
    if digest(COMPONENT / 'photos-strict.patch') != lock['patch']['sha256']:
        raise ValueError('Patch SHA-256 mismatch')
    archive = Path(archive).resolve() if archive else work / 'upstream.tar.gz'
    if not archive.exists():
        with urllib.request.urlopen(lock['archive']['url'], timeout=30) as response:
            data = response.read(lock['archive']['bytes'] + 1)
        if len(data) != lock['archive']['bytes']:
            raise ValueError('Upstream archive size mismatch')
        archive.write_bytes(data)
    if archive.stat().st_size != lock['archive']['bytes'] or digest(archive) != lock['archive']['sha256']:
        raise ValueError('Upstream archive SHA-256/size mismatch')
    source = work / 'source'
    if not source.exists():
        source.mkdir()
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            roots = {PurePosixPath(m.name).parts[0] for m in members}
            if len(roots) != 1 or sum(m.size for m in members) > 128 * 1024 * 1024:
                raise ValueError('Unexpected archive layout/size')
            for member in members:
                parts = PurePosixPath(member.name).parts
                if member.name.startswith('/') or '..' in parts or not (member.isdir() or member.isfile()):
                    raise ValueError('Unsafe archive member')
                if len(parts) == 1:
                    continue
                target = source.joinpath(*parts[1:])
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as original, target.open('xb') as output:
                        shutil.copyfileobj(original, output)
                    target.chmod(member.mode & 0o777)
        for check in [True, False]:
            args = ['git', 'apply'] + (['--check'] if check else []) + [str(COMPONENT / 'photos-strict.patch')]
            subprocess.run(args, cwd=source, check=True)
    for name, expected in {**lock['patch']['changed_files_sha256'], **lock['licenses_sha256']}.items():
        if digest(source / name) != expected:
            raise ValueError(f'Locked source differs: {name}; preserve edits and use a fresh workspace')
    return source


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('workspace', type=Path)
    parser.add_argument('--archive', type=Path, help='Reuse a previously downloaded locked source archive')
    args = parser.parse_args()
    print(prepare(args.workspace, args.archive))
