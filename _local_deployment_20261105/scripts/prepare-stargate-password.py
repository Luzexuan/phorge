#!/usr/bin/env python3
"""Prepare the pinned Stargate source plus the reviewed personal-password patch.

The source tree must match either the complete pinned upstream tree or the
complete patched tree. Unexpected local changes are preserved and rejected.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'config/stargate/personal-password-source.json'
TARGET = ROOT / 'vendor/stargate'


def tree_digest(path):
    digest = hashlib.sha256()
    for file in sorted(path.rglob('*')):
        relative = file.relative_to(path)
        if '.git' in relative.parts or relative.as_posix() == '.source-commit':
            continue
        if file.is_symlink():
            raise SystemExit('Unexpected source symlink; source preserved.')
        if file.is_file():
            digest.update(relative.as_posix().encode() + b'\0')
            digest.update(hashlib.sha256(file.read_bytes()).digest())
    return digest.hexdigest()


def main():
    manifest = json.loads(MANIFEST.read_text())
    commit = manifest['commit']
    patch = ROOT / manifest['patch']['path']
    if hashlib.sha256(patch.read_bytes()).hexdigest() != manifest['patch']['sha256']:
        raise SystemExit('Personal-password patch digest does not match reviewed manifest.')
    if not TARGET.exists():
        TARGET.parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=TARGET.parent) as temporary:
            archive = Path(temporary) / 'source.tar.gz'
            urllib.request.urlretrieve(
                'https://codeload.github.com/soulteary/stargate/tar.gz/' + commit, archive)
            with tarfile.open(archive) as source:
                source.extractall(temporary, filter='data')
            (Path(temporary) / ('stargate-' + commit)).rename(TARGET)
    actual = tree_digest(TARGET)
    if actual == manifest['patchedTreeSha256']:
        print('Pinned Stargate personal-password source already prepared.')
        return
    if actual != manifest['upstreamTreeSha256']:
        raise SystemExit('Stargate source differs from reviewed upstream/patched trees; preserved without changes.')
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=TARGET, check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=TARGET, check=True)
    if tree_digest(TARGET) != manifest['patchedTreeSha256']:
        raise SystemExit('Patched Stargate source digest mismatch; do not build.')
    (TARGET / '.source-commit').write_text(commit + '\n')
    print('Pinned Stargate personal-password source prepared and verified.')


if __name__ == '__main__':
    main()
