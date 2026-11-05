#!/usr/bin/env python3
"""Fetch pinned source archives. Existing vendor checkouts are never replaced."""
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import urllib.request
ROOT = Path(__file__).resolve().parents[1]
sources = [dict(repository='soulteary/phorge', commit='e5141c768b37eeb9a114198cc8df9664173be638'),
           dict(repository='soulteary/gorge', commit='f1130b74f072c1d1d5ad7ad11b626be3d6a5d3ad')]
sources += json.loads((ROOT/'config/identity-sources.json').read_text())
(ROOT/'vendor').mkdir(exist_ok=True)
for source in sources:
    name = source['repository'].split('/')[-1]
    target = ROOT/'vendor'/name
    if target.exists():
        print(f'{name}: existing source preserved')
        continue
    url = f'https://codeload.github.com/{source["repository"]}/tar.gz/{source["commit"]}'
    with tempfile.TemporaryDirectory(dir=ROOT/'vendor') as temp:
        archive = Path(temp)/'source.tar.gz'
        urllib.request.urlretrieve(url, archive)
        with tarfile.open(archive) as tar:
            tar.extractall(temp, filter='data')
        directory = next(p for p in Path(temp).iterdir() if p.is_dir())
        directory.rename(target)
        print(f'{name}: {source["commit"]} archive sha256={hashlib.sha256(archive.read_bytes()).hexdigest()}')
