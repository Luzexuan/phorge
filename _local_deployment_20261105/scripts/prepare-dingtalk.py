#!/usr/bin/env python3
"""Fetch the fixed DingTalk revision and idempotently apply reviewed local patches."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
COMMIT='f03650d66779c1021e80d70d6f23a8ed1fc77d06'
target=ROOT/'vendor/herald-dingtalk'
patches=[ROOT/'config/dingtalk/mobile-lookup-post.patch',
         ROOT/'config/dingtalk/transport-error-redaction.patch']
if not target.exists():
    target.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as temp:
        archive=Path(temp)/'source.tar.gz'
        urllib.request.urlretrieve('https://codeload.github.com/soulteary/herald-dingtalk/tar.gz/'+COMMIT,archive)
        with tarfile.open(archive) as tar:
            tar.extractall(temp,filter='data')
        next(p for p in Path(temp).iterdir() if p.is_dir()).rename(target)
        (target/'.source-commit').write_text(COMMIT+'\n')
else:
    if (target/'.git').exists():
        actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=target,text=True).strip()
    elif (target/'.source-commit').exists():
        actual=(target/'.source-commit').read_text().strip()
    else:
        raise SystemExit('Existing adapter source has no revision marker; verify it before rebuilding.')
    if actual != COMMIT:
        raise SystemExit('Existing adapter source is not the pinned revision; preserved without changes.')
    print('Existing adapter source preserved.')
for patch in patches:
    check=subprocess.run(['git','apply','--check',str(patch)],cwd=target,capture_output=True)
    if check.returncode == 0:
        subprocess.run(['git','apply',str(patch)],cwd=target,check=True)
    else:
        reverse=subprocess.run(['git','apply','--reverse','--check',str(patch)],cwd=target,capture_output=True)
        if reverse.returncode != 0:
            raise SystemExit('Adapter source conflicts with '+patch.name+'; inspect before rebuilding.')
manifest={'repository':'soulteary/herald-dingtalk','ref':'v1.2.5','commit':COMMIT,
          'localVersion':'v1.2.5-mobile-post-redacted',
          'image':'team-management/herald-dingtalk:f03650d-mobile-post-redacted',
          'patches':[{'path':str(patch.relative_to(ROOT)),
                      'sha256':hashlib.sha256(patch.read_bytes()).hexdigest()} for patch in patches]}
(ROOT/'config/dingtalk/source.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Pinned DingTalk adapter source, POST mobile lookup and transport-redaction patches ready.')
