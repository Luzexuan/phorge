#!/usr/bin/env python3
"""Build a small, data-free companion kit for an existing portable backup."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'scripts/migrate.py', 'scripts/migration_process.py',
    'scripts/migration_endpoint.py', 'scripts/migration_probe.php',
    'scripts/backup.py', 'scripts/migration_preflight.py',
)

GUIDE = r'''团队管理服务：通用迁移随身工具包

本包只有工具、清单和说明，不含生产数据或密码。当前不绑定目标服务器。
另行携带：最新的 portable-*.tar.gpg、对应 .sha256、单独保存的解密密钥。
数据包是导出时的快照；后续新增数据须重新导出。源服务仍是当前权威实例。

1. 新机准备（获得实例后，在新机本地执行）
   Linux、root、本地 Docker daemon（不启用 rootless/userns remap）、Bash、Python 3.12+、PyYAML、GnuPG。
   Docker Compose 须支持 JSON config 和 !override；预检会实际检查这些能力。
   CPU 架构须与数据包镜像一致；目前已验收包是 amd64。
   内存、解压空间、Docker 数据盘空间应按实际数据和服务规模预留。
   宿主机不用安装 PHP/MySQL；Node/Chromium/OpenSSL 仅用于额外浏览器演练。
   按目标发行版安装依赖，本包不自动修改软件、Docker context、防火墙或 DNS。

   解包本工具包后，进入其目录，先执行：
     sha256sum -c SHA256SUMS
     python3 scripts/migration_preflight.py

   只有宿主检查通过而目标信息缺失时，readyForRestore 仍为 false。
   退出码 0 只表示已检查项目无失败；1 表示检查失败；2 表示报告文件写入失败。
   不要把缺少目标参数、端口占用或依赖失败当成成功的目标验收。

2. 源实例最终导出（维护窗口，在原部署目录执行）
   以下命令会暂停应用写入；成功后旧实例保持停写：
     python3 scripts/migrate.py export --output backups/cutover-YYYYMMDD --leave-stopped
     python3 scripts/migrate.py seal backups/cutover-YYYYMMDD \
       --output backups/cutover-YYYYMMDD.tar.gpg \
       --passphrase-file /root/private-backups/team-management.key
     (cd backups && sha256sum cutover-YYYYMMDD.tar.gpg > cutover-YYYYMMDD.tar.gpg.sha256)

   如果只是生成日常携带包，export 不加 --leave-stopped，会自动恢复原服务。
   这个随身工具包不具备源实例的 Compose 配置；export/resume-source 必须使用原部署脚本。
   通过指定的 SSH/SFTP 或其他私有通道传输加密包，密钥另行保存和传递。
   目前未配置远程地址或计划任务，本包不会自动上传或定时停写。

3. 目标参数（取得实例后修改下面五个值，再逐步执行）
   这些变量是命令示例；不要直接使用占位地址。
     MIGRATION_ARCHIVE='/srv/incoming/portable-DATE.tar.gpg'
     MIGRATION_KEY='/root/private-backups/team-management.key'
     MIGRATION_BUNDLE='/srv/migration/bundle-DATE'
     MIGRATION_TARGET='/srv/team-management'
     MIGRATION_ORIGIN='https://NEW-IP-OR-DOMAIN'

   MIGRATION_BUNDLE 和 MIGRATION_TARGET 必须是尚不存在的目录；不要提前 mkdir。
   密钥应为本地普通文件、权限 0600，不使用软链接或硬链接。
   正式 origin 支持 IPv4 或域名的 HTTPS，默认 443，也可指定其他 HTTPS 端口；不能用 80。

4. 解密、预检及恢复（仍在工具包目录逐条运行；任何失败均先处理，不继续下一步）
     python3 scripts/migrate.py unseal "$MIGRATION_ARCHIVE" \
       --output "$MIGRATION_BUNDLE" --passphrase-file "$MIGRATION_KEY"
     python3 scripts/migrate.py verify "$MIGRATION_BUNDLE"
     python3 scripts/migration_preflight.py --bundle "$MIGRATION_BUNDLE" \
       --target "$MIGRATION_TARGET" --origin "$MIGRATION_ORIGIN" \
       --report /root/migration-target-preflight.json

   报告路径也须为新文件。先处理预检失败，并人工确认尚未验证的公网条件。
   使用解密包自带、与数据一起验收的恢复工具：
     python3 "$MIGRATION_BUNDLE/tooling/scripts/migrate.py" restore "$MIGRATION_BUNDLE" \
       --target "$MIGRATION_TARGET" --origin "$MIGRATION_ORIGIN"
     python3 "$MIGRATION_TARGET/scripts/migrate.py" start --target "$MIGRATION_TARGET"
     python3 "$MIGRATION_TARGET/scripts/migrate.py" check --target "$MIGRATION_TARGET"

   restore/check 会验证数据库、权限和附件；check 还检查公信 HTTPS 登录页。
   在开放成员写入前完成初始快照比对和本人登录、项目/团队/节点/附件检查。
   已正常新增业务后，不能继续用原始快照作为日常健康检查基准。

5. 公网切换与回退
   到实际新机再确认 DNS、HTTP 80 与所选 HTTPS 端口、云防火墙、ACME 出站及可用容量。
   预检不证明 DNS 已指向新机或公网证书已签发，也不能代替运行后的验收。
   复用域名时按维护窗口修改 DNS；改用新地址时通知成员重新登录。
   SSH、宿主防火墙等系统配置不在应用数据包内；正文中的手工旧链接保留原文。
   取消切换且新机尚无新业务写入时，先在目标机停止新实例：
     "$MIGRATION_TARGET/scripts/compose.sh" stop --timeout 30
   再回到源部署目录执行：
     python3 scripts/migrate.py resume-source backups/cutover-YYYYMMDD
   若最终导出后的加密/传输失败，可同样在源部署 resume-source，再重新安排窗口。
   新实例已有业务写入时，不可直接回到旧库；应先停写并保存新数据，制定数据恢复方案。

6. 可选完整演练
   解密包内 tooling/tests/browser 已包含浏览器测试源码与锁文件。
   在 tooling/tests/browser 按 package-lock 安装依赖及 Playwright Chromium 后，可运行：
     python3 "$MIGRATION_BUNDLE/tooling/scripts/migrate.py" rehearse "$MIGRATION_BUNDLE" \
       --target /srv/migration-rehearsal-NEW --report /root/migration-rehearsal-NEW --port 18443
   成功后自动清理隔离副本。失败副本的 cleanup 命令只允许明确标记的演练实例。
   当前完整迁移已通过同机隔离实测；实际异机和公网切换须在拿到实例后验收。
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(output, root=ROOT):
    root = Path(root).resolve()
    output = Path(output).absolute()
    archive = Path(str(output)+'.tar.gz')
    checksum = Path(str(archive)+'.sha256')
    if any(p.exists() or p.is_symlink() for p in (output, archive, checksum)):
        raise ValueError('Output directory, archive and checksum must all be new paths.')
    payloads = {}
    for name in FILES:
        path = root/name
        if (not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink() or
                any(p.is_symlink() for p in path.parents if p != root and p.is_relative_to(root)) or
                not path.resolve().is_relative_to(root)):
            raise ValueError('Only regular allowlisted source files may enter the toolkit.')
        payloads[name] = path.read_bytes()
    payloads['START-HERE.txt'] = GUIDE.encode('utf-8')
    manifest = {'formatVersion': 1, 'kind': 'team-management-migration-toolkit',
                'createdAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                'containsProductionData': False, 'requiresSeparateDataArchiveAndKey': True,
                'files': {name: {'sha256': sha(data), 'bytes': len(data)}
                          for name, data in payloads.items()}}
    payloads['kit.json'] = (json.dumps(manifest, indent=2, ensure_ascii=False)+'\n').encode()
    payloads['SHA256SUMS'] = ''.join(
        sha(data)+'  '+name+'\n' for name, data in sorted(payloads.items())).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    created = []
    try:
        for name, data in payloads.items():
            path = output/name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with path.open('xb') as stream:
                stream.write(data)
            path.chmod(0o600)
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created.append(archive)
        with os.fdopen(fd, 'wb') as stream, tarfile.open(fileobj=stream, mode='w:gz') as tar:
            for name in sorted(payloads):
                tar.add(output/name, arcname=output.name+'/'+name, recursive=False)
        digest = sha(archive.read_bytes())
        fd = os.open(checksum, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created.append(checksum)
        with os.fdopen(fd, 'w') as stream:
            stream.write(digest+'  '+archive.name+'\n')
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        shutil.rmtree(output)
        raise
    return {'directory': str(output), 'archive': str(archive), 'sha256': digest,
            'bytes': archive.stat().st_size, 'files': len(payloads), 'containsProductionData': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='New kit directory; also creates .tar.gz and .sha256 siblings.')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(prepare(args.output), indent=2, ensure_ascii=False))
    except (ValueError, OSError) as error:
        parser.exit(1, 'Toolkit preparation stopped: '+str(error)+'\n')
