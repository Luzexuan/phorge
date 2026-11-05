#!/usr/bin/env python3
"""Generate the pinned core deployment without printing credentials.

Requires PyYAML. Run after fetching vendor/phorge and generating .env.
All runtime SQL credentials are rendered only into state/mysql-accounts.sql.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
PHORGE_COMMIT = "e5141c768b37eeb9a114198cc8df9664173be638"
GORGE_COMMIT = "f1130b74f072c1d1d5ad7ad11b626be3d6a5d3ad"
CORE = ["mysql", "db-init", "gorge-render", "gorge-conduit",
        "gorge-notification", "gorge-file-storage", "gorge-webhook",
        "gorge-taskqueue", "gorge-worker", "gorge-db-api",
        "phorge-migrate", "phorge", "phorge-daemon"]


def organization_runtime_sources(staging=False):
    """Resolve the organization extension and its native schema migration."""
    manifest = json.loads(
        (ROOT / "config/phorge/overrides/organization-runtime.json").read_text())
    if manifest["baseCommit"] != PHORGE_COMMIT:
        raise ValueError("Review organization runtime before changing Phorge revision")
    result = []
    for row in manifest["files"]:
        source = Path(row["source"])
        staged = Path("config/phorge/organization-staging") / row["file"]
        if staging and (ROOT / staged).is_file():
            source = staged
        result.append({"source": source, "path": row["path"]})
    return result


def localization_runtime_sources(staging=False):
    """Resolve the reviewed Chinese translation of the deployed base image."""
    manifest = json.loads(
        (ROOT / "config/phorge/overrides/localization-runtime.json").read_text())
    if manifest["baseCommit"] != PHORGE_COMMIT:
        raise ValueError("Review localization runtime before changing Phorge revision")
    result = []
    for row in manifest["files"]:
        source = Path(row["source"])
        staged = Path("config/phorge/progress-staging") / row["file"]
        if staging and (ROOT / staged).is_file():
            source = staged
        result.append({"source": source, "path": row["path"]})
    return result


def project_runtime_sources(staging=False):
    """Resolve reviewed PHP/schema files; staging is only for isolated tests."""
    manifest = json.loads(
        (ROOT / "config/phorge/overrides/project-hierarchy-overrides.json").read_text())
    if manifest["baseCommit"] != PHORGE_COMMIT:
        raise ValueError("Rebase project overrides before changing Phorge revision")
    result = []
    for section, directory in (("files", "overrides"), ("extensions", "extensions")):
        for row in manifest.get(section, []):
            source = Path("config/phorge") / directory / row["file"]
            staged = Path("config/phorge/progress-staging") / row["file"]
            if staging and (ROOT / staged).is_file():
                source = staged
            result.append({"source": source, "path": row["path"]})
    result.extend(organization_runtime_sources(staging=staging))
    result.extend(localization_runtime_sources(staging=staging))
    if len({row["path"] for row in result}) != len(result):
        raise ValueError("Runtime manifest contains duplicate mount targets")
    return result


def required(name):
    return "${" + name + ":?Set " + name + "}"


def merge(parent, child):
    result = copy.deepcopy(parent)
    for key, value in child.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_service(source, filename, service):
    data = yaml.safe_load((source / filename).read_text())
    result = copy.deepcopy(data["services"][service])
    extension = result.pop("extends", None)
    if extension:
        parent = load_service(source, extension["file"], extension["service"])
        result = merge(parent, result)
    return result


def generate_compose(source):
    services = {name: load_service(source, "docker-compose.yml", name)
                for name in CORE}
    for name, service in services.items():
        for key in ("container_name", "ports", "build", "profiles"):
            service.pop(key, None)
        service["logging"] = {"driver": "json-file", "options": {
            "max-size": "10m", "max-file": "3"}}
        service["mem_limit"] = "128m"
        service["cpus"] = 0.5
        service["pids_limit"] = 128
        service["security_opt"] = ["no-new-privileges:true"]
        if name.startswith("gorge-"):
            service["image"] = "team-management/" + name + ":f1130b7"
            service["pull_policy"] = "never"
            service["networks"] = {"rpc": {}}
            service["cap_drop"] = ["ALL"]
            service["read_only"] = True
            service["tmpfs"] = ["/tmp:rw,noexec,nosuid,size=32m"]
        if name in ("mysql", "db-init"):
            service["image"] = "${MYSQL_IMAGE:-mysql:8.0.46}"
            service["networks"] = {"core": {}}
        if name in ("gorge-file-storage", "gorge-webhook", "gorge-taskqueue",
                    "gorge-worker", "gorge-db-api"):
            service["networks"]["core"] = {}
        if name.startswith("phorge"):
            service["image"] = "team-management/phorge:e5141c7"
            service["pull_policy"] = "never"
            service["networks"] = {"core": {}, "rpc": {}, "notify_admin": {}}
            service["mem_limit"] = "512m" if name != "phorge-daemon" else "256m"
            service["cpus"] = 1.0
            env = service["environment"]
            env.update({"MYSQL_USER": "phorge", "MYSQL_PASS": required("MYSQL_PASSWORD"),
                        "PHORGE_BASE_URI": required("PHORGE_BASE_URI"),
                        "PHORGE_TIMEZONE": "Asia/Shanghai",
                        "PHORGE_DB_NAMESPACE": "${PHORGE_DB_NAMESPACE:-phabricator}",
                        "PHORGE_GORGE_POLICY": "required",
                        "PHORGE_GORGE_STARTUP_TIMEOUT": "180",
                        "GORGE_WORKER_TOKEN": required("GORGE_WORKER_TOKEN")})

    mysql = services["mysql"]
    mysql.update(mem_limit="1g", cpus=1.0, pids_limit=256)
    mysql["environment"] = {
        "MYSQL_ROOT_PASSWORD": required("MYSQL_ROOT_PASSWORD"),
        "MYSQL_DATABASE": "phorge", "MYSQL_USER": "phorge",
        "MYSQL_PASSWORD": required("MYSQL_PASSWORD")}
    mysql["command"] = ["--sql-mode=STRICT_ALL_TABLES", "--max-allowed-packet=134217728",
                        "--innodb-buffer-pool-size=512M", "--local-infile=0",
                        "--ft-min-word-len=3", "--partial-revokes=ON"]
    services["db-init"]["environment"] = {
        "MYSQL_PWD": required("MYSQL_ROOT_PASSWORD")}
    services["db-init"]["volumes"] = ["./state/mysql-accounts.sql:/run/accounts.sql:ro"]
    services["db-init"]["command"] = [
        "sh", "-ec", "mysql --protocol=TCP -h mysql -P 3306 -u root < /run/accounts.sql"]

    for service, token in (("render", "RENDER"), ("conduit", "CONDUIT"),
                           ("file-storage", "FILE"), ("webhook", "WEBHOOK"),
                           ("taskqueue", "TASKQUEUE"), ("worker", "WORKER"),
                           ("db-api", "DB")):
        services["gorge-" + service]["environment"]["GORGE_SERVICE_TOKEN"] = required(
            "GORGE_" + token + "_TOKEN")
    services["gorge-render"]["mem_limit"] = "256m"
    for service, prefix, account, password_prefix in (
            ("file-storage", "FILE", "gorge_file", "FILE"),
            ("webhook", "WEBHOOK", "gorge_webhook", "WEBHOOK"),
            ("taskqueue", "TASKQUEUE", "gorge_queue", "QUEUE"),
            ("db-api", "DB", "gorge_db", "DB")):
        env = services["gorge-" + service]["environment"]
        env["GORGE_" + prefix + "_MYSQL_USER"] = account
        env["GORGE_" + prefix + "_MYSQL_PASS"] = required(
            "GORGE_" + password_prefix + "_MYSQL_PASSWORD")
    services["gorge-file-storage"]["environment"].update({
        "GORGE_FILE_LOCAL_DISK_PATH": "/var/lib/gorge/files",
        "GORGE_FILE_UPLOAD_ROOT": "", "GORGE_FILE_DELETION_DSN": ""})
    services["gorge-file-storage"]["volumes"] = [
        "phorge-files:/var/lib/gorge/files"]

    worker = services["gorge-worker"]
    worker["networks"]["notify_admin"] = {}
    # Only delivery executors have an external route. No destinations are
    # configured by this bootstrap; operators configure recipients explicitly.
    worker["networks"]["core_egress"] = {}
    services["gorge-webhook"]["networks"]["core_egress"] = {}
    worker["depends_on"]["phorge-migrate"] = {"condition": "service_completed_successfully"}
    worker["environment"].update({
        "GORGE_WORKER_TASK_QUEUE_TOKEN": required("GORGE_TASKQUEUE_TOKEN"),
        "GORGE_WORKER_CONDUIT_TOKEN": required("GORGE_CONDUIT_TOKEN"),
        "GORGE_WORKER_OUTBOX_DSN": "gorge_feed:" + required("GORGE_FEED_MYSQL_PASSWORD")
            + "@tcp(mysql:3306)/${PHORGE_DB_NAMESPACE:-phabricator}_feed",
        "GORGE_WORKER_DRAIN_TIMEOUT_SEC": "30",
        "GORGE_WORKER_NOTIFICATION_MODE": "native",
        "GORGE_WORKER_MAIL_OUTBOX_DSN": "", "GORGE_WORKER_MAILER_URL": "",
        "GORGE_WORKER_MAILER_TOKEN": ""})
    worker["stop_grace_period"] = "45s"

    notification = services["gorge-notification"]
    notification["networks"] = {
        "notify_admin": {"ipv4_address": "172.29.241.10"},
        "notify_client": {"ipv4_address": "172.29.242.10"}}
    notification["environment"] = {"GORGE_NOTIFICATION_CONFIG_FILE": "/etc/gorge/notification.json"}
    notification["volumes"] = ["./config/notification.json:/etc/gorge/notification.json:ro"]
    notification["healthcheck"]["test"] = [
        "CMD", "wget", "-qO-", "http://172.29.241.10:22281/healthz"]

    migrate = services["phorge-migrate"]["environment"]
    migrate.update({"PHORGE_PRODUCT_PROFILE": "collaboration",
                    "GORGE_NOTIFICATION_ADMIN_HOST": "172.29.241.10",
                    "GORGE_NOTIFICATION_ADMIN_PORT": "22281",
                    "GORGE_NOTIFICATION_CLIENT_HOST": required("PHORGE_HOST"),
                    "GORGE_NOTIFICATION_CLIENT_PORT": "${PUBLIC_HTTPS_PORT:-8443}",
                    "GORGE_NOTIFICATION_CLIENT_PROTOCOL": "https",
                    "GORGE_NOTIFICATION_CLIENT_PATH": "/ws/",
                    "GORGE_NOTIFICATION_OUTBOX": "true",
                    "GORGE_FILE_UPLOADS": "false",
                    "GORGE_FILE_DELETION_OUTBOX": "false"})
    for token in ("RENDER", "CONDUIT", "FILE", "WEBHOOK", "TASKQUEUE", "DB"):
        migrate["GORGE_" + token + "_TOKEN"] = required("GORGE_" + token + "_TOKEN")
    services["phorge"]["networks"]["web"] = {}
    services["phorge"]["volumes"].append(
        "./config/phorge-apache.conf:/etc/apache2/sites-available/000-default.conf:ro")
    services["phorge"]["volumes"].append(
        "./config/phorge-trusted-proxy.php:/etc/phorge/trusted-proxy.php:ro")
    project_sources = project_runtime_sources()
    for role in ("phorge", "phorge-daemon", "phorge-migrate"):
        services[role]["volumes"].append(
            "./config/phorge/extensions/TeamEntrySessionGuard.php:/opt/phorge/phorge/src/extensions/TeamEntrySessionGuard.php:ro")
        services[role]["volumes"].append(
            "./config/phorge/overrides/PhabricatorFileQuery.php:/opt/phorge/phorge/src/applications/files/query/PhabricatorFileQuery.php:ro")
        for override in project_sources:
            services[role]["volumes"].append(
                "./" + override["source"].as_posix() +
                ":/opt/phorge/phorge/" + override["path"] + ":ro")
    # The internal Conduit proxy uses this exact Docker hostname. Authorize it
    # explicitly before any PHP callback can be accepted by PlatformSite.
    services["phorge-migrate"]["command"] = [
        "/opt/phorge/phorge/bin/config", "set", "phabricator.allowed-uris",
        '["http://phorge/"]']
    for optional in ("phorge-mailer-config", "phorge-search-config"):
        services["phorge"]["depends_on"].pop(optional, None)

    return {"name": "team-management", "services": services,
            "volumes": {name: {} for name in (
                "phorge-db", "phorge-conf", "phorge-repo", "phorge-files")},
            "networks": {
                "core": {"internal": True}, "rpc": {"internal": True},
                "web": {"internal": True},
                "core_egress": {},
                "notify_admin": {"internal": True, "ipam": {"config": [{"subnet": "172.29.241.0/24"}]}},
                "notify_client": {"internal": True, "ipam": {"config": [{"subnet": "172.29.242.0/24"}]}}}}


def load_env(path):
    result = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            raise ValueError("Invalid environment entry")
        result[name] = value.strip().strip("\"'")
    return result


def generate_sql(source, namespace):
    builtin = (source / "src/infrastructure/storage/patch/PhabricatorBuiltinPatchList.php").read_text()
    databases = set(re.findall(r"'db\.([a-z0-9_]+)'\s*=>", builtin))
    for path in (source / "resources/sql/autopatches").glob("*.db"):
        databases.add(json.loads(path.read_text())["name"])
    if not re.fullmatch(r"[a-zA-Z0-9_]{1,44}", namespace):
        raise ValueError("Invalid PHORGE_DB_NAMESPACE")
    lines = ["-- Generated from the pinned Phorge schema registry.",
             "-- Requires MySQL partial_revokes=ON: underscores are literal.",
             "-- Secret placeholders are expanded only into state/mysql-accounts.sql."]
    for account, password in (("phorge", "MYSQL_PASSWORD"),
                              ("gorge_queue", "GORGE_QUEUE_MYSQL_PASSWORD"),
                              ("gorge_file", "GORGE_FILE_MYSQL_PASSWORD"),
                              ("gorge_feed", "GORGE_FEED_MYSQL_PASSWORD"),
                              ("gorge_webhook", "GORGE_WEBHOOK_MYSQL_PASSWORD"),
                              ("gorge_db", "GORGE_DB_MYSQL_PASSWORD")):
        lines.append(f"CREATE USER IF NOT EXISTS '{account}'@'%' IDENTIFIED BY '@@{password}@@';")
        lines.append(f"ALTER USER '{account}'@'%' IDENTIFIED BY '@@{password}@@';")
    for database in sorted(databases):
        if not re.fullmatch(r"[a-z0-9_]+", database):
            raise ValueError("Invalid schema registry")
        lines.append(f"GRANT ALL PRIVILEGES ON `{namespace}_{database}`.* TO 'phorge'@'%';")
        lines.append(f"GRANT SELECT ON `{namespace}_{database}`.* TO 'gorge_db'@'%';")
    for account, database, rights in (
            ("gorge_queue", "worker", "SELECT, INSERT, UPDATE, DELETE"),
            ("gorge_file", "file", "SELECT, INSERT, UPDATE, DELETE"),
            ("gorge_feed", "feed", "SELECT, UPDATE"),
            ("gorge_webhook", "herald", "SELECT, UPDATE")):
        lines.append(f"GRANT {rights} ON `{namespace}_{database}`.* TO '{account}'@'%';")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "vendor/phorge")
    parser.add_argument("--env", type=Path, default=ROOT / ".env")
    parser.add_argument("--without-secrets", action="store_true")
    args = parser.parse_args()
    env = load_env(args.env) if args.env.exists() else {}
    compose = generate_compose(args.source)
    (ROOT / "compose.core.yaml").write_text(
        "# Generated by scripts/generate-core.py from pinned upstream Compose.\n"
        f"# Phorge {PHORGE_COMMIT}; Gorge {GORGE_COMMIT}.\n"
        "# Optional integrations are disabled; no core host ports are published.\n"
        + yaml.safe_dump(compose, sort_keys=False, allow_unicode=True))
    (ROOT / "config/mysql").mkdir(parents=True, exist_ok=True)
    notification = {"servers": [
        {"type": "admin", "listen": "172.29.241.10", "port": 22281},
        {"type": "client", "listen": "172.29.242.10", "port": 22280}]}
    (ROOT / "config/notification.json").write_text(json.dumps(notification, indent=2) + "\n")
    apache = (args.source / "docker/phorge-apache.conf").read_text()
    apache = apache.replace("    RewriteEngine on", "    # Only the directly connected Traefik may assert TLS or personal identity.\n"
                            "    SetEnvIfExpr \"%{REMOTE_ADDR} == '172.29.240.2' && req('X-Forwarded-Proto') == 'https'\" HTTPS=on\n"
                            "    php_admin_value auto_prepend_file /etc/phorge/trusted-proxy.php\n\n"
                            "    RewriteEngine on")
    # Existing single-file bind mounts retain their inode until the operator
    # recreates Phorge. Never partly replace an active Apache configuration.
    with tempfile.NamedTemporaryFile(mode="w", dir=ROOT / "config", delete=False) as output:
        output.write(apache)
        temporary = Path(output.name)
    temporary.chmod(0o644)
    temporary.replace(ROOT / "config/phorge-apache.conf")
    sql = generate_sql(args.source, env.get("PHORGE_DB_NAMESPACE", "phabricator"))
    (ROOT / "config/mysql/grants.sql.template").write_text(sql)
    if not args.without_secrets:
        for name in sorted(set(re.findall(r"@@([A-Z_]+)@@", sql))):
            value = env.get(name, "")
            # This deployment generates random hex secrets; restricting the alphabet
            # prevents SQL injection and ambiguous DSNs without shell expansion.
            if not re.fullmatch(r"[a-fA-F0-9]{32,128}", value):
                raise ValueError(f"{name} must contain 32..128 hexadecimal characters")
            sql = sql.replace("@@" + name + "@@", value)
        state = ROOT / "state"
        state.mkdir(mode=0o700, exist_ok=True)
        path = state / "mysql-accounts.sql"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(sql)
        path.chmod(0o600)
    print("Generated core Compose, isolated notification listeners, and SQL grants.")


if __name__ == "__main__":
    main()
