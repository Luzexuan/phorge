#!/usr/bin/env python3
"""Check the intentionally closed local identity deployment without real email."""
import datetime
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = str(ROOT / "scripts" / "compose.sh")


def inspect_service(service):
    cid = subprocess.check_output([COMPOSE, "ps", "-q", service], text=True).strip()
    if not cid:
        raise RuntimeError(f"{service} is not running")
    info = json.loads(subprocess.check_output(["docker", "inspect", cid]))[0]
    assert info["State"]["Running"], service
    assert info["State"]["Health"]["Status"] == "healthy", service
    assert not any(info["HostConfig"].get("PortBindings", {}).values()), service
    return info


def environment(info):
    return dict(line.split("=", 1) for line in info["Config"]["Env"])


def endpoint(info, port):
    address = next(value["IPAddress"] for value in info["NetworkSettings"]["Networks"].values()
                   if value["IPAddress"])
    return f"http://{address}:{port}"


def request(base, path, expected, payload=None, key=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        headers["X-API-Key"] = key
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read()
    assert response.code == expected, f"{path}: expected {expected}, got {response.code}"
    return json.loads(body)


def main():
    assert json.loads((ROOT / "config" / "warden" / "users.json").read_text()) == [], (
        "This check only applies to empty-directory initialization; do not run after activation.")
    services = {name: inspect_service(name) for name in
                ("stargate", "warden", "herald", "herald-smtp", "stargate-redis", "herald-redis")}
    warden = environment(services["warden"])
    herald = environment(services["herald"])
    smtp = environment(services["herald-smtp"])
    assert herald["ENVIRONMENT"] == "production"
    assert herald["PROVIDER_FAILURE_POLICY"] == "strict"
    assert herald.get("HERALD_SMTP_API_URL", "") == ""
    assert herald.get("SMTP_HOST", "") == ""
    assert herald["HERALD_TEST_MODE"] == "false"
    assert smtp.get("SMTP_HOST", "") == "" and smtp.get("SMTP_FROM", "") == ""
    warden_base = endpoint(services["warden"], 8081)
    herald_base = endpoint(services["herald"], 8082)
    smtp_base = endpoint(services["herald-smtp"], 8084)
    request(warden_base, "/v1/users", 401)
    request(warden_base, "/v1/lookup?identifier=init-check%40example.invalid", 404,
            key=warden["API_KEY"])
    request(herald_base, "/readyz", 200)
    payload = {"user_id": "init-check-" + uuid.uuid4().hex, "channel": "email",
               "destination": "init-check@example.invalid", "purpose": "login"}
    request(herald_base, "/v1/otp/challenges", 401, payload)
    result = request(herald_base, "/v1/otp/challenges", 500, payload, herald["API_KEY"])
    assert result.get("reason") == "send_failed" and not result.get("ok")
    assert "challenge_id" not in result and "debug_code" not in result
    request(smtp_base, "/healthz", 200)
    result = request(smtp_base, "/readyz", 503)
    assert result.get("reason") == "smtp_not_configured"
    result = request(smtp_base, "/v1/send", 503, {"channel": "email",
                     "to": "init-check@example.invalid", "body": "configuration check"}, smtp["API_KEY"])
    assert result.get("error_code") == "provider_down"
    report = {
        "verifiedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "healthyInternalServices": list(services),
        "hostPublishedIdentityPorts": [], "directory": "empty-deny-all",
        "unauthenticatedWarden": 401, "unknownWardenUser": 404,
        "unauthenticatedHerald": 401, "heraldUndeliverableChallenge": "500 send_failed; no challenge/code returned",
        "smtpReadiness": "503 smtp_not_configured", "smtpSend": "503 provider_down",
        "G03": "pending: requires real two-user identity and session acceptance before public activation",
    }
    (ROOT / "state" / "identity-initial-check.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
