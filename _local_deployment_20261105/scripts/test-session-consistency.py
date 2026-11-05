#!/usr/bin/env python3
"""Run destructive-to-test-sessions G03 checks with real browser cookie jars.

Inputs are Playwright storage_state JSON files (or plain cookie-name maps).
Run only with disposable, fully registered test-user sessions: the stale A
Phorge session is intentionally revoked. No cookie values enter the report.
"""
import argparse
import datetime
import json
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_cookies(path, host):
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict) and 'cookies' in data:
        data = data['cookies']
    if isinstance(data, list):
        data = {item['name']: item['value'] for item in data
                if host == item.get('domain', '').lstrip('.')
                or (item.get('domain', '').startswith('.') and
                    host.endswith(item['domain']))}
    if not isinstance(data, dict):
        raise ValueError('Expected Playwright cookie list or a cookie dictionary')
    for name in ('phsid', 'stargate_session_id'):
        if not isinstance(data.get(name), str) or not data[name]:
            raise ValueError(f'{path}: missing {name}')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='HTTPS Phorge base URI')
    parser.add_argument('--a-cookies', required=True)
    parser.add_argument('--b-cookies', required=True)
    parser.add_argument('--a-new-cookies', help='A separate new Stargate login by the SAME A user')
    parser.add_argument('--ca-file', default=str(ROOT/'config/tls/localhost.crt'))
    parser.add_argument('--report', default=str(ROOT/'state/session-consistency-check.json'))
    args = parser.parse_args()
    if not args.url.startswith('https://'):
        parser.error('Use the HTTPS entrypoint')
    context = ssl.create_default_context(cafile=args.ca_file)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    checks = []

    def request(cookies, method='GET', path='/settings/'):
        headers = {'Cookie': '; '.join(f'{k}={v}' for k, v in cookies.items()),
                   'Origin': args.url.rstrip('/'), 'Content-Type': 'application/x-www-form-urlencoded'}
        req = urllib.request.Request(args.url.rstrip('/')+path,
                                     data=b'params=%7B%7D&output=json' if method == 'POST' else None,
                                     method=method, headers=headers)
        try:
            response = opener.open(req, timeout=20)
        except urllib.error.HTTPError as response:
            return response.code, response.headers, response.read().decode(errors='replace')
        with response:
            return response.status, response.headers, response.read().decode(errors='replace')

    def check(name, passed, status):
        checks.append({'name': name, 'passed': bool(passed), 'http_status': status})
        print(('PASS ' if passed else 'FAIL ')+name+f' ({status})')

    host = urllib.parse.urlsplit(args.url).hostname
    a = read_cookies(args.a_cookies, host)
    b = read_cookies(args.b_cookies, host)
    if a['phsid'] == b['phsid'] or a['stargate_session_id'] == b['stargate_session_id']:
        raise SystemExit('A and B must have distinct independently authenticated sessions')

    for label, cookies in (('A', a), ('B', b)):
        status, _, _ = request(cookies, path='/settings/user/'+urllib.parse.quote(cookies['phusr'])+'/')
        check(f'{label} valid matching session can access settings', status == 200, status)
    if not all(c['passed'] for c in checks):
        raise SystemExit('Baseline sessions are not usable; no stale-session tests executed')

    # Do the same-person new-entry test first with a SEPARATE old application
    # session, otherwise cross-user rejection would already revoke A's session.
    if args.a_new_cookies:
        fresh_a = read_cookies(args.a_new_cookies, host)
        if fresh_a['stargate_session_id'] == a['stargate_session_id']:
            raise SystemExit('A-new must come from a different entry login')
        status, _, _ = request(fresh_a, path='/settings/user/'+urllib.parse.quote(fresh_a['phusr'])+'/')
        check('A-new matching session initializes independently', status == 200, status)
        changed = dict(a, phsid=fresh_a['phsid'])
        status, headers, body = request(changed, 'POST', '/api/user.whoami')
        check('same user with a different entry session cannot reuse phsid',
              status == 409 and 'ENTRY_SESSION_MISMATCH' in body, status)
        check('same-user stale phsid cookie cleared',
              any(value.startswith('phsid=') and ('deleted' in value or 'expires=' in value.lower())
                  for value in headers.get_all('Set-Cookie', [])), status)

    mixed = dict(b, phsid=a['phsid'])
    status, headers, body = request(mixed, 'POST', '/api/user.whoami')
    check('A phsid with B entry cannot execute POST',
          status == 409 and 'ENTRY_SESSION_MISMATCH' in body, status)
    check('cross-user stale phsid cookie cleared',
          any(value.startswith('phsid=') and ('deleted' in value or 'expires=' in value.lower())
              for value in headers.get_all('Set-Cookie', [])), status)
    status, _, body = request(a)
    check('revoked A phsid no longer opens settings',
          status in (301, 302, 303, 401, 403) and 'ENTRY_SESSION_MISMATCH' not in body, status)
    status, _, _ = request(b, path='/settings/user/'+urllib.parse.quote(b['phusr'])+'/')
    check('B independent session remains valid', status == 200, status)

    report = {'verified_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'passed': all(c['passed'] for c in checks), 'checks': checks,
              'scope': 'real browser session pair; stale cookies intentionally revoked; no business mutations'}
    Path(args.report).write_text(json.dumps(report, indent=2)+'\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
