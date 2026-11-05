#!/usr/bin/env python3
"""Read-only live credential/mobile check. Never sends a message or prints tokens."""
import datetime
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
os.umask(0o077)
settings = dict(line.split('=', 1) for line in (ROOT/'.env.dingtalk').read_text().splitlines()
                if line and not line.startswith('#') and '=' in line)
users = json.loads((ROOT/'config/warden/users.json').read_text())
admin = next(user for user in users if user.get('user_id') == 'linkerbot-site-admin')
phone = admin.get('phone', '')
redactions = [value for value in settings.values() if value] + ([phone] if phone else [])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(NoRedirect)


def safe_message(value):
    message = str(value)
    for secret in redactions:
        message = message.replace(secret, '[redacted]')
    message = re.sub(r'https?://\S+', '[provider documentation URL]', message)
    return message[:500]


def call(path, query, body=None):
    url = 'https://oapi.dingtalk.com' + path + '?' + urllib.parse.urlencode(query)
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data,
                                     headers={'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=20) as response:
            return response.status, json.loads(response.read(1024 * 1024))
    except urllib.error.HTTPError as error:
        return error.code, {'errcode': 'HTTP_ERROR', 'errmsg': 'Provider returned HTTP error'}
    except Exception as error:
        # A transport exception string may contain a URL with credentials.
        return None, {'errcode': type(error).__name__, 'errmsg': 'Transport or response decoding failed'}


def result(status, body, **extra):
    return dict(httpStatus=status, success=str(body.get('errcode')) == '0',
                code=body.get('errcode'), message=safe_message(body.get('errmsg', '')), **extra)


report = dict(checkedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
              messagesSent=0, user='siteadmin', phonePresent=bool(phone), checks={})
required = ('DINGTALK_APP_KEY', 'DINGTALK_APP_SECRET', 'DINGTALK_AGENT_ID')
report['credentialsPresent'] = all(settings.get(key) for key in required)
if report['credentialsPresent']:
    status, body = call('/gettoken', {'appkey': settings['DINGTALK_APP_KEY'],
                                    'appsecret': settings['DINGTALK_APP_SECRET']})
    token = body.get('access_token', '')
    if token:
        redactions.append(token)
    report['checks']['token'] = result(status, body, tokenPresent=bool(token))
    if report['checks']['token']['success'] and token and phone:
        status, body = call('/topapi/v2/user/getbymobile', {'access_token': token}, {'mobile': phone})
        user_id = (body.get('result') or {}).get('userid', '')
        if user_id:
            redactions.append(user_id)
        report['checks']['mobileLookup'] = result(status, body, userIdPresent=bool(user_id))
        if user_id and report['checks']['mobileLookup']['success']:
            private = ROOT/'state/dingtalk'
            private.mkdir(mode=0o700, exist_ok=True)
            identity = private/'resolved-admin.json'
            identity.write_text(json.dumps({'user_id': admin['user_id'], 'dingtalk_userid': user_id})+'\n')
            identity.chmod(0o600)

report['passed'] = (report['checks'].get('token', {}).get('success', False)
                    and report['checks'].get('token', {}).get('tokenPresent', False)
                    and report['checks'].get('mobileLookup', {}).get('success', False)
                    and report['checks'].get('mobileLookup', {}).get('userIdPresent', False))
report['scope'] = 'Token and exact administrator mobile lookup only; no send, scope mutation or login proof.'
target = ROOT/'state/acceptance/dingtalk-preflight.json'
target.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
target.chmod(0o600)
print(json.dumps(report, ensure_ascii=False, indent=2))
sys.exit(0 if report['passed'] else 1)
