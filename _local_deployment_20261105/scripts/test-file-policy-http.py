#!/usr/bin/env python3
"""Actual public file-URL regression; never prints bearer URLs or cookies."""
import datetime
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BASE = 'https://45.77.36.106'
os.umask(0o077)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

class Inputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}
    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag == 'input' and attr.get('name'):
            self.values[attr['name']] = attr.get('value', '')

context = ssl.create_default_context(cafile=str(ROOT/'config/tls/public-ip.crt'))
opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
checks = []

def cookies(user):
    data = json.loads((ROOT/f'state/acceptance/browser/{user}.json').read_text())
    return {c['name']: c['value'] for c in data['cookies']
            if c['domain'].lstrip('.') == urllib.parse.urlsplit(BASE).hostname}

def request(jar, path, method='GET', headers=None, form=None):
    parsed = urllib.parse.urlsplit(path)
    target = BASE + parsed.path + ('?'+parsed.query if parsed.query else '')
    fields = {'Cookie': '; '.join(k+'='+v for k, v in jar.items()), 'Origin': BASE}
    fields.update(headers or {})
    data = None
    if method == 'POST':
        fields['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(form or {}).encode()
    req = urllib.request.Request(target, data=data, headers=fields, method=method)
    try:
        response = opener.open(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read()

def check(name, passed, status=None):
    checks.append({'name': name, 'passed': bool(passed), 'httpStatus': status})
    print(('PASS ' if passed else 'FAIL ')+name+(f' ({status})' if status else ''))

def denied(name, result):
    status, headers, body = result
    check(name, status == 404 and body == b'Not Found\n' and
          not headers.get('Content-Disposition') and 'no-store' in headers.get('Cache-Control',''), status)

report = json.loads((ROOT/'state/permissions-acceptance.json').read_text())
fixture = report['fixtures']['files']['a_secret']
download = urllib.parse.urlsplit(fixture['downloadUrl']).path
parts = download.split('/')
key, phid = parts[3:5]
data_path = download.replace('/file/download/', '/file/data/', 1)
xform = '/file/xform/preview/'+phid+'/'+key+'/'
paths = {
    'download': download, 'data': data_path,
    'download-instance': download.replace('/file/download/', '/file/download/@acceptance/', 1),
    'data-instance': data_path.replace('/file/data/', '/file/data/@acceptance/', 1),
    'xform': xform, 'xform-instance': xform.replace('/file/xform/', '/file/xform/@acceptance/', 1),
    'encoded-data': data_path.replace('/file/', '/%66ile/', 1),
    'routed-query-data': '/?__path__='+urllib.parse.quote(data_path,safe=''),
    'encoded-routed-query-data': '/?%5f%5fpath%5f%5f='+urllib.parse.quote(data_path,safe=''),
}

try:
    # Read fixture-only derivative/builtin URLs through the internal CLI. Keep
    # these bearer values in memory, with no command-line or report exposure.
    php = '''<?php
require_once '/opt/phorge/phorge/scripts/__init_script__.php';
$viewer = PhabricatorUser::getOmnipotentUser();
$derived = id(new PhabricatorFileQuery())->setViewer($viewer)
  ->withNames(array('ACC26-G04-derived-policy.txt'))->executeOne();
$builtin = id(new PhabricatorFileQuery())->setViewer($viewer)
  ->withIsBuiltin(true)->withIsDeleted(false)->setLimit(1)->executeOne();
$avatar = id(new PhabricatorFileQuery())->setViewer($viewer)
  ->withNames(array('ACC26-G04-standalone-avatar.png'))->executeOne();
echo json_encode(array('derived' => (string)$derived->getDownloadURI(),
  'derivedPHID' => $derived->getPHID(), 'derivedID' => $derived->getID(),
  'avatar' => $avatar ? (string)$avatar->getBestURI() : null,
  'builtin' => (string)$builtin->getBestURI()));
'''
    obtained = subprocess.run([str(ROOT/'scripts/compose.sh'), 'exec', '-T', 'phorge', 'php'],
                              input=php, text=True, capture_output=True, check=True)
    resources = json.loads(obtained.stdout)
    paths['profile-derived'] = resources['derived']
    jars = {u: cookies(u) for u in ('test_admin', 'b_member', 'guest')}
    for user, jar in jars.items():
        status, _, _ = request(jar, '/settings/user/'+user+'/')
        check(user+' valid matching session', status == 200, status)
    if not all(c['passed'] for c in checks):
        raise RuntimeError('Baseline unavailable')

    # The real primary-domain download form supplies the legitimate CSRF token.
    status, _, body = request(jars['test_admin'], download)
    inputs = Inputs()
    inputs.feed(body.decode(errors='replace'))
    check('authorized primary-domain GET shows download confirmation',
          status == 200 and '__csrf__' in inputs.values, status)
    status, headers, body = request(jars['test_admin'], download, 'POST', form=inputs.values)
    check('authorized actual confirmation POST downloads exact original bytes',
          status == 200 and hashlib.sha256(body).hexdigest() == fixture['sha256'] and
          len(body) == fixture['bytes'], status)
    check('actual binary POST response is private no-store',
          'private' in headers.get('Cache-Control','') and 'no-store' in headers.get('Cache-Control',''), status)

    def conduit(jar, token, method, params):
        status, _, body = request(jar, '/api/'+method, 'POST', form={
            '__csrf__':token, '__form__':'1', 'params':json.dumps(params), 'output':'json'})
        return status, json.loads(body)

    status, api_result = conduit(jars['test_admin'], inputs.values['__csrf__'],
                                'file.download', {'phid':resources['derivedPHID']})
    check('authorized Conduit can download source-restricted derivative',
          status == 200 and not api_result.get('error_code') and bool(api_result.get('result')),status)
    status, api_result = conduit(jars['test_admin'], inputs.values['__csrf__'],
                                'file.search', {'constraints':{'ids':[int(resources['derivedID'])]}})
    check('authorized Conduit search finds source-restricted derivative',
          status == 200 and not api_result.get('error_code') and bool(api_result['result']['data']),status)
    status, _, body = request(jars['test_admin'], '/F'+str(resources['derivedID']))
    check('authorized file detail exposes derivative',
          status == 200 and b'ACC26-G04-derived-policy.txt' in body,status)

    status, headers, body = request(jars['test_admin'], data_path,
                                    headers={'X-Phabricator-Request-Type':'git-lfs', 'Range':'bytes=0-7'})
    check('authorized Range and Git LFS request returns requested bytes',
          status == 206 and body == b'ACC26FIL' and 'no-store' in headers.get('Cache-Control',''), status)
    for kind in ('data-instance', 'download-instance', 'encoded-data',
                 'routed-query-data', 'encoded-routed-query-data'):
        status, headers, body = request(jars['test_admin'], paths[kind],
                                   headers={'X-Phabricator-Request-Type':'git-lfs'})
        check('authorized supported route '+kind,
              status == 200 and hashlib.sha256(body).hexdigest() == fixture['sha256'] and
              'no-store' in headers.get('Cache-Control',''),status)
    status, headers, body = request(jars['test_admin'], paths['profile-derived'],
                                     headers={'X-Phabricator-Request-Type':'git-lfs'})
    check('authorized source viewer can retrieve profile derivative',
          status == 200 and body == b'G04 synthetic profile derivative.\n' and
          'no-store' in headers.get('Cache-Control',''),status)

    for user in ('b_member', 'guest'):
        status, _, csrf_body = request(jars[user], '/logout/')
        user_inputs = Inputs()
        user_inputs.feed(csrf_body.decode(errors='replace'))
        check(user+' obtains own valid form token without logging out',
              status == 200 and '__csrf__' in user_inputs.values,status)
        user_form = {'__csrf__':user_inputs.values['__csrf__'], '__form__':'1', '__dialog__':'1'}
        status, api_result = conduit(jars[user], user_inputs.values['__csrf__'], 'user.whoami', {})
        check(user+' own CSRF accepted by authenticated Conduit',
              status == 200 and not api_result.get('error_code') and api_result['result']['userName']==user,status)
        status, api_result = conduit(jars[user], user_inputs.values['__csrf__'],
                                    'file.download', {'phid':resources['derivedPHID']})
        check(user+' Conduit derivative download denied without bytes',
              status == 200 and bool(api_result.get('error_code')) and api_result.get('result') is None,status)
        status, api_result = conduit(jars[user], user_inputs.values['__csrf__'],
                                    'file.search', {'constraints':{'ids':[int(resources['derivedID'])]}})
        check(user+' Conduit search cannot discover restricted derivative',
              status == 200 and not api_result.get('error_code') and api_result['result']['data']==[],status)
        status, _, body = request(jars[user], '/F'+str(resources['derivedID']))
        check(user+' file detail cannot disclose derivative name or bytes',
              status in (200,403,404) and b'ACC26-G04-derived-policy.txt' not in body and
              b'G04 synthetic profile derivative.' not in body,status)
        status, _, body = request(jars[user], resources['avatar'])
        check(user+' ordinary standalone public avatar remains readable',
              status == 200 and body.startswith(b'\x89PNG\r\n\x1a\n'),status)
        for kind, path in paths.items():
            denied(user+' GET '+kind, request(jars[user], path))
            denied(user+' valid-CSRF POST '+kind, request(jars[user], path, 'POST', form=user_form))
        denied(user+' Git LFS shortcut', request(jars[user], download,
               headers={'X-Phabricator-Request-Type':'git-lfs'}))
        denied(user+' Range shortcut', request(jars[user], data_path,
               headers={'X-Phabricator-Request-Type':'git-lfs', 'Range':'bytes=0-7'}))
        denied(user+' conditional request cannot obtain 304 cache reuse', request(jars[user], data_path,
               headers={'If-Modified-Since':'Wed, 01 Jan 2031 00:00:00 GMT'}))

    entry_only = {k:v for k,v in jars['test_admin'].items() if k not in ('phsid','phusr')}
    for kind, path in paths.items():
        denied('entry only, no Phorge session '+kind, request(entry_only, path,
               headers={'X-Phabricator-Request-Type':'git-lfs'}))
    probe_path = ROOT/'state/acceptance/browser/public_signup_probe.json'
    if probe_path.exists():
        probe = cookies('public_signup_probe')
        status, _, body = request(probe, '/settings/user/public_signup_probe/')
        check('unapproved fixture is actually waiting for approval',
              status == 200 and b'approval' in body.lower(),status)
        for kind, path in paths.items():
            denied('unapproved Phorge account '+kind, request(probe, path,
                   headers={'X-Phabricator-Request-Type':'git-lfs'}))
    status, _, body = request(entry_only, resources['builtin'],
                              headers={'X-Phabricator-Request-Type':'git-lfs'})
    check('entry-only login builtin resource remains available', status == 200 and bool(body),status)
except Exception as error:
    # HTTP errors can include bearer URLs. Keep the exception message private.
    check('suite completed without unexpected operation failure',False)
finally:
    result = {'verifiedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'passed': bool(checks) and all(c['passed'] for c in checks), 'checks': checks,
              'scope':'Real public-IP HTTP; authorized binary POST and denied raw/derived file requests; no session mutation'}
    (ROOT/'state/acceptance/file-policy-http.json').write_text(json.dumps(result,indent=2)+'\n')
raise SystemExit(0 if result['passed'] else 1)
