#!/usr/bin/env python3
"""Public registration applications. This service never grants login access."""
from dataclasses import dataclass
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import time
import unicodedata
from urllib.parse import parse_qs, urlsplit
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from credential_hashes import hash_password, validate_password, valid_hash

COOKIE = '__Host-registration_csrf'
MAX_BODY = 8192
TOKEN_SECONDS = 1800
SCHEMA = '''
CREATE TABLE IF NOT EXISTS org_units (
  org_unit_id TEXT PRIMARY KEY,
  parent_org_unit_id TEXT REFERENCES org_units(org_unit_id),
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS registrations (
  registration_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  approved_at INTEGER,
  approved_by TEXT,
  approval_note TEXT,
  phorge_username TEXT,
  phorge_phid TEXT,
  password_hash TEXT,
  org_unit_id TEXT REFERENCES org_units(org_unit_id),
  manager_user_id TEXT,
  position TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS registrations_live_phone ON registrations(phone)
  WHERE status IN ('pending','approved');
CREATE UNIQUE INDEX IF NOT EXISTS registrations_live_email ON registrations(email)
  WHERE status IN ('pending','approved');
CREATE TABLE IF NOT EXISTS request_limits (
  bucket TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
'''


def connect_db(path):
    connection = sqlite3.connect(str(path), timeout=5, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    connection.execute('PRAGMA busy_timeout=5000')
    return connection


def initialize_db(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    connection = connect_db(path)
    try:
        connection.execute('PRAGMA journal_mode=WAL')
        connection.executescript(SCHEMA)
        columns = {row['name'] for row in connection.execute('PRAGMA table_info(registrations)')}
        if 'password_hash' not in columns:
            connection.execute('ALTER TABLE registrations ADD COLUMN password_hash TEXT')
    finally:
        connection.close()
    path.chmod(0o600)


def has_controls(value):
    return any(unicodedata.category(c).startswith('C') for c in value)


def normalize_phone(value):
    if not isinstance(value, str) or len(value) > 40 or has_controls(value):
        raise ValueError('请填写有效的手机号。')
    if not re.fullmatch(r'[+0-9 ()\-\u00a0]+', value.strip()):
        raise ValueError('请填写有效的手机号。')
    value = re.sub(r'[ ()\-\u00a0]', '', value.strip())
    if value.startswith('0086'):
        value = '+86' + value[4:]
    if value.startswith('+86'):
        if not re.fullmatch(r'1[3-9][0-9]{9}', value[3:]):
            raise ValueError('请填写有效的大陆手机号。')
        value = value[3:]
    if re.fullmatch(r'1[3-9][0-9]{9}', value):
        return value
    if re.fullmatch(r'\+[1-9][0-9]{7,14}', value):
        return value
    raise ValueError('请填写大陆手机号，或带国家区号的有效手机号。')


def normalize_email(value):
    if not isinstance(value, str) or has_controls(value):
        raise ValueError('请填写有效的邮箱地址。')
    value = value.strip().casefold()
    if len(value) > 128 or value.count('@') != 1:
        raise ValueError('请填写有效的邮箱地址。')
    local, domain = value.split('@')
    if (not re.fullmatch(r'[a-z0-9_+.!-]{1,64}', local)
            or local.startswith('.') or local.endswith('.') or '..' in local):
        raise ValueError('请填写有效的邮箱地址。')
    try:
        domain = domain.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('请填写有效的邮箱地址。') from None
    parts = domain.split('.')
    if len(parts) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in parts):
        raise ValueError('请填写有效的邮箱地址。')
    value = local+'@'+domain
    if len(value) > 128:
        raise ValueError('请填写有效的邮箱地址。')
    return value


def validate_name(value):
    if not isinstance(value, str) or has_controls(value):
        raise ValueError('请填写真实姓名，不能包含控制字符。')
    value = value.strip()
    if not 1 <= len(value) <= 80:
        raise ValueError('姓名长度应为 1 至 80 个字符。')
    return value


@dataclass
class Settings:
    database: Path
    warden_file: Path
    secret: bytes
    origin: str = 'https://45.77.36.106'
    trusted_proxy: str = '172.30.10.2'
    post_ip_limit: int = 20
    post_global_limit: int = 200
    max_pending: int = 1000

    def __post_init__(self):
        parsed = urlsplit(self.origin)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username:
            raise ValueError('Registration origin must be an HTTPS origin without path or credentials')
        if len(self.secret) < 32:
            raise ValueError('Registration CSRF secret must be at least 32 bytes')
        ipaddress.ip_address(self.trusted_proxy)


class Application:
    def __init__(self, settings):
        self.settings = settings
        initialize_db(settings.database)

    def csrf(self, now=None):
        now = int(time.time()) if now is None else now
        unsigned = str(now)+'.'+secrets.token_hex(24)
        return unsigned+'.'+hmac.new(self.settings.secret, unsigned.encode(), hashlib.sha256).hexdigest()

    def valid_csrf(self, token, cookie, now=None):
        now = int(time.time()) if now is None else now
        if (not isinstance(token, str) or not isinstance(cookie, str)
                or not token or not cookie or not token.isascii() or not cookie.isascii()
                or len(token) > 200 or not hmac.compare_digest(token, cookie)):
            return False
        try:
            timestamp, nonce, signature = token.split('.')
            issued = int(timestamp)
        except (ValueError, TypeError):
            return False
        if issued > now+30 or now-issued > TOKEN_SECONDS or not re.fullmatch('[0-9a-f]{48}', nonce):
            return False
        expected = hmac.new(self.settings.secret, (timestamp+'.'+nonce).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)

    def rate_allowed(self, client_ip, method, now=None):
        now = int(time.time()) if now is None else now
        window = 3600 if method == 'POST' else 300
        count_limit = self.settings.post_ip_limit if method == 'POST' else 120
        global_limit = self.settings.post_global_limit if method == 'POST' else 2400
        subject = hmac.new(self.settings.secret, client_ip.encode(), hashlib.sha256).hexdigest()
        buckets = [('client:'+method+':'+subject, count_limit), ('global:'+method, global_limit)]
        connection = connect_db(self.settings.database)
        try:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('DELETE FROM request_limits WHERE expires_at <= ?', (now,))
            for key, maximum in buckets:
                row = connection.execute('SELECT count FROM request_limits WHERE bucket=?', (key,)).fetchone()
                if row and row['count'] >= maximum:
                    connection.rollback()
                    return False
            for key, _ in buckets:
                connection.execute('INSERT INTO request_limits(bucket,count,expires_at) VALUES(?,1,?) '
                                   'ON CONFLICT(bucket) DO UPDATE SET count=count+1', (key, now+window))
            connection.commit()
            return True
        finally:
            connection.close()

    def submit(self, phone, email, name, password_hash):
        if not valid_hash(password_hash):
            raise ValueError('Invalid password credential')
        # This file is mounted read-only. No HTTP request can activate an identity.
        directory = json.loads(self.settings.warden_file.read_text())
        if not isinstance(directory, list) or any(not isinstance(u, dict) for u in directory):
            raise ValueError('Invalid authoritative identity directory')
        for user in directory:
            current_mail = user.get('mail', '')
            current_phone = user.get('phone', '')
            if current_mail and normalize_email(current_mail) == email:
                return
            if current_phone and normalize_phone(current_phone) == phone:
                return
        connection = connect_db(self.settings.database)
        try:
            connection.execute('BEGIN IMMEDIATE')
            existing = connection.execute("SELECT 1 FROM registrations WHERE status IN ('pending','approved') "
                                          'AND (phone=? OR email=?)', (phone, email)).fetchone()
            if existing:
                connection.rollback()
                return
            count = connection.execute("SELECT count(*) FROM registrations WHERE status='pending'").fetchone()[0]
            if count >= self.settings.max_pending:
                connection.rollback()
                raise OverflowError('Registration queue capacity reached')
            identifier = str(uuid.uuid4())
            now = int(time.time())
            connection.execute('INSERT INTO registrations(registration_id,user_id,phone,email,name,status,created_at,updated_at,password_hash) '
                               "VALUES(?,?,?,?,?,'pending',?,?,?)", (identifier, 'reg-'+identifier, phone, email, name, now, now, password_hash))
            connection.commit()
        finally:
            connection.close()


def render_form(token, submitted=False, error=''):
    message = ('<p class="notice" role="status">注册申请已提交。管理员审核通过后，您才可以登录。'
               '如果资料已登记，现有账户和申请会保持不变。</p>') if submitted else ''
    if error:
        message += '<p class="error" role="alert">'+html.escape(error)+'</p>'
    return '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>注册账户</title>
<style>body{margin:0;background:#f4f7fa;color:#172033;font:16px/1.6 system-ui,sans-serif}main{max-width:460px;margin:7vh auto;padding:32px;background:white;border:1px solid #dde4ec;border-radius:14px}h1{margin:0 0 8px;font-size:28px}p{color:#536078}label{display:block;margin-top:18px;font-weight:600}input{box-sizing:border-box;width:100%;padding:12px;font:inherit;border:1px solid #bac5d4;border-radius:7px}button{width:100%;margin-top:24px;padding:13px;background:#2463c7;border:0;border-radius:7px;color:white;font:inherit;cursor:pointer}.notice{background:#eaf5ee;padding:12px;color:#235837}.error{color:#a32424}a{color:#2463c7}small{color:#617087}@media(max-width:540px){main{margin:20px 14px;padding:24px}}</style>
</head><body><main><h1>注册账户</h1><p>填写手机号、邮箱和姓名，并设置登录密码。管理员审核通过后，可以使用账号密码登录；钉钉验证码通道保留。</p>'''+message+'''
<form method="post" action="/_register">
<input type="hidden" name="csrf" value="'''+html.escape(token, quote=True)+'''">
<label for="name">姓名</label><input id="name" name="name" maxlength="80" autocomplete="name" required>
<label for="phone">手机号</label><input id="phone" name="phone" type="tel" maxlength="40" autocomplete="tel" required placeholder="手机号或 +86 手机号">
<label for="email">邮箱</label><input id="email" name="email" type="email" maxlength="128" autocomplete="email" required>
<label for="password">登录密码</label><input id="password" name="password" type="password" minlength="15" maxlength="256" autocomplete="new-password" required aria-describedby="password-help">
<small id="password-help">至少 15 个字符，最多 128 个字符。可以使用多个词组成的长密码，空格会保留。</small>
<label for="password_confirm">确认密码</label><input id="password_confirm" name="password_confirm" type="password" minlength="15" maxlength="256" autocomplete="new-password" required>
<button type="submit">提交注册申请</button></form>
<p><small>部门、上下级及职务信息将由管理员后续维护。提交申请不会自动授予项目访问权限。</small></p>
<p>已有账户？<a href="/_login">前往登录</a></p></main></body></html>'''


def handler_for(app):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        server_version = 'Registration'
        sys_version = ''

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass  # No request path, headers, form contents, phone or email logs.

        def send(self, status, body='', headers=None):
            if isinstance(body, str):
                body = body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # Chromium suppresses native POST Origin under no-referrer. Keep
            # same-origin form submissions attributable; external refs omitted.
            self.send_header('Referrer-Policy', 'same-origin')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header('Connection', 'close')
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def trusted(self):
            return (self.client_address[0] == app.settings.trusted_proxy
                    and len(self.headers.get_all('Host', [])) == 1
                    and len(self.headers.get_all('X-Forwarded-Proto', [])) == 1
                    and self.headers.get('Host') == urlsplit(app.settings.origin).netloc
                    and self.headers.get('X-Forwarded-Proto') == 'https')

        def client_ip(self):
            candidate = self.headers.get('X-Forwarded-For', self.client_address[0]).split(',')[-1].strip()
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                return self.client_address[0]

        def page(self, status=200, error='', submitted=False):
            token = app.csrf()
            self.send(status, render_form(token, submitted, error),
                      {'Set-Cookie': COOKIE+'='+token+'; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age='+str(TOKEN_SECONDS)})

        def do_GET(self):
            if self.path == '/healthz':
                if self.client_address[0] not in ('127.0.0.1', '::1'):
                    return self.send(404)
                try:
                    connection = connect_db(app.settings.database)
                    connection.execute('SELECT 1 FROM registrations LIMIT 1')
                    connection.close()
                    return self.send(200, 'ready')
                except sqlite3.Error:
                    return self.send(503)
            parsed = urlsplit(self.path)
            if parsed.path != '/_register' or len(parsed.query) > 128:
                return self.send(404)
            if not self.trusted():
                return self.send(403)
            try:
                if not app.rate_allowed(self.client_ip(), 'GET'):
                    return self.send(429, '请求过于频繁，请稍后再试。', {'Retry-After': '300'})
                self.page(submitted=parsed.query == 'submitted=1')
            except (OSError, sqlite3.Error):
                self.send(503, '注册服务暂不可用，请稍后再试。')

        def do_POST(self):
            if self.path != '/_register':
                return self.send(404)
            if not self.trusted() or len(self.headers.get_all('Origin', [])) != 1 or self.headers.get('Origin') != app.settings.origin:
                return self.send(403, '请从本站注册页面提交申请。')
            if self.headers.get('Sec-Fetch-Site') not in (None, 'same-origin'):
                return self.send(403)
            if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/x-www-form-urlencoded':
                return self.send(415)
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                return self.send(400)
            length = int(lengths[0])
            if length < 1 or length > MAX_BODY:
                return self.send(413)
            try:
                if not app.rate_allowed(self.client_ip(), 'POST'):
                    return self.send(429, '请求过于频繁，请稍后再试。', {'Retry-After': '3600'})
                body = self.rfile.read(length)
                if len(body) != length:
                    return self.send(400)
                fields = parse_qs(body.decode('utf-8', 'strict'), keep_blank_values=True, strict_parsing=True, max_num_fields=6)
                if set(fields) != {'csrf', 'name', 'phone', 'email', 'password', 'password_confirm'} or any(len(v) != 1 for v in fields.values()):
                    return self.page(400, '请填写手机号、邮箱、姓名、密码及密码确认。')
                jar = cookies.SimpleCookie()
                jar.load(self.headers.get('Cookie', ''))
                token_cookie = jar[COOKIE].value if COOKIE in jar else ''
                if not app.valid_csrf(fields['csrf'][0], token_cookie):
                    return self.page(403, '页面已过期，请重新填写并提交。')
                try:
                    phone = normalize_phone(fields['phone'][0])
                    email = normalize_email(fields['email'][0])
                    name = validate_name(fields['name'][0])
                    password = fields['password'][0]
                    validate_password(password)
                    if password != fields['password_confirm'][0]:
                        raise ValueError('两次输入的密码不一致。')
                except ValueError as error:
                    return self.page(400, str(error))
                try:
                    credential = hash_password(password)
                    app.submit(phone, email, name, credential)
                except (OSError, ValueError, OverflowError, sqlite3.Error):
                    return self.send(503, '注册服务暂不可用，请稍后再试。')
                self.send(303, headers={'Location': '/_register?submitted=1'})
            except (ValueError, UnicodeError, cookies.CookieError):
                self.page(400, '提交格式不正确，请重新填写。')
            except (OSError, sqlite3.Error):
                self.send(503, '注册服务暂不可用，请稍后再试。')

    return Handler


class RegistrationHTTPServer(ThreadingHTTPServer):
    def handle_error(self, _request, _client_address):
        # socketserver's default handler prints client IP and exception details.
        # No request data belongs in this public service's logs.
        pass


if __name__ == '__main__':
    os.umask(0o077)
    application = Application(Settings(
        database=Path(os.environ.get('REGISTRATION_DATABASE', '/data/registrations.sqlite3')),
        warden_file=Path(os.environ.get('REGISTRATION_WARDEN_FILE', '/warden/users.json')),
        secret=Path(os.environ.get('REGISTRATION_CSRF_KEY_FILE', '/run/secrets/registration_csrf_key')).read_bytes(),
        origin=os.environ.get('REGISTRATION_ORIGIN', 'https://45.77.36.106'),
        trusted_proxy=os.environ.get('REGISTRATION_TRUSTED_PROXY', '172.30.10.2'),
    ))
    server = RegistrationHTTPServer(('0.0.0.0', 8085), handler_for(application))
    server.serve_forever()
