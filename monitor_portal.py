#!/usr/bin/env python3
"""Web Security Workbench v5: localhost-only unified owner monitoring prototype.

Read-only, verified-domain HTTPS header checks. No active exploitation.
"""
import base64
import contextlib
import datetime as dt
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import socket
import sqlite3
import ssl
import threading
import time
from email.message import EmailMessage
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo
import v5_suite as suite
import v5_features as v5
import v5_ux as ux
import v5_traffic as traffic

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / 'monitor_data'
DB_FILE = DATA_DIR / 'monitor.sqlite3'
HOST, PORT = '127.0.0.1', 18771
UTC = dt.timezone.utc
FREQUENCIES = {'daily', 'weekly', 'monthly'}
TIMEZONES = ('America/Toronto', 'America/Vancouver', 'America/Edmonton', 'America/Winnipeg',
             'America/Halifax', 'America/St_Johns', 'UTC')
MAX_BODY = 8192
USER_AGENT = 'WebSecurityWorkbench-Monitor/5.0 (+authorized verification)'
LOGIN_ATTEMPTS = {}
LOGIN_LOCK = threading.Lock()


def demo_mode_enabled():
    # Explicit opt-in. NEVER enable this for a public-facing deployment.
    return os.environ.get('MONITOR_DEMO_MODE') == '1'


def is_demo_user(email):
    return email.startswith('demo-') and email.endswith('@local.invalid')


def utcnow():
    return dt.datetime.now(UTC)


def iso(t=None):
    return (t or utcnow()).astimezone(UTC).isoformat(timespec='seconds')


def esc(s):
    return html.escape(str(s), quote=True)


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000)
    return 'pbkdf2_sha256$310000$' + base64.b64encode(salt).decode() + '$' + base64.b64encode(digest).decode()


def password_ok(password, stored):
    try:
        alg, iters, salt, expected = stored.split('$')
        if alg != 'pbkdf2_sha256' or int(iters) > 600000:
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), base64.b64decode(salt), int(iters))
        return hmac.compare_digest(actual, base64.b64decode(expected))
    except (ValueError, TypeError):
        return False


@contextlib.contextmanager
def db():
    con = sqlite3.connect(str(DB_FILE), timeout=15)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    with db() as con:
        con.execute('PRAGMA journal_mode=WAL')
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf TEXT NOT NULL, expires_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            host TEXT NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0,
            verification_token TEXT NOT NULL, verified_at TEXT,
            frequency TEXT NOT NULL, timezone TEXT NOT NULL, send_hour INTEGER NOT NULL DEFAULT 9,
            email_updates INTEGER NOT NULL DEFAULT 1, urgent_alerts INTEGER NOT NULL DEFAULT 1,
            next_run_at TEXT NOT NULL, last_checked_at TEXT, last_status TEXT,
            UNIQUE(user_id, host));
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL, trigger TEXT NOT NULL, status TEXT NOT NULL,
            findings_json TEXT NOT NULL, summary TEXT NOT NULL, ai_used INTEGER NOT NULL,
            evidence_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL,
            scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
            detail TEXT NOT NULL);
        ''')
    os.chmod(DB_FILE, 0o600)
    v5.init_schema(db)
    traffic.init_schema(db)


def normalize_host(value):
    value = value.strip().lower().rstrip('.')
    if len(value) > 253 or len(value) < 4 or any(c in value for c in '/:@?#\\'):
        raise ValueError('Enter a domain only, e.g. shop.yourbusiness.com (no URL or port).')
    if not re.fullmatch(r'(?=.{4,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)+', value):
        raise ValueError('Invalid domain name.')
    labels = value.split('.')
    if any(x.startswith('-') or x.endswith('-') or len(x) > 63 for x in labels):
        raise ValueError('Invalid domain label.')
    if value.endswith(('.local', '.localhost', '.internal', '.test', '.example', '.invalid')):
        raise ValueError('Reserved or local domains cannot be scanned.')
    try:
        ipaddress.ip_address(value)
        raise ValueError('IP addresses are not accepted.')
    except ValueError as e:
        if str(e) == 'IP addresses are not accepted.':
            raise
    return value


def resolve_public_ip(host):
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    ips = sorted({info[4][0] for info in infos})
    if not ips or len(ips) > 20:
        raise ValueError('DNS did not return a usable public address.')
    if not all(ipaddress.ip_address(ip).is_global for ip in ips):
        raise ValueError('DNS contains a non-public address. Request blocked.')
    return ips[0]


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, hostname, ip, timeout=7):
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())
        self.pinned_ip = ip

    def connect(self):
        raw = socket.create_connection((self.pinned_ip, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def fetch_https(host, path='/', max_bytes=0):
    """Only GET https://<verified public hostname>:443/<fixed path>; no redirects."""
    if path not in ('/', '/.well-known/security-workbench-verification.txt', '/openapi.json', '/swagger.json', '/.well-known/openapi.json'):
        raise ValueError('Path is not approved.')
    ip = resolve_public_ip(host)
    conn = PinnedHTTPS(host, ip)
    try:
        conn.request('GET', path, headers={'Host': host, 'User-Agent': USER_AGENT,
                                           'Accept': 'text/plain, text/html;q=0.8',
                                           'Connection': 'close'})
        cert = conn.sock.getpeercert()
        response = conn.getresponse()
        headers = [(k.lower(), v) for k, v in response.getheaders()]
        body = response.read(max_bytes + 1) if max_bytes else b''
        return {'status': response.status, 'headers': headers, 'body': body[:max_bytes],
                'cert_not_after': cert.get('notAfter')}
    finally:
        conn.close()


def verify_site(host, token):
    result = fetch_https(host, '/.well-known/security-workbench-verification.txt', max_bytes=512)
    expected = ('workbench-verification=' + token).encode()
    return result['status'] == 200 and hmac.compare_digest(result['body'].strip(), expected)


def next_due(freq, timezone, hour=9, now=None):
    if freq not in FREQUENCIES or timezone not in TIMEZONES or not (0 <= hour <= 23):
        raise ValueError('Invalid schedule.')
    now = now or utcnow()
    local = now.astimezone(ZoneInfo(timezone))
    for offset in range(0, 40):
        day = local.date() + dt.timedelta(days=offset)
        if freq == 'weekly' and day.weekday() != 0:
            continue
        if freq == 'monthly' and day.day != 1:
            continue
        candidate = dt.datetime.combine(day, dt.time(hour=hour), ZoneInfo(timezone))
        if candidate.astimezone(UTC) > now:
            return iso(candidate)
    raise RuntimeError('Could not calculate next assessment.')


def baseline_findings(response):
    headers = response['headers']
    values = {}
    for key, value in headers:
        values.setdefault(key, []).append(value)
    findings = []
    if 300 <= response['status'] < 400:
        findings.append({'severity': 'advisory', 'title': 'Website redirects; destination not inspected',
                         'fix': 'Review the redirect destination separately within approved scope.'})
    if response['status'] >= 400:
        findings.append({'severity': 'warning', 'title': 'Website returned an HTTP error',
                         'fix': 'Investigate the response status and application or hosting logs.'})
    for name, label, fix in (
        ('content-security-policy', 'Content Security Policy not observed', 'Configure an appropriate Content-Security-Policy.'),
        ('x-content-type-options', 'X-Content-Type-Options not observed', 'Set X-Content-Type-Options: nosniff.'),
        ('referrer-policy', 'Referrer-Policy not observed', 'Set a suitable Referrer-Policy.'),
    ):
        if name not in values:
            findings.append({'severity': 'advisory', 'title': label, 'fix': fix})
    for cookie in values.get('set-cookie', []):
        lc = cookie.lower()
        if 'secure' not in [x.strip().split('=')[0] for x in lc.split(';')[1:]]:
            findings.append({'severity': 'warning', 'title': 'Cookie without Secure flag observed',
                             'fix': 'Set Secure on cookies delivered over HTTPS.'})
        if 'httponly' not in [x.strip().split('=')[0] for x in lc.split(';')[1:]]:
            findings.append({'severity': 'advisory', 'title': 'Cookie without HttpOnly flag observed',
                             'fix': 'Use HttpOnly on session cookies where JavaScript access is unnecessary.'})
    expiry = response.get('cert_not_after')
    days = None
    if expiry:
        days = int((ssl.cert_time_to_seconds(expiry) - time.time()) / 86400)
        if days <= 14:
            findings.append({'severity': 'warning', 'title': 'TLS certificate expires soon',
                             'fix': 'Renew the TLS certificate before expiration.'})
    evidence = {'http_status': response['status'], 'certificate_days_remaining': days,
                'checked_header_names': sorted(values.keys()), 'method': 'HTTPS GET /; headers only',
                'scope': 'Verified domain; no redirects; no active exploitation'}
    return findings, evidence


def deterministic_summary(status, findings):
    if status == 'unavailable':
        return 'The approved website could not be checked. Verify that it is online, that HTTPS works, and that ownership verification is still present. This is not proof of an attack.'
    if status == 'verification-lost':
        return 'Ownership verification could not be confirmed, so no website assessment was performed. Restore the verification file to resume monitoring.'
    if not findings:
        return 'No issues were observed in the limited HTTPS configuration checks. This does not establish that the website is free of vulnerabilities.'
    return (f'The limited HTTPS configuration check observed {len(findings)} item(s) worth reviewing. '
            'These are configuration observations, not confirmed SQL injection or other exploitable vulnerabilities. '
            'Review the recommendations and retest after changes.')


def ai_summary(status, findings):
    fallback = deterministic_summary(status, findings)
    key = os.environ.get('GEMINI_API_KEY', '').strip()
    if not key or status in ('unavailable', 'verification-lost'):
        return fallback, False
    model = os.environ.get('GEMINI_MODEL', 'gemini-3.5-flash-lite')
    if not re.fullmatch(r'[a-zA-Z0-9._-]{2,100}', model):
        return fallback, False
    # No customer name, hostname, URL, credentials, cookies, or page content is sent.
    safe = [{'severity': f['severity'], 'title': f['title']} for f in findings[:20]]
    prompt = ('You are writing a plain-English 70-word website security checkup for a nontechnical owner. '
              'Only summarize the evidence given. This is a LIMITED passive HTTPS configuration check, '
              'not a penetration test. Never claim the website is secure, breached, or SQLi-free. '
              'Mention the most useful next action. No markdown.\n' +
              json.dumps({'status': status, 'observations': safe}, ensure_ascii=True))
    payload = json.dumps({'contents': [{'parts': [{'text': prompt}]}],
                          'generationConfig': {'temperature': 0.2, 'maxOutputTokens': 220}}).encode()
    try:
        url = 'https://generativelanguage.googleapis.com/v1beta/models/' + quote(model) + ':generateContent'
        req = Request(url, data=payload, method='POST',
                      headers={'Content-Type': 'application/json', 'x-goog-api-key': key})
        with urlopen(req, timeout=12) as res:
            data = json.loads(res.read(32000))
        text = data['candidates'][0]['content']['parts'][0]['text'].strip()
        if not 20 <= len(text) <= 1600:
            return fallback, False
        return text, True
    except (Exception):
        return fallback, False


def perform_assessment(site):
    if site['is_demo']:
        findings = [
            {'severity': 'advisory', 'title': 'Demo: Content Security Policy not observed',
             'fix': 'Add a Content-Security-Policy appropriate for your application.'},
            {'severity': 'advisory', 'title': 'Demo: Referrer-Policy not observed',
             'fix': 'Set an appropriate Referrer-Policy.'},
        ]
        return 'attention', findings, {'demo': True, 'network_requests': 0, 'http_status': 200}
    try:
        if not verify_site(site['host'], site['verification_token']):
            return 'verification-lost', [], {'note': 'Verification file missing or does not match; scan skipped'}
        result = fetch_https(site['host'], '/')
        findings, evidence = baseline_findings(result)
        status = 'attention' if findings else 'healthy'
        return status, findings, evidence
    except (OSError, ValueError, ssl.SSLError, http.client.HTTPException) as exc:
        return 'unavailable', [], {'error_type': type(exc).__name__, 'note': 'HTTPS check could not complete'}


def email_configured():
    return bool(os.environ.get('SMTP_HOST') and os.environ.get('SMTP_FROM'))


def send_email(to_address, subject, content):
    if not email_configured():
        raise RuntimeError('SMTP not configured')
    host = os.environ['SMTP_HOST']
    port = int(os.environ.get('SMTP_PORT', '587'))
    if port not in (465, 587):
        raise ValueError('Only SMTP TLS ports 465 and 587 are supported.')
    msg = EmailMessage()
    msg['From'] = os.environ['SMTP_FROM']
    msg['To'] = to_address
    msg['Subject'] = subject
    msg.set_content(content)
    if port == 465:
        client = smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(host, port, timeout=15)
    with client as smtp:
        if port == 587:
            smtp.starttls(context=ssl.create_default_context())
        username = os.environ.get('SMTP_USER', '')
        if username:
            smtp.login(username, os.environ.get('SMTP_PASSWORD', ''))
        smtp.send_message(msg)


def record_notification(user_id, site_id, scan_id, kind, status, detail):
    with db() as con:
        con.execute('INSERT INTO notifications(user_id,site_id,scan_id,created_at,kind,status,detail) VALUES(?,?,?,?,?,?,?)',
                    (user_id, site_id, scan_id, iso(), kind, status, detail[:250]))


def notify(user, site, scan_id, kind, summary, findings):
    if is_demo_user(user['email']):
        record_notification(user['id'], site['id'], scan_id, kind, 'demo-only',
                            'Demo accounts never send external email.')
        return False
    if not email_configured():
        record_notification(user['id'], site['id'], scan_id, kind, 'not-configured', 'Set up SMTP to deliver emails.')
        return False
    subject = ('[Action needed] ' if kind == 'urgent' else '[Security checkup] ') + site['host']
    lines = [f'Website: {site["host"]}', f'Update type: {kind}', '', summary, '', 'Observations:']
    lines += ['- ' + f['title'] + ' — ' + f['fix'] for f in findings[:20]] or ['- None in the limited checks.']
    lines += ['', 'This is a limited HTTPS configuration review, not a full penetration test.',
              'Open the local Web Security Workbench portal for the saved evidence.']
    try:
        send_email(user['email'], subject, '\n'.join(lines))
        record_notification(user['id'], site['id'], scan_id, kind, 'sent', 'Email submitted to SMTP server.')
        return True
    except Exception as exc:
        record_notification(user['id'], site['id'], scan_id, kind, 'failed', type(exc).__name__)
        return False


def run_scan(site_id, trigger='manual'):
    with db() as con:
        site = con.execute('SELECT * FROM sites WHERE id=?', (site_id,)).fetchone()
        if not site or (not site['is_demo'] and not site['verified_at']):
            raise ValueError('Verify ownership before scanning.')
        user = con.execute('SELECT id,email FROM users WHERE id=?', (site['user_id'],)).fetchone()
        old_status = site['last_status']
    status, findings, evidence = perform_assessment(site)
    summary, used_ai = ai_summary(status, findings)
    with db() as con:
        cur = con.execute('INSERT INTO scans(user_id,site_id,created_at,trigger,status,findings_json,summary,ai_used,evidence_json) '
                          'VALUES(?,?,?,?,?,?,?,?,?)',
                          (user['id'], site_id, iso(), trigger, status, json.dumps(findings), summary,
                           int(used_ai), json.dumps(evidence)))
        scan_id = cur.lastrowid
        con.execute('UPDATE sites SET last_checked_at=?,last_status=? WHERE id=?', (iso(), status, site_id))
    if trigger == 'scheduled' and site['email_updates']:
        notify(user, site, scan_id, 'digest', summary, findings)
    if (site['urgent_alerts'] and status in ('unavailable', 'verification-lost') and
            old_status not in ('unavailable', 'verification-lost')):
        notify(user, site, scan_id, 'urgent', summary, findings)
    return scan_id


def scheduler_once(now=None):
    now = now or utcnow()
    with db() as con:
        due = con.execute('SELECT * FROM sites WHERE next_run_at<=? AND (verified_at IS NOT NULL OR is_demo=1) '
                          'ORDER BY next_run_at LIMIT 10', (iso(now),)).fetchall()
        # Claim each job before doing network requests to avoid duplicate mail after a crash/restart.
        for site in due:
            con.execute('UPDATE sites SET next_run_at=? WHERE id=?',
                        (next_due(site['frequency'], site['timezone'], site['send_hour'], now), site['id']))
    for site in due:
        try:
            run_scan(site['id'], 'scheduled')
        except Exception as exc:
            print('Scheduled check failed:', type(exc).__name__, flush=True)
    return len(due)


def scheduler_loop(stop_event):
    while not stop_event.is_set():
        try:
            scheduler_once()
        except Exception as exc:
            print('Scheduler error:', type(exc).__name__, flush=True)
        stop_event.wait(45)


CSS = ux.CSS


def csrf_input(token):
    return '<input type="hidden" name="csrf" value="' + esc(token) + '">'


def layout(title, content, user=None, notice='', csrf='', nonce=''):
    if user:
        menu = ('<a href="/" class="nav-link">Overview</a>'
                '<details class="nav-drop"><summary>Security <span class="chev">⌄</span></summary>'
                '<div class="nav-pop"><a href="/security">Security Center<small>17 API &amp; web training modules</small></a>'
                '<a href="/">Website checkups<small>Verified domains and scheduled reports</small></a>'
                '</div></details>'
                '<details class="nav-drop"><summary>Insights <span class="chev">⌄</span></summary>'
                '<div class="nav-pop"><a href="/traffic">Traffic map<small>Visitors and flagged requests</small></a>'
                '<a href="/security">Saved security reports<small>Training evidence and AI explanations</small></a>'
                '</div></details>'
                '<span class="account-name" title="Signed-in account">' + esc(user['email']) + '</span>'
                '<form class="inline" action="/logout" method="post">' + csrf_input(csrf) +
                '<button class="alt">Sign out</button></form>')
    else:
        menu = '<a href="/login" class="nav-link">Sign in</a>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} · Web Security Workbench</title><style nonce="{nonce}">{CSS}</style></head>
<body><!-- v5.1 async UX compatibility preserved --><header><nav><a href="/" class="brand"><span class="brand-mark" aria-hidden="true">◈</span><span>Web Security Workbench<small>v5.4 · Security operations</small></span></a><div class="nav-actions">{menu}</div></nav></header>
<main class="wrap{' dashboard-home' if user and title == 'Customer security dashboard' else ''}"><div class="hero"><p class="eyebrow">Your security operations center</p><h1>{esc(title)}</h1><p>Website monitoring · API security · AI explanations · Traffic intelligence</p>
<div class="hero-chips"><span class="hero-chip">Local prototype</span><span class="hero-chip">Evidence-first</span><span class="hero-chip">Privacy-aware</span></div></div>
<div id="wb-status" role="status" aria-live="polite" hidden></div>
{('<div class="notice">'+esc(notice)+'</div>') if notice else ''}{content}
<div class="footer-note">Active security tests are synthetic localhost training only. Verified real domains receive limited read-only checks. Traffic geography requires imported authorized logs; IP locations are approximate. This prototype is not a public SaaS service or a full penetration test.</div></main>
<script nonce="{nonce}">{ux.JS}</script></body></html>'''


def session_from_cookie(handler):
    raw = handler.headers.get('Cookie', '')
    try:
        jar = SimpleCookie(); jar.load(raw)
        token = jar['monitor_session'].value if 'monitor_session' in jar else ''
    except Exception:
        return None, None
    if not re.fullmatch('[a-zA-Z0-9_-]{35,120}', token):
        return None, None
    with db() as con:
        row = con.execute('SELECT sessions.*,users.email FROM sessions JOIN users ON users.id=sessions.user_id '
                          'WHERE token_hash=? AND expires_at>?',
                          (hashlib.sha256(token.encode()).hexdigest(), iso())).fetchone()
    return row, token


def make_session(user_id):
    token = secrets.token_urlsafe(40)
    csrf = secrets.token_urlsafe(30)
    with db() as con:
        con.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)',
                    (hashlib.sha256(token.encode()).hexdigest(), user_id, csrf, iso(utcnow()+dt.timedelta(hours=12))))
    return token


def site_card(site, csrf):
    verified = bool(site['verified_at']) or site['is_demo']
    status = site['last_status'] or 'Not checked yet'
    out = f'''<div class="card"><h2>{esc(site['host'])} {'<span class="pill">DEMO</span>' if site['is_demo'] else ''}</h2>
<p><span class="pill">{esc(status)}</span> · {esc(site['frequency'].capitalize())} checkups · {esc(site['timezone'])}</p>
<p class="hint">Next scheduled check: {esc(site['next_run_at'].replace('T',' ')[:16])} UTC</p>'''
    if not verified:
        token = 'workbench-verification=' + site['verification_token']
        out += f'''<p>Before we make any network requests, prove you control this domain.</p>
<p>Publish a plain-text file at:<br><code>https://{esc(site['host'])}/.well-known/security-workbench-verification.txt</code></p>
<p>Exact file contents:</p><pre>{esc(token)}</pre>
<form class="inline" method="post" action="/verify">{csrf_input(csrf)}<input type="hidden" name="site_id" value="{site['id']}"><button>Verify ownership</button></form>'''
    else:
        out += f'''<form class="inline" method="post" action="/scan">{csrf_input(csrf)}<input type="hidden" name="site_id" value="{site['id']}"><button>Run checkup now</button></form>
<form class="inline" method="post" action="/api-discover">{csrf_input(csrf)}<input type="hidden" name="site_id" value="{site['id']}"><button class="alt">Discover documented APIs</button></form>
<a class="btn alt" href="/site?id={site['id']}">Reports &amp; settings</a>'''
    return out + '</div>'


class Handler(BaseHTTPRequestHandler):
    server_version = 'WorkbenchMonitor/5.0'

    def log_message(self, fmt, *args):
        # Do not log user-controlled paths or form values.
        pass

    def send_page(self, code, title, content, user=None, notice='', csrf='', cookies=()):
        nonce = secrets.token_urlsafe(16)
        body = layout(title, content, user, notice, csrf, nonce).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', f"default-src 'none'; style-src 'nonce-{nonce}' 'unsafe-inline'; script-src 'nonce-{nonce}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        for cookie in cookies:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, path, cookies=()):
        if not re.fullmatch(r'/[a-zA-Z0-9/?=&_-]*', path):
            path = '/'
        self.send_response(303)
        self.send_header('Location', path)
        self.send_header('Cache-Control', 'no-store')
        for cookie in cookies:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()

    def parse_post(self):
        if not self.headers.get('Content-Type', '').startswith('application/x-www-form-urlencoded'):
            raise ValueError('Expected a browser form submission.')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise ValueError('Invalid request length.')
        limit = 24576 if urlsplit(self.path).path == '/traffic-import' else MAX_BODY
        if not (0 < length <= limit):
            raise ValueError('Invalid request size.')
        values = parse_qs(self.rfile.read(length).decode('utf-8'), keep_blank_values=True)
        return {k: v[0] for k, v in values.items()}

    def anon_csrf(self):
        try:
            jar = SimpleCookie(); jar.load(self.headers.get('Cookie', ''))
            token = jar['monitor_anon'].value if 'monitor_anon' in jar else ''
        except Exception:
            token = ''
        if not re.fullmatch(r'[A-Za-z0-9_-]{30,120}', token):
            token = secrets.token_urlsafe(32)
        return token

    def do_GET(self):
        if self.headers.get('Host', '').lower() not in (f'127.0.0.1:{PORT}', f'localhost:{PORT}'):
            return self.send_page(403, 'Forbidden', '<p>Invalid local host.</p>')
        path = urlsplit(self.path)
        if path.path == '/health':
            data = b'{"service":"workbench-monitor","version":"5.4","localhost_only":true}'
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
            return
        session, _ = session_from_cookie(self)
        if not session:
            if path.path not in ('/', '/login', '/signup'):
                return self.redirect('/login')
            token = self.anon_csrf()
            if path.path == '/signup':
                form = f'''<div class="card"><h2>Create a local demo account</h2><form method="post" action="/signup">{csrf_input(token)}
<label>Email</label><input type="email" name="email" required maxlength="200" autocomplete="email">
<label>Password (at least 12 characters)</label><input type="password" name="password" required minlength="12" maxlength="128" autocomplete="new-password">
<button>Create account</button></form><p class="hint">Local-only prototype. Do not use a password you use elsewhere.</p></div>'''
                title = 'Create account'
            elif path.path == '/login':
                form = f'''<div class="card"><h2>Sign in</h2><form method="post" action="/login">{csrf_input(token)}
<label>Email</label><input type="email" name="email" required autocomplete="email">
<label>Password</label><input type="password" name="password" required autocomplete="current-password">
<button>Sign in</button></form><p><a href="/signup">Create a local account</a></p></div>'''
                title = 'Sign in'
            else:
                form = '''<div class="card"><h2>Your website security checkups, simplified</h2><p>Create a local account, add a demo website, choose daily/weekly/monthly checks, and preview plain-English security summaries.</p><p>Real domains require proof of ownership before any requests are made.</p><a class="btn" href="/signup">Get started</a> <a class="btn alt" href="/login">Sign in</a></div>'''
                title = 'Security checkups for business owners'
            if demo_mode_enabled():
                form += f'''<div class="card"><h2>Just looking around?</h2>
<p>Try a complete sample account and report without entering any details.</p>
<form method="post" action="/demo-login" data-native-submit="1">{csrf_input(token)}
<button>Explore demo — no sign-up</button></form>
<p class="hint">Synthetic data only. No real website scanning or email delivery.</p></div>'''
            return self.send_page(200, title, form, cookies=(f'monitor_anon={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600',))
        user = session
        csrf = session['csrf']
        if path.path == '/traffic':
            return self.send_page(200, 'Traffic intelligence map',
                                  traffic.page(db, user['user_id'], csrf), user, csrf=csrf)
        if path.path == '/security':
            return self.send_page(200, 'Unified Security Center',
                                  v5.security_page(db, user['user_id'], csrf), user, csrf=csrf)
        if path.path in ('/security-report','/security-json'):
            rid = parse_qs(path.query).get('id', [''])[0]
            row = v5.load_report(db, user['user_id'], rid)
            if not row:
                return self.send_page(404, 'Not found', '<p>Report not found.</p>', user, csrf=csrf)
            if path.path == '/security-json':
                data = row['report_json'].encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="security-report-'+str(row['id'])+'.json"')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            return self.send_page(200, 'Security Center report', v5.report_page(row, csrf), user, csrf=csrf)
        if path.path == '/':
            with db() as con:
                sites = con.execute('SELECT * FROM sites WHERE user_id=? ORDER BY id DESC', (user['user_id'],)).fetchall()
                recent = con.execute('SELECT scans.*, sites.host FROM scans JOIN sites ON sites.id=scans.site_id '
                                     'WHERE scans.user_id=? ORDER BY scans.id DESC LIMIT 5', (user['user_id'],)).fetchall()
            if is_demo_user(user['email']):
                blocks = ('<div class="card"><h2>Sample customer account</h2>'
                          '<p>Your demo website and sample report are ready below. '
                          'No personal details, real domains, or email configuration needed.</p>'
                          '<p class="hint">Try Run checkup now, change the report schedule, '
                          'and open the saved report. Demo accounts cannot scan external websites.</p></div>')
            else:
                blocks = '''<div class="grid"><div class="card"><h2>Add your website</h2><p class="hint">Ownership verification required. Only low-impact HTTPS checks.</p>'''
                blocks += f'''<form method="post" action="/add">{csrf_input(csrf)}<label>Domain name</label><input name="host" placeholder="shop.yourbusiness.com" required>
    <label>Report frequency</label><select name="frequency"><option>weekly</option><option>daily</option><option>monthly</option></select>
    <label>Time zone</label><select name="timezone">{''.join('<option value="'+esc(z)+'">'+esc(z)+'</option>' for z in TIMEZONES)}</select>
    <button>Add website</button></form></div><div class="card"><h2>Try the demo first</h2><p>See the entire customer experience with synthetic findings. No website or internet requests required.</p>
    <form method="post" action="/demo" data-native-submit="1">{csrf_input(csrf)}<button class="alt">Create demo website</button></form>
    <p class="hint">AI analysis: {'Gemini key configured' if os.environ.get('GEMINI_API_KEY') else 'rule-based summaries (Gemini not configured)'}<br>
    Email delivery: {'SMTP configured' if email_configured() else 'preview only until SMTP is configured'}</p></div></div>'''
            blocks = '<div class="card feature-card"><h2>Unified Security Center — API + Web</h2><p>All 17 synthetic vulnerability modules in one test, including API authorization, token handling, SQLi, XSS, CSRF, and business logic. Real sites receive separately authorized read-only checks.</p><a class="btn" href="/security">Open Security Center · Run all tests</a></div>' + blocks
            blocks = traffic.overview_map(db, user['user_id']) + blocks
            if parse_qs(path.query).get('demo', [''])[0] == 'existing':
                blocks = (
                    '<div class="notice"><p>You are already signed in. '
                    'Use this fresh form to open the demo.</p>'
                    '<form method="post" action="/demo" data-native-submit="1">'
                    + csrf_input(csrf) +
                    '<button class="alt">Open demo website</button>'
                    '</form></div>'
                ) + blocks
            blocks += '<h2>My websites</h2>' + (''.join(site_card(s, csrf) for s in sites) if sites else '<p>No websites yet.</p>')
            blocks += '<h2>Recent checkups</h2><div class="card">'
            for item in recent:
                blocks += f'''<p><a href="/report?id={item['id']}">{esc(item['host'])}</a> · {esc(item['status'])} · {esc(item['created_at'][:16])} UTC</p>'''
            blocks += '</div>'
            return self.send_page(200, 'Customer security dashboard', blocks, user, csrf=csrf)
        if path.path == '/site':
            sid = parse_qs(path.query).get('id', [''])[0]
            with db() as con:
                site = con.execute('SELECT * FROM sites WHERE id=? AND user_id=?', (sid, user['user_id'])).fetchone()
                scans = con.execute('SELECT * FROM scans WHERE site_id=? AND user_id=? ORDER BY id DESC LIMIT 30',
                                    (sid, user['user_id'])).fetchall()
                notifications = con.execute('SELECT * FROM notifications WHERE site_id=? AND user_id=? ORDER BY id DESC LIMIT 10',
                                            (sid, user['user_id'])).fetchall()
            if not site:
                return self.send_page(404, 'Not found', '<p>Unknown website.</p>', user, csrf=csrf)
            content = site_card(site, csrf)
            content += f'''<div class="card"><h2>Update schedule and notifications</h2>
<form method="post" action="/settings">{csrf_input(csrf)}<input type="hidden" name="site_id" value="{site['id']}">
<label>Report frequency</label><select name="frequency">{''.join('<option value="'+f+'" '+('selected' if site['frequency']==f else '')+'>'+f.capitalize()+'</option>' for f in ('daily','weekly','monthly'))}</select>
<label>Time zone</label><select name="timezone">{''.join('<option value="'+esc(z)+'" '+('selected' if site['timezone']==z else '')+'>'+esc(z)+'</option>' for z in TIMEZONES)}</select>
<label>Local delivery hour (24h)</label><select name="send_hour">{''.join('<option value="'+str(h)+'" '+('selected' if site['send_hour']==h else '')+'>'+f'{h:02d}:00'+'</option>' for h in range(6,22))}</select>
<label><input type="checkbox" name="email_updates" value="1" {'checked' if site['email_updates'] else ''}> Email me scheduled checkup summaries</label><br>
<label><input type="checkbox" name="urgent_alerts" value="1" {'checked' if site['urgent_alerts'] else ''}> Alert me if the website becomes unreachable or verification fails</label><br><br>
<button>Save preferences</button></form><p class="hint">Email requires SMTP configuration. Scheduling runs while Termux and this server remain running.</p></div>'''
            content += f'''<div class="card"><h2>Email delivery</h2><p>{'SMTP is configured.' if email_configured() else 'SMTP is not configured yet. Reports remain in the dashboard.'}</p>
<form method="post" action="/test-email">{csrf_input(csrf)}<input type="hidden" name="site_id" value="{site['id']}"><button class="alt">Send test email</button></form></div>'''
            content += '<div class="card"><h2>Checkup history</h2>'
            for scan in scans:
                content += f'''<p><a href="/report?id={scan['id']}">{esc(scan['created_at'][:16])} UTC</a> · {esc(scan['status'])} · {esc(scan['trigger'])} · {'Gemini' if scan['ai_used'] else 'Rule-based'} summary</p>'''
            content += '</div><div class="card"><h2>Notification history</h2>'
            for n in notifications:
                content += f'''<p>{esc(n['created_at'][:16])} · {esc(n['kind'])} · {esc(n['status'])} <small>{esc(n['detail'])}</small></p>'''
            content += '</div><a href="/">Back to dashboard</a>'
            return self.send_page(200, site['host'], content, user, csrf=csrf)
        if path.path == '/report':
            rid = parse_qs(path.query).get('id', [''])[0]
            with db() as con:
                scan = con.execute('SELECT scans.*,sites.host FROM scans JOIN sites ON sites.id=scans.site_id '
                                   'WHERE scans.id=? AND scans.user_id=?', (rid, user['user_id'])).fetchone()
            if not scan:
                return self.send_page(404, 'Not found', '<p>Report not found.</p>', user, csrf=csrf)
            findings = json.loads(scan['findings_json'])
            evidence = json.loads(scan['evidence_json'])
            content = f'''<div class="card"><h2>{esc(scan['host'])} · {esc(scan['status'])}</h2><p class="hint">{esc(scan['created_at'])} · {esc(scan['trigger'])}</p>
<h3>{'Gemini AI' if scan['ai_used'] else 'Rule-based'} owner summary</h3><p>{esc(scan['summary'])}</p>
<h3>Findings ({len(findings)})</h3>'''
            for f in findings:
                content += f'''<p><span class="pill">{esc(f['severity'])}</span> <strong>{esc(f['title'])}</strong><br>{esc(f['fix'])}</p>'''
            if not findings:
                content += '<p>No configuration findings in the limited checks.</p>'
            content += '<h3>Evidence (redacted)</h3><pre>' + esc(json.dumps(evidence, indent=2)) + '</pre>'
            content += '<p class="hint">These results are not proof of SQLi or a full vulnerability assessment.</p></div><a href="/site?id=' + str(scan['site_id']) + '">Back to website</a>'
            return self.send_page(200, 'Security checkup report', content, user, csrf=csrf)
        return self.send_page(404, 'Not found', '<p>Unknown page.</p>', user, csrf=csrf)

    def do_POST(self):
        if self.headers.get('Host', '').lower() not in (f'127.0.0.1:{PORT}', f'localhost:{PORT}'):
            return self.send_page(403, 'Forbidden', '<p>Invalid local host.</p>')
        if urlsplit(self.path).path == '/__v5_fixture':
            # A private, side-effect-free fixture API for this process's local test runner.
            # Never connects to a customer site and never accesses real data.
            if self.headers.get('Origin') or not hmac.compare_digest(self.headers.get('X-Workbench-Lab',''), suite.LAB_SECRET):
                return self.send_page(403, 'Forbidden', '<p>Local fixture authorization required.</p>')
            if self.headers.get('Content-Type','').split(';')[0].strip() != 'application/json':
                return self.send_page(415, 'Unsupported type', '<p>JSON required.</p>')
            try:
                size = int(self.headers.get('Content-Length','0'))
                if not 1 <= size <= suite.MAX_LAB_BODY: raise ValueError('Invalid fixture size')
                payload = json.loads(self.rfile.read(size))
                if not isinstance(payload,dict) or not isinstance(payload.get('fields'),dict): raise ValueError('Invalid fixture JSON')
                status, result = suite.fixture(payload.get('case'), payload.get('mode'), payload['fields'])
            except (ValueError,TypeError,json.JSONDecodeError):
                status,result = 400,{'error':'Invalid fixture request'}
            data = json.dumps(result,separators=(',',':')).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type','application/json; charset=utf-8')
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        try:
            form = self.parse_post()
        except ValueError as e:
            return self.send_page(400, 'Bad request', '<p>'+esc(e)+'</p>')
        path = urlsplit(self.path).path
        session, raw_token = session_from_cookie(self)
        if path == '/demo-login' and session:
            # Recover gracefully from an old browser demo form.
            if hmac.compare_digest(
                form.get('csrf', ''), session['csrf']
            ):
                path = '/demo'
            else:
                with db() as con:
                    existing = con.execute(
                        'SELECT id FROM sites WHERE user_id=? AND is_demo=1',
                        (session['user_id'],)
                    ).fetchone()
                return self.redirect(
                    '/site?id='+str(existing['id'])
                    if existing else '/?demo=existing'
                )
        if path == '/demo-login' and not session:
            if not demo_mode_enabled():
                return self.send_page(404, 'Not found', '<p>Demo access is disabled.</p>')
            if not hmac.compare_digest(form.get('csrf', ''), self.anon_csrf()):
                return self.send_page(403, 'Forbidden', '<p>Form verification failed. Refresh and retry.</p>')
            # New isolated synthetic account for each demo visit. Never a shared password.
            demo_email = 'demo-' + secrets.token_hex(12) + '@local.invalid'
            status, findings, evidence = perform_assessment({'is_demo': 1})
            with db() as con:
                uid = con.execute('INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)',
                                  (demo_email, password_hash(secrets.token_urlsafe(40)), iso())).lastrowid
                sid = con.execute('INSERT INTO sites(user_id,host,is_demo,verification_token,verified_at,frequency,timezone,send_hour,email_updates,urgent_alerts,next_run_at,last_checked_at,last_status) '
                                  'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                                  (uid, 'demo.security-checkup.invalid', 1, 'demo-only', iso(), 'weekly',
                                   'America/Toronto', 9, 0, 0, next_due('weekly', 'America/Toronto', 9), iso(), status)).lastrowid
                con.execute('INSERT INTO scans(user_id,site_id,created_at,trigger,status,findings_json,summary,ai_used,evidence_json) '
                            'VALUES(?,?,?,?,?,?,?,?,?)',
                            (uid, sid, iso(), 'demo-preview', status, json.dumps(findings),
                             deterministic_summary(status, findings), 0, json.dumps(evidence)))
            token = make_session(uid)
            return self.redirect('/', cookies=(f'monitor_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200',
                                               'monitor_anon=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'))
        if path in ('/login', '/signup') and not session:
            if not hmac.compare_digest(form.get('csrf', ''), self.anon_csrf()):
                return self.send_page(403, 'Forbidden', '<p>Form verification failed. Refresh and retry.</p>')
            email = form.get('email', '').strip().lower()
            pw = form.get('password', '')
            if len(email) > 200 or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
                return self.send_page(400, 'Invalid email', '<p>Enter a valid email address.</p>')
            if path == '/signup':
                if not 12 <= len(pw) <= 128:
                    return self.send_page(400, 'Invalid password', '<p>Use 12–128 characters.</p>')
                try:
                    with db() as con:
                        cur = con.execute('INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)',
                                          (email, password_hash(pw), iso()))
                        uid = cur.lastrowid
                except sqlite3.IntegrityError:
                    return self.send_page(409, 'Account exists', '<p>Account already exists. Please sign in.</p>')
            else:
                with LOGIN_LOCK:
                    history = [t for t in LOGIN_ATTEMPTS.get(email, []) if time.time()-t < 900]
                    if len(history) >= 7:
                        return self.send_page(429, 'Too many attempts', '<p>Wait 15 minutes before retrying.</p>')
                with db() as con:
                    row = con.execute('SELECT id,password_hash FROM users WHERE email=?', (email,)).fetchone()
                valid = password_ok(pw, row['password_hash']) if row else password_ok(pw, password_hash('dummy-not-a-real-password'))
                if not row or not valid:
                    with LOGIN_LOCK:
                        LOGIN_ATTEMPTS.setdefault(email, []).append(time.time())
                    return self.send_page(401, 'Sign-in failed', '<p>Invalid email or password.</p>')
                with LOGIN_LOCK:
                    LOGIN_ATTEMPTS.pop(email, None)
                uid = row['id']
            token = make_session(uid)
            return self.redirect('/', cookies=(f'monitor_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200',
                                               'monitor_anon=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'))
        if not session or not hmac.compare_digest(form.get('csrf', ''), session['csrf']):
            return self.send_page(403, 'Forbidden', '<p>Sign in and refresh the form.</p>')
        uid = session['user_id']
        if path == '/traffic-import':
            try:
                count = traffic.import_events(db, uid, form.get('site_id',''),
                                              form.get('csv',''), DATA_DIR)
                return self.redirect('/traffic')
            except ValueError as exc:
                return self.send_page(400, 'Traffic import needs attention',
                                      traffic.page(db, uid, session['csrf'], str(exc)),
                                      session, csrf=session['csrf'])
        if path == '/security-ask':
            if form.get('consent') != 'yes':
                return self.send_page(400,'Consent required','<p>Confirm that your question contains no private data.</p>',session,csrf=session['csrf'])
            try:
                answer = v5.ai_question(form.get('question',''))
                content = '<div class="card"><h2>Gemini security guidance</h2><pre>'+esc(answer)+'</pre><p class="hint">AI advice is not evidence of a vulnerability or a completed security assessment.</p></div>'
                return self.send_page(200,'Gemini Security Assistant',content+'<a href="/security">Back to Security Center</a>',session,csrf=session['csrf'])
            except ValueError as exc:
                return self.send_page(400,'Gemini unavailable','<p>'+esc(str(exc))+'</p><a href="/security">Back to Security Center</a>',session,csrf=session['csrf'])
        if path == '/security-run':
            try:
                report = suite.run_suite(PORT)
                rid = v5.save_report(db, uid, None, report)
                return self.redirect('/security-report?id='+str(rid))
            except (OSError,ValueError,urllib.error.URLError) as exc:
                return self.send_page(503, 'Training tests unavailable',
                                      '<p>Could not complete the local training suite: '+esc(type(exc).__name__)+'</p>',
                                      session, csrf=session['csrf'])
        if path == '/api-discover':
            with db() as con:
                site = con.execute('SELECT * FROM sites WHERE id=? AND user_id=?',
                                   (form.get('site_id',''),uid)).fetchone()
            if not site:
                return self.send_page(404,'Not found','<p>Website not found.</p>',session,csrf=session['csrf'])
            try:
                report = v5.discover_openapi(site,verify_site,fetch_https)
                rid = v5.save_report(db,uid,site['id'],report)
                return self.redirect('/security-report?id='+str(rid))
            except (ValueError,OSError,ssl.SSLError,http.client.HTTPException) as exc:
                return self.send_page(400,'API inventory unavailable',
                                      '<p>'+esc(str(exc) if isinstance(exc,ValueError) else 'Could not read approved API document.')+'</p><a href="/security">Back to Security Center</a>',
                                      session,csrf=session['csrf'])
        if path == '/security-ai':
            row = v5.load_report(db,uid,form.get('report_id',''))
            if not row or row['kind']!='lab':
                return self.send_page(404,'Not found','<p>Training report not found.</p>',session,csrf=session['csrf'])
            try:
                explanation = v5.ai_lab_explanation(json.loads(row['report_json']))
                with db() as con:
                    con.execute('UPDATE security_reports SET ai_text=? WHERE id=? AND user_id=?',
                                (explanation,row['id'],uid))
                return self.redirect('/security-report?id='+str(row['id']))
            except ValueError as exc:
                return self.send_page(400,'Gemini unavailable','<p>'+esc(str(exc))+'</p><a href="/security-report?id='+str(row['id'])+'">Back to report</a>',session,csrf=session['csrf'])
        if path == '/logout':
            with db() as con:
                con.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(raw_token.encode()).hexdigest(),))
            return self.redirect('/login', cookies=('monitor_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',))
        if path == '/demo':
            status, findings, evidence = perform_assessment({'is_demo': 1})
            with db() as con:
                existing = con.execute('SELECT id FROM sites WHERE user_id=? AND is_demo=1', (uid,)).fetchone()
                if existing:
                    sid = existing['id']
                else:
                    sid = con.execute('INSERT INTO sites(user_id,host,is_demo,verification_token,verified_at,frequency,timezone,send_hour,next_run_at,last_checked_at,last_status) '
                                      'VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                                      (uid, 'demo.security-checkup.invalid', 1, 'demo-only', iso(), 'weekly',
                                       'America/Toronto', 9, next_due('weekly','America/Toronto',9), iso(), status)).lastrowid
                prior = con.execute('SELECT id FROM scans WHERE site_id=? AND user_id=? LIMIT 1', (sid,uid)).fetchone()
                if not prior:
                    con.execute('INSERT INTO scans(user_id,site_id,created_at,trigger,status,findings_json,summary,ai_used,evidence_json) '
                                'VALUES(?,?,?,?,?,?,?,?,?)',
                                (uid, sid, iso(), 'demo-preview', status, json.dumps(findings),
                                 deterministic_summary(status, findings), 0, json.dumps(evidence)))
            return self.redirect('/site?id='+str(sid))
        if path == '/add':
            if is_demo_user(session['email']):
                return self.send_page(403, 'Demo account',
                                      '<p>Demo accounts cannot add or scan real websites. Create a separate account for authorized website checks.</p>',
                                      session, csrf=session['csrf'])
            try:
                host = normalize_host(form.get('host', ''))
                freq = form.get('frequency', 'weekly')
                tz = form.get('timezone', 'America/Toronto')
                due = next_due(freq, tz)
                with db() as con:
                    con.execute('INSERT INTO sites(user_id,host,verification_token,frequency,timezone,next_run_at) VALUES(?,?,?,?,?,?)',
                                (uid, host, secrets.token_urlsafe(24), freq, tz, due))
                return self.redirect('/')
            except (ValueError, sqlite3.IntegrityError) as exc:
                return self.send_page(400, 'Cannot add website', '<p>'+esc(str(exc))+'</p>', session, csrf=session['csrf'])
        if path in ('/verify', '/scan', '/settings', '/test-email'):
            with db() as con:
                site = con.execute('SELECT * FROM sites WHERE id=? AND user_id=?',
                                   (form.get('site_id', ''), uid)).fetchone()
            if not site:
                return self.send_page(404, 'Not found', '<p>Website not found.</p>', session, csrf=session['csrf'])
            if path == '/verify':
                try:
                    verified = verify_site(site['host'], site['verification_token'])
                except Exception:
                    verified = False
                if not verified:
                    return self.send_page(400, 'Verification failed', '<p>We could not retrieve the exact token over valid HTTPS. Check the file, DNS and TLS, then retry.</p><p><a href="/">Back</a></p>', session, csrf=session['csrf'])
                with db() as con:
                    con.execute('UPDATE sites SET verified_at=? WHERE id=? AND user_id=?', (iso(), site['id'], uid))
                return self.redirect('/')
            if path == '/settings':
                try:
                    freq = form.get('frequency', '')
                    tz = form.get('timezone', '')
                    hour = int(form.get('send_hour', '9'))
                    if hour not in range(6,22):
                        raise ValueError('Choose a delivery hour from 06:00 to 21:00.')
                    due = next_due(freq, tz, hour)
                    with db() as con:
                        con.execute('UPDATE sites SET frequency=?,timezone=?,send_hour=?,email_updates=?,urgent_alerts=?,next_run_at=? '
                                    'WHERE id=? AND user_id=?',
                                    (freq, tz, hour, int(form.get('email_updates')=='1') if not is_demo_user(session['email']) else 0,
                                     int(form.get('urgent_alerts')=='1') if not is_demo_user(session['email']) else 0,
                                     due, site['id'], uid))
                    return self.redirect('/site?id='+str(site['id']))
                except ValueError as exc:
                    return self.send_page(400, 'Invalid schedule', '<p>'+esc(exc)+'</p>', session, csrf=session['csrf'])
            if path == '/test-email':
                if is_demo_user(session['email']):
                    return self.send_page(403, 'Demo account',
                                          '<p>Demo accounts do not send email. Sign up with a real address to test notifications.</p>',
                                          session, csrf=session['csrf'])
                try:
                    with db() as con:
                        user = con.execute('SELECT email FROM users WHERE id=?', (uid,)).fetchone()
                    send_email(user['email'], '[Workbench] Test notification',
                               'This is a test from your local Web Security Workbench monitoring prototype.')
                    record_notification(uid, site['id'], None, 'test', 'sent', 'Email submitted to SMTP server.')
                    return self.send_page(200, 'Test email sent', '<p>Your SMTP server accepted the test message. Check your inbox and spam folder.</p><a href="/site?id='+str(site['id'])+'">Back</a>', session, csrf=session['csrf'])
                except Exception as exc:
                    record_notification(uid, site['id'], None, 'test', 'failed', type(exc).__name__)
                    return self.send_page(400, 'Email not delivered', '<p>SMTP failed or is not configured. Check your Termux configuration.</p><a href="/site?id='+str(site['id'])+'">Back</a>', session, csrf=session['csrf'])
            if path == '/scan':
                try:
                    rid = run_scan(site['id'])
                    return self.redirect('/report?id='+str(rid))
                except ValueError as exc:
                    return self.send_page(400, 'Checkup not started', '<p>'+esc(exc)+'</p>', session, csrf=session['csrf'])
        return self.send_page(404, 'Not found', '<p>Unknown action.</p>', session, csrf=session['csrf'])


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    stop = threading.Event()
    thread = threading.Thread(target=scheduler_loop, args=(stop,), daemon=True)
    thread.start()
    print(f'Web Security Workbench v5 at http://{HOST}:{PORT}/ (demo: {demo_mode_enabled()})', flush=True)
    print('Gemini:', 'configured' if os.environ.get('GEMINI_API_KEY') else 'not configured',
          '| SMTP:', 'configured' if email_configured() else 'not configured', flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set(); server.server_close()


if __name__ == '__main__':
    main()
