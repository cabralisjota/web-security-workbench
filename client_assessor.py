#!/usr/bin/env python3
"""Scope-limited, low-impact client website assessment for authorized use.

Separate from the deliberately vulnerable Flask training application.
Only GET requests, no payload injection, no login attempts, no form submission.
"""

import argparse
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
import html
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import posixpath
import re
import secrets
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit, unquote, parse_qs
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request


ROOT = Path(__file__).resolve().parent
REPORT_DIR = ROOT / 'reports' / 'client'
APP_HOST, APP_PORT = '127.0.0.1', 18767
USER_AGENT = 'PurpleTeamClientAssessor/1.0 (authorized, low-impact assessment)'
MAX_BODY = 262144
MAX_REDIRECTS = 4
SKIP_PATH_WORDS = ('logout', 'signout', 'delete', 'remove', 'reset', 'purchase',
                   'checkout', 'transfer', 'unsubscribe', 'payment', 'trigger',
                   'execute', 'terminate', 'download', 'export', 'action')

CSRF_TOKEN = secrets.token_urlsafe(32)  # new token each server launch


class ScopeError(ValueError):
    pass


class StopRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = build_opener(ProxyHandler({}), StopRedirect())


def display_url(url):
    """Avoid storing query strings, which may contain tokens or private data."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or '/', '[query redacted]' if p.query else '', ''))


def normalize_path(path):
    path = unquote(path or '/')
    if '\\' in path or '\x00' in path or not path.startswith('/'):
        raise ScopeError('Invalid scope path')
    return posixpath.normpath(path).replace('//', '/')


def same_path_scope(path, prefix):
    try:
        normalized = normalize_path(path)
    except ScopeError:
        return False
    return prefix == '/' or normalized == prefix or normalized.startswith(prefix.rstrip('/') + '/')


def check_address(host, port, allow_loopback):
    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ScopeError('DNS resolution failed for approved host') from exc
    if not results:
        raise ScopeError('No DNS addresses for approved host')
    for result in results:
        try:
            addr = ipaddress.ip_address(result[4][0])
        except ValueError as exc:
            raise ScopeError('Unexpected resolved address') from exc
        if addr.is_loopback and allow_loopback and host in ('localhost', '127.0.0.1', '::1'):
            continue
        if not addr.is_global:
            raise ScopeError('Private, local, reserved, and link-local targets are blocked by default')


class Scope:
    def __init__(self, target, scope_path='/', allow_loopback=False):
        if not isinstance(target, str) or len(target) > 2048 or any(ord(c) < 32 for c in target):
            raise ScopeError('Invalid target URL')
        parsed = urlsplit(target.strip())
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ScopeError('Target must start with http:// or https://')
        if parsed.username or parsed.password:
            raise ScopeError('URLs containing credentials are not accepted')
        try:
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        except ValueError as exc:
            raise ScopeError('Invalid target port') from exc
        self.host = parsed.hostname.lower().rstrip('.')
        self.scheme = parsed.scheme
        self.port = port
        self.path = normalize_path(scope_path)
        self.allow_loopback = allow_loopback
        check_address(self.host, self.port, self.allow_loopback)
        self.validate(target)
        self.target = target.strip()

    def validate(self, url):
        parsed = urlsplit(url)
        try:
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        except ValueError as exc:
            raise ScopeError('Redirect contains invalid port') from exc
        if parsed.username or parsed.password or not parsed.hostname:
            raise ScopeError('Redirect or link has invalid authority')
        if parsed.hostname.lower().rstrip('.') != self.host:
            raise ScopeError('Out-of-scope hostname blocked')
        if parsed.scheme != self.scheme:
            if not (self.scheme == 'http' and parsed.scheme == 'https'
                    and self.port == 80 and port == 443):
                raise ScopeError('Out-of-scope scheme or HTTPS downgrade blocked')
        elif port != self.port:
            raise ScopeError('Out-of-scope port blocked')
        if not same_path_scope(parsed.path or '/', self.path):
            raise ScopeError('Out-of-scope path blocked')
        if parsed.scheme not in ('http', 'https'):
            raise ScopeError('Unsupported URL scheme')
        check_address(self.host, port, self.allow_loopback)
        return True


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = []
        self.resources = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])
        if tag == 'form':
            self._form = {'method': (attrs.get('method') or 'GET').upper(),
                          'action': attrs.get('action') or '', 'password': False}
            self.forms.append(self._form)
        if tag == 'input' and self._form is not None:
            if (attrs.get('type') or '').lower() == 'password':
                self._form['password'] = True
        if tag in ('script', 'img', 'iframe', 'link'):
            ref = attrs.get('src') or attrs.get('href')
            if ref:
                self.resources.append((tag, ref))

    def handle_endtag(self, tag):
        if tag == 'form':
            self._form = None


def fetch_page(url, scope, timeout=6):
    current = url
    hops = []
    for _ in range(MAX_REDIRECTS + 1):
        scope.validate(current)
        req = Request(current, headers={
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
            'Accept-Encoding': 'identity',
        }, method='GET')
        try:
            response = OPENER.open(req, timeout=timeout)
        except HTTPError as exc:
            response = exc
        except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            raise ScopeError('Request failed (network, TLS, or connection error): ' + type(exc).__name__) from exc
        try:
            status = response.code
            headers = response.headers
            if status in (301, 302, 303, 307, 308) and headers.get('Location'):
                next_url = urljoin(current, headers['Location'])
                scope.validate(next_url)
                hops.append({'from': display_url(current), 'to': display_url(next_url), 'status': status})
                current = next_url
                continue
            body = response.read(MAX_BODY + 1)
            truncated = len(body) > MAX_BODY
            body = body[:MAX_BODY]
            content_type = headers.get('Content-Type', '')
            charset = headers.get_content_charset() or 'utf-8'
            try:
                decoded = body.decode(charset, errors='replace')
            except LookupError:
                decoded = body.decode('utf-8', errors='replace')
            return {'url': current, 'status': status, 'headers': headers,
                    'body': decoded, 'truncated': truncated, 'type': content_type,
                    'redirects': hops}
        finally:
            response.close()
    raise ScopeError('Too many redirects; request stopped')


def finding(findings, severity, title, detail, recommendation, url):
    findings.append({'severity': severity, 'title': title, 'detail': detail,
                     'recommendation': recommendation, 'url': display_url(url)})


def inspect_page(result, findings, scope):
    url = result['url']
    h = result['headers']
    status = result['status']
    parser = PageParser()
    if 'html' in result['type'].lower():
        parser.feed(result['body'])

    if urlsplit(url).scheme == 'http' and scope.host not in ('localhost', '127.0.0.1', '::1'):
        finding(findings, 'medium', 'Page served over HTTP',
                'Traffic is not protected by HTTPS.', 'Redirect to HTTPS and enable HSTS.', url)
    if urlsplit(url).scheme == 'https' and not h.get('Strict-Transport-Security'):
        finding(findings, 'low', 'HSTS header absent',
                'The response does not advertise HTTP Strict Transport Security.',
                'Review an appropriate HSTS policy after confirming HTTPS works for all subdomains.', url)
    csp = h.get('Content-Security-Policy', '')
    if not csp:
        finding(findings, 'low', 'Content Security Policy absent',
                'No CSP header was observed. This is defense-in-depth guidance, not proof of XSS.',
                'Deploy and test a restrictive Content-Security-Policy.', url)
    if h.get('X-Content-Type-Options', '').lower() != 'nosniff':
        finding(findings, 'low', 'MIME sniffing protection absent',
                'X-Content-Type-Options: nosniff was not observed.',
                'Set X-Content-Type-Options: nosniff.', url)
    if not h.get('X-Frame-Options') and 'frame-ancestors' not in csp.lower():
        finding(findings, 'low', 'Frame embedding policy absent',
                'No X-Frame-Options or CSP frame-ancestors directive was observed.',
                'Consider CSP frame-ancestors for pages that should not be embedded.', url)
    if not h.get('Referrer-Policy'):
        finding(findings, 'info', 'Referrer Policy absent',
                'No explicit Referrer-Policy header was observed.',
                'Set an appropriate Referrer-Policy for the application.', url)
    for banner in ('Server', 'X-Powered-By'):
        if h.get(banner):
            finding(findings, 'info', f'{banner} banner exposed',
                    f'The response includes a {banner} header.',
                    'Review whether this banner is necessary.', url)
    for cookie in h.get_all('Set-Cookie', []):
        cookie_name = cookie.split('=', 1)[0].strip()[:80]
        parts = [p.strip().lower() for p in cookie.split(';')[1:]]
        if urlsplit(url).scheme == 'https' and 'secure' not in parts:
            finding(findings, 'medium', 'Cookie lacks Secure flag',
                    f'Cookie {cookie_name!r} does not advertise Secure. Cookie values are not recorded.',
                    'Set Secure on HTTPS cookies.', url)
        if 'httponly' not in parts:
            finding(findings, 'low', 'Cookie lacks HttpOnly flag',
                    f'Cookie {cookie_name!r} does not advertise HttpOnly; this may be intentional for some cookies.',
                    'Use HttpOnly for cookies not needed by client-side JavaScript.', url)
        if not any(p.startswith('samesite=') for p in parts):
            finding(findings, 'low', 'Cookie lacks explicit SameSite policy',
                    f'Cookie {cookie_name!r} has no explicit SameSite attribute.',
                    'Set SameSite=Lax or Strict where compatible with the application.', url)
    for form in parser.forms:
        action = urljoin(url, form['action'])
        if form['password'] and form['method'] == 'GET':
            finding(findings, 'high', 'Password form uses GET',
                    'A password input is present in a GET form.',
                    'Submit passwords with POST over HTTPS.', url)
        if form['password'] and (urlsplit(url).scheme == 'http' or urlsplit(action).scheme == 'http'):
            finding(findings, 'high', 'Password form uses insecure HTTP',
                    'A password form is served from or submits to an HTTP URL.',
                    'Serve and submit credential forms exclusively over HTTPS.', url)
    for tag, ref in parser.resources:
        full = urljoin(url, ref)
        if urlsplit(url).scheme == 'https' and urlsplit(full).scheme == 'http':
            finding(findings, 'medium' if tag in ('script', 'iframe') else 'low',
                    'Mixed content reference', f'HTTPS page references an HTTP {tag} resource.',
                    'Use HTTPS for embedded resources.', url)
    if status >= 500:
        finding(findings, 'info', 'Server returned an error',
                f'The response returned HTTP {status}. This alone does not establish a vulnerability.',
                'Review server logs and error handling.', url)
    return parser


def check_tls(scope, findings):
    if scope.scheme != 'https':
        return {'status': 'not_applicable'}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((scope.host, scope.port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=scope.host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
        expiration = cert.get('notAfter')
        days_left = None
        if expiration:
            days_left = int((ssl.cert_time_to_seconds(expiration) - time.time()) / 86400)
            if days_left < 30:
                finding(findings, 'medium' if days_left < 14 else 'low',
                        'TLS certificate nearing expiry',
                        f'Certificate expires in approximately {days_left} days.',
                        'Renew and deploy a valid certificate before expiration.', scope.target)
        return {'status': 'valid', 'protocol': version, 'days_until_expiry': days_left}
    except (OSError, ssl.SSLError, ValueError) as exc:
        finding(findings, 'medium', 'TLS certificate could not be verified',
                'Certificate inspection failed: ' + type(exc).__name__,
                'Check the certificate chain, hostname, and network connection.', scope.target)
        return {'status': 'verification_failed', 'error_type': type(exc).__name__}


def crawl(target, scope_path='/', max_pages=3, delay=0.8, allow_loopback=False):
    if not 1 <= int(max_pages) <= 10:
        raise ValueError('max_pages must be between 1 and 10')
    if float(delay) < 0.5:
        raise ValueError('delay must be at least 0.5 seconds')
    scope = Scope(target, scope_path, allow_loopback)
    findings = []
    pages = []
    queue = deque([scope.target])
    seen = set()
    tls = check_tls(scope, findings)
    while queue and len(pages) < int(max_pages):
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        if pages:
            time.sleep(float(delay))
        try:
            result = fetch_page(url, scope)
        except ScopeError as exc:
            finding(findings, 'info', 'Page not assessed', str(exc),
                    'Confirm the approved scope, URL, DNS and connectivity.', url)
            pages.append({'url': display_url(url), 'status': 'error', 'forms': 0,
                          'links': 0, 'truncated': False})
            continue
        parser = inspect_page(result, findings, scope)
        pages.append({'url': display_url(result['url']), 'status': result['status'],
                      'forms': len(parser.forms), 'links': len(parser.links),
                      'truncated': result['truncated'], 'redirects': result['redirects']})
        for ref in parser.links:
            if len(queue) + len(seen) >= int(max_pages) * 8:
                break
            next_url = urljoin(result['url'], ref).split('#', 1)[0]
            parts = urlsplit(next_url)
            if parts.query or any(word in (parts.path or '').lower() for word in SKIP_PATH_WORDS):
                continue
            try:
                scope.validate(next_url)
            except ScopeError:
                continue
            if next_url not in seen and next_url not in queue:
                queue.append(next_url)
    # Avoid a wall of duplicates across pages; retain URL-specific evidence.
    counts = dict(Counter(f['severity'] for f in findings))
    return {
        'tool': 'Purple Team Client Website Assessor',
        'version': '1.0',
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'authorized_scope': {'host': scope.host, 'path_prefix': scope.path,
                             'scheme': scope.scheme, 'port': scope.port},
        'method': 'Low-impact GET-only inspection; no authentication or injection payloads',
        'target': display_url(scope.target),
        'pages': pages,
        'tls': tls,
        'counts': counts,
        'findings': findings,
        'limitations': [
            'This is a baseline configuration review, not a full penetration test.',
            'Header/cookie observations are advisory and require manual verification.',
            'No authenticated areas, SQL injection, XSS exploitation, or access-control tests are performed.',
            'Crawling can still generate requests; use staging and an agreed testing window.',
        ],
    }


def render_report(report):
    escape = lambda value: html.escape(str(value), quote=True)
    counts = report['counts']
    cards = ''.join(f'<span class="chip">{escape(sev)}: {counts.get(sev, 0)}</span>'
                    for sev in ('high', 'medium', 'low', 'info'))
    rows = ''.join('<tr><td><b>{}</b></td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
        escape(f['severity'].upper()), escape(f['title']),
        escape(f['detail']), escape(f['recommendation'])) for f in report['findings'])
    if not rows:
        rows = '<tr><td colspan="4">No observations in the checks performed.</td></tr>'
    pages = ''.join('<li>{} — HTTP {}</li>'.format(escape(p['url']), escape(p['status']))
                    for p in report['pages'])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Website Assessment Report</title>
<style>body{{font-family:Arial,sans-serif;background:#101827;color:#e2e8f0;line-height:1.5;margin:0;padding:24px}}
main{{max-width:1100px;margin:auto}}h1,h2{{color:#c4b5fd}}.chip{{display:inline-block;background:#28344b;
margin:4px;padding:8px;border-radius:8px}}table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border:1px solid #48536a;padding:10px;vertical-align:top;text-align:left}}th{{background:#28344b}}
.note{{background:#28344b;padding:15px;border-radius:8px}}@media(max-width:650px){{body{{padding:10px}}table{{font-size:12px}}}}</style>
</head><body><main><h1>🛡️ Website Security Baseline</h1>
<p>Target: <b>{escape(report['target'])}</b></p>
<p>Scope: {escape(report['authorized_scope']['host'])} {escape(report['authorized_scope']['path_prefix'])}</p>
<p>UTC: {escape(report['timestamp_utc'])}</p><div>{cards}</div>
<h2>Findings / recommendations</h2><div style="overflow-x:auto"><table><tr>
<th>Level</th><th>Observation</th><th>Evidence</th><th>Suggested action</th></tr>{rows}</table></div>
<h2>Pages inspected</h2><ul>{pages}</ul>
<h2>Limitations</h2><div class="note"><ul>{''.join('<li>'+escape(s)+'</li>' for s in report['limitations'])}</ul></div>
<p>Use only with written authorization. Observations require human verification.</p></main></body></html>'''


def save_report(report):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stem = 'client_' + datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S') + '_' + secrets.token_hex(4)
    (REPORT_DIR / (stem + '.json')).write_text(json.dumps(report, indent=2), encoding='utf-8')
    (REPORT_DIR / (stem + '.html')).write_text(render_report(report), encoding='utf-8')
    return stem



STYLE = '''*{box-sizing:border-box}body{margin:0;background:#0b1120;color:#e2e8f0;font-family:Arial,sans-serif}
header{background:#172036;padding:24px 18px;border-bottom:2px solid #8b5cf6}
main{max-width:850px;margin:auto;padding:16px}.card{background:#1b263b;border:1px solid #34435b;
border-radius:13px;padding:19px;margin:0 0 18px}h1{font-size:24px;margin:0 0 8px}h2{color:#c4b5fd}
p,small{color:#bdc9dd;line-height:1.5}label{display:block;margin:14px 0 5px;font-weight:bold}
input[type=url],input[type=text],input[type=number]{width:100%;font-size:16px;padding:12px;
background:#0f172a;color:#fff;border:1px solid #68768e;border-radius:8px}
button,.btn{display:inline-block;border:0;background:#7c3aed;color:white;padding:13px 17px;
font-size:16px;border-radius:8px;text-decoration:none;margin:8px 6px 8px 0}
.checkbox{display:flex;gap:10px;align-items:flex-start;margin:16px 0}.checkbox input{width:20px;height:20px;flex-shrink:0}
.notice{padding:12px;background:#313251;border-radius:8px}.error{background:#5e2637}
.badge{display:inline-block;padding:8px 12px;background:#29344b;border-radius:8px;margin:5px}
li{padding:5px 0}footer{text-align:center;color:#9aacc6;padding:24px}'''


def render_page(values=None, error=None, result=None, stem=None):
    values = values or {'url': '', 'path': '/', 'pages': 3, 'loopback': False}
    esc = lambda v: html.escape(str(v), quote=True)
    checked = 'checked' if values.get('loopback') else ''
    error_html = f'<div class="notice error">{esc(error)}</div>' if error else ''
    results_html = ''
    if result is not None:
        badges = ''.join(f'<span class="badge">{sev.upper()}: {result["counts"].get(sev,0)}</span>'
                         for sev in ('high', 'medium', 'low', 'info'))
        observations = ''.join(f'<li><b>{esc(f["severity"].upper())} — {esc(f["title"])}</b>'
                               f'<p>{esc(f["detail"])}</p></li>' for f in result['findings'])
        if not observations:
            observations = '<li>No observations from these baseline checks.</li>'
        results_html = f'''<section class="card"><h2>📊 Assessment results</h2>
<p>Target: <b>{esc(result['target'])}</b> · {len(result['pages'])} page(s) inspected</p>
{badges}<p><a class="btn" href="/reports/{esc(stem)}.html">📄 HTML report</a>
<a class="btn" href="/reports/{esc(stem)}.json">⬇️ JSON evidence</a></p>
<h3>Observations</h3><ul>{observations}</ul>
<p class="notice">Baseline configuration review only; findings require manual verification.</p></section>'''
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Client Web Security Assessor</title><style>{STYLE}</style></head>
<body><header><h1>🛡️ Client Website Security Assessor</h1>
<p>External website baseline checks · authorized use only</p></header><main>
<section class="card"><h2>🎯 Approved target</h2>
<p>This module is separate from the intentionally vulnerable training app. It only makes GET requests and does not attempt exploits.</p>
{error_html}<form method="post" action="/assess">
<input type="hidden" name="csrf" value="{CSRF_TOKEN}">
<label for="url">Website URL (include https://)</label>
<input type="url" id="url" name="url" placeholder="https://staging.client.example" required maxlength="2048" value="{esc(values['url'])}">
<label for="path">Approved path prefix</label>
<input type="text" id="path" name="path" value="{esc(values['path'])}" required maxlength="256">
<label for="pages">Maximum pages (1–10)</label>
<input type="number" id="pages" name="pages" min="1" max="10" value="{esc(values['pages'])}">
<label class="checkbox"><input type="checkbox" name="loopback" value="yes" {checked}>
<span>Allow localhost / 127.0.0.1 for my own training lab (other private network hosts remain blocked)</span></label>
<label class="checkbox"><input type="checkbox" name="authorized" value="yes" required>
<span>I confirm that I own this website or have written authorization to assess this exact host and path.</span></label>
<button type="submit">🔍 Run low-impact assessment</button></form></section>
{results_html}
<section class="card"><h2>🔒 Built-in safeguards</h2>
<p>Exact-host and path scope · redirect restrictions · public-IP checks · no credentials collected ·
no SQLi/XSS payloads · no form submission · maximum 10 pages · 0.8s between requests · JSON/HTML reports.</p>
<p><small>Even GET requests can have side effects on poorly designed applications. Prefer staging and an agreed testing window.</small></p></section>
</main><footer>Purple Team Portfolio · Python · localhost control panel</footer></body></html>'''


class DashboardHandler(BaseHTTPRequestHandler):
    def _reply(self, status, body, content_type='text/html; charset=utf-8', attachment=None):
        body = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        if attachment:
            self.send_header('Content-Disposition', f'attachment; filename="{attachment}"')
        self.end_headers()
        self.wfile.write(body)

    def _local_only(self):
        if self.client_address[0] not in ('127.0.0.1', '::1'):
            self._reply(403, 'Forbidden')
            return False
        return True

    def do_GET(self):
        if not self._local_only():
            return
        if self.path == '/':
            return self._reply(200, render_page())
        if self.path.startswith('/reports/'):
            name = self.path.removeprefix('/reports/')
            if not re.fullmatch(r'client_\d{8}_\d{6}_[0-9a-f]{8}\.(?:json|html)', name):
                return self._reply(404, 'Not found')
            path = REPORT_DIR / name
            if not path.is_file():
                return self._reply(404, 'Not found')
            if name.endswith('.json'):
                return self._reply(200, path.read_bytes(), 'application/json; charset=utf-8', attachment=name)
            return self._reply(200, path.read_bytes())
        return self._reply(404, 'Not found')

    def do_POST(self):
        if not self._local_only():
            return
        if self.path != '/assess':
            return self._reply(404, 'Not found')
        origin = self.headers.get('Origin')
        if origin and origin not in ('http://127.0.0.1:18767', 'http://localhost:18767',
                                     f'http://127.0.0.1:{self.server.server_port}'):
            return self._reply(403, 'Forbidden: cross-origin request')
        if self.headers.get('Sec-Fetch-Site', 'same-origin') not in ('same-origin', 'none'):
            return self._reply(403, 'Forbidden: cross-site request')
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/x-www-form-urlencoded':
            return self._reply(415, 'Expected form data')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self._reply(400, 'Invalid content length')
        if not 0 < length <= 16384:
            return self._reply(413, 'Form too large')
        data = parse_qs(self.rfile.read(length).decode('utf-8', errors='replace'), keep_blank_values=True)
        one = lambda key, default='': data.get(key, [default])[0]
        if not secrets.compare_digest(one('csrf'), CSRF_TOKEN):
            return self._reply(403, 'Forbidden: invalid request token')
        values = {'url': one('url').strip(), 'path': one('path', '/').strip(),
                  'pages': one('pages', '3').strip(), 'loopback': one('loopback') == 'yes'}
        if one('authorized') != 'yes':
            return self._reply(400, render_page(values, 'Written authorization confirmation is required'))
        try:
            result = crawl(values['url'], scope_path=values['path'],
                           max_pages=int(values['pages']), allow_loopback=values['loopback'])
            stem = save_report(result)
            return self._reply(200, render_page(values, result=result, stem=stem))
        except (ScopeError, ValueError) as exc:
            return self._reply(400, render_page(values, error=str(exc)))

    def log_message(self, fmt, *args):
        print('[client-assessor]', fmt % args)


def main():
    parser = argparse.ArgumentParser(description='Authorized client website baseline assessor')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('serve', help='Open local Android browser dashboard')
    scan = commands.add_parser('scan', help='Run an assessment from Termux')
    scan.add_argument('--url', required=True)
    scan.add_argument('--scope-path', default='/')
    scan.add_argument('--max-pages', type=int, default=3)
    scan.add_argument('--allow-loopback', action='store_true')
    scan.add_argument('--authorized', action='store_true', help='Confirm written permission')
    args = parser.parse_args()
    if args.command == 'serve':
        with ThreadingHTTPServer((APP_HOST, APP_PORT), DashboardHandler) as server:
            print(f'Client assessor dashboard: http://{APP_HOST}:{APP_PORT}', flush=True)
            server.serve_forever()
    else:
        if not args.authorized:
            parser.error('Use --authorized only after obtaining written permission')
        try:
            report = crawl(args.url, scope_path=args.scope_path,
                           max_pages=args.max_pages, allow_loopback=args.allow_loopback)
        except (ScopeError, ValueError) as exc:
            parser.error(str(exc))
        stem = save_report(report)
        print('Target:', report['target'])
        print('Pages:', len(report['pages']))
        print('Findings:', report['counts'])
        print('HTML report:', REPORT_DIR / (stem + '.html'))
        print('JSON report:', REPORT_DIR / (stem + '.json'))


if __name__ == '__main__':
    main()
