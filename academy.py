#!/usr/bin/env python3
"""Web Security Workbench Academy v2: localhost-only simulated web weaknesses.
No external HTTP calls, file reads from user paths, or actual account changes.
"""
import html
import json
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST, PORT = '127.0.0.1', 18769
ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / 'reports' / 'academy'
REPORTS.mkdir(parents=True, exist_ok=True)
CSRF = secrets.token_urlsafe(24)
ENGAGEMENT_DIR = REPORTS / 'engagements'
ENGAGEMENT_DIR.mkdir(parents=True, exist_ok=True)
ENGAGEMENT = None

MODULES = [
    ('authentication', 'Authentication & password reset',
     'Look for password-reset flows that accept an account name without verifying ownership.',
     'A reset request without a valid reset token succeeds in vulnerable mode.',
     'An attacker could take over a test account if the reset endpoint were real.',
     'Require short-lived, single-use reset tokens and notify the account owner.'),
    ('session', 'Session management',
     'Check whether logout and expiration actually invalidate sessions on the server.',
     'An expired test session can still retrieve a simulated protected resource.',
     'Stolen or expired session tokens could remain usable.',
     'Invalidate sessions server-side, rotate IDs at login, and set secure cookie flags.'),
    ('csrf', 'Cross-site request forgery',
     'Inspect state-changing requests for CSRF tokens and Origin checks.',
     'A simulated account change is accepted without a CSRF token.',
     'A signed-in user could be tricked into performing an unintended action.',
     'Use unpredictable per-session CSRF tokens, SameSite cookies, and Origin checks.'),
    ('upload', 'Unsafe file upload',
     'Compare allowed filenames and content types; check whether uploaded files execute.',
     'The simulated upload endpoint accepts a disallowed file extension.',
     'Unsafe handling could lead to malicious content being hosted or executed.',
     'Allowlist extensions, verify file types, rename uploads, and store outside webroot.'),
    ('traversal', 'Path traversal',
     'Review file download parameters for unsafely constructed filesystem paths.',
     'A traversal-like name returns a fictional private training note.',
     'A real application might disclose files outside its intended directory.',
     'Use server-side file IDs, canonicalize paths, and enforce an allowlisted root.'),
    ('ssrf', 'Server-side request forgery',
     'Identify URL fetchers, previews, webhooks, and import-from-URL features.',
     'A simulated URL fetch reaches a fictional internal service.',
     'An attacker could make a server reach internal or restricted services.',
     'Allowlist destinations, block internal IP ranges, validate redirects, and restrict egress.'),
    ('logic', 'Business-logic flaws',
     'Test assumptions about quantities, prices, discounts, and workflow order.',
     'A fictional checkout accepts a negative quantity and calculates a negative total.',
     'An application could grant improper discounts or mishandle transactions.',
     'Validate business invariants on the server and test unusual workflows.'),
]
LOOKUP = {m[0]: m for m in MODULES}

# Only synthetic values are used. Nothing is read from the device or network.
def evaluate(module, mode, fields):
    fixed = mode == 'fixed'
    if module == 'authentication':
        ok = not fixed or fields.get('token') == 'demo-reset-token'
        return (200 if ok else 403), {'message': 'Simulated reset accepted' if ok else 'Reset token required'}
    if module == 'session':
        sid = fields.get('session', '')
        ok = sid == 'active-alice' or (not fixed and sid == 'expired-alice')
        return (200 if ok else 401), {'message': 'Fictional Alice profile' if ok else 'Session invalid'}
    if module == 'csrf':
        ok = not fixed or fields.get('csrf_token') == 'demo-csrf-token'
        return (200 if ok else 403), {'message': 'Simulated email change accepted' if ok else 'CSRF token required'}
    if module == 'upload':
        name = fields.get('filename', '')
        ok = bool(name) and (not fixed or name.lower().endswith(('.txt', '.png', '.jpg')))
        return (200 if ok else 415), {'message': 'Filename accepted (not saved or executed)' if ok else 'File type rejected'}
    if module == 'traversal':
        name = fields.get('name', '')
        if name == 'public/welcome.txt':
            return 200, {'message': 'Public training welcome file'}
        if name == '../private/demo-note.txt' and not fixed:
            return 200, {'message': 'LAB_ONLY_FICTIONAL_PRIVATE_NOTE'}
        return 403, {'message': 'File path denied'}
    if module == 'ssrf':
        url = fields.get('url', '')
        if url == 'https://example.org/public':
            return 200, {'message': 'Simulated public response; no outbound request made'}
        if url == 'http://127.0.0.1/internal/status' and not fixed:
            return 200, {'message': 'SIMULATED_INTERNAL_SERVICE_REACHED'}
        return 403, {'message': 'Destination blocked; no outbound request made'}
    if module == 'logic':
        try:
            qty = int(fields.get('qty', '0'))
        except ValueError:
            return 422, {'message': 'Invalid quantity'}
        if fixed and not 1 <= qty <= 20:
            return 422, {'message': 'Quantity must be between 1 and 20'}
        return 200, {'message': 'Fictional checkout calculated; no order created', 'total': qty * 10}
    return 404, {'message': 'Unknown lab module'}

# Requests use the real localhost HTTP endpoints, not just function calls.
TESTS = {
    'authentication': ({'username': 'alice', 'new_password': 'demo'}, {'username': 'alice', 'token': 'demo-reset-token'}),
    'session': ({'session': 'expired-alice'}, {'session': 'active-alice'}),
    'csrf': ({'email': 'demo@example.org'}, {'email': 'demo@example.org', 'csrf_token': 'demo-csrf-token'}),
    'upload': ({'filename': 'proof.php'}, {'filename': 'notes.txt'}),
    'traversal': ({'name': '../private/demo-note.txt'}, {'name': 'public/welcome.txt'}),
    'ssrf': ({'url': 'http://127.0.0.1/internal/status'}, {'url': 'https://example.org/public'}),
    'logic': ({'qty': '-2'}, {'qty': '2'}),
}

def request_lab(module, mode, fields):
    data = urllib.parse.urlencode(fields).encode('utf-8')
    req = urllib.request.Request(
        f'http://{HOST}:{PORT}/api/{module}?mode={mode}', data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def run_suite():
    results = []
    for key, title, discovery, demonstration, impact, fix in MODULES:
        attack, valid = TESTS[key]
        vulnerable_code, vulnerable_data = request_lab(key, 'vulnerable', attack)
        fixed_code, fixed_data = request_lab(key, 'fixed', attack)
        valid_code, valid_data = request_lab(key, 'fixed', valid)
        passed = vulnerable_code == 200 and fixed_code != 200 and valid_code == 200
        results.append({
            'module': key, 'title': title, 'discovery': discovery,
            'demonstration': demonstration, 'impact': impact, 'remediation': fix,
            'controlled_input': attack, 'vulnerable_http': vulnerable_code,
            'fixed_http': fixed_code, 'valid_fixed_http': valid_code,
            'vulnerable_response': vulnerable_data, 'fixed_response': fixed_data,
            'outcome': 'LAB WEAKNESS REPRODUCED; FIX VERIFIED' if passed else 'REVIEW NEEDED',
        })
    return {'project': 'Web Security Workbench Academy', 'environment': 'localhost simulated training only',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'passed': sum(r['outcome'].startswith('LAB WEAKNESS') for r in results),
            'total': len(results), 'results': results}

def create_engagement(fields):
    client = fields.get('client', '').strip()[:80]
    target = fields.get('target', '').strip()[:300]
    path = fields.get('path', '/').strip()[:200]
    window = fields.get('window', '').strip()[:80]
    notes = fields.get('notes', '').strip()[:400]
    try:
        limit = int(fields.get('limit', '3'))
    except ValueError:
        raise ValueError('Page limit must be a number')
    url = urllib.parse.urlsplit(target)
    if not client or url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Provide a client label and a valid HTTP(S) host URL without credentials, query, or fragment')
    if not path.startswith('/') or '..' in path:
        raise ValueError('Approved path must start with / and cannot contain traversal')
    if not 1 <= limit <= 10:
        raise ValueError('Page limit must be 1–10')
    if fields.get('authorized') != 'yes':
        raise ValueError('Written authorization confirmation required')
    record = {'created_utc': datetime.now(timezone.utc).isoformat(),
              'client_label': client, 'target': target, 'approved_path': path,
              'maximum_baseline_pages': limit, 'approved_window_notes': window,
              'engagement_notes': notes,
              'permission_status': 'Self-attested only; not independently verified',
              'active_testing_enabled': False}
    filename = 'engagement-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(4) + '.json'
    output = ENGAGEMENT_DIR / filename
    output.write_text(json.dumps(record, indent=2), encoding='utf-8')
    output.chmod(0o600)
    return record

def esc(x):
    return html.escape(str(x), quote=True)

CSS = '''*{box-sizing:border-box}body{background:#0c1423;color:#e6ebf5;font:16px/1.5 system-ui;margin:0}
main{max-width:970px;margin:auto;padding:18px}header{background:#17243a;border-bottom:2px solid #8764e8;padding:18px}
h1{margin:0;font-size:26px}h2{font-size:20px;color:#d9c8ff}h3{font-size:17px;color:#d9c8ff}
.card{background:#1a2940;border:1px solid #354763;border-radius:12px;padding:17px;margin:14px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
button,.btn{background:#7957db;color:white;border:0;border-radius:8px;padding:11px 16px;font-size:15px;cursor:pointer;text-decoration:none;display:inline-block;margin:4px}
.sub{color:#b9c7dd}a{color:#d6c5ff}code{overflow-wrap:anywhere}table{border-collapse:collapse;width:100%}
th,td{padding:8px;text-align:left;border-bottom:1px solid #44536a}details{margin:12px 0}summary{cursor:pointer;font-weight:700}
input{padding:9px;background:#101d30;color:white;border:1px solid #70809b;border-radius:6px;max-width:100%}
.ok{color:#a5f0c0}.warn{color:#ffc6a0}small{color:#b7c6da}'''

def page(report=None, error=''):
    cards = ''
    for key, title, discovery, demo, impact, fix in MODULES:
        cards += f'''<details class="card"><summary>{esc(title)}</summary>
<p><b>Discovery clues:</b> {esc(discovery)}</p>
<p><b>Controlled lab demonstration:</b> {esc(demo)}</p>
<p><b>Potential real-world impact:</b> {esc(impact)}</p>
<p><b>Remediation:</b> {esc(fix)}</p>
<p><b>Live lab endpoint:</b> <code>POST /api/{esc(key)}?mode=vulnerable|fixed</code></p>
<p><b>Training input:</b> <code>{esc(json.dumps(TESTS[key][0]))}</code></p>
</details>'''
    result = ''
    if report:
        rows = ''.join(f'<tr><td>{esc(r["title"])}</td><td>{r["vulnerable_http"]}</td><td>{r["fixed_http"]}</td><td>{r["valid_fixed_http"]}</td><td>{esc(r["outcome"])}</td></tr>' for r in report['results'])
        result = f'''<section class="card"><h2>Automated lab verification: {report['passed']}/{report['total']} passed</h2>
<div style="overflow-x:auto"><table><tr><th>Module</th><th>Vulnerable</th><th>Fixed</th><th>Legitimate request</th><th>Outcome</th></tr>{rows}</table></div>
<p>All requests stayed on 127.0.0.1. An HTTP 200 on a lab endpoint is simulated behavior, not evidence about any external website.</p>
<a class="btn" href="/report/latest.html">View HTML report</a><a class="btn" href="/report/latest.json">Download JSON</a></section>'''
    err = f'<section class="card warn">{esc(error)}</section>' if error else ''
    engagement_info = ''
    if ENGAGEMENT:
        engagement_info = f'<p class="ok">Scope record saved for {esc(ENGAGEMENT["client_label"])}: {esc(ENGAGEMENT["target"])} · {esc(ENGAGEMENT["approved_path"])}. This does not initiate a scan.</p><a href="/engagement/latest.json">View saved scope JSON</a>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Academy · Web Security Workbench</title><style>{CSS}</style></head><body>
<header><main><h1>🛡️ Web Security Academy v2</h1><p class="sub">Seven simulated vulnerability modules · Android / Termux</p></main></header><main>
<p><a class="btn" href="http://127.0.0.1:18768/">← Main Workbench</a><a class="btn" href="http://127.0.0.1:18766/">Original XSS/SQLi/IDOR Lab</a></p>
<section class="card"><h2>Automated vulnerability lab</h2><p>Run seven controlled tests in vulnerable mode, retest in fixed mode, and check that legitimate requests still work.</p>
<form method="post" action="/run"><input type="hidden" name="csrf" value="{CSRF}"><button type="submit">Run all 7 modules (21 checks)</button></form>
<small>Lab-only. Simulated responses: no real password resets, file writes, purchases, or outbound SSRF requests.</small></section>
{err}{result}
<h2>Explore each vulnerability</h2>{cards}
<section class="card"><h2>Authorized client mode</h2><p>Use the existing Workbench baseline scanner for external sites within a documented scope. This Academy never sends attacks to external sites.</p>
<a class="btn" href="http://127.0.0.1:18768/">Open client baseline scanner</a>
<h3>Client scope worksheet</h3><p class="sub">Save an engagement note before using the existing baseline scanner. This form does not verify permission or enable active testing. Avoid storing credentials or secrets.</p>
<form method="post" action="/engagement"><input type="hidden" name="csrf" value="{CSRF}">
<label>Client label <input name="client" required maxlength="80" placeholder="Client A"></label><br>
<label>Approved website <input name="target" type="url" required maxlength="300" placeholder="https://example.org"></label><br>
<label>Approved path <input name="path" required value="/" maxlength="200"></label><br>
<label>Baseline page limit (1–10) <input name="limit" type="number" min="1" max="10" value="3"></label><br>
<label>Approved testing window / notes <input name="window" maxlength="80" placeholder="As agreed in writing"></label><br>
<label>Engagement notes <input name="notes" maxlength="400" placeholder="No production login tests"></label><br>
<label><input type="checkbox" name="authorized" value="yes" required> I have written authorization for this scope</label><br>
<button type="submit">Save scope record (no scan)</button></form>{engagement_info}
<p class="sub">Future: manual evidence capture and reviewed active test plans. Automated lab success does not mean an external vulnerability was found.</p></section>
<footer><small>Bound to localhost. Synthetic test data only. OWASP WSTG is a useful testing methodology reference.</small></footer>
</main></body></html>'''

def report_html(report):
    rows = ''.join(f'''<tr><td>{esc(r['title'])}</td><td>{r['vulnerable_http']}</td><td>{r['fixed_http']}</td><td>{r['valid_fixed_http']}</td><td>{esc(r['outcome'])}</td></tr>
<tr><td colspan="5"><b>Discovery:</b> {esc(r['discovery'])}<br><b>Impact:</b> {esc(r['impact'])}<br><b>Fix:</b> {esc(r['remediation'])}</td></tr>''' for r in report['results'])
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lab Verification Report</title><style>{CSS}</style></head><body><main><h1>Web Security Academy — Lab Verification</h1><p>{esc(report['timestamp'])} · {report['passed']}/{report['total']} passed</p><p><b>Scope:</b> Local synthetic training endpoints only. No client site tested.</p><div style="overflow-x:auto"><table><tr><th>Module</th><th>Vulnerable</th><th>Fixed</th><th>Legitimate</th><th>Outcome</th></tr>{rows}</table></div><p>Tests demonstrate expected behavior for the specified inputs only, not comprehensive security.</p></main></body></html>'''

LATEST = None
RUN_LOCK = threading.Lock()

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, data, mime='text/html; charset=utf-8'):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def local(self):
        if self.client_address[0] != '127.0.0.1':
            self.reply(403, 'Forbidden')
            return False
        return True

    def do_GET(self):
        if not self.local():
            return
        path = urllib.parse.urlsplit(self.path).path
        if path == '/':
            return self.reply(200, page(LATEST))
        if path == '/health':
            return self.reply(200, json.dumps({'status': 'ok', 'lab_only': True, 'modules': 7}), 'application/json')
        if path == '/report/latest.html' and LATEST:
            return self.reply(200, report_html(LATEST))
        if path == '/report/latest.json' and LATEST:
            return self.reply(200, json.dumps(LATEST, indent=2), 'application/json')
        if path == '/engagement/latest.json' and ENGAGEMENT:
            return self.reply(200, json.dumps(ENGAGEMENT, indent=2), 'application/json')
        return self.reply(404, 'Not found')

    def do_POST(self):
        global LATEST, ENGAGEMENT
        if not self.local():
            return
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path not in ('/run', '/engagement') and not (parsed.path.startswith('/api/') and parsed.path[5:] in LOOKUP):
            return self.reply(404, 'Not found')
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/x-www-form-urlencoded':
            return self.reply(415, 'Form encoding required')
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            size = 0
        if not 0 < size <= 8192:
            return self.reply(413, 'Invalid request length')
        data = urllib.parse.parse_qs(self.rfile.read(size).decode('utf-8', 'replace'), keep_blank_values=True)
        fields = {key: values[0] for key, values in data.items()}
        if parsed.path.startswith('/api/'):
            mode = urllib.parse.parse_qs(parsed.query).get('mode', [''])[0]
            if mode not in ('fixed', 'vulnerable'):
                return self.reply(400, json.dumps({'error': 'mode must be vulnerable or fixed'}), 'application/json')
            status, result = evaluate(parsed.path[5:], mode, fields)
            return self.reply(status, json.dumps({'module': parsed.path[5:], 'mode': mode, 'simulated': True, **result}), 'application/json')
        if not secrets.compare_digest(fields.get('csrf', ''), CSRF):
            return self.reply(403, page(error='Invalid form token'))
        if parsed.path == '/engagement':
            try:
                ENGAGEMENT = create_engagement(fields)
                return self.reply(200, page(LATEST))
            except ValueError as exc:
                return self.reply(400, page(LATEST, error=str(exc)))
        if not RUN_LOCK.acquire(blocking=False):
            return self.reply(429, page(error='Another lab run is already in progress'))
        try:
            LATEST = run_suite()
            stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
            (REPORTS / f'academy-{stamp}.json').write_text(json.dumps(LATEST, indent=2), encoding='utf-8')
            (REPORTS / f'academy-{stamp}.html').write_text(report_html(LATEST), encoding='utf-8')
            return self.reply(200, page(LATEST))
        except Exception as exc:
            return self.reply(500, page(error='Test run failed: ' + str(exc)))
        finally:
            RUN_LOCK.release()

    def log_message(self, fmt, *args):
        print('[academy]', fmt % args, flush=True)

if __name__ == '__main__':
    with ThreadingHTTPServer((HOST, PORT), Handler) as server:
        print(f'Academy: http://{HOST}:{PORT}/', flush=True)
        server.serve_forever()
