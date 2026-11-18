#!/usr/bin/env python3
"""Unified local dashboard for an existing Termux web pentest lab and baseline assessor.

Install next to client_assessor.py and web_pentest.py. Uses stdlib only.
Active XSS proof is restricted to the local training lab at 127.0.0.1:18766.
"""
import html
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import client_assessor as assessor

HOST, PORT = '127.0.0.1', 18768
LAB = 'http://127.0.0.1:18766'
ROOT = Path(__file__).resolve().parent
CSRF = secrets.token_urlsafe(24)
PROOF = {'token': None, 'started': None, 'confirmed': False, 'mode': None, 'unescaped': None}
LOCK = threading.Lock()

CSS = '''*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e5eaf5;font:16px/1.5 system-ui,Arial}
header{padding:22px 16px;background:#172036;border-bottom:2px solid #8055df}main{max-width:920px;margin:auto;padding:18px}
h1{font-size:25px;margin:0}h2{font-size:21px;color:#d6c3ff}h3{color:#d6c3ff}
.card{background:#19263a;border:1px solid #34465e;border-radius:13px;padding:20px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}.sub{color:#b8c5db}
input[type=url],input[type=text],input[type=number]{display:block;width:100%;padding:12px;font-size:16px;color:white;background:#0d182b;border:1px solid #65758c;border-radius:7px}
label{display:block;font-weight:600;margin:12px 0 5px}.check{font-weight:400;display:flex;align-items:flex-start;gap:8px}
.check input{width:20px;height:20px;flex-shrink:0}.btn,button{display:inline-block;border:0;background:#7750d6;color:#fff;padding:11px 15px;border-radius:8px;font-size:15px;text-decoration:none;cursor:pointer;margin:8px 5px 8px 0}
.btn.alt{background:#334560}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #42536a;padding:8px;text-align:left;vertical-align:top}
.pill{background:#2a3d57;border-radius:20px;padding:4px 10px;display:inline-block;margin:4px}.err{color:#ffadad}.ok{color:#a5f3bd}
code{overflow-wrap:anywhere}small{color:#aabbd4}a{color:#c7b6ff}li{margin:6px 0}'''


def esc(value):
    return html.escape(str(value), quote=True)


def lab_health():
    try:
        with urllib.request.urlopen(LAB + '/health', timeout=3) as response:
            if response.status != 200:
                return None
            data = json.load(response)
        if data.get('scope') != 'localhost training lab' or data.get('mode') not in ('fixed', 'vulnerable'):
            return None
        return data
    except (OSError, ValueError, urllib.error.URLError):
        return None


def proof_status():
    with LOCK:
        snap = PROOF.copy()
    if not snap['token']:
        return {'state': 'not-started'}
    elapsed = round(time.monotonic() - snap['started'], 1)
    state = 'confirmed' if snap['confirmed'] else 'waiting' if elapsed < 60 else 'inconclusive'
    return {'state': state, 'mode': snap['mode'], 'elapsed_seconds': elapsed,
            'note': 'A missing callback does not prove the application is safe.'}


def findings_table(report):
    if not report:
        return ''
    items = report.get('findings', [])
    rows = ''.join('<tr><td>' + esc(x.get('severity','?')).upper() + '</td><td><b>' + esc(x.get('title','')) + '</b></td><td>' + esc(x.get('detail','')) + '</td></tr>' for x in items)
    if not rows:
        rows = '<tr><td colspan="3">No findings from the baseline checks; this is not proof of security.</td></tr>'
    return '<div class="card"><h2>Baseline assessment results</h2><p>' + esc(report.get('target','')) + '</p><table><tr><th>Severity</th><th>Finding</th><th>Evidence</th></tr>' + rows + '</table><p class="sub">These are configuration observations, not confirmed exploits.</p></div>'


def page(error='', report=None, stem=None, values=None):
    values = values or {'url': LAB + '/', 'path': '/', 'pages': 3, 'loopback': True}
    health = lab_health()
    mode = esc(health['mode']) if health else 'offline'
    lab_status = '<span class="ok">Online · ' + mode + '</span>' if health else '<span class="err">Offline</span>'
    result = findings_table(report)
    if stem:
        result += '<p><a class="btn" href="/report/' + esc(stem) + '.html" target="_blank">Open HTML report</a><a class="btn alt" href="/report/' + esc(stem) + '.json">Download JSON</a></p>'
    error_html = '<div class="card err"><b>' + esc(error) + '</b></div>' if error else ''
    checked = 'checked' if values.get('loopback') else ''
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Web Security Workbench</title><style>{CSS}</style></head>
<body><header><main><h1>🛡️ Web Security Workbench</h1><div class="sub">Unified training and authorized baseline assessment · Android / Termux</div></main></header><main>
<div class="grid"><section class="card"><h2>Training lab</h2><p>Status: {lab_status}</p><p>Port 18766 · XSS, SQLi, IDOR exercises</p><a class="btn alt" href="{LAB}/" target="_blank">Open training lab</a></section>
<section class="card"><h2>Client baseline assessor</h2><p>HTTP headers, cookies, TLS, and limited same-site page discovery</p><p><span class="pill">Low-impact GET only</span></p><a class="btn alt" href="http://127.0.0.1:18767/" target="_blank">Open original assessor</a></section></div>
{error_html}<section class="card"><h2>1. Scan an authorized website</h2><p class="sub">Enter a permitted URL. Exact-host and path restrictions, private-IP blocking, and redirect controls come from your existing Client Assessor.</p>
<form method="post" action="/scan"><input type="hidden" name="csrf" value="{CSRF}">
<label for="url">Target URL</label><input id="url" type="url" name="url" required maxlength="2048" value="{esc(values['url'])}">
<label for="path">Approved path prefix</label><input id="path" type="text" name="path" required maxlength="256" value="{esc(values['path'])}">
<label for="pages">Maximum pages (1–10)</label><input id="pages" type="number" name="pages" min="1" max="10" value="{esc(values['pages'])}">
<label class="check"><input type="checkbox" name="loopback" value="yes" {checked}>Allow localhost for the training lab only</label>
<label class="check"><input type="checkbox" name="authorized" value="yes" required>I own the target or have written permission for this exact host and path</label>
<button type="submit">Run baseline assessment</button></form></section>
{result}
<section class="card"><h2>2. Verify JavaScript execution — training lab only</h2>
<p>Launches a harmless XSS proof against <code>127.0.0.1:18766/search</code>. Chrome must execute JavaScript and contact this local dashboard before execution is marked confirmed. No cookies or private data are collected.</p>
<form action="/lab-proof/start" method="post" target="_blank"><input type="hidden" name="csrf" value="{CSRF}"><button type="submit">Open XSS proof in Chrome</button></form>
<div id="proof-status" class="sub" role="status">Proof status: not started</div>
<small>Switch between vulnerable and fixed modes in tmux, then run the proof again. Fixed-mode results should not be interpreted as proof that every XSS vector is blocked.</small></section>
<section class="card"><h2>3. How a tester discovers and verifies weaknesses</h2>
<div class="grid"><div><h3>Cross-site scripting (XSS)</h3><p>Find reflected input; check output encoding and browser execution; assess the affected context. Fix with contextual escaping, safe DOM APIs, and appropriate CSP.</p></div>
<div><h3>SQL injection</h3><p>Identify database-backed inputs; compare baseline and controlled lab inputs; confirm unintended query behavior. Fix with parameterized statements and least-privilege DB access.</p></div>
<div><h3>Broken access control (IDOR)</h3><p>Compare responses for two authorized test accounts accessing different resources. Fix by enforcing server-side ownership and permission checks on every request.</p></div>
<div><h3>Other areas to learn</h3><p>Authentication, CSRF, file uploads, path traversal, SSRF, session management, and business-logic flaws. These are <b>guided topics</b>, not automatically tested by this version.</p></div></div>
<p><a href="https://owasp.org/www-project-web-security-testing-guide/" target="_blank" rel="noopener noreferrer">OWASP Web Security Testing Guide</a></p></section>
<section class="card"><h2>4. Security Academy — seven new modules</h2>
<p>Authentication, sessions, CSRF, file uploads, traversal, SSRF, and business logic. Simulated local attacks, fixed-mode verification, explanations, and reports.</p>
<a class="btn" href="http://127.0.0.1:18769/" target="_blank">Open Security Academy</a>
</section>
<section class="card"><h2>AI SQLi Copilot — v3</h2>
<p>Controlled SQL injection lab verification, optional AI explanation, evidence review and reports. Active tests are localhost only.</p>
<a class="btn" href="http://127.0.0.1:18770/" target="_blank">Open AI SQLi Copilot</a>
</section>
<footer><small>External active exploitation is not enabled. This tool cannot guarantee a website is secure.</small></footer>
</main><script>
async function poll(){{try{{const r=await fetch('/api/proof-status',{{cache:'no-store'}});const d=await r.json();const e=document.getElementById('proof-status');if(d.state==='confirmed')e.textContent='CONFIRMED: JavaScript executed in Chrome ('+d.mode+' mode)';else if(d.state==='waiting')e.textContent='Waiting for browser proof ('+d.mode+' mode, '+d.elapsed_seconds+'s)';else if(d.state==='inconclusive')e.textContent='INCONCLUSIVE: No browser callback after 60 seconds';else e.textContent='Proof status: not started';}}catch(e){{}}}}poll();setInterval(poll,2500);
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, data, mime='text/html; charset=utf-8', attachment=None):
        data = data.encode('utf-8') if isinstance(data, str) else data
        self.send_response(code)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        if attachment:
            self.send_header('Content-Disposition', 'attachment; filename="' + attachment + '"')
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def local(self):
        if self.client_address[0] not in ('127.0.0.1', '::1'):
            self.reply(403, 'Forbidden')
            return False
        return True

    def do_GET(self):
        if not self.local():
            return
        path = urllib.parse.urlsplit(self.path)
        if path.path == '/':
            return self.reply(200, page())
        if path.path == '/api/proof-status':
            return self.reply(200, json.dumps(proof_status()), 'application/json')
        if path.path == '/proof':
            token = urllib.parse.parse_qs(path.query).get('token', [''])[0]
            with LOCK:
                valid = PROOF['token'] is not None and secrets.compare_digest(token, PROOF['token']) and (time.monotonic() - PROOF['started']) < 90
                if valid:
                    PROOF['confirmed'] = True
            return self.reply(204 if valid else 404, b'', 'text/plain')
        if path.path.startswith('/report/'):
            name = path.path[len('/report/'):]
            if not re.fullmatch(r'client_\d{8}_\d{6}_[0-9a-f]{8}\.(?:html|json)', name):
                return self.reply(404, 'Not found')
            file = assessor.REPORT_DIR / name
            if not file.is_file():
                return self.reply(404, 'Not found')
            mime = 'application/json' if name.endswith('.json') else 'text/html; charset=utf-8'
            return self.reply(200, file.read_bytes(), mime, name if name.endswith('.json') else None)
        return self.reply(404, 'Not found')

    def form(self):
        origin = self.headers.get('Origin')
        if origin and origin not in (f'http://127.0.0.1:{PORT}', f'http://localhost:{PORT}'):
            self.reply(403, 'Forbidden: origin')
            return None
        if self.headers.get('Sec-Fetch-Site', 'same-origin') not in ('same-origin', 'none'):
            self.reply(403, 'Forbidden: cross-site')
            return None
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/x-www-form-urlencoded':
            self.reply(415, 'Expected form data')
            return None
        try:
            n = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            n = 0
        if not 0 < n <= 16384:
            self.reply(413, 'Invalid form length')
            return None
        fields = urllib.parse.parse_qs(self.rfile.read(n).decode('utf-8', 'replace'), keep_blank_values=True)
        one = lambda k, d='': fields.get(k, [d])[0]
        if not secrets.compare_digest(one('csrf'), CSRF):
            self.reply(403, 'Invalid form token')
            return None
        return one

    def do_POST(self):
        if not self.local():
            return
        if self.path not in ('/scan', '/lab-proof/start'):
            return self.reply(404, 'Not found')
        one = self.form()
        if one is None:
            return
        if self.path == '/scan':
            values = {'url': one('url').strip(), 'path': one('path', '/').strip(), 'pages': one('pages', '3'), 'loopback': one('loopback') == 'yes'}
            if one('authorized') != 'yes':
                return self.reply(400, page('Written permission confirmation required', values=values))
            try:
                report = assessor.crawl(values['url'], scope_path=values['path'], max_pages=int(values['pages']), allow_loopback=values['loopback'])
                stem = assessor.save_report(report)
                return self.reply(200, page(report=report, stem=stem, values=values))
            except (assessor.ScopeError, ValueError, OSError) as e:
                return self.reply(400, page(error=str(e), values=values))
        health = lab_health()
        if not health:
            return self.reply(503, page(error='Training lab is offline or /health did not match the expected local lab.'))
        token = secrets.token_urlsafe(24)
        with LOCK:
            PROOF.update(token=token, started=time.monotonic(), confirmed=False, mode=health['mode'], unescaped=None)
        callback = f'http://{HOST}:{PORT}/proof?token={token}'
        payload = '<script>new Image().src=' + json.dumps(callback) + '</script>'
        url = LAB + '/search?' + urllib.parse.urlencode({'q': payload})
        self.send_response(303)
        self.send_header('Location', url)
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()

    def log_message(self, fmt, *args):
        print('[workbench]', fmt % args, flush=True)


def main():
    with ThreadingHTTPServer((HOST, PORT), Handler) as server:
        print(f'Unified dashboard: http://{HOST}:{PORT}/', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()
