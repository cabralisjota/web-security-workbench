"""Public, read-only synthetic training demo for Web Security Workbench.

This is deliberately NOT the local customer portal and does not scan websites.
Only the 17 predefined in-memory vulnerable/fixed training fixtures are run.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, abort, jsonify, send_from_directory

from v5_suite import BY_KEY, CASES, fixture, fixture_control_ok, weakness_seen

ROOT = Path(__file__).resolve().parent
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 4096


@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-Frame-Options'] = 'DENY'
    if response.mimetype == 'application/json':
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/')
def homepage():
    """Keep the existing showcase design; add live controls only on this server."""
    html = (ROOT / 'render-showcase' / 'index.html').read_text(encoding='utf-8')
    if '</body>' not in html:
        abort(500)
    html = html.replace('</body>', '<script defer src="/live.js"></script>\n</body>', 1)
    return Response(html, mimetype='text/html')


@app.get('/live.js')
def live_script():
    return send_from_directory(ROOT / 'render-live', 'live.js', mimetype='application/javascript')


@app.get('/health')
def health():
    return jsonify(status='ok', service='synthetic-training', modules=len(CASES))


@app.get('/api/training/modules')
def modules():
    return jsonify(modules=[{
        'key': case['key'], 'group': case['group'], 'title': case['title'],
        'cwe': case['cwe']
    } for case in CASES], count=len(CASES),
        scope='Predefined synthetic localhost-style fixtures; no external targets')


def run_one(case):
    """Execute real Python fixture comparisons, without public vulnerable endpoints."""
    key = case['key']
    vulnerable = fixture(key, 'vulnerable', dict(case['attack']))
    fixed = fixture(key, 'fixed', dict(case['attack']))
    control = fixture(key, 'fixed', dict(case['control']))
    reproduced = bool(weakness_seen(key, *vulnerable))
    prevented = not bool(weakness_seen(key, *fixed))
    normal = bool(fixture_control_ok(key, *control))
    return {
        'key': key, 'group': case['group'], 'title': case['title'],
        'cwe': case['cwe'], 'passed': reproduced and prevented and normal,
        'vulnerable_indicator': reproduced,
        'fixed_prevented': prevented,
        'normal_request_ok': normal,
        'vulnerable_http': vulnerable[0], 'fixed_http': fixed[0],
        'normal_http': control[0],
        'impact': case['impact'], 'remediation': case['remediation'],
        'evidence': {
            'vulnerable': vulnerable[1], 'fixed': fixed[1], 'normal': control[1]
        },
    }


@app.post('/api/training/run/<key>')
def run_module(key):
    case = BY_KEY.get(key)
    if case is None:
        abort(404)
    return jsonify(
        kind='synthetic-training',
        timestamp_utc=datetime.now(timezone.utc).isoformat(timespec='seconds'),
        scope='In-memory training fixtures only. No external systems tested.',
        result=run_one(case),
    )


@app.post('/api/training/run-all')
def run_all():
    results = [run_one(case) for case in CASES]
    return jsonify(
        kind='synthetic-training',
        timestamp_utc=datetime.now(timezone.utc).isoformat(timespec='seconds'),
        scope='In-memory training fixtures only. No external systems tested.',
        total=len(results), passed=sum(int(row['passed']) for row in results),
        results=results,
    )


if __name__ == '__main__':
    # Local development only. Render uses Gunicorn with $PORT.
    app.run(host='127.0.0.1', port=18772, debug=False)
