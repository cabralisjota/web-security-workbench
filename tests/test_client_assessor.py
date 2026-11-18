import json
import re
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from urllib.error import HTTPError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import client_assessor as ca


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/out':
            self.send_response(302)
            self.send_header('Location', 'https://example.org/')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Set-Cookie', 'sessionid=SECRET; Path=/')
        self.end_headers()
        self.wfile.write(b'<h1>Local lab</h1><a href="/second">Next</a>'
                         b'<a href="/logout">Logout</a>'
                         b'<form method="get"><input type="password"></form>')

    def log_message(self, *args):
        pass


class ClientAssessmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.base = f'http://127.0.0.1:{cls.port}'
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_private_targets_blocked_by_default(self):
        with self.assertRaises(ca.ScopeError):
            ca.Scope(self.base)

    def test_local_lab_opt_in_and_exact_host(self):
        scope = ca.Scope(self.base, allow_loopback=True)
        self.assertTrue(scope.validate(self.base + '/second'))
        with self.assertRaises(ca.ScopeError):
            scope.validate('http://example.org/')
        with self.assertRaises(ca.ScopeError):
            scope.validate('http://127.0.0.1:1/')

    def test_path_prefix_enforced(self):
        scope = ca.Scope(self.base + '/approved', '/approved', allow_loopback=True)
        self.assertTrue(scope.validate(self.base + '/approved/page'))
        with self.assertRaises(ca.ScopeError):
            scope.validate(self.base + '/admin')
        with self.assertRaises(ca.ScopeError):
            scope.validate(self.base + '/approved2')

    def test_crawl_real_local_http_and_findings(self):
        report = ca.crawl(self.base + '/', max_pages=2, delay=0.5, allow_loopback=True)
        self.assertEqual(len(report['pages']), 2)
        titles = [f['title'] for f in report['findings']]
        self.assertIn('Password form uses GET', titles)
        self.assertIn('Cookie lacks HttpOnly flag', titles)
        self.assertTrue(all('SECRET' not in json.dumps(f) for f in report['findings']))
        self.assertTrue(all('/logout' not in p['url'] for p in report['pages']))

    def test_redirect_out_of_scope_not_followed(self):
        scope = ca.Scope(self.base, allow_loopback=True)
        with self.assertRaisesRegex(ca.ScopeError, 'Out-of-scope hostname'):
            ca.fetch_page(self.base + '/out', scope)

    def test_html_report_escapes_user_content(self):
        report = {'target': '<script>alert(1)</script>',
                  'authorized_scope': {'host': 'local', 'path_prefix': '/'},
                  'timestamp_utc': 'now', 'counts': {}, 'findings': [],
                  'pages': [], 'limitations': []}
        rendered = ca.render_report(report)
        self.assertNotIn('<script>alert(1)</script>', rendered)
        self.assertIn('&lt;script&gt;', rendered)

    def test_web_ui_requires_csrf_and_authorization(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), ca.DashboardHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        ui = f'http://127.0.0.1:{server.server_port}'
        def post(values):
            body = urlencode(values).encode()
            return urlopen(Request(ui + '/assess', data=body,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}), timeout=6)
        try:
            page = urlopen(ui, timeout=3).read().decode()
            token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
            self.assertIn('Client Website Security Assessor', page)
            with self.assertRaises(HTTPError) as err:
                post({'authorized': 'yes'})
            self.assertEqual(err.exception.code, 403)
            with self.assertRaises(HTTPError) as err:
                post({'csrf': token, 'url': self.base, 'path': '/', 'pages': '1'})
            self.assertEqual(err.exception.code, 400)
            self.assertIn('Written authorization', err.exception.read().decode())
            with tempfile.TemporaryDirectory() as tmp:
                previous = ca.REPORT_DIR
                ca.REPORT_DIR = Path(tmp)
                try:
                    resp = post({'csrf': token, 'url': self.base, 'path': '/',
                                 'pages': '1', 'loopback': 'yes', 'authorized': 'yes'})
                    self.assertEqual(resp.status, 200)
                    self.assertIn(b'Assessment results', resp.read())
                    self.assertEqual(len(list(Path(tmp).glob('*.json'))), 1)
                finally:
                    ca.REPORT_DIR = previous
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
