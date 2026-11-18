import datetime as dt
import http.client
import importlib.util
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

MODULE = Path(__file__).with_name('monitor_portal.py')
spec = importlib.util.spec_from_file_location('monitor_portal', MODULE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        m.DATA_DIR = Path(self.temp.name) / 'data'
        m.DB_FILE = m.DATA_DIR / 'monitor.sqlite3'
        m.init_db()
        with m.db() as con:
            cur = con.execute('INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)',
                              ('owner@example.org', m.password_hash('example-password-123'), m.iso()))
            self.user_id = cur.lastrowid

    def add_demo(self):
        with m.db() as con:
            cur = con.execute('INSERT INTO sites(user_id,host,is_demo,verification_token,verified_at,frequency,timezone,send_hour,next_run_at) '
                              'VALUES(?,?,?,?,?,?,?,?,?)',
                              (self.user_id, 'demo.security-checkup.invalid', 1, 'demo', m.iso(),
                               'daily', 'America/Toronto', 9, m.iso(m.utcnow()-dt.timedelta(minutes=1))))
            return cur.lastrowid

    def test_password_hash(self):
        h = m.password_hash('example-password-123')
        self.assertTrue(m.password_ok('example-password-123', h))
        self.assertFalse(m.password_ok('bad', h))
        self.assertNotIn('example-password-123', h)

    def test_domain_validation(self):
        self.assertEqual(m.normalize_host('SHOP.EXAMPLE.ORG'), 'shop.example.org')
        for host in ('127.0.0.1', 'localhost', 'foo.local', 'example.com:444',
                     'https://example.com', 'evil.com/path', 'foo..bar', 'bad.example'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                m.normalize_host(host)

    def test_dns_private_rejected(self):
        fake = [(2, 1, 6, '', ('127.0.0.1', 443))]
        with mock.patch.object(m.socket, 'getaddrinfo', return_value=fake):
            with self.assertRaises(ValueError):
                m.resolve_public_ip('example.org')

    def test_verification_exact_token(self):
        with mock.patch.object(m, 'fetch_https', return_value={'status': 200, 'body': b'workbench-verification=abc\n'}):
            self.assertTrue(m.verify_site('example.org', 'abc'))
            self.assertFalse(m.verify_site('example.org', 'different'))

    def test_schedule_timezone_and_frequencies(self):
        t = dt.datetime(2026, 11, 17, 14, 0, tzinfo=dt.timezone.utc)  # 9 AM Toronto
        self.assertEqual(m.next_due('daily', 'America/Toronto', 9, t)[:10], '2026-11-18')
        self.assertEqual(m.next_due('weekly', 'America/Toronto', 9, t)[:10], '2026-11-23')
        self.assertEqual(m.next_due('monthly', 'America/Toronto', 9, t)[:10], '2026-12-01')

    def test_findings_do_not_claim_sqli(self):
        findings, evidence = m.baseline_findings({'status': 200, 'headers': [], 'cert_not_after': None})
        self.assertEqual(len(findings), 3)
        self.assertNotIn('SQL injection', str(findings))
        self.assertIn('not confirmed SQL injection', m.deterministic_summary('attention', findings))

    def test_demo_scan_creates_report(self):
        site_id = self.add_demo()
        with mock.patch.object(m, 'ai_summary', side_effect=lambda s, f: (m.deterministic_summary(s, f), False)):
            scan_id = m.run_scan(site_id)
        with m.db() as con:
            scan = con.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
        self.assertEqual(scan['status'], 'attention')
        self.assertEqual(scan['trigger'], 'manual')
        self.assertEqual(scan['ai_used'], 0)

    def test_scheduler_claims_once_and_records_email_unconfigured(self):
        site_id = self.add_demo()
        with mock.patch.object(m, 'ai_summary', side_effect=lambda s, f: (m.deterministic_summary(s, f), False)):
            with mock.patch.dict(os.environ, {'SMTP_HOST': '', 'SMTP_FROM': ''}):
                self.assertEqual(m.scheduler_once(), 1)
                self.assertEqual(m.scheduler_once(), 0)
        with m.db() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM scans WHERE site_id=?', (site_id,)).fetchone()[0], 1)
            notification = con.execute('SELECT status FROM notifications WHERE site_id=?', (site_id,)).fetchone()
        self.assertEqual(notification['status'], 'not-configured')

    def test_no_scan_before_verification(self):
        with m.db() as con:
            cur = con.execute('INSERT INTO sites(user_id,host,verification_token,frequency,timezone,next_run_at) VALUES(?,?,?,?,?,?)',
                              (self.user_id, 'shop.example.org', 'token', 'weekly', 'UTC', m.iso()))
            site_id = cur.lastrowid
        with self.assertRaises(ValueError):
            m.run_scan(site_id)

    def test_ai_fallback_without_key(self):
        with mock.patch.dict(os.environ, {'GEMINI_API_KEY': ''}):
            summary, used = m.ai_summary('healthy', [])
        self.assertFalse(used)
        self.assertIn('limited', summary)

    def test_browser_login_csrf_and_report_isolation(self):
        self.add_demo()
        server = m.ThreadingHTTPServer(('127.0.0.1', 0), m.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        def request(method, path, body=None, cookie=None):
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            headers = {'Host': '127.0.0.1:18771'}
            if cookie:
                headers['Cookie'] = cookie
            if body is not None:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            conn.request(method, path, body, headers=headers)
            res = conn.getresponse()
            result = res.status, res.getheaders(), res.read().decode()
            conn.close()
            return result
        code, hdrs, page = request('GET', '/login')
        self.assertEqual(code, 200)
        self.assertIn('Sign in', page)
        anon_cookie = next(v for k,v in hdrs if k.lower()=='set-cookie' and v.startswith('monitor_anon=')).split(';')[0]
        csrf = anon_cookie.split('=',1)[1]
        code, _, _ = request('POST', '/login', 'email=owner%40example.org&password=example-password-123&csrf=WRONG', anon_cookie)
        self.assertEqual(code, 403)
        code, hdrs, _ = request('POST', '/login', 'email=owner%40example.org&password=example-password-123&csrf='+csrf, anon_cookie)
        self.assertEqual(code, 303)
        session_cookie = next(v for k,v in hdrs if k.lower()=='set-cookie' and v.startswith('monitor_session=')).split(';')[0]
        code, _, page = request('GET', '/', cookie=session_cookie)
        self.assertEqual(code, 200)
        self.assertIn('demo.security-checkup.invalid', page)
        code, _, _ = request('GET', '/report?id=999999', cookie=session_cookie)
        self.assertEqual(code, 404)
        code, _, _ = request('GET', '/', cookie=None)
        self.assertEqual(code, 200)
        self.assertNotIn('demo.security-checkup.invalid', request('GET', '/')[2])

    def test_one_tap_demo_isolated_and_no_external_scans(self):
        from urllib.parse import urlencode
        with mock.patch.dict(os.environ, {'MONITOR_DEMO_MODE': '1'}):
            server = m.ThreadingHTTPServer(('127.0.0.1', 0), m.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            port = server.server_address[1]

            def request(method, path, data=None, cookie=None):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                headers = {'Host': '127.0.0.1:18771'}
                if cookie:
                    headers['Cookie'] = cookie
                if data is not None:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                conn.request(method, path, data, headers)
                res = conn.getresponse()
                result = res.status, res.getheaders(), res.read().decode()
                conn.close()
                return result

            status, hdrs, page = request('GET', '/')
            self.assertEqual(status, 200)
            self.assertIn('Explore demo', page)
            anon_cookie = next(v for k,v in hdrs if k.lower() == 'set-cookie' and v.startswith('monitor_anon=')).split(';')[0]
            csrf = anon_cookie.split('=',1)[1]
            status, _, _ = request('POST', '/demo-login', urlencode({'csrf':'wrong'}), anon_cookie)
            self.assertEqual(status, 403)
            status, hdrs, _ = request('POST', '/demo-login', urlencode({'csrf':csrf}), anon_cookie)
            self.assertEqual(status, 303)
            sess_cookie = next(v for k,v in hdrs if k.lower() == 'set-cookie' and v.startswith('monitor_session=')).split(';')[0]
            status, _, page = request('GET', '/', cookie=sess_cookie)
            self.assertEqual(status, 200)
            self.assertIn('Sample customer account', page)
            self.assertIn('demo.security-checkup.invalid', page)
            self.assertNotIn('action="/add"', page)
            with m.db() as con:
                user = con.execute("SELECT * FROM users WHERE email LIKE 'demo-%@local.invalid'").fetchone()
                self.assertIsNotNone(user)
                self.assertEqual(con.execute('SELECT count(*) FROM scans WHERE user_id=?', (user['id'],)).fetchone()[0], 1)
                csrf_logged = con.execute('SELECT csrf FROM sessions WHERE user_id=?', (user['id'],)).fetchone()['csrf']
            status, _, _ = request('POST', '/add', urlencode({'csrf':csrf_logged, 'host':'shop.example.org'}), sess_cookie)
            self.assertEqual(status, 403)
            status, _, _ = request('POST', '/test-email', urlencode({'csrf':csrf_logged, 'site_id':'2'}), sess_cookie)
            self.assertEqual(status, 404)  # No access to another account's site

    def test_demo_disabled_by_default(self):
        with mock.patch.dict(os.environ, {'MONITOR_DEMO_MODE': ''}):
            self.assertFalse(m.demo_mode_enabled())

if __name__ == '__main__':
    unittest.main(verbosity=2)
