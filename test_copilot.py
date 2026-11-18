"""Offline regression tests for Web Security Workbench v3.1.
Run: python -m unittest -v test_copilot.py
No Gemini API key or external network required.
"""
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import sqli_copilot as app


class FakeResponse:
    def __init__(self, payload):
        self.buffer = io.BytesIO(json.dumps(payload).encode('utf-8'))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.buffer.close()

    def read(self, *args):
        return self.buffer.read(*args)


class CopilotTests(unittest.TestCase):
    def test_without_key_does_not_contact_ai(self):
        with patch.dict(os.environ, {'GEMINI_API_KEY': ''}), patch.object(app.urllib.request, 'urlopen') as request:
            with self.assertRaisesRegex(ValueError, 'not configured'):
                app.ai_text({'question': 'hello'})
            request.assert_not_called()

    def test_gemini_rest_payload_and_output(self):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured['url'] = req.full_url
            captured['headers'] = req.headers
            captured['body'] = json.loads(req.data)
            return FakeResponse({'candidates': [{'content': {'parts': [{'text': 'Assessment: parameterized queries help.'}]}}]})

        with patch.dict(os.environ, {'GEMINI_API_KEY': 'example-test-key'}), patch.object(app.urllib.request, 'urlopen', side_effect=fake_urlopen):
            result = app.ai_text({'context': 'synthetic lab', 'question': 'How do I fix SQLi?'})
        self.assertIn('parameterized', result)
        self.assertTrue(captured['url'].startswith('https://generativelanguage.googleapis.com/'))
        self.assertIn('gemini-3.5-flash-lite:generateContent', captured['url'])
        self.assertIn('example-test-key', captured['headers'].values())
        self.assertIn('systemInstruction', captured['body'])
        self.assertIn('synthetic lab', captured['body']['contents'][0]['parts'][0]['text'])

    def test_quota_error_has_actionable_message(self):
        error = urllib.error.HTTPError('https://example.invalid', 429, 'quota', {}, None)
        with patch.dict(os.environ, {'GEMINI_API_KEY': 'example-test-key'}), patch.object(app.urllib.request, 'urlopen', side_effect=error):
            with self.assertRaisesRegex(ValueError, 'free-tier request limit'):
                app.ai_text({'question': 'hi'})

    def test_empty_model_response_is_handled(self):
        with patch.dict(os.environ, {'GEMINI_API_KEY': 'example-test-key'}), patch.object(app.urllib.request, 'urlopen', return_value=FakeResponse({'candidates': []})):
            with self.assertRaisesRegex(ValueError, 'no readable analysis'):
                app.ai_text({'question': 'hi'})

    def test_local_sqli_indicators_and_report(self):
        def fake_get(url):
            value = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get('name', [''])[0]
            if value == 'alice':
                return 200, 'alice'
            if " OR " in value:
                return 200, 'alice bob'
            return 200, '[]'

        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'REPORTS', Path(directory)), patch.object(app, 'lab_health', return_value={'mode': 'vulnerable'}), patch.object(app, 'get_json_url', side_effect=fake_get):
            report, name = app.run_lab_tests()
            self.assertTrue(report['outcome'].startswith('POSITIVE'))
            self.assertEqual(report['requests_sent'], 4)
            self.assertTrue((Path(directory) / name).is_file())
            self.assertIn('fictional', app.report_html(report).lower())

    def test_html_escapes_untrusted_content(self):
        with patch.object(app, 'lab_health', return_value=None), patch.dict(os.environ, {'GEMINI_API_KEY': ''}):
            body = app.page(review='<script>alert(1)</script>')
        self.assertNotIn('<script>alert(1)</script>', body)
        self.assertIn('&lt;script&gt;', body)
        self.assertIn('Test Gemini connection', body)

    def test_local_ai_check_endpoint(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'http://127.0.0.1:{server.server_address[1]}/ai-check'
            body = urllib.parse.urlencode({'csrf': app.CSRF}).encode('utf-8')
            with patch.object(app, 'ai_text', return_value='Safe mock AI response') as ai:
                req = urllib.request.Request(url, data=body, method='POST', headers={'Content-Type': 'application/x-www-form-urlencoded'})
                with urllib.request.urlopen(req, timeout=3) as response:
                    page = response.read().decode('utf-8')
            self.assertIn('Gemini API responded successfully', page)
            self.assertIn('Safe mock AI response', page)
            self.assertEqual(ai.call_args[0][0]['context'], 'Connectivity test only. No client data.')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
