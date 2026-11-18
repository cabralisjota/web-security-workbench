"""Run with: python -m unittest discover -s render-live -v"""
import unittest
from render_live import app, run_one
from v5_suite import CASES


class PublicTrainingTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_module_catalog(self):
        response = self.client.get('/api/training/modules')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['count'], 17)

    def test_each_module_passes(self):
        self.assertEqual(len(CASES), 17)
        for case in CASES:
            with self.subTest(module=case['key']):
                self.assertTrue(run_one(case)['passed'])

    def test_one_module(self):
        response = self.client.post('/api/training/run/bola')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['result']['passed'])

    def test_all_modules(self):
        response = self.client.post('/api/training/run-all')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['total'], 17)
        self.assertEqual(response.json['passed'], 17)

    def test_unknown_module(self):
        self.assertEqual(self.client.post('/api/training/run/not-a-module').status_code, 404)

    def test_homepage_and_script(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        self.assertIn(b'/live.js', self.client.get('/').data)
        self.assertEqual(self.client.get('/live.js').status_code, 200)


if __name__ == '__main__':
    unittest.main()
