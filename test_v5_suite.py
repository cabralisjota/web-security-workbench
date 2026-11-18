import json
import os
import tempfile
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
import unittest
from pathlib import Path
from unittest import mock

import v5_suite as suite
import v5_features as v5
import monitor_portal as portal


class SuiteTests(unittest.TestCase):
    def test_all_modules_reproduce_and_fix(self):
        self.assertEqual(len(suite.CASES),17)
        for case in suite.CASES:
            key=case['key']
            with self.subTest(case=key):
                vuln=suite.fixture(key,'vulnerable',case['attack'])
                fixed=suite.fixture(key,'fixed',case['attack'])
                control=suite.fixture(key,'fixed',case['control'])
                self.assertTrue(suite.weakness_seen(key,*vuln))
                self.assertFalse(suite.weakness_seen(key,*fixed))
                self.assertTrue(suite.fixture_control_ok(key,*control))

    def test_full_http_training_suite_and_fixture_auth(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),portal.Handler)
        old_port=portal.PORT
        portal.PORT=server.server_address[1]
        worker=threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        try:
            report=suite.run_suite(portal.PORT)
            self.assertEqual(report['passed'],17)
            self.assertEqual(report['requests'],51)
            unauth=urllib.request.Request('http://127.0.0.1:'+str(portal.PORT)+'/__v5_fixture',
                                          data=b'{}',headers={'Content-Type':'application/json'},method='POST')
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(unauth,timeout=3)
            self.assertEqual(raised.exception.code,403)
        finally:
            server.shutdown(); server.server_close();worker.join(timeout=3)
            portal.PORT=old_port

    def test_sql_parameterization(self):
        payload={"name":"' OR '1'='1"}
        self.assertEqual(suite.fixture('api-sqli','vulnerable',payload)[1]['fictional_users'],['alice','bob'])
        self.assertEqual(suite.fixture('api-sqli','fixed',payload)[1]['fictional_users'],[])

    def test_api_ssrf_is_simulated(self):
        status,data=suite.fixture('api-ssrf','vulnerable',{'url':'http://127.0.0.1/internal/status'})
        self.assertEqual(status,200)
        self.assertEqual(data['network_requests'],0)

    def test_fixture_rejects_unknown(self):
        self.assertEqual(suite.fixture('unknown','fixed',{})[0],404)
        self.assertEqual(suite.fixture('bola','unsupported',{})[0],404)

    def test_openapi_summary(self):
        spec={'openapi':'3.0.0','paths':{'/a':{'get':{}},'/b':{'post':{'security':[]}}}}
        report=suite.inspect_openapi(json.dumps(spec))
        self.assertEqual(report['total'],2)
        self.assertEqual(report['counts']['auth_not_specified'],1)
        self.assertEqual(report['rows'][1]['auth_documentation'],'declared public')

    def test_openapi_rejects_non_spec(self):
        with self.assertRaises(ValueError): suite.inspect_openapi('{}')
        with self.assertRaises(ValueError): suite.inspect_openapi('x'*300000)

    def test_openapi_no_ref_dereference(self):
        spec={'openapi':'3.1.0','paths':{'/a':{'get':{'parameters':[{'$ref':'https://example.com/x'}]}}}}
        report=suite.inspect_openapi(json.dumps(spec))
        self.assertEqual(report['rows'][0]['parameter_names'],['?'])

    def test_demo_inventory_is_network_free(self):
        report=v5.discover_openapi({'is_demo':1},lambda *a: self.fail('network'),lambda *a,**k:self.fail('network'))
        self.assertEqual(report['total'],4)

    def test_real_site_verification_required(self):
        site={'is_demo':0,'verified_at':'2026-11-17','host':'example.org','verification_token':'fake'}
        with self.assertRaises(ValueError):
            v5.discover_openapi(site,lambda *a:False,lambda *a,**k:self.fail('network'))

    def test_openapi_fetch_paths_limited(self):
        with self.assertRaises(ValueError): portal.fetch_https('example.org','/secret')

    def test_ai_requires_key(self):
        with mock.patch.dict(os.environ,{'GEMINI_API_KEY':''}):
            with self.assertRaises(ValueError): v5.ai_lab_explanation({'rows':[]})

    def test_report_owner_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            original_dir,original_db=portal.DATA_DIR,portal.DB_FILE
            portal.DATA_DIR=Path(directory)/'data'; portal.DB_FILE=portal.DATA_DIR/'db.sqlite3'
            try:
                portal.init_db()
                with portal.db() as con:
                    a=con.execute('INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)',('a@example.org','x',portal.iso())).lastrowid
                    b=con.execute('INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)',('b@example.org','x',portal.iso())).lastrowid
                rid=v5.save_report(portal.db,a,None,suite.demo_openapi())
                self.assertIsNotNone(v5.load_report(portal.db,a,rid))
                self.assertIsNone(v5.load_report(portal.db,b,rid))
            finally:
                portal.DATA_DIR,portal.DB_FILE=original_dir,original_db

if __name__=='__main__': unittest.main()
