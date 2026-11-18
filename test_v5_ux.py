import re
import unittest
import v5_ux as ux
import monitor_portal as portal
import v5_features as v5

class UXTests(unittest.TestCase):
    def test_ux_assets(self):
        self.assertIn('result-panel',ux.CSS)
        self.assertIn('addEventListener(\'submit\'',ux.JS)
        self.assertIn('scrollIntoView',ux.JS)
        self.assertIn('module-search',ux.JS)

    def test_layout_nonce_and_status(self):
        page=portal.layout('Example', '<div>Test</div>', nonce='test-nonce')
        self.assertIn('id="wb-status"',page)
        self.assertIn('script nonce="test-nonce"',page)
        self.assertIn('v5.1',page)
        self.assertIn('Test</div>',page)

    def test_module_catalog_filter_markup(self):
        class FakeDB:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def execute(self,*args):return self
            def fetchall(self):return []
        page=v5.security_page(lambda:FakeDB(),1,'csrf-test')
        self.assertIn('id="module-search"',page)
        self.assertIn('module-group',page)
        self.assertIn('17 of 17',page)

if __name__=='__main__':unittest.main()
