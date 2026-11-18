"""Regression tests for mobile layout, demo onboarding, and version detection."""
import unittest
from pathlib import Path
from unittest.mock import patch
import monitor_portal as m
import v5_traffic as traffic
import v5_ux as ux

class V54Tests(unittest.TestCase):
    def test_health_version_markup(self):
        page=m.layout('Customer security dashboard','<p>OK</p>',{'email':'demo@local.invalid'},csrf='x',nonce='nonce')
        self.assertIn('v5.4 · Security operations',page)
        self.assertIn('class="wrap dashboard-home"',page)
    def test_map_first_and_sample_data_label(self):
        with patch.object(traffic,'_all_events',return_value=(traffic.demo_events(),[],True)):
            sample=traffic.overview_map(None,1)
        self.assertIn('SYNTHETIC DEMO · NOT LIVE',sample)
        self.assertIn('map-frame',sample)
    def test_mobile_dropdown_css_and_single_open_logic(self):
        self.assertIn('position:absolute!important',ux.CSS)
        self.assertIn('grid-template-columns:repeat(4,minmax(0,1fr))!important',ux.CSS)
        self.assertIn("if(other!==item)other.open=false",ux.JS)
    def test_demo_forms_are_native_and_reports_created(self):
        source=Path(m.__file__).read_text(encoding='utf-8')
        self.assertIn('action="/demo-login" data-native-submit="1"',source)
        self.assertIn('action="/demo" data-native-submit="1"',source)
        self.assertIn("return self.redirect('/site?id='+str(sid))",source)
    def test_no_external_traffic_collection(self):
        with patch.object(traffic,'_all_events',return_value=([],[],False)):
            sample=traffic.overview_map(None,1)
        self.assertIn('NO TRAFFIC CONNECTED',sample)
        self.assertNotIn('class="traffic-dot',sample)
if __name__=='__main__':unittest.main()
