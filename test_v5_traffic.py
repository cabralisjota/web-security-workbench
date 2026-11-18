import contextlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
import v5_traffic as traffic


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.dbfile=Path(self.tmp.name)/'test.sqlite3'
        def database():
            @contextlib.contextmanager
            def ctx():
                con=sqlite3.connect(str(self.dbfile))
                con.row_factory=sqlite3.Row
                con.execute('PRAGMA foreign_keys=ON')
                try:
                    yield con
                    con.commit()
                except Exception:
                    con.rollback();raise
                finally:con.close()
            return ctx()
        self.db=database
        with self.db() as con:
            con.execute('CREATE TABLE users(id INTEGER PRIMARY KEY)')
            con.execute('CREATE TABLE sites(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),host TEXT,is_demo INTEGER,verified_at TEXT)')
            con.executemany('INSERT INTO users(id) VALUES(?)',[(1,),(2,)])
            con.executemany('INSERT INTO sites VALUES(?,?,?,?,?)',[(10,1,'example.test',0,'2026-01-01'),(11,1,'demo.invalid',1,'2026-01-01'),(20,2,'other.test',0,'2026-01-01'),(12,1,'notverified.test',0,None)])
        traffic.init_schema(self.db)

    def tearDown(self):self.tmp.cleanup()

    def test_demo_is_explicitly_synthetic(self):
        html=traffic.page(self.db,1,'csrf')
        self.assertIn('SYNTHETIC DEMO DATA',html)
        self.assertIn('DEMO · NOT LIVE',html)
        self.assertIn('not</strong> a confirmed attack',html)
        self.assertIn('Toronto',html)
        self.assertIn('traffic-map',html)

    def test_import_and_no_raw_ip_storage(self):
        csv='country,city,latitude,longitude,type,count,status\nCanada,Toronto,43.65,-79.38,visitor,25,200\nCanada,Toronto,43.65,-79.38,flagged,3,403'
        self.assertEqual(traffic.import_events(self.db,1,10,csv,self.tmp.name),2)
        with self.db() as con:
            rows=con.execute('SELECT * FROM traffic_events WHERE user_id=1').fetchall()
        self.assertEqual(len(rows),2)
        self.assertNotIn('ip',rows[0].keys())
        self.assertEqual(rows[1]['category'],'flagged')
        self.assertEqual(rows[0]['request_count'],25)
        self.assertIn('IMPORTED DATA — NOT LIVE',traffic.page(self.db,1,'csrf'))
        self.assertNotIn('SYNTHETIC DEMO DATA',traffic.page(self.db,1,'csrf'))
        self.assertIn('NO TRAFFIC DATA',traffic.page(self.db,2,'csrf'))
        self.assertNotIn('class="traffic-dot',traffic.page(self.db,2,'csrf'))

    def test_cross_tenant_and_unverified_rejected(self):
        csv='country,city,latitude,longitude,type\nCanada,Toronto,43.65,-79.38,visitor'
        for site in (11,12,20):
            with self.assertRaises(ValueError):traffic.import_events(self.db,1,site,csv,self.tmp.name)
        with self.db() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM traffic_events').fetchone()[0],0)

    def test_bad_inputs(self):
        for csv in (
            'country,city,latitude,longitude,type\nCanada,Toronto,NaN,-79.38,visitor',
            'country,city,latitude,longitude,type\nCanada,Toronto,100,-79.38,visitor',
            'country,city,latitude,longitude,type\nCanada,Toronto,43,-79,attack',
            'country,city,latitude,longitude,type,count\nCanada,Toronto,43,-79,visitor,0',
            'country,city,type,ip\nCanada,Toronto,visitor,127.0.0.1',
        ):
            with self.subTest(csv=csv),self.assertRaises(ValueError):traffic.parse_csv(csv,Path(self.tmp.name)/'GeoLite2-City.mmdb')

    def test_svg_map_has_no_external_dependency(self):
        svg=traffic._map(traffic.demo_events())
        self.assertIn('viewBox="0 0 1000 460"',svg)
        self.assertIn('data-category="flagged"',svg)
        self.assertNotIn('http://',svg)
        self.assertNotIn('https://',svg)

    def test_import_is_atomic(self):
        csv=('country,city,latitude,longitude,type,count\n'
             'Canada,Toronto,43.65,-79.38,visitor,5\n'
             'Canada,Toronto,invalid,-79.38,visitor,5')
        with self.assertRaises(ValueError):traffic.import_events(self.db,1,10,csv,self.tmp.name)
        with self.db() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM traffic_events').fetchone()[0],0)


if __name__=='__main__':unittest.main()
