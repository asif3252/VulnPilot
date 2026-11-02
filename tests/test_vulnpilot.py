import csv
import http.client
import io
import json
import tempfile
import threading
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer
import core
from server import make_handler

ROOT = Path(__file__).resolve().parents[1]
RAW = (ROOT/'samples/demo_findings.csv').read_text()

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'test.db'
        core.init_db(self.path)
        self.rows=core.parse_csv(RAW)
        core.import_rows(self.path,self.rows)

    def tearDown(self):
        self.temp.cleanup()

    def test_upsert_preserves_workflow_and_first_seen(self):
        row=core.findings(self.path)[0]
        core.update_finding(self.path,row['id'],'In progress','Assigned to patch window')
        core.import_rows(self.path,self.rows)
        actual=next(r for r in core.findings(self.path) if r['id']==row['id'])
        self.assertEqual(actual['status'],'In progress')
        self.assertEqual(actual['notes'],'Assigned to patch window')
        self.assertEqual(actual['first_seen'],row['first_seen'])
        self.assertEqual(len(core.findings(self.path)),len(self.rows))

    def test_unknown_intelligence_is_provisional(self):
        self.assertTrue(all(r['kev'] is None and r['epss'] is None and r['provisional'] for r in core.findings(self.path)))

    def test_exposed_kev_overrides_band(self):
        row=dict(core.findings(self.path)[0],cvss=0,criticality=1,internet_exposed=1)
        p=core.priority(row,{'kev':True,'epss':0})
        self.assertEqual(p['priority'],'P1')
        self.assertEqual(p['score'],40)
        self.assertTrue(any('override' in s for s in p['reasons']))

    def test_resolved_does_not_count_overdue(self):
        row=dict(core.findings(self.path)[0],first_seen='2020-01-01T00:00:00+00:00',status='Resolved')
        self.assertFalse(core.priority(row,{})['overdue'])
        row['status']='Open'
        self.assertTrue(core.priority(row,{})['overdue'])

    def test_bad_csv_is_rejected_before_import(self):
        for raw in [RAW.replace('9.8,','nan,',1),RAW.replace(',true,',',yes,',1),RAW.replace(',5,',',2.5,',1),RAW+RAW.splitlines()[1]+'\n']:
            with self.assertRaises(ValueError):
                core.parse_csv(raw)
        self.assertEqual(len(core.findings(self.path)),8)

    def test_invalid_status_and_id(self):
        with self.assertRaises(ValueError):
            core.update_finding(self.path,1,'Deleted','')
        with self.assertRaises(ValueError):
            core.update_finding(self.path,999999,'Resolved','')

    def test_snapshot_validation(self):
        raw=(ROOT/'samples/demo_intelligence.json').read_text()
        for value in ['"invalid"','1.5']:
            with self.assertRaises(ValueError):
                core.parse_snapshot(raw.replace('0.94',value))
        with self.assertRaises(ValueError):
            core.parse_snapshot(raw.replace('"kev":true','"kev":"false"',1))

    def test_failed_refresh_preserves_snapshot(self):
        intel,meta=core.parse_snapshot((ROOT/'samples/demo_intelligence.json').read_text())
        core.save_intel(self.path,intel,meta)
        before=core.summary(self.path)['metadata']
        with patch('core.fetch_json',side_effect=OSError('Offline')):
            with self.assertRaises(OSError):
                core.refresh_live(self.path)
        self.assertEqual(core.summary(self.path)['metadata'],before)
        self.assertTrue(any(r['kev'] is True for r in core.findings(self.path)))

    def test_live_sync_joins_evidence_and_keeps_missing_epss_unknown(self):
        kev={'count':1,'catalogVersion':'test','vulnerabilities':[{'cveID':self.rows[0]['cve']}]}
        epss={'total':1,'data':[{'cve':self.rows[0]['cve'],'epss':'0.9','date':'2026-11-01'}]}
        with patch('core.fetch_json',side_effect=[kev,epss]):
            core.refresh_live(self.path)
        rows=core.findings(self.path)
        self.assertEqual(sum(r['kev'] is True for r in rows),1)
        self.assertEqual(sum(r['epss'] is None for r in rows),7)
        self.assertTrue(all(r['intel_source']=='CISA KEV + FIRST EPSS' for r in rows))

    def test_export_neutralizes_spreadsheet_formulas(self):
        rows=core.findings(self.path)
        rows[0]['asset']='=HYPERLINK("https://example.invalid")'
        exported=list(csv.DictReader(io.StringIO(core.export_csv(rows))))
        self.assertTrue(exported[0]['asset'].startswith("'="))

    def test_demo_does_not_overwrite_inventory(self):
        with self.assertRaises(ValueError):
            core.load_demo(self.path,ROOT/'samples')
        self.assertEqual(len(core.findings(self.path)),8)

class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.path=Path(cls.temp.name)/'server.db'
        core.init_db(cls.path)
        cls.port=8787

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def request(self,method,path,body=None,headers=None):
        # Exercise the actual HTTP handler/parser without requiring network permission.
        class MemorySocket:
            def __init__(self, data):
                self.data=data;self.output=bytearray()
            def makefile(self,*args,**kwargs):
                return io.BytesIO(self.data)
            def sendall(self,data):
                self.output.extend(data)
        body=(body or '').encode('utf-8')
        fields={'Host':f'127.0.0.1:{self.port}','Content-Length':str(len(body))}
        fields.update(headers or {})
        raw=(f'{method} {path} HTTP/1.1\r\n'+''.join(f'{k}: {v}\r\n' for k,v in fields.items())+'\r\n').encode()+body
        sock=MemorySocket(raw)
        make_handler(self.path,'test-token')(sock,('127.0.0.1',12345),SimpleNamespace(server_port=self.port))
        response=http.client.HTTPResponse(MemorySocket(bytes(sock.output)))
        response.begin()
        return response.status,dict(response.getheaders()),response.read()

    def test_health_and_security_headers(self):
        status,headers,body=self.request('GET','/')
        self.assertEqual(status,200)
        self.assertIn(b'Know what to fix first',body)
        self.assertEqual(headers['X-Frame-Options'],'DENY')
        self.assertIn("script-src 'self'",headers['Content-Security-Policy'])

    def test_cross_origin_and_wrong_host_are_rejected(self):
        self.assertEqual(self.request('POST','/api/demo','{}',{'Content-Type':'application/json'})[0],403)
        self.assertEqual(self.request('GET','/api/state',headers={'Host':'evil.invalid'})[0],403)

    def test_authenticated_local_import_roundtrip(self):
        headers={'Content-Type':'application/json','Origin':f'http://127.0.0.1:{self.port}','X-VulnPilot-Token':'test-token'}
        status,_,_=self.request('POST','/api/import',json.dumps({'csv':RAW}),headers)
        self.assertEqual(status,200)
        status,_,body=self.request('GET','/api/state')
        self.assertEqual(json.loads(body)['stats']['total'],8)

    def test_path_traversal_is_not_served(self):
        self.assertEqual(self.request('GET','/../core.py')[0],404)

if __name__=='__main__':
    unittest.main()
