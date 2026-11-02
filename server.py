"""Local-only dashboard server. Standard-library dependencies only."""
import argparse
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import core

ROOT = Path(__file__).resolve().parent

def make_handler(db_path, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Asset names and notes are deliberately excluded from access logs.

        def allowed_host(self):
            return self.headers.get('Host') == f'127.0.0.1:{self.server.server_port}'

        def send(self, code, body, mime='application/json; charset=utf-8'):
            if not isinstance(body, bytes):
                body = body.encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type',mime)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('X-Frame-Options','DENY')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def json(self, value, code=200):
            self.send(code,json.dumps(value, allow_nan=False))

        def do_GET(self):
            if not self.allowed_host():
                return self.json({'error':'Use the printed 127.0.0.1 URL.'},403)
            path = urlsplit(self.path).path
            if path == '/api/state':
                return self.json(core.summary(db_path))
            if path == '/api/session':
                # A cross-origin page cannot read this response (no CORS headers).
                return self.json({'token':token})
            if path == '/api/export.csv':
                return self.send(200,core.export_csv(core.findings(db_path)), 'text/csv; charset=utf-8')
            if path == '/api/report.json':
                return self.json(core.summary(db_path))
            routes = {'/':('index.html','text/html; charset=utf-8'),
                      '/app.js':('app.js','text/javascript; charset=utf-8'),
                      '/style.css':('style.css','text/css; charset=utf-8')}
            if path not in routes:
                return self.json({'error':'Not found'},404)
            filename, mime = routes[path]
            return self.send(200,(ROOT/'web'/filename).read_bytes(),mime)

        def do_POST(self):
            origin = self.headers.get('Origin')
            if not self.allowed_host() or origin != f'http://127.0.0.1:{self.server.server_port}' or not secrets.compare_digest(self.headers.get('X-VulnPilot-Token',''),token):
                return self.json({'error':'Request rejected. Refresh the local dashboard.'},403)
            if self.headers.get('Content-Type','').split(';')[0] != 'application/json':
                return self.json({'error':'JSON required'},415)
            try:
                length = int(self.headers.get('Content-Length','0'))
                if not 0 < length <= 2_200_000:
                    raise ValueError('Request limit is 2 MB of source text.')
                raw = self.rfile.read(length)
                data = json.loads(raw)
                if not isinstance(data,dict):
                    raise ValueError('Request must be an object.')
                path = urlsplit(self.path).path
                if path == '/api/import':
                    result = {'imported':core.import_rows(db_path,core.parse_csv(data['csv']))}
                elif path == '/api/demo':
                    result = {'imported':core.load_demo(db_path,ROOT/'samples')}
                elif path == '/api/update':
                    core.update_finding(db_path,int(data['id']),data['status'],data.get('notes',''))
                    result = {'updated':True}
                elif path == '/api/snapshot':
                    intel, meta = core.parse_snapshot(data['snapshot'])
                    core.save_intel(db_path,intel,meta)
                    result = meta
                elif path == '/api/sync':
                    result = core.refresh_live(db_path)
                else:
                    return self.json({'error':'Not found'},404)
                return self.json(result)
            except (ValueError,KeyError,TypeError,UnicodeError) as exc:
                return self.json({'error':str(exc)},400)
            except Exception:
                # Failed refresh is atomic: old evidence remains available.
                return self.json({'error':'Operation failed. A feed may be unavailable or the database may be busy. Existing intelligence was retained if refresh failed.'},502)
    return Handler

def main():
    parser = argparse.ArgumentParser(description='VulnPilot local vulnerability triage workbench')
    parser.add_argument('--port',type=int,default=8795)
    parser.add_argument('--db',default=str(ROOT/'data'/'vulnpilot.db'))
    args = parser.parse_args()
    core.init_db(args.db)
    server = ThreadingHTTPServer(('127.0.0.1',args.port),make_handler(args.db,secrets.token_urlsafe(32)))
    print(f'VulnPilot is ready: http://127.0.0.1:{server.server_port}',flush=True)
    print('Keep this terminal open. Press Ctrl+C to stop. No third-party Python packages required.',flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__':
    main()
