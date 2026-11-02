"""VulnPilot: deterministic vulnerability triage, not a scanner or risk predictor."""
import csv
import io
import json
import math
import re
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.parse import urlencode

SCHEMA = ['asset', 'cve', 'title', 'cvss', 'criticality', 'internet_exposed', 'owner']
STATUSES = ['Open', 'In progress', 'Mitigated', 'Resolved', 'Accepted risk']
CVE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
POLICY = '1.0'

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def text(value, limit=200):
    value = str(value).strip()
    if len(value) > limit or any(ord(c) < 32 and c not in '\n\t' for c in value):
        raise ValueError(f'Text must be at most {limit} characters without control characters.')
    return value

def number(value, lo, hi, label):
    try:
        result = float(value)
    except (ValueError, TypeError):
        raise ValueError(f'{label} must be numeric.') from None
    if not math.isfinite(result) or not lo <= result <= hi:
        raise ValueError(f'{label} must be between {lo} and {hi}.')
    return result

def parse_csv(raw):
    if len(raw.encode('utf-8')) > 2_000_000:
        raise ValueError('CSV limit is 2 MB.')
    reader = csv.DictReader(io.StringIO(raw.lstrip('\ufeff')))
    if not reader.fieldnames or not set(SCHEMA).issubset(reader.fieldnames):
        raise ValueError('Required columns: ' + ', '.join(SCHEMA))
    if len(reader.fieldnames) != len(set(reader.fieldnames)):
        raise ValueError('Duplicate column names are not allowed.')
    rows = []
    seen = set()
    for line, item in enumerate(reader, 2):
        if len(rows) >= 2000:
            raise ValueError('Import limit is 2,000 findings.')
        if None in item or any(item.get(k) is None for k in SCHEMA):
            raise ValueError(f'Row {line}: incorrect number of fields.')
        row = {k: text(item[k]) for k in SCHEMA}
        row['cve'] = row['cve'].upper()
        if not row['asset'] or not row['title'] or not row['owner'] or not CVE.fullmatch(row['cve']):
            raise ValueError(f'Row {line}: asset, title, owner and a valid CVE are required.')
        row['cvss'] = number(row['cvss'], 0, 10, 'CVSS')
        crit = number(row['criticality'], 1, 5, 'Criticality')
        if crit != int(crit):
            raise ValueError('Criticality must be a whole number from 1 to 5.')
        row['criticality'] = int(crit)
        if row['internet_exposed'].lower() not in ['true', 'false']:
            raise ValueError('internet_exposed must be true or false.')
        row['internet_exposed'] = int(row['internet_exposed'].lower() == 'true')
        key = (row['asset'], row['cve'])
        if key in seen:
            raise ValueError(f'Row {line}: duplicate asset/CVE pair in this import.')
        seen.add(key)
        rows.append(row)
    if not rows:
        raise ValueError('CSV has no findings.')
    return rows

@contextmanager
def connect(path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        with db:
            yield db
    finally:
        db.close()

def init_db(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS findings (
          id INTEGER PRIMARY KEY, asset TEXT NOT NULL, cve TEXT NOT NULL,
          title TEXT NOT NULL, cvss REAL NOT NULL, criticality INTEGER NOT NULL,
          internet_exposed INTEGER NOT NULL, owner TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'Open', notes TEXT NOT NULL DEFAULT '',
          first_seen TEXT NOT NULL, updated_at TEXT NOT NULL,
          UNIQUE(asset,cve));
        CREATE TABLE IF NOT EXISTS intel (cve TEXT PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, finding_id INTEGER,
          at TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
        ''')

def import_rows(path, rows):
    """Atomic upsert; an import never silently resets workflow state."""
    stamp = now()
    with connect(path) as db:
        total = db.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
        keys = {(r['asset'], r['cve']) for r in db.execute('SELECT asset,cve FROM findings')}
        if total + sum((r['asset'], r['cve']) not in keys for r in rows) > 5000:
            raise ValueError('Database limit is 5,000 findings. Use a separate database for a larger exercise.')
        for r in rows:
            db.execute('''INSERT INTO findings
              (asset,cve,title,cvss,criticality,internet_exposed,owner,first_seen,updated_at)
              VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(asset,cve) DO UPDATE SET
              title=excluded.title,cvss=excluded.cvss,criticality=excluded.criticality,
              internet_exposed=excluded.internet_exposed,owner=excluded.owner,updated_at=excluded.updated_at''',
              tuple(r[k] for k in SCHEMA) + (stamp, stamp))
        db.execute('INSERT INTO audit(at,action,detail) VALUES(?,?,?)', (stamp, 'import', json.dumps({'rows':len(rows)})))
    return len(rows)

def update_finding(path, ident, status, notes):
    if status not in STATUSES:
        raise ValueError('Unsupported workflow status.')
    notes = text(notes, 2000)
    with connect(path) as db:
        old = db.execute('SELECT * FROM findings WHERE id=?', (ident,)).fetchone()
        if not old:
            raise ValueError('Finding does not exist.')
        stamp = now()
        db.execute('UPDATE findings SET status=?,notes=?,updated_at=? WHERE id=?', (status, notes, stamp, ident))
        db.execute('INSERT INTO audit(finding_id,at,action,detail) VALUES(?,?,?,?)',
                   (ident, stamp, 'workflow', json.dumps({'before':old['status'], 'after':status, 'notes':notes})))

def priority(row, intel, today=None):
    today = today or date.today()
    reasons = []
    score = row['cvss'] * 3
    reasons.append(f"CVSS {row['cvss']:g}: +{score:g}")
    impact = (row['criticality'] - 1) * 5
    score += impact
    reasons.append(f"Asset criticality {row['criticality']}/5: +{impact}")
    if row['internet_exposed']:
        score += 15
        reasons.append('Internet exposed: +15')
    kev = intel.get('kev')
    epss = intel.get('epss')
    if kev is True:
        score += 25
        reasons.append('Listed in imported KEV snapshot: +25')
    elif kev is None:
        reasons.append('KEV status unknown; no negative assurance')
    else:
        reasons.append('Not listed in imported KEV snapshot; this does not establish safety')
    if epss is not None:
        score += epss * 10
        reasons.append(f'EPSS {epss:.1%}: +{epss*10:.2f}')
    else:
        reasons.append('EPSS unavailable; score is provisional')
    score = round(min(100, score), 2)
    if kev is True and row['internet_exposed']:
        band = 'P1'
        reasons.append('Policy override: exposed KEV finding is P1')
    else:
        band = 'P1' if score >= 75 else 'P2' if score >= 50 else 'P3' if score >= 25 else 'P4'
    days = {'P1':2, 'P2':7, 'P3':30, 'P4':90}[band]
    first = datetime.fromisoformat(row['first_seen']).date()
    target = first + timedelta(days=days)
    age = max(0, (today - first).days)
    return dict(score=score, priority=band, reasons=reasons, target_date=target.isoformat(),
                overdue=target < today and row['status'] in ['Open', 'In progress'], age_days=age,
                provisional=kev is None or epss is None,
                intel_source=intel.get('source','Unavailable'), intel_date=intel.get('date'),
                kev=kev, epss=epss, policy_version=POLICY)

def findings(path):
    with connect(path) as db:
        intel = {r['cve']:json.loads(r['data']) for r in db.execute('SELECT * FROM intel')}
        rows = [dict(r) for r in db.execute('SELECT * FROM findings')]
    for r in rows:
        r.update(priority(r, intel.get(r['cve'], {})))
    return sorted(rows, key=lambda r:(r['priority'], -r['score'], r['asset'], r['cve']))

def summary(path):
    rows = findings(path)
    active = [r for r in rows if r['status'] in ['Open', 'In progress']]
    with connect(path) as db:
        meta = {r['key']:json.loads(r['value']) for r in db.execute('SELECT * FROM metadata')}
        audit = [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]
    return {'findings':rows, 'stats':{'total':len(rows), 'active':len(active),
            'urgent':sum(r['priority']=='P1' for r in active), 'overdue':sum(r['overdue'] for r in active),
            'provisional':sum(r['provisional'] for r in rows)}, 'metadata':meta, 'audit':audit,
            'generated_at':now(), 'policy_version':POLICY}

def save_intel(path, intel, metadata):
    with connect(path) as db:
        # Replace the whole snapshot atomically; never mix live and demo evidence.
        db.execute('DELETE FROM intel')
        db.executemany('INSERT INTO intel(cve,data) VALUES(?,?)', [(k,json.dumps(v)) for k,v in intel.items()])
        db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)', ('intelligence',json.dumps(metadata)))
        db.execute('INSERT INTO audit(at,action,detail) VALUES(?,?,?)', (now(),'intelligence',json.dumps(metadata)))

def parse_snapshot(raw):
    """Import small normalized evidence snapshots, not arbitrary vendor feeds."""
    if len(raw.encode()) > 2_000_000:
        raise ValueError('Snapshot limit is 2 MB.')
    payload = json.loads(raw)
    if not isinstance(payload, dict) or not isinstance(payload.get('records'), list) or len(payload['records']) > 5000:
        raise ValueError('Snapshot requires at most 5,000 records.')
    source = text(payload.get('source',''), 100)
    if not source:
        raise ValueError('Snapshot source is required.')
    stamp = date.fromisoformat(payload['date']).isoformat()
    if date.fromisoformat(stamp) > date.today():
        raise ValueError('Snapshot date cannot be in the future.')
    result = {}
    for r in payload['records']:
        if not isinstance(r, dict) or not CVE.fullmatch(str(r.get('cve',''))) or r['cve'] in result:
            raise ValueError('Snapshot requires unique valid CVE IDs.')
        if r.get('kev') is not None and type(r['kev']) is not bool:
            raise ValueError('kev must be true, false, or null.')
        ep = r.get('epss')
        if ep is not None:
            ep = number(ep, 0, 1, 'EPSS')
        result[r['cve']] = {'kev':r.get('kev'), 'epss':ep, 'date':stamp, 'source':source}
    return result, {'source':source, 'date':stamp, 'retrieved_at':now(), 'count':len(result)}

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Feed redirected; update the allowlisted endpoint after review.')

def fetch_json(url):
    # Only internal fixed URLs call this function; no asset addresses or user URLs.
    req = Request(url, headers={'User-Agent':'VulnPilot/1.0', 'Accept':'application/json'})
    with build_opener(NoRedirect).open(req, timeout=15) as response:
        data = response.read(12_000_001)
    if len(data) > 12_000_000:
        raise ValueError('Feed exceeded the 12 MB response limit.')
    return json.loads(data)

def refresh_live(path):
    with connect(path) as db:
        cves = [r[0] for r in db.execute('SELECT DISTINCT cve FROM findings ORDER BY cve')]
    if not cves or len(cves) > 100:
        raise ValueError('Live lookup supports 1–100 unique CVEs; use snapshot import for larger inventories.')
    kev = fetch_json('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    if not isinstance(kev.get('vulnerabilities'), list) or not kev['vulnerabilities'] or kev.get('count') != len(kev['vulnerabilities']):
        raise ValueError('CISA catalog failed completeness checks. Existing intelligence was retained.')
    kev_ids = {v['cveID'] for v in kev['vulnerabilities']}
    if len(kev_ids) != len(kev['vulnerabilities']) or any(not CVE.fullmatch(c) for c in kev_ids):
        raise ValueError('CISA catalog has invalid or duplicate IDs.')
    result = {c:{'kev':c in kev_ids, 'epss':None, 'source':'CISA KEV + FIRST EPSS',
                 'date':None, 'kev_catalog_version':kev.get('catalogVersion'),
                 'kev_date_released':kev.get('dateReleased')} for c in cves}
    for start in range(0, len(cves), 50):
        batch = cves[start:start+50]
        payload = fetch_json('https://api.first.org/data/v1/epss?' + urlencode({'cve':','.join(batch), 'limit':100}))
        data = payload.get('data')
        if not isinstance(data, list) or len(data) != int(payload.get('total',-1)):
            raise ValueError('FIRST response failed completeness checks. Existing intelligence was retained.')
        for record in data:
            if record['cve'] not in batch:
                raise ValueError('Unexpected CVE returned by FIRST.')
            result[record['cve']]['epss'] = number(record['epss'], 0, 1, 'EPSS')
            result[record['cve']]['date'] = date.fromisoformat(record['date']).isoformat()
    meta = {'source':'CISA KEV + FIRST EPSS', 'retrieved_at':now(), 'count':len(result),
            'kev_catalog_version':kev.get('catalogVersion'), 'kev_date_released':kev.get('dateReleased')}
    save_intel(path, result, meta)
    return meta

def safe_cell(value):
    value = str(value)
    return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) else value

def export_csv(rows):
    columns = ['asset','cve','title','cvss','priority','score','kev','epss','intel_source','intel_date',
               'provisional','owner','status','target_date','overdue','notes']
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell('Unknown' if row.get(c) is None else row[c]) for c in columns])
    return output.getvalue()

def load_demo(path, folder):
    with connect(path) as db:
        if db.execute('SELECT COUNT(*) FROM findings').fetchone()[0]:
            raise ValueError('Demo loads only into an empty database. Your existing findings were preserved.')
    rows = parse_csv((Path(folder)/'demo_findings.csv').read_text(encoding='utf-8'))
    intel, meta = parse_snapshot((Path(folder)/'demo_intelligence.json').read_text(encoding='utf-8'))
    import_rows(path, rows)
    save_intel(path, intel, meta)
    return len(rows)
