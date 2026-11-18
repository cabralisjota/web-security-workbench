"""Privacy-minimized traffic visualization for Workbench v5.2.

This module does NOT detect attacks, track browsers, or geolocate live traffic.
It visualizes synthetic demo data or user-supplied, already-authorized web/WAF
log exports. No external lookup or raw IP persistence occurs.
"""
import csv
import datetime as dt
import html
import io
import ipaddress
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORLD = ROOT / 'v5_world.svg'
UTC = dt.timezone.utc
MAX_ROWS = 100


def esc(value):
    return html.escape(str(value), quote=True)


def init_schema(db):
    with db() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS traffic_events (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
            observed_at TEXT NOT NULL,
            country TEXT NOT NULL,
            city TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            category TEXT NOT NULL CHECK(category IN ('visitor','flagged')),
            request_count INTEGER NOT NULL CHECK(request_count BETWEEN 1 AND 10000),
            http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
            source TEXT NOT NULL DEFAULT 'imported'
        )''')
        con.execute('CREATE INDEX IF NOT EXISTS idx_traffic_owner ON traffic_events(user_id,site_id,id)')


def demo_events():
    # These are synthetic aggregates, not observed traffic or threat intelligence.
    sample = [
        ('Toronto','Canada',43.65,-79.38,184,'visitor'),
        ('Vancouver','Canada',49.28,-123.12,68,'visitor'),
        ('New York','United States',40.71,-74.01,121,'visitor'),
        ('Chicago','United States',41.88,-87.63,58,'visitor'),
        ('London','United Kingdom',51.51,-0.13,73,'visitor'),
        ('Paris','France',48.86,2.35,36,'visitor'),
        ('Berlin','Germany',52.52,13.40,28,'visitor'),
        ('Tokyo','Japan',35.68,139.69,45,'visitor'),
        ('Sydney','Australia',-33.87,151.21,22,'visitor'),
        ('Singapore','Singapore',1.35,103.82,32,'visitor'),
        ('Ashburn','United States',39.04,-77.49,19,'flagged'),
        ('Frankfurt','Germany',50.11,8.68,13,'flagged'),
        ('São Paulo','Brazil',-23.55,-46.63,8,'flagged'),
        ('Mumbai','India',19.08,72.88,6,'flagged'),
        ('Amsterdam','Netherlands',52.37,4.90,9,'flagged'),
    ]
    return [{'city':city,'country':country,'latitude':lat,'longitude':lon,
             'request_count':count,'category':category,'source':'demo','http_status':200}
            for city,country,lat,lon,count,category in sample]


def _safe_name(value, limit=60):
    value=' '.join(str(value).split())
    if not value or len(value)>limit or any(ord(c)<32 for c in value):
        raise ValueError('Country and city must be present and under 60 characters.')
    return value


def _coordinates(row, local_geoip_path):
    latitude=(row.get('latitude') or '').strip()
    longitude=(row.get('longitude') or '').strip()
    if latitude and longitude:
        try:
            lat,lon=float(latitude),float(longitude)
        except ValueError:
            raise ValueError('Invalid latitude or longitude.')
    elif row.get('ip','').strip():
        ip=ipaddress.ip_address(row['ip'].strip())
        if not ip.is_global:
            raise ValueError('Only public IP addresses can be geolocated. No IP was stored.')
        if not local_geoip_path.is_file():
            raise ValueError('IP-to-location needs a local GeoLite2-City.mmdb file; alternatively provide latitude and longitude.')
        try:
            import geoip2.database
        except ImportError:
            raise ValueError('Install the optional offline geoip2 package, or provide latitude and longitude.')
        with geoip2.database.Reader(str(local_geoip_path)) as reader:
            try:
                match=reader.city(str(ip))
            except Exception:
                raise ValueError('This IP was not found in the local GeoIP database.')
        lat,lon=match.location.latitude,match.location.longitude
        if lat is None or lon is None:
            raise ValueError('No approximate coordinates found for the supplied IP.')
    else:
        raise ValueError('Provide approximate latitude and longitude, or a public IP with a local GeoIP database.')
    if not (math.isfinite(lat) and math.isfinite(lon) and -90<=lat<=90 and -180<=lon<=180):
        raise ValueError('Coordinates are outside valid world bounds.')
    return round(lat,3),round(lon,3)


def parse_csv(raw, local_geoip_path):
    if not raw.strip():
        raise ValueError('Paste a CSV export before importing.')
    if len(raw.encode('utf-8'))>7500:
        raise ValueError('CSV is too large. Import up to 100 rows per batch, under 7.5 KB.')
    reader=csv.DictReader(io.StringIO(raw))
    if not reader.fieldnames or not {'country','city','type'}.issubset(set(reader.fieldnames)):
        raise ValueError('CSV needs country, city and type columns, plus latitude/longitude or an IP.')
    records=[]
    for index,row in enumerate(reader,1):
        if index>MAX_ROWS:raise ValueError('Import at most 100 records per batch.')
        if None in row:raise ValueError('CSV row has too many columns.')
        category=(row.get('type') or '').strip().lower()
        if category not in ('visitor','flagged'):
            raise ValueError('Type must be visitor or flagged; this does not confirm an attack.')
        lat,lon=_coordinates(row,local_geoip_path)
        try:
            count=int((row.get('count') or '1').strip())
            status=int((row.get('status') or '200').strip())
        except ValueError:
            raise ValueError('Count and HTTP status must be integers.')
        if not 1<=count<=10000 or not 100<=status<=599:
            raise ValueError('Count must be 1–10000 and HTTP status 100–599.')
        timestamp=(row.get('timestamp') or '').strip()
        if timestamp:
            try:
                t=dt.datetime.fromisoformat(timestamp.replace('Z','+00:00'))
                if t.tzinfo is None:raise ValueError('Timestamp needs a UTC offset.')
                timestamp=t.astimezone(UTC).isoformat(timespec='seconds')
            except ValueError:
                raise ValueError('Timestamp must be ISO 8601 with timezone, or blank.')
        else:
            timestamp=dt.datetime.now(UTC).isoformat(timespec='seconds')
        records.append((timestamp,_safe_name(row['country']),_safe_name(row['city']),lat,lon,category,count,status))
    if not records:raise ValueError('CSV contains no data rows.')
    return records


def import_events(db,user_id,site_id,raw,data_dir):
    with db() as con:
        site=con.execute('SELECT id,verified_at,is_demo FROM sites WHERE id=? AND user_id=?',(site_id,user_id)).fetchone()
    if not site:raise ValueError('Website not found in this account.')
    if site['is_demo']:raise ValueError('Demo websites only show clearly labeled sample traffic.')
    if not site['verified_at']:raise ValueError('Verify ownership before importing traffic data.')
    records=parse_csv(raw,Path(data_dir)/'GeoLite2-City.mmdb')
    with db() as con:
        con.executemany('''INSERT INTO traffic_events
            (user_id,site_id,observed_at,country,city,latitude,longitude,category,request_count,http_status)
            VALUES(?,?,?,?,?,?,?,?,?,?)''',[(user_id,site['id'],*r) for r in records])
        # Limit per-account retained records; never retain the raw IP column.
        con.execute('''DELETE FROM traffic_events WHERE user_id=? AND id NOT IN
            (SELECT id FROM traffic_events WHERE user_id=? ORDER BY id DESC LIMIT 2000)''',(user_id,user_id))
    return len(records)


def _all_events(db,user_id):
    with db() as con:
        real=[dict(r) for r in con.execute('''SELECT country,city,latitude,longitude,category,
            request_count,http_status,source FROM traffic_events WHERE user_id=? ORDER BY id DESC LIMIT 2000''',(user_id,)).fetchall()]
        sites=[dict(r) for r in con.execute('''SELECT id,host,is_demo,verified_at FROM sites WHERE user_id=? ORDER BY id DESC''',(user_id,)).fetchall()]
    demo=bool(not real and any(s['is_demo'] for s in sites))
    return (demo_events() if demo else real),sites,demo


def _aggregate(events):
    result={}
    for r in events:
        key=(r['country'],r['city'],r['latitude'],r['longitude'],r['category'])
        if key not in result:result[key]=dict(r)
        else:result[key]['request_count']+=r['request_count']
    return sorted(result.values(),key=lambda r:r['request_count'],reverse=True)


def _map(events):
    try:
        world=WORLD.read_text(encoding='utf-8')
    except OSError:
        world=''
    lines=[]
    for lat in (-60,-30,0,30,60):
        y=(82-lat)/160*460
        lines.append(f'<line x1="0" y1="{y:.1f}" x2="1000" y2="{y:.1f}"/>')
    for lon in (-120,-60,0,60,120):
        x=(lon+180)/360*1000
        lines.append(f'<line x1="{x:.1f}" y1="0" x2="{x:.1f}" y2="460"/>')
    dots=[]
    for r in _aggregate(events):
        x=(r['longitude']+180)/360*1000
        y=(82-r['latitude'])/160*460
        if not (0<=y<=460):continue
        count=r['request_count']
        radius=min(16,4+math.sqrt(count)*.48)
        category=r['category']
        label=f"{r['city']}, {r['country']} — {count} {'flagged requests' if category=='flagged' else 'visits'}"
        dots.append(f'<circle class="traffic-dot {category}" data-category="{category}" '
                    f'data-location="{esc(label)}" cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}" '
                    f'tabindex="0" role="button" aria-label="{esc(label)}"><title>{esc(label)}</title></circle>')
    return ('<svg class="traffic-map" viewBox="0 0 1000 460" role="img" '
            'aria-label="Approximate geographic origins of supplied website traffic">'
            '<rect class="map-ocean" x="0" y="0" width="1000" height="460"/>'
            '<g class="map-grid">'+''.join(lines)+'</g>'
            '<g class="map-land">'+world+'</g>'
            '<g class="map-dots">'+''.join(dots)+'</g></svg>')


def home_card(db,user_id):
    events,sites,demo=_all_events(db,user_id)
    label='Sample locations' if demo else ('Imported traffic' if events else 'No traffic connected')
    return ('<div class="card traffic-promo"><div><p class="eyebrow">Traffic intelligence</p>'
            '<h2>Explore your visitor map</h2><p class="muted">View approximate visitor origins and requests '
            'flagged by your existing logs or WAF. No live tracking is enabled.</p>'
            '<span class="pill">'+esc(label)+'</span></div>'
            '<a class="btn alt" href="/traffic">Open traffic map</a></div>')


def page(db,user_id,csrf,notice=''):
    events,sites,demo=_all_events(db,user_id)
    total=sum(e['request_count'] for e in events)
    visitors=sum(e['request_count'] for e in events if e['category']=='visitor')
    flagged=total-visitors
    regions=len({(e['city'],e['country']) for e in events})
    status='SYNTHETIC DEMO DATA' if demo else ('IMPORTED DATA — NOT LIVE' if events else 'NO TRAFFIC DATA')
    out=('<div class="card traffic-head"><div><p class="eyebrow">Geographic traffic intelligence</p>'
         '<h2>Where your traffic appears to originate</h2><p>Approximate locations from website or WAF log exports. '
         'A flagged request is <strong>not</strong> a confirmed attack or the actual location of an attacker.</p>'
         '<span class="pill">'+status+'</span></div></div>')
    if notice:out+='<div class="notice">'+esc(notice)+'</div>'
    out+=('<div class="traffic-stats">'
          f'<div class="traffic-stat"><span>Visitor requests</span><strong>{visitors:,}</strong></div>'
          f'<div class="traffic-stat"><span>Flagged requests</span><strong>{flagged:,}</strong></div>'
          f'<div class="traffic-stat"><span>Observed locations</span><strong>{regions:,}</strong></div>'
          '</div>')
    out+='<div class="card traffic-map-card"><div class="traffic-map-top"><h2>World traffic map</h2>'
    out+='<div class="traffic-filters" role="group" aria-label="Filter map points">'
    for category,label in (('all','All traffic'),('visitor','Visitors'),('flagged','Flagged requests')):
        out+=f'<button type="button" class="alt map-filter" data-map-filter="{category}" aria-pressed="{str(category=="all").lower()}">{label}</button>'
    out+='</div></div>'
    out+='<div class="map-frame">'+_map(events)
    if demo:out+='<span class="map-watermark">DEMO · NOT LIVE</span>'
    out+='</div><div class="traffic-legend"><span><i class="legend-visitor"></i> Visitor requests</span><span><i class="legend-flagged"></i> Flagged by log source</span></div>'
    out+='<p id="map-detail" role="status" aria-live="polite" class="map-detail">Select a point to see its approximate location and request count.</p>'
    if not events:
        out+='<p class="notice">No locations available yet. Import an authorized, geolocated log export below to populate the map. This app does not automatically see your customers’ visitors.</p>'
    out+='</div>'
    out+='<div class="grid"><div class="card"><h2>Top locations</h2><div class="table-scroll"><table><thead><tr><th>City</th><th>Country</th><th>Type</th><th>Requests</th></tr></thead><tbody>'
    for r in _aggregate(events)[:12]:
        out+='<tr><td>'+esc(r['city'])+'</td><td>'+esc(r['country'])+'</td><td>'+('Flagged' if r['category']=='flagged' else 'Visitor')+'</td><td>'+str(r['request_count'])+'</td></tr>'
    if not events:out+='<tr><td colspan="4">No traffic data</td></tr>'
    out+='</tbody></table></div></div>'
    out+='<div class="card"><h2>What this map means</h2><p><strong>Visitors</strong> are requests labeled as normal by the source log. '
    out+='<strong>Flagged</strong> means the source log or WAF marked a request suspicious; it is not proof of compromise.</p>'
    out+='<p>Geolocation is approximate and may reflect VPNs, proxies, hosting providers or CDNs. '
    out+='No exact visitor addresses or identities are shown. We store imported approximate locations, counts and status codes—not raw IP addresses.</p>'
    out+='<p class="hint">Data stays on your local Workbench. No third-party map tiles or external IP lookup services are contacted.</p></div></div>'
    real_sites=[s for s in sites if s['verified_at'] and not s['is_demo']]
    out+='<details class="card traffic-import"><summary>Import traffic data from my website or WAF</summary>'
    if real_sites:
        out+='<p>Paste an authorized, geolocated CSV export. Do not include passwords, cookies, tokens or raw request bodies.</p>'
        out+='<form method="post" action="/traffic-import"><input type="hidden" name="csrf" value="'+esc(csrf)+'">'
        out+='<label for="traffic-site">Verified website</label><select id="traffic-site" name="site_id">'
        for site in real_sites:
            out+='<option value="'+str(site['id'])+'">'+esc(site['host'])+'</option>'
        out+='</select><label for="traffic-csv">Traffic CSV (up to 100 rows, 7.5 KB)</label>'
        out+='<textarea id="traffic-csv" name="csv" rows="7" required spellcheck="false" '
        out+='placeholder="country,city,latitude,longitude,type,count,status&#10;Canada,Toronto,43.65,-79.38,visitor,25,200&#10;United States,Ashburn,39.04,-77.49,flagged,3,403"></textarea>'
        out+='<button type="submit">Import and update map</button></form>'
        out+='<p class="hint">Optional: IP column can be geolocated locally if you install geoip2 and provide GeoLite2-City.mmdb in monitor_data. '
        out+='IP values are never stored or sent to a third party.</p>'
    else:
        out+='<p>To use real data, add and verify a website in your dashboard first. Demo accounts cannot import real customer traffic.</p>'
    out+='</details>'
    return out


def overview_map(db, user_id):
    """Render a compact, interactive, account-scoped map on the signed-in home page."""
    events, sites, demo = _all_events(db, user_id)
    visitors = sum(r['request_count'] for r in events if r['category'] == 'visitor')
    flagged = sum(r['request_count'] for r in events if r['category'] == 'flagged')
    regions = len({(r['city'], r['country']) for r in events})
    state = ('SYNTHETIC DEMO · NOT LIVE' if demo else
             ('IMPORTED DATA · NOT LIVE' if events else 'NO TRAFFIC CONNECTED'))
    out = ('<section class="card traffic-map-card overview-map" aria-label="Website traffic overview">'
           '<div class="traffic-map-top"><div><p class="eyebrow">Traffic intelligence</p>'
           '<h2>Where your website traffic comes from</h2>'
           '<p>Approximate visitor locations and requests flagged by your log source.</p></div>'
           '<a class="btn alt" href="/traffic">Full map &amp; import</a></div>')
    out += '<div class="overview-map-meta"><span class="pill">' + esc(state) + '</span></div>'
    out += '<div class="traffic-filters" role="group" aria-label="Filter overview map">'
    for category, label in (('all','All traffic'),('visitor','Visitors'),('flagged','Flagged')):
        out += ('<button type="button" class="alt map-filter" data-map-filter="' + category +
                '" aria-pressed="' + str(category == 'all').lower() + '">' + label + '</button>')
    out += '</div><div class="map-frame">' + _map(events)
    if demo:
        out += '<span class="map-watermark">DEMO · NOT LIVE</span>'
    out += '</div><div class="overview-summary">'
    out += '<span><strong>' + f'{visitors:,}' + '</strong> visitor requests</span>'
    out += '<span><strong>' + f'{flagged:,}' + '</strong> flagged requests</span>'
    out += '<span><strong>' + str(regions) + '</strong> locations</span></div>'
    out += ('<p id="map-detail" role="status" aria-live="polite" class="map-detail">'
            'Select a point for its approximate location and request count.</p>')
    if not events:
        out += ('<p class="hint">No traffic is connected. Import an authorized website or WAF '
                'log export from the full map page to see locations here.</p>')
    out += ('<p class="hint">Flagged requests are not confirmed attacks. '
            'Geolocation is approximate; no live visitor tracking is enabled.</p></section>')
    return out
