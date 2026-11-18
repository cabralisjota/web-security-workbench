#!/usr/bin/env python3
"""Web Security Workbench v5 — synthetic API/web lab + bounded OpenAPI inventory.

No arbitrary targets, no real credentials, no external exploitation. All active
lab probes are sent to a loopback-only fixture owned by this process.
"""
import datetime as dt
import html
import json
import re
import secrets
import sqlite3
import urllib.error
import urllib.request

LAB_SECRET = secrets.token_urlsafe(36)
MAX_LAB_BODY = 2048

# Every example is fictional. The 'attack' values are only used against our
# built-in local fixtures. The owner does not select external active targets.
CASES = [
    dict(key='bola', group='API', title='Broken object authorization (BOLA)', cwe='CWE-639',
         attack={'user':'alice','invoice':'B-200'}, control={'user':'alice','invoice':'A-100'},
         remediation='Check object ownership on every API request; use server-side authorization.',
         impact='One customer could retrieve another customer\'s records.'),
    dict(key='bfla', group='API', title='Broken function authorization (BFLA)', cwe='CWE-862',
         attack={'role':'viewer','action':'admin-report'}, control={'role':'admin','action':'admin-report'},
         remediation='Enforce role permissions server-side on each privileged action.',
         impact='A low-privilege account could invoke administrative API operations.'),
    dict(key='mass-assignment', group='API', title='Mass assignment / object property authorization', cwe='CWE-915',
         attack={'role':'member','requested_role':'admin'}, control={'role':'member','requested_role':'member'},
         remediation='Allowlist writable properties and ignore client-supplied privileged fields.',
         impact='A client could assign itself privileges by modifying protected fields.'),
    dict(key='api-token', group='API', title='Expired API token accepted', cwe='CWE-613',
         attack={'token':'expired'}, control={'token':'valid'},
         remediation='Validate token signature, expiration, audience, and revocation server-side.',
         impact='An expired token could continue accessing protected API resources.'),
    dict(key='api-sqli', group='API', title='SQL injection in API query', cwe='CWE-89',
         attack={'name':"' OR '1'='1"}, control={'name':'alice'},
         remediation='Use parameterized queries and least-privilege database accounts.',
         impact='Unsafe SQL construction can change database query behavior.'),
    dict(key='api-ssrf', group='API', title='API server-side request forgery', cwe='CWE-918',
         attack={'url':'http://127.0.0.1/internal/status'}, control={'url':'https://public.invalid/preview'},
         remediation='Allowlist destinations, pin validated DNS, block internal IPs, and restrict egress.',
         impact='A URL-fetching API might reach restricted internal services.'),
    dict(key='api-rate', group='API', title='API rate limiting', cwe='CWE-770',
         attack={'attempt':'6'}, control={'attempt':'1'},
         remediation='Apply rate limits per identity and endpoint; add monitoring and abuse controls.',
         impact='Unlimited requests can enable abuse and service exhaustion.'),
    dict(key='api-logic', group='API', title='API business-logic invariants', cwe='CWE-840',
         attack={'quantity':'-2'}, control={'quantity':'2'},
         remediation='Validate prices, quantities, discounts and workflow order on the server.',
         impact='Manipulated input could produce invalid transactions.'),
    dict(key='api-exposure', group='API', title='Excessive API data exposure', cwe='CWE-200',
         attack={'viewer':'customer'}, control={'viewer':'customer'},
         remediation='Return only explicitly approved response fields for each caller.',
         impact='API responses might disclose unnecessary internal attributes.'),
    dict(key='api-inventory', group='API', title='Undocumented API endpoint', cwe='CWE-1059',
         attack={'path':'/api/internal/debug'}, control={'path':'/api/public/status'},
         remediation='Maintain an API inventory and restrict or remove unused internal endpoints.',
         impact='Unmanaged endpoints may bypass expected protections.'),
    dict(key='xss', group='Web', title='Reflected HTML injection indicator', cwe='CWE-79',
         attack={'q':'<script>lab</script>'}, control={'q':'hello'},
         remediation='Contextually encode output and enforce a defense-in-depth CSP.',
         impact='Unescaped HTML reflection can enable script injection.'),
    dict(key='csrf', group='Web', title='Missing CSRF protection', cwe='CWE-352',
         attack={'csrf':''}, control={'csrf':'lab-valid'},
         remediation='Validate unpredictable CSRF tokens and Origin on state-changing requests.',
         impact='A browser could be induced to submit unwanted account changes.'),
    dict(key='session', group='Web', title='Expired session accepted', cwe='CWE-613',
         attack={'session':'expired'}, control={'session':'valid'},
         remediation='Invalidate sessions server-side on logout and expiry; rotate IDs on login.',
         impact='Expired sessions might remain usable.'),
    dict(key='upload', group='Web', title='Unsafe file upload policy', cwe='CWE-434',
         attack={'filename':'demo.php'}, control={'filename':'notes.txt'},
         remediation='Allowlist extensions and verified content types; store uploads outside webroot.',
         impact='Dangerous file types could be accepted.'),
    dict(key='traversal', group='Web', title='Path traversal', cwe='CWE-22',
         attack={'name':'../private/demo-note.txt'}, control={'name':'public/welcome.txt'},
         remediation='Use server-generated file IDs and enforce a canonicalized allowlisted root.',
         impact='An unsafe file path could disclose unintended files.'),
    dict(key='auth-reset', group='Web', title='Password reset authorization', cwe='CWE-640',
         attack={'token':''}, control={'token':'lab-valid'},
         remediation='Require short-lived single-use reset tokens bound to the correct account.',
         impact='An unauthorized password reset could enable account takeover.'),
    dict(key='headers', group='Web', title='Missing browser security headers', cwe='CWE-693',
         attack={'path':'/'}, control={'path':'/'},
         remediation='Set CSP, X-Content-Type-Options, and other appropriate response headers.',
         impact='Missing browser defenses can increase the impact of other weaknesses.'),
]
BY_KEY = {c['key']: c for c in CASES}


def fixture(key, mode, fields):
    """Return (HTTP status, synthetic JSON). No filesystem/network side effects."""
    if key not in BY_KEY or mode not in ('vulnerable','fixed'):
        return 404, {'error':'unknown fixture'}
    f = mode == 'fixed'
    if key == 'bola':
        invoice = fields.get('invoice')
        allowed = invoice == 'A-100' or not f
        return (200 if allowed else 403), ({'invoice':invoice,'owner':'bob' if invoice=='B-200' else 'alice'} if allowed else {'error':'not authorized'})
    if key == 'bfla':
        allowed = fields.get('role') == 'admin' or not f
        return (200 if allowed else 403), {'result':'admin-report' if allowed else 'denied'}
    if key == 'mass-assignment':
        requested = fields.get('requested_role','member')
        role = 'member' if f else requested
        return 200, {'role':role,'updated':True}
    if key == 'api-token':
        allowed = fields.get('token') == 'valid' or not f
        return (200 if allowed else 401), {'authenticated':allowed}
    if key == 'api-sqli':
        # Deliberately unsafe query ONLY against an ephemeral fictional in-memory DB.
        name = str(fields.get('name',''))[:100]
        con = sqlite3.connect(':memory:')
        try:
            con.execute('CREATE TABLE people(name TEXT)')
            con.executemany('INSERT INTO people(name) VALUES (?)', [('alice',),('bob',)])
            try:
                if f:
                    rows = con.execute('SELECT name FROM people WHERE name=?', (name,)).fetchall()
                else:
                    rows = con.execute("SELECT name FROM people WHERE name='" + name + "'").fetchall()
            except sqlite3.Error:
                rows = []
            return 200, {'fictional_users':[r[0] for r in rows]}
        finally:
            con.close()
    if key == 'api-ssrf':
        internal = fields.get('url','').startswith('http://127.0.0.1/')
        allowed = not (internal and f)
        return (200 if allowed else 403), {'simulated_internal_access':bool(internal and allowed),'network_requests':0}
    if key == 'api-rate':
        attempt = int(fields.get('attempt','1')) if str(fields.get('attempt','1')).isdigit() else 999
        allowed = attempt <= 5 or not f
        return (200 if allowed else 429), {'allowed':allowed}
    if key == 'api-logic':
        qty = int(fields.get('quantity','0')) if re.fullmatch(r'-?\d{1,3}',str(fields.get('quantity',''))) else 0
        allowed = qty > 0 or not f
        return (200 if allowed else 422), {'total':qty*10 if allowed else None}
    if key == 'api-exposure':
        data = {'customer':'fictional-alice'}
        if not f:
            data['internal_note'] = 'LAB-ONLY-INTERNAL-FIELD'
        return 200, data
    if key == 'api-inventory':
        internal = fields.get('path') == '/api/internal/debug'
        allowed = not (internal and f)
        return (200 if allowed else 404), {'visible':allowed,'fictional_endpoint':fields.get('path','')}
    if key == 'xss':
        q = str(fields.get('q',''))[:100]
        return 200, {'rendered_html':'<p>'+ (html.escape(q,quote=True) if f else q) +'</p>'}
    if key == 'csrf':
        allowed = fields.get('csrf') == 'lab-valid' or not f
        return (200 if allowed else 403), {'change_accepted':allowed}
    if key == 'session':
        allowed = fields.get('session') == 'valid' or not f
        return (200 if allowed else 401), {'session_accepted':allowed}
    if key == 'upload':
        name = str(fields.get('filename',''))
        allowed = name.endswith(('.txt','.png','.jpg')) or not f
        return (200 if allowed else 415), {'accepted':allowed,'saved_to_disk':False}
    if key == 'traversal':
        private = fields.get('name') == '../private/demo-note.txt'
        allowed = not (private and f)
        return (200 if allowed else 403), {'fictional_private_note':bool(private and allowed),'filesystem_access':False}
    if key == 'auth-reset':
        allowed = fields.get('token') == 'lab-valid' or not f
        return (200 if allowed else 403), {'reset_accepted':allowed,'account_changed':False}
    if key == 'headers':
        headers = {'x-content-type-options':'nosniff','content-security-policy':"default-src 'self'"} if f else {}
        return 200, {'response_headers':headers}
    return 404, {'error':'unknown fixture'}


def weakness_seen(key, status, result):
    if key == 'mass-assignment': return result.get('role') == 'admin'
    if key == 'api-sqli': return 'bob' in result.get('fictional_users',[])
    if key == 'api-ssrf': return bool(result.get('simulated_internal_access'))
    if key == 'api-logic': return status == 200 and isinstance(result.get('total'),int) and result['total'] < 0
    if key == 'api-exposure': return 'internal_note' in result
    if key == 'xss': return '<script>' in result.get('rendered_html','')
    if key == 'traversal': return bool(result.get('fictional_private_note'))
    if key == 'headers': return 'content-security-policy' not in result.get('response_headers',{})
    return status == 200


def fixture_control_ok(key, status, result):
    if status != 200: return False
    if key == 'api-sqli': return result.get('fictional_users') == ['alice']
    if key == 'bola': return result.get('owner') == 'alice'
    if key == 'mass-assignment': return result.get('role') == 'member'
    if key == 'api-exposure': return 'customer' in result
    if key == 'xss': return 'hello' in result.get('rendered_html','')
    if key == 'headers': return 'content-security-policy' in result.get('response_headers',{})
    return True


def http_fixture(port, key, mode, fields):
    body = json.dumps({'case':key,'mode':mode,'fields':fields},separators=(',',':')).encode()
    req = urllib.request.Request('http://127.0.0.1:'+str(port)+'/__v5_fixture', data=body, method='POST',
                                 headers={'Content-Type':'application/json','X-Workbench-Lab':LAB_SECRET})
    try:
        with urllib.request.urlopen(req,timeout=4) as response:
            return response.status,json.loads(response.read(4096))
    except urllib.error.HTTPError as error:
        return error.code,json.loads(error.read(4096))


def run_suite(port=18771):
    rows=[]
    for case in CASES:
        key=case['key']
        vulnerable = http_fixture(port,key,'vulnerable',case['attack'])
        fixed = http_fixture(port,key,'fixed',case['attack'])
        control = http_fixture(port,key,'fixed',case['control'])
        reproduced = weakness_seen(key,*vulnerable)
        prevented = not weakness_seen(key,*fixed)
        normal = fixture_control_ok(key,*control)
        rows.append({'key':key,'group':case['group'],'title':case['title'],'cwe':case['cwe'],
                     'vulnerable_http':vulnerable[0],'fixed_http':fixed[0],
                     'normal_http':control[0], 'vulnerable_indicator':reproduced,
                     'fixed_prevented':prevented,'normal_request_ok':normal,
                     'passed':bool(reproduced and prevented and normal),
                     'impact':case['impact'],'remediation':case['remediation'],
                     'evidence':{'vulnerable':vulnerable[1], 'fixed':fixed[1], 'normal':control[1]}})
    return {'kind':'lab','title':'Unified API + Web Training Assessment',
            'timestamp_utc':dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
            'environment':'LOCAL SYNTHETIC FIXTURES ONLY — not an external website scan',
            'total':len(rows),'passed':sum(r['passed'] for r in rows),
            'requests':len(rows)*3,'rows':rows,
            'limitations':'The checks demonstrate known vulnerabilities and fixes in fictional local applications. They do not establish detection accuracy on real sites.'}


def inspect_openapi(raw):
    """Static, read-only OpenAPI 2/3 summary; never dereference remote $ref."""
    if isinstance(raw,bytes):
        if len(raw)>262144: raise ValueError('OpenAPI document too large (256 KiB maximum).')
        raw=raw.decode('utf-8')
    if len(raw)>262144: raise ValueError('OpenAPI document too large (256 KiB maximum).')
    spec=json.loads(raw)
    if not isinstance(spec,dict) or not (isinstance(spec.get('openapi'),str) or isinstance(spec.get('swagger'),str)):
        raise ValueError('Not a supported OpenAPI/Swagger JSON document.')
    paths=spec.get('paths')
    if not isinstance(paths,dict): raise ValueError('OpenAPI paths are missing.')
    if len(paths)>300: raise ValueError('OpenAPI path limit exceeded (300).')
    operations=[]
    verbs={'get','post','put','patch','delete','options','head','trace'}
    for path,items in paths.items():
        if not isinstance(path,str) or not isinstance(items,dict): continue
        for method,definition in items.items():
            if method.lower() not in verbs or not isinstance(definition,dict): continue
            if len(operations)>=500: raise ValueError('OpenAPI operation limit exceeded (500).')
            declared=definition.get('security','INHERIT')
            if declared=='INHERIT': declared=spec.get('security','UNSPECIFIED')
            if declared == []: auth='declared public'
            elif declared == 'UNSPECIFIED': auth='not specified in document'
            else: auth='security requirement declared'
            params=definition.get('parameters',[])
            if not isinstance(params,list): params=[]
            param_names=[p.get('name','?') for p in params[:20] if isinstance(p,dict)]
            operations.append({'method':method.upper(),'path':path[:180], 'auth_documentation':auth,
                               'parameter_names':[str(n)[:60] for n in param_names]})
    unspecified=sum(o['auth_documentation']=='not specified in document' for o in operations)
    return {'kind':'inventory','title':'OpenAPI Inventory (documentation review)',
            'timestamp_utc':dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
            'environment':'Read-only OpenAPI document inspection; no active vulnerability tests',
            'total':len(operations),'passed':None,'rows':operations[:150],
            'counts':{'documented_operations':len(operations),'auth_not_specified':unspecified,
                      'paths':len(paths)},
            'limitations':'Missing OpenAPI security declarations do not prove missing authentication. Undocumented endpoints cannot be found by this static inspection. Only the supplied document was reviewed.'}


def demo_openapi():
    return inspect_openapi(json.dumps({'openapi':'3.0.3','info':{'title':'Fictional Demo API','version':'1'},
        'security':[{'BearerAuth':[]}],
        'paths':{'/api/products':{'get':{'security':[],'parameters':[{'name':'category'}]}},
                 '/api/invoices/{id}':{'get':{'parameters':[{'name':'id'}]}},
                 '/api/orders':{'post':{'parameters':[{'name':'quantity'}]}},
                 '/api/admin/report':{'get':{'security':[{'AdminAuth':[]}]}}}}))


def lab_summary(report):
    return (f"Local training: {report['passed']} of {report['total']} expected vulnerable-versus-fixed "
            f"comparisons passed across API and web modules. These are fictional lab results, "
            'not proof that any real customer website is vulnerable or secure. '
            'Prioritize API object authorization, role permissions, token validation and parameterized SQL.')
