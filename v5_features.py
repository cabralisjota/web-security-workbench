#!/usr/bin/env python3
"""UI, persistence and optional AI for Workbench v5's unified Security Center."""
import datetime as dt
import html
import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import quote

import v5_suite as suite


def esc(value): return html.escape(str(value),quote=True)


def init_schema(db):
    with db() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS security_reports (
          id INTEGER PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL,
          created_at TEXT NOT NULL,
          kind TEXT NOT NULL,
          title TEXT NOT NULL,
          report_json TEXT NOT NULL,
          ai_text TEXT NOT NULL DEFAULT ''
        )''')
        con.execute('CREATE INDEX IF NOT EXISTS idx_security_reports_owner ON security_reports(user_id,id)')


def save_report(db,user_id,site_id,report):
    with db() as con:
        cursor=con.execute('INSERT INTO security_reports(user_id,site_id,created_at,kind,title,report_json) VALUES(?,?,?,?,?,?)',
                           (user_id,site_id,report['timestamp_utc'],report['kind'],report['title'],json.dumps(report,ensure_ascii=True)))
        return cursor.lastrowid


def load_report(db,user_id,report_id):
    with db() as con:
        row=con.execute('SELECT * FROM security_reports WHERE id=? AND user_id=?',(report_id,user_id)).fetchone()
    return row


def security_page(db,user_id,csrf):
    with db() as con:
        rows=con.execute('SELECT id,created_at,title,kind FROM security_reports WHERE user_id=? ORDER BY id DESC LIMIT 20',(user_id,)).fetchall()
    groups={}
    for case in suite.CASES: groups.setdefault(case['group'],[]).append(case)
    output='''<div class="card feature-card"><h2>One-click unified security test</h2>
<p>Run the full API + web training suite with no registration details, targets, or configuration. Every active request goes only to this application's built-in fictional localhost lab.</p>
<form method="post" action="/security-run"><input type="hidden" name="csrf" value="'''+esc(csrf)+'''"><button>Run all training checks</button></form>
<p class="hint">The suite is a training demonstration, not a scan of your customer's website. Actual verified-domain monitoring remains read-only.</p></div>'''
    output += ('<div class="card"><h2>Ask Gemini Security Assistant</h2>'
               '<p>Ask about API authorization, SQL injection, defensive remediation, or synthetic test results. '
               'The assistant does not execute scans or access websites.</p>'
               '<form method="post" action="/security-ask"><input type="hidden" name="csrf" value="'+esc(csrf)+'">'
               '<label>Your security question</label><textarea name="question" required minlength="10" maxlength="1000" rows="4" '
               'placeholder="How can a small business prevent BOLA and SQL injection in its API?"></textarea>'
               '<label><input type="checkbox" name="consent" value="yes" required> My question contains no credentials, personal data, or confidential customer information.</label><br>'
               '<button>Ask Gemini</button></form><p class="hint">Requires a configured Gemini key. Your question is sent to Google only when you submit it. Free-tier prompts may be used for product improvement.</p></div>')
    output+='<div class="module-toolbar"><label for="module-search">Find a training module</label>'+'<input id="module-search" type="search" placeholder="Search SQLi, BOLA, CSRF…" aria-label="Filter training modules">'+'<p id="module-count" class="hint" aria-live="polite">Showing 17 of 17 training modules</p></div>'+'<div class="grid" id="module-catalog">'
    for group,cases in groups.items():
        output+='<details class="card module-group"><summary>'+esc(group)+' modules ('+str(len(cases))+')</summary><ul>'
        for c in cases: output+='<li>'+esc(c['title'])+' <small>'+esc(c['cwe'])+'</small></li>'
        output+='</ul></details>'
    output+='</div><div class="card"><h2>Authorized website checks</h2><p>For your verified website, use <b>Run checkup now</b> for HTTPS/TLS/header checks, or <b>Discover documented APIs</b> to inspect its published OpenAPI JSON without submitting test payloads.</p><p>Daily, weekly, and monthly monitoring and optional email alerts remain available from the customer dashboard.</p><a class="btn alt" href="/">My websites and schedules</a></div>'
    output+='<div class="card"><h2>Saved security center reports</h2>'
    for row in rows:
        output+='<p><a href="/security-report?id='+str(row['id'])+'">'+esc(row['title'])+'</a> · '+esc(row['kind'])+' · '+esc(row['created_at'][:16])+' UTC</p>'
    if not rows: output+='<p class="muted">No Security Center reports yet.</p>'
    return output+'</div>'


def report_page(row,csrf):
    report=json.loads(row['report_json'])
    is_lab=row['kind']=='lab'
    content='<div class="card"><h2>'+esc(report['title'])+'</h2><p class="hint">'+esc(report['timestamp_utc'])+'</p>'
    content+='<p><strong>Scope:</strong> '+esc(report['environment'])+'</p>'
    if is_lab:
        content+='<p><strong>'+str(report['passed'])+' / '+str(report['total'])+'</strong> synthetic training comparisons passed · '+str(report['requests'])+' local requests.</p>'
        content+='<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse"><tr><th>Module</th><th>Vulnerable</th><th>Fixed</th><th>Control</th><th>Result</th></tr>'
        for r in report['rows']:
            content+='<tr><td>'+esc(r['title'])+' <small>'+esc(r['cwe'])+'</small></td><td>'+str(r['vulnerable_http'])+'</td><td>'+str(r['fixed_http'])+'</td><td>'+str(r['normal_http'])+'</td><td>'+('PASS' if r['passed'] else 'REVIEW')+'</td></tr>'
        content+='</table></div><p class="hint">PASS means the intentionally vulnerable fixture behaved differently from the fixed fixture as expected.</p>'
        content+='<h3>Evidence and remediation</h3>'
        for r in report['rows']:
            content+='<details><summary>'+esc(r['title'])+'</summary><p><b>Impact:</b> '+esc(r['impact'])+'</p><p><b>Fix:</b> '+esc(r['remediation'])+'</p><pre>'+esc(json.dumps(r['evidence'],indent=2))+'</pre></details>'
        content+='<h3>Analyst summary</h3><p>'+esc(row['ai_text'] or suite.lab_summary(report))+'</p>'
        content+='''<form method="post" action="/security-ai"><input type="hidden" name="csrf" value="'''+esc(csrf)+'''"><input type="hidden" name="report_id" value="'''+str(row['id'])+'''"><button>Explain these synthetic results with Gemini</button></form>
<p class="hint">Optional: this sends only synthetic test names and pass/fail results to Google. No customer website, API spec, credentials, or raw response bodies are sent.</p>'''
    else:
        counts=report.get('counts',{})
        content+='<p><b>'+str(report['total'])+'</b> documented operations across '+str(counts.get('paths',0))+' paths. '+str(counts.get('auth_not_specified',0))+' operations have no explicit security declaration in this document.</p>'
        content+='<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse"><tr><th>Method</th><th>Documented path</th><th>Auth documentation</th><th>Parameters</th></tr>'
        for r in report['rows']:
            content+='<tr><td>'+esc(r['method'])+'</td><td><code>'+esc(r['path'])+'</code></td><td>'+esc(r['auth_documentation'])+'</td><td>'+esc(', '.join(r['parameter_names']))+'</td></tr>'
        content+='</table></div>'
    content+='<p class="hint">'+esc(report['limitations'])+'</p><a class="btn alt" href="/security-json?id='+str(row['id'])+'">Download JSON evidence</a> <a class="btn alt" href="/security">Security Center</a></div>'
    return content


def discover_openapi(site, verify_site, fetch_https):
    if site['is_demo']:
        return suite.demo_openapi()
    if not site['verified_at']:
        raise ValueError('Verify domain ownership before API inventory discovery.')
    if not verify_site(site['host'],site['verification_token']):
        raise ValueError('Ownership verification was not found. No API discovery was performed.')
    errors=[]
    for path in ('/openapi.json','/swagger.json','/.well-known/openapi.json'):
        try:
            response=fetch_https(site['host'],path,max_bytes=262144)
            if response['status']!=200:
                continue
            report=suite.inspect_openapi(response['body'])
            report['environment']='Verified domain, read-only HTTPS GET '+path+'; no redirects or active tests'
            return report
        except (ValueError,UnicodeError,json.JSONDecodeError) as exc:
            errors.append(type(exc).__name__)
        except (OSError,TimeoutError) as exc:
            errors.append(type(exc).__name__)
    raise ValueError('No readable OpenAPI JSON document found at the three approved paths. No active testing was performed.')


def ai_lab_explanation(report):
    """Only fictional case names + pass/fail values are sent to Gemini."""
    key=os.getenv('GEMINI_API_KEY','').strip()
    if not key:
        raise ValueError('Gemini is not configured. Your rule-based explanation is still available.')
    model=os.getenv('GEMINI_MODEL','gemini-3.5-flash-lite')
    if not re.fullmatch(r'[A-Za-z0-9._-]{2,100}',model):
        raise ValueError('Invalid Gemini model setting.')
    synthetic={'scope':'Synthetic local security lab only','tests':[
        {'name':r['title'],'category':r['group'],'expected_comparison_passed':r['passed']}
        for r in report['rows']]}
    prompt=('Explain this fictional API and web security lab result in plain English for a small business owner. '
            'State clearly that no real website was tested and do not claim a real vulnerability was found. '
            'Prioritize object authorization, API roles, SQL parameterization, and practical remediation. '
            'Maximum 250 words. No private data is provided.\n'+json.dumps(synthetic))
    payload=json.dumps({'contents':[{'parts':[{'text':prompt}]}],
                        'generationConfig':{'temperature':0.2,'maxOutputTokens':550}}).encode()
    req=urllib.request.Request('https://generativelanguage.googleapis.com/v1beta/models/'+quote(model)+':generateContent',
                               data=payload,method='POST',headers={'x-goog-api-key':key,'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=20) as response:
            data=json.loads(response.read(32768))
        result='\n'.join(p.get('text','') for p in data['candidates'][0]['content']['parts'] if isinstance(p.get('text'),str)).strip()
        if not result: raise ValueError('Gemini returned an empty response.')
        return result[:2800]
    except urllib.error.HTTPError as exc:
        raise ValueError('Gemini returned HTTP '+str(exc.code)+'. Check your key, model, and free-tier limits.') from None
    except (OSError,KeyError,IndexError,json.JSONDecodeError):
        raise ValueError('Gemini could not be reached or returned an unexpected response.') from None


def ai_question(question):
    """Optional question-answering. Never sends stored client details or scan data."""
    if not 10 <= len(question.strip()) <= 1000:
        raise ValueError('Enter a security question between 10 and 1000 characters.')
    key=os.getenv('GEMINI_API_KEY','').strip()
    if not key: raise ValueError('Gemini is not configured. Your local tests still work.')
    model=os.getenv('GEMINI_MODEL','gemini-3.5-flash-lite')
    if not re.fullmatch(r'[A-Za-z0-9._-]{2,100}',model): raise ValueError('Invalid Gemini model setting.')
    instructions=('You are a defensive application security assistant for small business owners. '
                  'Give practical, evidence-aware guidance for authorized systems. '
                  'Do not claim you scanned a website or found vulnerabilities. '
                  'You cannot execute tests. Prefer parameterized queries, object-level access controls, '
                  'secure authentication, logging and safe retesting. Answer concisely.')
    payload=json.dumps({'systemInstruction':{'parts':[{'text':instructions}]},
                        'contents':[{'parts':[{'text':question.strip()}]}],
                        'generationConfig':{'temperature':0.2,'maxOutputTokens':700}}).encode()
    req=urllib.request.Request('https://generativelanguage.googleapis.com/v1beta/models/'+quote(model)+':generateContent',
                               data=payload,method='POST',headers={'x-goog-api-key':key,'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=25) as response:
            data=json.loads(response.read(32768))
        result='\n'.join(p.get('text','') for p in data['candidates'][0]['content']['parts'] if isinstance(p.get('text'),str)).strip()
        if not result: raise ValueError('Gemini returned an empty answer.')
        return result[:3500]
    except urllib.error.HTTPError as exc:
        raise ValueError('Gemini returned HTTP '+str(exc.code)+'. Check your key, model and quota.') from None
    except (OSError,KeyError,IndexError,json.JSONDecodeError):
        raise ValueError('Gemini could not be reached or returned an unexpected response.') from None
