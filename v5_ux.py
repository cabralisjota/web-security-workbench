"""Visual and asynchronous UX assets for Web Security Workbench v5.1.

No third-party JS/CSS. All interactive requests remain same-origin and retain the
existing form CSRF tokens and server-side authorization checks.
"""

CSS = r'''
:root{
 color-scheme:dark; --bg:#080f1d; --panel:#111d31; --panel2:#162640;
 --line:#2c405c; --line2:#3b5273; --text:#f0f6ff; --muted:#afc1d7;
 --accent:#6cd6ec; --accent2:#a5a1ff; --green:#83e6bd; --amber:#f4c87d;
 font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
 background:var(--bg);color:var(--text);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;min-height:100vh;background:
 radial-gradient(ellipse 780px 490px at 85% -5%,#18365c88,transparent 72%),
 radial-gradient(ellipse 500px 420px at -15% 45%,#26265766,transparent 70%),var(--bg)}
header{position:sticky;top:0;z-index:30;background:#0b1526eF;
 backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
 border-bottom:1px solid #344865a8;box-shadow:0 5px 25px #03070e38}
nav,.wrap{max-width:1080px;margin:auto}
nav{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:12px 18px;flex-wrap:wrap}
.brand{display:inline-flex;align-items:center;gap:9px;font-weight:850;color:#e6faff;text-decoration:none;letter-spacing:-.02em}
.brand-mark{display:inline-grid;place-items:center;width:35px;height:35px;border-radius:11px;
 background:linear-gradient(145deg,#52d8d9,#7382f2);color:#081528;font-size:1.15rem;box-shadow:0 4px 15px #44c4e04a}
.brand small{display:block;font-size:.68rem;font-weight:600;color:var(--muted);letter-spacing:.02em}
.nav-actions{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.nav-actions a:not(.btn){color:#d8e8f8;text-decoration:none;padding:8px 10px;border-radius:9px;font-size:.9rem;font-weight:650}
.nav-actions a:not(.btn):hover,.nav-actions a[aria-current="page"]{background:#273e5a;color:white}
.account-name{font-size:.78rem;color:var(--muted);max-width:175px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.wrap{padding:24px 18px 75px;min-height:80vh}
.hero{margin-bottom:23px;padding:12px 0 2px}
.eyebrow{text-transform:uppercase;letter-spacing:.15em;color:#91dfe7;font-weight:800;font-size:.7rem;margin:0 0 11px}
h1{font-size:clamp(1.8rem,4vw,2.65rem);line-height:1.15;letter-spacing:-.045em;margin:0 0 12px;
 background:linear-gradient(90deg,#fff 20%,#a8d6ff 65%,#b3abff);color:transparent;background-clip:text;-webkit-background-clip:text}
h2{font-size:1.18rem;letter-spacing:-.015em;margin:0 0 13px;color:#f4f8ff}
h3{font-size:1rem;margin:16px 0 8px}
p,li{line-height:1.6}p{margin:9px 0 13px}
.muted,.hint,small{color:var(--muted)}.hint{font-size:.85rem}
.hero p{max-width:740px;color:#b8cce0;font-size:.96rem;margin:0}
.hero-chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:15px}
.hero-chip{font-size:.72rem;font-weight:700;padding:6px 9px;border:1px solid #31526b;border-radius:99px;background:#183148;color:#bbf4ed}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:16px;align-items:start}
.card{position:relative;overflow:hidden;background:linear-gradient(150deg,#172840ed,#101c30fa);
 border:1px solid #324864;border-radius:17px;padding:20px;margin-bottom:16px;
 box-shadow:0 12px 34px #00000022;transition:border-color .18s,box-shadow .18s}
.card:hover{border-color:#446181;box-shadow:0 15px 35px #00000036}
.card h2:first-child{margin-top:0}
.feature-card{background:linear-gradient(120deg,#1b3550,#1b2b50 75%,#2b2751);border-color:#46739b}
.feature-card:before{content:"";position:absolute;right:-40px;top:-70px;width:210px;height:210px;border-radius:50%;background:#7b8dff16;pointer-events:none}
.feature-card h2{font-size:1.34rem}
input,select,textarea{background:#0b1729;border:1px solid #526985;border-radius:10px;color:#f6f9ff;
 padding:12px 13px;width:100%;margin:6px 0 13px;font:inherit;font-size:.94rem;outline-offset:2px}
input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid #73dbe9;border-color:#72c9da}
textarea{resize:vertical;min-height:95px}
input[type=checkbox]{width:auto;margin:8px;vertical-align:middle;accent-color:#65c8e5}
label{font-size:.91rem;font-weight:670;color:#dce9fa}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;
 background:linear-gradient(110deg,#75d8e6,#82a9f8);color:#071629;border:1px solid transparent;
 border-radius:10px;padding:11px 15px;font-weight:800;cursor:pointer;text-decoration:none;
 font-size:.89rem;line-height:1.2;min-height:42px;transition:filter .15s,transform .15s}
button:hover,.btn:hover{filter:brightness(1.09);transform:translateY(-1px)}
button:active,.btn:active{transform:translateY(0)}
button:focus-visible,.btn:focus-visible,a:focus-visible{outline:2px solid #a4f2ff;outline-offset:3px}
button.alt,.btn.alt{background:#243a55;color:#e4efff;border:1px solid #45617e}
button.warn{background:#f6ce83;color:#372500}
button:disabled{cursor:progress;opacity:.7;transform:none;filter:none}
form.inline{display:inline-block;margin:4px 7px 4px 0;vertical-align:middle}
form.inline button{font-size:.86rem}
.pill{display:inline-block;border:1px solid #446080;border-radius:99px;padding:4px 10px;background:#243c56;color:#e1edff;font-size:.74rem;font-weight:750}
.ok{color:var(--green)}.bad{color:#ffb7b7}
.notice{padding:13px 16px;background:#193b50;border:1px solid #3a7e8b;border-radius:11px;margin-bottom:17px}
code,pre{overflow-wrap:anywhere;background:#091627;padding:3px 6px;border:1px solid #263d58;border-radius:6px}
pre{white-space:pre-wrap;padding:14px;line-height:1.5;overflow-x:auto;font-size:.86rem}
a{color:#93dfee}a:hover{color:#c6f6ff}
.stat{font-size:1.7rem;font-weight:850}ul{padding-left:23px}
li{margin:5px 0}hr{border:0;border-top:1px solid #334963;margin:20px 0}
th,td{padding:11px 10px;border-bottom:1px solid #36506d;text-align:left;font-size:.85rem;vertical-align:top}
th{color:#bde9f5;font-weight:800}table{width:100%;border-collapse:collapse}
details{margin:12px 0;padding:13px 14px;border:1px solid #3a526e;border-radius:11px;background:#0c1a2d}
details[open]{border-color:#567da0}summary{cursor:pointer;font-weight:750;line-height:1.5}
#wb-status{border-radius:11px;padding:12px 15px;margin:0 0 16px;background:#183a52;border:1px solid #3d8195;color:#e1faff;font-weight:700;font-size:.9rem}
#wb-status[data-kind="error"]{background:#43232c;border-color:#a35769;color:#ffe5e8}
#wb-status[data-kind="success"]{background:#183b35;border-color:#3e8e75;color:#c9ffdf}
.result-panel{scroll-margin-top:95px;margin:18px 0 5px;border:1px solid #5283a1;border-radius:15px;padding:14px;background:#0b1a2e;box-shadow:0 10px 30px #0004}
.result-panel[data-state="error"]{border-color:#c67b7b}
.result-panel .card{margin-bottom:10px}
.result-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:2px 3px 12px;border-bottom:1px solid #3a5670;margin-bottom:14px}
.result-head strong{font-size:.96rem;color:#c5f4ff}
.result-actions{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.result-actions a,.result-actions button{font-size:.78rem;min-height:35px;padding:7px 11px}
.result-body>p:first-child{margin-top:0}
.loading-row{display:flex;align-items:center;gap:11px;font-size:.91rem;color:#cfe6fa;padding:8px 2px}
.spinner{display:inline-block;width:19px;height:19px;border:2px solid #547d9c;border-top-color:#85eff4;border-radius:50%;animation:spin .8s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.module-toolbar{display:flex;align-items:center;justify-content:space-between;gap:13px;flex-wrap:wrap;margin:17px 0 12px}
.module-toolbar input{max-width:360px;margin:0}
.module-toolbar .hint{margin:0}
.module-group ul{margin-bottom:0}
.module-group li{border-bottom:1px solid #30445d;padding:6px 0;list-style:none;margin:0}
.module-group li:last-child{border-bottom:0}
.module-group ul{padding-left:0}
.module-group li small{display:block;font-size:.72rem}
.footer-note{margin-top:30px;padding-top:20px;border-top:1px solid #334963;font-size:.77rem;color:#a6bad1}
[hidden]{display:none!important}
@media(max-width:640px){
 nav{padding:10px 13px;gap:9px}.brand{font-size:.88rem}.brand-mark{width:31px;height:31px}
 .nav-actions{gap:3px}.nav-actions a:not(.btn){font-size:.8rem;padding:7px 8px}
 .account-name{display:none}.wrap{padding:16px 12px 55px}.hero{padding-top:7px}
 .card{padding:15px;border-radius:14px}.grid{gap:12px}
 form.inline{display:inline-block;max-width:100%}button,.btn{font-size:.86rem}
 .result-panel{padding:10px;scroll-margin-top:118px}.result-head{align-items:start}
}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*,*:before,*:after{animation-duration:.01ms!important;transition-duration:.01ms!important}}
'''

JS = r'''
(()=>{
  'use strict';
  const inlineActions=new Set(['/security-run','/security-ai','/security-ask','/scan','/api-discover','/test-email']);
  const authActions=new Set(['/login','/signup','/demo-login','/logout']);
  const actionLabels={
    '/security-run':'Running 17 local training comparisons (51 requests)…',
    '/security-ai':'Asking Gemini to explain the synthetic results…',
    '/security-ask':'Waiting for Gemini to respond…',
    '/scan':'Running the approved website checkup…',
    '/api-discover':'Checking published API documentation…',
    '/test-email':'Sending a test notification…',
    '/verify':'Verifying website ownership…',
    '/settings':'Saving your preferences…',
    '/add':'Adding your website…',
    '/demo':'Preparing the sample website…',
    '/demo-login':'Opening the sample dashboard…',
    '/login':'Signing in…',
    '/signup':'Creating your account…',
    '/logout':'Signing out…'
  };
  let inFlight=false;
  function status(message,kind='info'){
    const el=document.getElementById('wb-status');if(!el)return;
    el.textContent=message;el.dataset.kind=kind;el.hidden=false;
  }
  function setPanelState(panel,message,state){
    panel.dataset.state=state;
    panel.replaceChildren();
    const row=document.createElement('div');row.className='loading-row';
    if(state==='loading'){
      const spinner=document.createElement('span');spinner.className='spinner';spinner.setAttribute('aria-hidden','true');row.append(spinner);
    }
    const label=document.createElement('span');label.textContent=message;row.append(label);panel.append(row);
  }
  function cleanMain(doc){
    const main=doc.querySelector('main.wrap');if(!main)return null;
    main.querySelector('.hero')?.remove();
    main.querySelector('#wb-status')?.remove();
    main.querySelector('.footer-note')?.remove();
    // Older pages use an HR + SMALL footer; remove only that last pair.
    const tail=main.lastElementChild;
    if(tail&&tail.tagName==='SMALL'){
      tail.remove();if(main.lastElementChild?.tagName==='HR')main.lastElementChild.remove();
    }
    return main;
  }
  function showInline(panel,doc,url,ok){
    panel.replaceChildren();panel.dataset.state=ok?'success':'error';
    const head=document.createElement('div');head.className='result-head';
    const title=document.createElement('strong');
    const sourceTitle=doc.querySelector('main h1')?.textContent||'Action results';
    title.textContent=(ok?'✓ ':'! ')+sourceTitle;
    head.append(title);
    const actions=document.createElement('div');actions.className='result-actions';
    if(ok&&['/report','/security-report'].includes(url.pathname)){
      const link=document.createElement('a');link.className='btn alt';link.href=url.pathname+url.search;
      link.textContent='Open full report';actions.append(link);
    }
    const close=document.createElement('button');close.type='button';close.className='alt';close.textContent='Hide results';close.dataset.dismissResult='1';actions.append(close);
    head.append(actions);panel.append(head);
    const body=document.createElement('div');body.className='result-body';
    const main=cleanMain(doc);
    if(main){while(main.firstChild)body.append(main.firstChild);}else body.textContent='The server did not return a readable result.';
    panel.append(body);
    panel.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'start'});
  }
  document.addEventListener('click',event=>{
    const close=event.target.closest('[data-dismiss-result]');
    if(close){const panel=close.closest('.result-panel');if(panel)panel.remove();}
  });
  document.addEventListener('input',event=>{
    if(event.target.id!=='module-search')return;
    const raw=event.target.value.toLocaleLowerCase().trim();
    const aliases={sqli:'sql injection',xss:'html injection',idor:'object authorization',ssrf:'server-side request forgery',csrf:'csrf'};
    const term=aliases[raw]||raw;let count=0;
    for(const group of document.querySelectorAll('.module-group')){
      let visible=0;
      for(const item of group.querySelectorAll('li')){
        const match=item.textContent.toLocaleLowerCase().includes(term);
        item.hidden=!match;if(match){visible++;count++;}
      }
      group.hidden=visible===0;
    }
    const countLabel=document.getElementById('module-count');
    if(countLabel)countLabel.textContent='Showing '+count+' of 17 training modules';
  });
  document.addEventListener('submit',async event=>{
    const form=event.target;
    if(!(form instanceof HTMLFormElement)||form.method.toLowerCase()!=='post'||form.dataset.nativeSubmit==='1')return;
    const url=new URL(form.action,location.href);
    if(url.origin!==location.origin||form.enctype==='multipart/form-data')return;
    event.preventDefault();
    if(inFlight)return;
    if(!form.reportValidity())return;
    inFlight=true;
    const action=url.pathname,inline=inlineActions.has(action);
    const btn=event.submitter||form.querySelector('button[type="submit"],button:not([type])');
    const original=btn?.textContent||'';
    const busyText=actionLabels[action]||'Processing your request…';
    const card=form.closest('.card')||form.parentElement;
    let panel=null;
    if(inline){
      const old=card.querySelector(':scope > .result-panel');if(old)old.remove();
      panel=document.createElement('section');panel.className='result-panel';
      panel.setAttribute('aria-live','polite');panel.setAttribute('aria-label','Action results');
      card.append(panel);setPanelState(panel,busyText,'loading');
    }
    if(btn){btn.disabled=true;btn.textContent='Working…';}
    form.setAttribute('aria-busy','true');status(busyText);
    const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),90000);
    try{
      const response=await fetch(url.toString(),{
        method:'POST',body:new URLSearchParams(new FormData(form)),credentials:'same-origin',
        cache:'no-store',redirect:'follow',signal:controller.signal,
        headers:{'X-Requested-With':'XMLHttpRequest'}
      });
      const resultUrl=new URL(response.url);
      if(resultUrl.origin!==location.origin)throw new Error('Unexpected redirect outside the application.');
      const contentType=response.headers.get('content-type')||'';
      if(!contentType.includes('text/html'))throw new Error('The server returned an unexpected response format.');
      const html=await response.text();
      const doc=new DOMParser().parseFromString(html,'text/html');
      if(!doc.querySelector('main.wrap'))throw new Error('The server did not return a complete results page.');
      if(response.redirected&&resultUrl.pathname==='/login'&&!authActions.has(action)){
        location.assign('/login');return;
      }
      if(inline){
        showInline(panel,doc,resultUrl,response.ok);
        status(response.ok?'Completed. Results are displayed below the action button.':'The action returned an error. Details are displayed below the button.',response.ok?'success':'error');
      }else{
        const newHeader=doc.querySelector('header'),newMain=doc.querySelector('main.wrap');
        if(!newHeader)throw new Error('Incomplete server response.');
        const previousY=window.scrollY;
        document.querySelector('header')?.replaceWith(document.importNode(newHeader,true));
        document.querySelector('main.wrap')?.replaceWith(document.importNode(newMain,true));
        document.title=doc.title;
        history.replaceState(null,'',resultUrl.pathname+resultUrl.search);
        if(authActions.has(action))window.scrollTo({top:0,behavior:'auto'});
        else window.scrollTo({top:Math.min(previousY,Math.max(0,document.documentElement.scrollHeight-innerHeight)),behavior:'auto'});
        status(response.ok?'Saved. Your dashboard has been updated.':'The action could not be completed. Please review the message.',response.ok?'success':'error');
      }
    }catch(err){
      const message=err.name==='AbortError'?'This request took too long. Please check whether the server is running.':
        'Could not complete the request: '+(err.message||'Network error');
      if(panel)setPanelState(panel,message,'error');
      status(message,'error');
    }finally{
      clearTimeout(timeout);inFlight=false;
      if(btn){btn.disabled=false;btn.textContent=original;}
      form.removeAttribute('aria-busy');
    }
  });
})();
'''

# v5.2 visual refinements and privacy-aware traffic map interactions.
import v5_2_ui as addon
CSS += addon.CSS
JS += addon.JS

# v5.3 centered navigation, single-open dropdowns and overview map.
import v5_3_ui as polish
CSS += polish.CSS
JS += polish.JS

# v5.4 stable mobile menus and map-first dashboard.
import v5_4_ui as layout_fix
CSS += layout_fix.CSS
JS += layout_fix.JS
