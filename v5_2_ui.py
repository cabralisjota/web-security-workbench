"""Visual refinements and map interaction; appended to the tested v5.1 UX."""
CSS = r'''
:root{
  font-family:Roboto,"Segoe UI",Inter,system-ui,-apple-system,sans-serif;
  font-synthesis:none;--bg:#070e19;--panel:#101c2e;--panel2:#172a43;
  --line:#304660;--text:#f6f9ff;--muted:#afc3d7;--accent:#5be0da;
  --accent2:#96a9ff;--green:#68e1b3;
}
html{-webkit-text-size-adjust:100%;text-rendering:optimizeLegibility}
body{-webkit-font-smoothing:antialiased;background:
 radial-gradient(ellipse 900px 500px at 90% -8%,#163e6680,transparent 70%),
 radial-gradient(ellipse 700px 460px at 0% 40%,#1a244e42,transparent 70%),#070e19}
header{background:#081524f2;border-bottom:1px solid #2a4c61}
nav,.wrap{max-width:1220px}
nav{min-height:68px;gap:18px}
.brand{font-size:.95rem;letter-spacing:-.035em}
.brand small{letter-spacing:.025em}
.brand-mark{background:linear-gradient(145deg,#72ece1,#779dff);font-size:1.3rem;border-radius:12px}
.nav-actions{gap:7px}
.nav-drop{position:relative;margin:0;padding:0;border:0;background:transparent;z-index:50}
.nav-drop summary{list-style:none;display:flex;align-items:center;gap:8px;border-radius:10px;padding:9px 12px;
 font-size:.85rem;font-weight:760;color:#d4e4f7;white-space:nowrap;cursor:pointer}
.nav-drop summary::-webkit-details-marker{display:none}
.nav-drop summary:hover,.nav-drop[open] summary{background:#22384f;color:#fff}
.nav-drop summary .chev{font-size:.7rem;opacity:.7}
.nav-pop{position:absolute;top:calc(100% + 9px);right:0;width:242px;padding:7px;border:1px solid #46637e;
 border-radius:14px;background:#11243a;box-shadow:0 18px 55px #02060f9c;display:grid;gap:3px;z-index:60}
.nav-pop a{display:block!important;padding:12px 13px!important;border-radius:9px!important;
 font-size:.85rem!important;color:#e2efff!important;text-decoration:none!important}
.nav-pop a:hover{background:#29445f!important}
.nav-pop small{display:block;font-size:.7rem;margin-top:3px;color:#a9c3db}
.nav-link{color:#d8e9f6!important;text-decoration:none;padding:9px 11px;border-radius:9px;font-weight:750;font-size:.85rem}
.nav-link:hover{background:#22384f}
.wrap{padding-top:28px}
.hero{padding:8px 0 10px;margin-bottom:20px}
.eyebrow{color:#78e4dd;font-weight:850;letter-spacing:.17em}
h1{font-weight:840;font-size:clamp(1.85rem,3.8vw,2.9rem);letter-spacing:-.055em;line-height:1.1}
h2{font-weight:790;letter-spacing:-.03em;font-size:1.19rem}
p,li{line-height:1.62}
.card{background:linear-gradient(155deg,#15263c,#0f1d2f 90%);border-color:#32475f;
 border-radius:18px;box-shadow:0 14px 40px #0000002c;padding:22px}
.feature-card{background:linear-gradient(130deg,#163d54,#1c2e54 74%,#2b2c59)}
.card:hover{border-color:#47647d}
button,.btn{border-radius:11px;font-weight:770;letter-spacing:.005em}
input,select,textarea{border-radius:11px;font-size:.93rem}
.module-group{padding:0;overflow:hidden}
.module-group summary{padding:19px 21px;display:flex;align-items:center;justify-content:space-between;
 gap:10px;font-size:1rem;font-weight:800;letter-spacing:-.015em}
.module-group summary::after{content:'⌄';font-size:1.25rem;color:#78e4dd;transition:transform .2s}
.module-group[open] summary::after{transform:rotate(180deg)}
.module-group ul{padding:0 21px 18px;margin:0}
.module-group[open] summary{border-bottom:1px solid #2e4961;margin-bottom:8px}
.module-toolbar{margin-top:25px}
.traffic-promo{display:flex;align-items:center;justify-content:space-between;gap:24px;
 background:linear-gradient(115deg,#103447,#1a2b4a 70%,#25234b)}
.traffic-promo p{max-width:610px}
.traffic-promo .eyebrow{margin-bottom:6px}
.traffic-head{background:linear-gradient(120deg,#123c51,#182a48 75%,#252d52)}
.traffic-head p{max-width:850px}
.traffic-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:16px}
.traffic-stat{background:#112238;border:1px solid #35536e;border-radius:15px;padding:18px 19px}
.traffic-stat span{display:block;color:#acc4d9;font-size:.78rem;font-weight:700;margin-bottom:9px}
.traffic-stat strong{display:block;font-size:clamp(1.35rem,3.2vw,2.05rem);letter-spacing:-.045em}
.traffic-map-card{padding:20px}
.traffic-map-top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.traffic-map-top h2{margin:0}
.traffic-filters{display:flex;gap:6px;flex-wrap:wrap}
.traffic-filters .map-filter{font-size:.77rem;padding:8px 11px;min-height:34px;background:#1b3049;
 border:1px solid #375a77;color:#bcd5e9}
.traffic-filters .map-filter[aria-pressed=true]{background:#2a666f;border-color:#5edacf;color:#e7ffff}
.map-frame{position:relative;border-radius:13px;overflow:hidden;border:1px solid #31536e;
 background:radial-gradient(ellipse at 50% 50%,#0d3048,#0b1d33);min-height:120px}
.traffic-map{display:block;width:100%;height:auto;aspect-ratio:1000/460}
.map-ocean{fill:#0c263b}
.map-grid line{stroke:#31516b;stroke-width:.7;opacity:.55}
.map-land polygon{fill:#234c61;stroke:#42718a;stroke-width:.65;stroke-linejoin:round}
.traffic-dot{stroke:#f3ffff;stroke-width:1.4;cursor:pointer;opacity:.9;transition:opacity .2s,stroke-width .2s}
.traffic-dot.visitor{fill:#67dfc9;fill-opacity:.75}
.traffic-dot.flagged{fill:#ffb076;fill-opacity:.88}
.traffic-dot:hover,.traffic-dot:focus{opacity:1;stroke-width:3;outline:none}
.traffic-dot[hidden]{display:none}
.map-watermark{position:absolute;top:14px;left:16px;background:#061625d9;border:1px solid #6c9ab1;
 color:#e6f8ff;font-size:.72rem;font-weight:850;letter-spacing:.09em;border-radius:7px;padding:7px 10px}
.traffic-legend{display:flex;gap:17px;flex-wrap:wrap;margin:14px 0 10px;color:#bcd1e5;font-size:.8rem}
.traffic-legend span{display:inline-flex;align-items:center;gap:7px}
.traffic-legend i{width:11px;height:11px;border-radius:50%;display:inline-block}
.legend-visitor{background:#67dfc9}.legend-flagged{background:#ffb076}
.map-detail{background:#102a3e;border:1px solid #315570;border-radius:9px;padding:10px 12px;
 color:#e4f3ff;font-size:.87rem;min-height:44px}
.traffic-import{margin-top:18px}
.traffic-import summary{font-size:1rem}
.traffic-import form{padding-top:15px}
.traffic-import textarea{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.8rem;line-height:1.5}
.table-scroll{overflow-x:auto}
@media(max-width:700px){
 nav{padding:9px 12px;min-height:58px}.brand{font-size:.81rem}
 .brand small{font-size:.6rem}.nav-actions{gap:3px}
 .nav-drop summary{font-size:.78rem;padding:7px 8px}.nav-pop{right:0;width:220px}
 .wrap{padding:18px 12px 55px}.card{padding:16px}
 .traffic-promo{flex-direction:column;align-items:flex-start;gap:9px}
 .traffic-stats{gap:8px}.traffic-stat{padding:12px 10px}.traffic-stat span{font-size:.67rem}
 .traffic-map-card{padding:12px}.map-watermark{font-size:.56rem;padding:5px 6px;top:7px;left:7px}
 .traffic-filters .map-filter{font-size:.7rem;padding:7px 9px}
 .module-group summary{padding:15px}.module-group ul{padding:0 15px 13px}
}
'''
JS = r'''
(()=>{
  'use strict';
  function activateMapFilter(type){
    const root=document.querySelector('.traffic-map-card');if(!root)return;
    for(const btn of root.querySelectorAll('[data-map-filter]')){
      btn.setAttribute('aria-pressed',String(btn.dataset.mapFilter===type));
    }
    for(const dot of root.querySelectorAll('.traffic-dot')){
      if(type!=='all'&&dot.dataset.category!==type)dot.setAttribute('hidden','');
      else dot.removeAttribute('hidden');
    }
    const label=root.querySelector('#map-detail');
    if(label)label.textContent=type==='all'?'Showing visitor and flagged request locations. Select a point for details.':
      'Showing '+(type==='visitor'?'visitor requests':'flagged requests')+'. Select a point for details.';
  }
  document.addEventListener('click',e=>{
    const filter=e.target.closest('[data-map-filter]');
    if(filter){activateMapFilter(filter.dataset.mapFilter);return;}
    const dot=e.target.closest('.traffic-dot');
    if(dot){const label=document.getElementById('map-detail');if(label)label.textContent=dot.dataset.location||'Approximate location';return;}
    const nav=e.target.closest('.nav-pop a');
    if(nav)document.querySelectorAll('.nav-drop[open]').forEach(d=>d.open=false);
  });
  document.addEventListener('keydown',e=>{
    if((e.key==='Enter'||e.key===' ')&&e.target.classList?.contains('traffic-dot')){
      e.preventDefault();const label=document.getElementById('map-detail');
      if(label)label.textContent=e.target.dataset.location||'Approximate location';
    }
    if(e.key==='Escape')document.querySelectorAll('.nav-drop[open]').forEach(d=>d.open=false);
  });
  document.addEventListener('input',e=>{
    if(e.target.id==='module-search'&&e.target.value.trim()){
      document.querySelectorAll('details.module-group:not([hidden])').forEach(d=>d.open=true);
    }
  });
})();
'''
