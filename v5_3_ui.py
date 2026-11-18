"""Workbench v5.3: responsive centered menus and single-open accordions.

Client-side only: no change to security testing, accounts, traffic ingestion, or APIs.
"""

CSS = r'''
/* v5.3 — centered, readable navigation and home-map presentation */
.nav-actions{justify-content:center;align-items:center;min-width:0}
.nav-drop{isolation:isolate}
.nav-drop summary{justify-content:center;white-space:normal;text-align:center;min-width:0}
.nav-pop{left:50%;right:auto;transform:translateX(-50%);width:min(310px,calc(100vw - 24px));
 max-height:min(65vh,440px);overflow-y:auto;overscroll-behavior:contain;text-align:left}
.nav-pop a{white-space:normal;overflow-wrap:anywhere;line-height:1.35}
.nav-pop small{white-space:normal;line-height:1.35}
.nav-link{text-align:center;display:inline-flex;align-items:center;justify-content:center}
.module-group summary{cursor:pointer;overflow-wrap:anywhere}
.module-group summary::after{flex:0 0 auto}
/* The traffic map is the first content panel on the signed-in overview. */
.overview-map{padding:18px 20px;margin-bottom:18px;overflow:visible}
.overview-map .traffic-map-top{margin-bottom:13px}
.overview-map .traffic-map-top h2{font-size:clamp(1.08rem,2.6vw,1.42rem);margin:0}
.overview-map .traffic-map-top p{margin:5px 0 0;color:var(--muted);font-size:.85rem}
.overview-map .traffic-map-top .btn{white-space:nowrap}
.overview-map .overview-map-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:7px 0 12px}
.overview-map .overview-map-meta .pill{font-size:.69rem}
.overview-map .traffic-filters{margin:0 0 12px}
.overview-map .map-frame{width:100%;min-height:0}
.overview-map .map-detail{margin:10px 0 0}
.overview-map .overview-summary{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 0}
.overview-map .overview-summary span{color:#c8dced;font-size:.78rem;background:#142a40;
 border:1px solid #34526d;padding:7px 10px;border-radius:9px}
.overview-map .overview-summary strong{color:#f6fcff;font-variant-numeric:tabular-nums}
@media(max-width:760px){
 header nav{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:9px;
   padding:10px 12px 9px;width:100%;max-width:100%;flex-wrap:nowrap}
 .brand{align-self:center;max-width:100%;font-size:.88rem;text-align:left}
 .brand small{font-size:.64rem}
 .nav-actions{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));width:100%;max-width:480px;
   margin:0 auto;gap:5px;align-items:stretch;justify-content:center}
 .nav-actions>.nav-link,.nav-actions>.nav-drop,.nav-actions>form.inline{min-width:0;width:100%;margin:0}
 .nav-actions>.nav-link,.nav-drop summary,.nav-actions>form.inline button{
   min-height:40px;width:100%;display:flex;justify-content:center;align-items:center;
   padding:7px 4px!important;font-size:clamp(.7rem,2.75vw,.85rem)!important;line-height:1.15;
   text-align:center;white-space:normal;overflow-wrap:anywhere;border-radius:9px}
 .nav-drop summary{gap:3px}
 .nav-drop summary .chev{font-size:.65rem}
 .nav-actions .account-name{display:none}
 .nav-actions form.inline button{margin:0}
 .nav-drop{position:static}
 .nav-pop{position:absolute;left:12px;right:12px;top:calc(100% + 6px);transform:none;
   width:auto;max-width:480px;margin:0 auto;max-height:min(58vh,390px);z-index:100;
   box-shadow:0 22px 70px #02070ed9}
 .nav-pop a{padding:14px 15px!important;font-size:.88rem!important}
 .nav-pop small{font-size:.75rem}
 .wrap{width:100%;max-width:100%;overflow-x:clip}
 .overview-map{padding:14px 12px}
 .overview-map .traffic-map-top{align-items:flex-start}
 .overview-map .traffic-map-top .btn{font-size:.76rem;padding:8px 10px;min-height:34px}
 .overview-map .traffic-filters{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:5px}
 .overview-map .traffic-filters .map-filter{min-width:0;white-space:normal;font-size:.7rem;padding:8px 3px}
 .overview-map .map-frame{min-height:165px;display:flex;align-items:center}
 .overview-map .traffic-map{min-height:155px;max-height:260px}
 .overview-map .overview-summary{gap:6px}
 .overview-map .overview-summary span{font-size:.71rem;padding:7px 8px}
 .overview-map .map-detail{font-size:.79rem}
}
@media(max-width:350px){
 .nav-actions{grid-template-columns:repeat(2,minmax(0,1fr));max-width:330px}
 .nav-actions>.nav-link,.nav-drop summary,.nav-actions>form.inline button{min-height:36px}
 .overview-map .traffic-map-top .btn{white-space:normal}
}
'''

JS = r'''
(()=>{
  'use strict';
  // Native details remain keyboard-accessible. Use a capturing toggle listener
  // so this works after v5.1 swaps main content without a full page reload.
  function positionMenu(){
    const header=document.querySelector('header');
    if(header){document.documentElement.style.setProperty('--wb-menu-top',
      Math.ceil(header.getBoundingClientRect().bottom+6)+'px');}
  }
  function closeOtherDetails(opened){
    if(!opened.open)return;
    // One dropdown at a time, across nav, training modules, and import panels.
    for(const el of document.querySelectorAll('details[open]')){
      if(el!==opened)el.open=false;
    }
    if(opened.classList.contains('nav-drop'))positionMenu();
  }
  document.addEventListener('toggle',event=>{
    const d=event.target;
    if(d instanceof HTMLDetailsElement && d.open)closeOtherDetails(d);
  },true);
  document.addEventListener('click',event=>{
    if(!event.target.closest('.nav-drop')){
      document.querySelectorAll('.nav-drop[open]').forEach(d=>d.open=false);
    }
  });
  window.addEventListener('resize',positionMenu,{passive:true});
  window.addEventListener('scroll',()=>{
    if(document.querySelector('.nav-drop[open]'))positionMenu();
  },{passive:true});
  // v5.2 expanded every category during search. Keep the first matching
  // category open, while preserving the existing item filtering and count.
  document.addEventListener('input',event=>{
    if(event.target.id!=='module-search')return;
    const groups=[...document.querySelectorAll('details.module-group:not([hidden])')];
    const active=groups.find(g=>g.open)||groups[0];
    document.querySelectorAll('details.module-group').forEach(g=>g.open=(g===active));
  });
  // When an async action swaps the page header, keep the menu positioning current.
  const observer=new MutationObserver(records=>{
    if(records.some(r=>[...r.addedNodes].some(n=>n.nodeType===1&&n.matches?.('header'))))positionMenu();
  });
  observer.observe(document.body,{childList:true});
  positionMenu();
})();
'''
