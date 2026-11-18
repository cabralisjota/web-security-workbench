"""Workbench v5.4: stable mobile menus, map-first home and demo usability.

No external assets, scripts, or tracking.
"""
CSS = r'''
/* v5.4 mobile layout: override older v5.2/v5.3 rules explicitly */
html,body{max-width:100%;overflow-x:clip}
header{z-index:300}
header nav{position:relative;max-width:100%;width:100%;box-sizing:border-box}
.nav-actions{min-width:0;max-width:100%;justify-content:center}
.nav-drop{position:static!important;isolation:auto!important;z-index:auto!important}
.nav-pop{position:absolute!important;top:calc(100% + 3px)!important;
 left:12px!important;right:12px!important;width:auto!important;transform:none!important;
 max-width:440px!important;margin-inline:auto!important;box-sizing:border-box;
 max-height:min(65vh,460px)!important;overflow-y:auto!important;
 overscroll-behavior:contain;z-index:999!important;padding:8px!important;
 background:#11243a;border:1px solid #4b6987;box-shadow:0 20px 45px #000b}
.nav-pop a{display:block!important;max-width:100%!important;white-space:normal!important;
 overflow-wrap:anywhere!important;line-height:1.35!important;padding:12px!important}
.nav-pop small{display:block;white-space:normal!important;overflow-wrap:anywhere}
.nav-drop summary{min-width:0;max-width:100%;justify-content:center}
.nav-actions>form.inline{min-width:0}
.nav-actions>form.inline button{width:100%;max-width:100%}
.dashboard-home .hero{display:none!important}
.dashboard-home{padding-top:12px!important}
.dashboard-home .overview-map{margin-top:0!important}
.dashboard-home .overview-map h2{font-size:clamp(1.2rem,4vw,1.6rem)}
@media(max-width:820px){
 header nav{display:flex!important;flex-direction:column!important;align-items:center!important;
  justify-content:center!important;flex-wrap:nowrap!important;gap:9px!important;padding:10px 12px!important}
 .brand{align-self:center!important;min-width:0;max-width:100%;font-size:.9rem!important}
 .brand small{font-size:.68rem!important}
 .nav-actions{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;
  gap:5px!important;width:100%!important;max-width:480px!important;margin:0 auto!important}
 .nav-actions>.nav-link,.nav-actions>.nav-drop,.nav-actions>form.inline{min-width:0!important;
  width:100%!important;max-width:100%!important;margin:0!important}
 .nav-actions>.nav-link,.nav-actions>.nav-drop>summary,.nav-actions>form.inline>button{
  box-sizing:border-box!important;display:flex!important;align-items:center!important;justify-content:center!important;
  padding:8px 3px!important;min-height:44px!important;font-size:clamp(.72rem,2.9vw,.9rem)!important;
  line-height:1.15!important;white-space:normal!important;overflow-wrap:anywhere!important;
  text-align:center!important;border-radius:10px!important}
 .nav-actions .chev{font-size:.65rem!important}
 .nav-actions .account-name{display:none!important}
 .nav-pop{left:12px!important;right:12px!important;top:calc(100% + 4px)!important;
  max-width:calc(100% - 24px)!important;max-height:min(65vh,400px)!important}
 .nav-pop a{font-size:.88rem!important;padding:13px!important}
 .nav-pop small{font-size:.76rem!important}
 .wrap{max-width:100%;min-width:0;overflow-x:clip}
 .dashboard-home{padding-top:12px!important}
 .overview-map{padding:13px 11px!important}
 .overview-map .traffic-map-top{gap:8px!important}
 .overview-map .traffic-map-top .btn{white-space:normal!important}
}
@media(max-width:345px){
 .nav-actions{grid-template-columns:repeat(2,minmax(0,1fr))!important}
 .nav-actions>.nav-link,.nav-actions>.nav-drop>summary,.nav-actions>form.inline>button{min-height:40px!important}
}
'''

JS = r'''
(()=>{
  'use strict';
  // One menu at a time; work with both native clicks and keyboard activation.
  document.addEventListener('toggle',event=>{
    const item=event.target;
    if(!(item instanceof HTMLDetailsElement)||!item.open)return;
    for(const other of document.querySelectorAll('details[open]')){
      if(other!==item)other.open=false;
    }
  },true);
  document.addEventListener('keydown',event=>{
    if(event.key==='Escape'){
      document.querySelectorAll('details.nav-drop[open]').forEach(item=>item.open=false);
    }
  });
})();
'''
