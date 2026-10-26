// src/dash/ui/js.rs — Comportement client (vanilla JS, extrait de ui.rs v0.5.8).

// ─────────────────────────────────────────── comportement (vanilla JS) ──────

pub const JS: &str = r##"
(function(){
'use strict';
/* ═══ 0 — utilitaires ═══════════════════════════════════════════════════ */
var D=document,W=window,R=Math,QS=function(s,r){return (r||D).querySelector(s);},
QSA=function(s,r){return Array.prototype.slice.call((r||D).querySelectorAll(s));},
ON=function(el,ev,fn,o){if(el)el.addEventListener(ev,fn,o||false);},
has=R.max&&R.min?true:false, REDUCED=false;
try{REDUCED=W.matchMedia('(prefers-reduced-motion: reduce)').matches;}catch(e){REDUCED=false;}
function el(tag,cls,html){var n=D.createElement(tag);if(cls)n.className=cls;if(html!=null)n.innerHTML=html;return n;}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function nfmt(n){if(n==null||isNaN(n))return '—';var v=Number(n);return (R.round(v*100)/100).toLocaleString('fr-FR');}
function bytes(n){n=Number(n)||0;var u=['o','ko','Mo','Go','To'],i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return (i===0?n:n.toFixed(n<10?1:0))+' '+u[i];}
function dur(s){s=R.max(0,R.floor(Number(s)||0));var d=R.floor(s/86400),h=R.floor(s%86400/3600),
  m=R.floor(s%3600/60),x=s%60,p=function(v){return (v<10?'0':'')+v;};
  if(d)return d+'j '+p(h)+'h';if(h)return h+'h '+p(m)+'m';if(m)return m+'m '+p(x)+'s';return x+'s';}
function tone(t){t=String(t||'').toLowerCase();
  if(/^(crit|critical|critique|blocker|fatal|5)$/.test(t))return'crit';
  if(/^(high|haut|eleve|élevé|4)$/.test(t))return'high';
  if(/^(med|medium|moyen|moderate|modere|3)$/.test(t))return'med';
  if(/^(low|faible|minor|2)$/.test(t))return'low';
  if(/^(info|information|notice|1)$/.test(t))return'info';
  if(/^(ok|pass|good|valid|0)$/.test(t))return'ok';return'mute';}
function sev(sevName){return '<span class="sev sev-'+tone(sevName)+'"><i class="dot"></i>'+esc(sevName||'inconnu')+'</span>';}
function debounce(fn,ms){var t;return function(){var a=arguments,c=this;clearTimeout(t);t=setTimeout(function(){fn.apply(c,a);},ms||140);};}
function throttleRAF(fn){var q=false;return function(){if(q)return;q=true;requestAnimationFrame(function(){q=false;fn();});};}
function lerp(a,b,t){return a+(b-a)*t;}
function clamp(v,a,b){return v<a?a:(v>b?b:v);}
/* easeOutExpo — pour tous les compteurs animés */
function easeOutExpo(t){return t>=1?1:1-R.pow(2,-10*t);}

/* ═══ 1 — état + stockage ══════════════════════════════════════════════ */
var S={data:null,live:[],search:'',filt:'',sort:{},hidden:{},folded:{},noob:true,theme:'void',
  font:'sans',motion:REDUCED?0:1,cursor:0,liveOn:true,busy:false,seq:0,lastGood:null};
var K={layout:'dash.layout.v1',pref:'dash.pref.v1',tab:'dash.tab.v1'};
var ST={
  get:function(k,d){try{var v=localStorage.getItem(k);return v==null?d:JSON.parse(v);}catch(e){return d;}},
  set:function(k,v){try{localStorage.setItem(k,JSON.stringify(v));return true;}catch(e){return false;}},
  del:function(k){try{localStorage.removeItem(k);}catch(e){return;}}
};
/* Onglet actif : persiste comme le reste des preferences. */
S.tab=ST.get(K.tab,'findings');

function saveLayout(){ST.set(K.layout,{hidden:S.hidden,folded:S.folded,order:currentOrder()});}
function savePref(){ST.set(K.pref,{theme:S.theme,font:S.font,noob:S.noob,motion:S.motion,cursor:S.cursor});}

/* ═══ 2 — préférences : thème, police, noob, mouvement ══════════════════ */
var THEMES=[['void','Void clair','#d9a24e'],['amber','Ambre chaud','#e8b05c'],['term','Vert terminal','#7ee08a']];
var FONTS=[['serif','Serif','Zodiak / Georgia'],['sans','Sans','Inter / Switzer'],['mono','Mono','JetBrains Mono']];
function applyTheme(t){S.theme=t;D.documentElement.setAttribute('data-theme',t);savePref();}
function applyFont(f){S.font=f;D.documentElement.setAttribute('data-font',f);savePref();}
function applyNoob(v){S.noob=!!v;D.documentElement.setAttribute('data-noob',v?'1':'0');savePref();rebuildTips();}
function applyMotion(v){S.motion=v?1:0;D.documentElement.setAttribute('data-motion',v?'1':'0');savePref();}
function applyCursor(v){S.cursor=v?1:0;
  var fine=false;try{fine=W.matchMedia('(pointer: fine)').matches;}catch(e){fine=false;}
  D.documentElement.setAttribute('data-cursor',(v&&fine&&!REDUCED)?'1':'0');savePref();}
function loadPref(){
  var p=ST.get(K.pref,null);
  if(p){S.theme=p.theme||'void';S.font=p.font||'sans';S.noob=p.noob!==false;S.motion=p.motion?1:0;S.cursor=!!p.cursor;}
  D.documentElement.setAttribute('data-theme',S.theme);
  D.documentElement.setAttribute('data-font',S.font);
  D.documentElement.setAttribute('data-noob',S.noob?'1':'0');
  D.documentElement.setAttribute('data-motion',S.motion?'1':'0');
  var fine=false;try{fine=W.matchMedia('(pointer: fine)').matches;}catch(e){fine=false;}
  D.documentElement.setAttribute('data-cursor',(S.cursor&&fine&&!REDUCED)?'1':'0');
  if(REDUCED){S.motion=0;D.documentElement.setAttribute('data-motion','0');}
}

/* ═══ 3 — toasts ═══════════════════════════════════════════════════════ */
function toast(title,msg,kind,ms){
  var t=D.getElementById('toasts');if(!t)return;
  var n=el('div','toast'+(kind?' toast-'+kind:''));
  n.innerHTML='<span class="toast-i">'+(kind==='err'?'!':kind==='ok'?'✓':'·')+'</span>'+
    '<div class="toast-b"><p class="toast-t"><b>'+esc(title)+'</b>'+esc(msg||'')+'</p></div>';
  t.appendChild(n);
  setTimeout(function(){n.className+=' out';setTimeout(function(){if(n.parentNode)n.parentNode.removeChild(n);},260);},ms||4200);
}

/* ═══ 4 — modale ═══════════════════════════════════════════════════════ */
var MO={node:null,title:'',body:null,prev:null};
function openModal(title,body,footer){
  MO.prev=D.activeElement;
  if(!MO.node){
    MO.node=el('div','mo');MO.node.setAttribute('role','dialog');MO.node.setAttribute('aria-modal','true');
    MO.node.innerHTML='<div class="mo-box"><header class="mo-h"><h2 class="mo-t"></h2>'+
      '<button class="mo-x" type="button" aria-label="Fermer">✕</button></header>'+
      '<div class="mo-b"></div><footer class="mo-f"></footer></div>';
    D.body.appendChild(MO.node);
    ON(QS('.mo-x',MO.node),'click',closeModal);
    ON(MO.node,'mousedown',function(e){if(e.target===MO.node)closeModal();});
  }
  QS('.mo-t',MO.node).textContent=title;
  QS('.mo-b',MO.node).innerHTML=body;
  QS('.mo-f',MO.node).innerHTML=footer||'<button class="btn" type="button" data-close="1">Fermer</button>';
  QSA('[data-close]',MO.node).forEach(function(b){ON(b,'click',closeModal);});
  var sc=D.getElementById('scrim');if(sc){sc.hidden=false;requestAnimationFrame(function(){sc.className='on';});}
  MO.node.className='mo on';
  var f=QS('.mo-box button, .mo-box [href], .mo-box input',MO.node);if(f)f.focus();
}
function closeModal(){
  if(!MO.node)return;
  MO.node.className='mo';
  var sc=D.getElementById('scrim');
  if(sc){sc.className='';setTimeout(function(){if(!QSA('.mo.on').length&&!QSA('.pal.on').length)sc.hidden=true;},240);}
  if(MO.prev&&MO.prev.focus)MO.prev.focus();
}

/* ═══ 5 — tooltips « mode noob » + glossaire ═══════════════════════════ */
var TIP=null;
function rebuildTips(){
  if(TIP&&TIP.parentNode)TIP.parentNode.removeChild(TIP);TIP=null;
  if(!S.noob){
    QSA('.tip-q').forEach(function(n){if(n.parentNode)n.parentNode.removeChild(n);});
    return;
  }
  QSA('[data-tip]').forEach(function(n){
    if(QS('.tip-q',n))return;
    var b=el('span','tip-q','?');
    b.setAttribute('aria-hidden','true');
    b.setAttribute('title','Qu’est-ce que ça veut dire ?');
    n.appendChild(b);
  });
}
function showTip(n){
  if(!S.noob)return;
  var txt=n.getAttribute('data-tip');if(!txt)return;
  if(!TIP){TIP=el('div','tip');D.body.appendChild(TIP);}
  var ttl=n.getAttribute('data-tip-title')||'En clair';
  TIP.innerHTML='<b>'+esc(ttl)+'</b>'+esc(txt);
  var r=n.getBoundingClientRect(),tr=TIP.offsetWidth,th=TIP.offsetHeight;
  var left=clamp(r.left+12,10,W.innerWidth-tr-10),top=r.top-th-10;
  if(top<10)top=R.min(r.bottom+10,W.innerHeight-th-10);
  TIP.style.left=left+'px';TIP.style.top=top+'px';
  TIP.style.maxWidth=Math.min(300,W.innerWidth-24)+'px';
  TIP.className='tip on';
}
function hideTip(){if(TIP)TIP.className='tip';}
function initTips(){
  D.addEventListener('mouseover',function(e){
    var n=e.target&&e.target.closest?e.target.closest('[data-tip]'):null;
    if(n&&S.noob)showTip(n);else hideTip();
  },true);
  D.addEventListener('focusin',function(e){
    var n=e.target&&e.target.closest?e.target.closest('[data-tip]'):null;
    if(n&&S.noob)showTip(n);else hideTip();
  },true);
  D.addEventListener('mouseleave',hideTip,true);
  D.addEventListener('scroll',hideTip,true);
  D.addEventListener('keydown',function(e){if(e.key==='Escape')hideTip();},true);
}

/* glossaire inline : <span class="gloss" data-gloss="…">terme</span> */
function initGloss(){
  D.addEventListener('mouseover',function(e){
    var g=e.target&&e.target.closest?e.target.closest('.gloss-b'):null;
    if(g)showTip({getAttribute:function(k){return k==='data-tip'?g.getAttribute('data-gloss'):null;},
      getBoundingClientRect:function(){return g.getBoundingClientRect();}});
  });
}

/* ═══ 6 — compteurs animés (easeOutExpo) ══════════════════════════════ */
var counterObserver=null;
function countUp(node,to,dec,prefix,suffix,dur2){
  var from=0,val=to,dur=dur2||1250,t0=0,decs=(dec!=null?dec:0);
  if(!S.motion){node.textContent=(prefix||'')+nfmt(to)+(suffix||'');return;}
  function step(t){
    if(!t0)t0=t;
    var p=clamp((t-t0)/dur,0,1),v=lerp(from,val,easeOutExpo(p));
    node.textContent=(prefix||'')+(decs?nfmt(R.round(v*100)/100):nfmt(v))+(suffix||'');
    if(p<1)requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}
function animateCounters(root){
  QSA('.num[data-count]',root||D).forEach(function(n){
    if(n.getAttribute('data-done')==='1')return;
    var raw=n.getAttribute('data-count');
    var v=parseFloat(raw);
    if(isNaN(v)){n.textContent=raw;return;}
    n.setAttribute('data-done','1');
    countUp(n,v,null,n.getAttribute('data-prefix'),n.getAttribute('data-suffix'));
  });
}
function setCounter(node,raw,dec){
  var v=parseFloat(raw);
  if(isNaN(v)){node.textContent=raw;return;}
  node.setAttribute('data-count',raw);
  if(S.motion){countUp(node,v,dec!=null?dec:null);}
  else node.textContent=nfmt(v);
}

/* ═══ 7 — reveal : IntersectionObserver + stagger 40ms ════════════════ */
function initReveal(){
  if(!('IntersectionObserver' in W)){QSA('.rv').forEach(function(n){n.className=n.className.replace(/\brv(-\d)?\b/,'')+' in';});return;}
  var io=new IntersectionObserver(function(es){
    var i=0;
    es.forEach(function(e){
      if(!e.isIntersecting)return;
      var n=e.target,st=parseInt(n.getAttribute('data-stagger')||'0',10);
      setTimeout(function(){n.className+=' in';},st||(i*40));
      i++;
      io.unobserve(n);
    });
  },{rootMargin:'0px 0px -8% 0px',threshold:0.06});
  QSA('.rv').forEach(function(n){io.observe(n);});
}
function stagger(root){
  QSA('.rv:not(.in)',root||D).forEach(function(n,i){
    n.setAttribute('data-stagger',String(Math.min(i*40,480)));
  });
}

/* ═══ 8 — animation des SVG reçus du serveur ══════════════════════════ */
function anchorCharts(root){
  QSA('svg',root||D).forEach(function(s){
    if(s.getAttribute('data-anim')==='1')return;
    s.setAttribute('data-anim','1');
    s.setAttribute('role','img');
    if(!s.getAttribute('aria-label'))s.setAttribute('aria-label','Graphique');
    var paths=QSA('path,polyline,line',s);
    paths.forEach(function(p){
      var len=0;
      try{len=p.getTotalLength?p.getTotalLength():0;}catch(e){len=0;}
      if(!len||isNaN(len))return;
      p.style.strokeDasharray=len;p.style.strokeDashoffset=len;
      p.style.transition='stroke-dashoffset 1100ms cubic-bezier(.16,1,.3,1)';
      if(S.motion)requestAnimationFrame(function(){p.style.strokeDashoffset='0';});
      else p.style.strokeDashoffset='0';
    });
    QSA('rect,circle.ring-arc',s).forEach(function(r,i){
      r.style.opacity='0';
      r.style.transition='opacity 520ms cubic-bezier(.16,1,.3,1) '+(i*45)+'ms';
      if(S.motion)requestAnimationFrame(function(){r.style.opacity='1';});
      else r.style.opacity='1';
    });
  });
}

/* ═══ 9 — curseur custom : point + anneau avec lerp (desktop only) ═════ */
function initCursor(){
  var wrap=QS('.cursor');if(!wrap)return;
  var dot=QS('.cursor-dot',wrap),ring=QS('.cursor-ring',wrap);
  if(!dot||!ring)return;
  var mx=W.innerWidth/2,my=W.innerHeight/2,dx=mx,dy=my,rx=mx,ry=my,raf=null;
  D.addEventListener('mousemove',function(e){
    mx=e.clientX;my=e.clientY;
    if(!raf)raf=requestAnimationFrame(loop);
    var hot=e.target&&e.target.closest?
      !!e.target.closest('a,button,.card,.tbl tbody tr,.rail-link,.opt,.kpi,.chart,.acc-h,[role="button"],input,select'):
      false;
    D.body.className=hot?'cur-hot':D.body.className.replace(/\bcur-hot\b/,'').trim();
  },{passive:true});
  function loop(){
    raf=null;
    dx=lerp(dx,mx,0.34);dy=lerp(dy,my,0.34);
    rx=lerp(rx,mx,0.12);ry=lerp(ry,my,0.12);
    dot.style.transform='translate3d('+dx+'px,'+dy+'px,0)';
    ring.style.transform='translate3d('+rx+'px,'+ry+'px,0)';
    if(R.abs(dx-mx)>0.1||R.abs(dy-my)>0.1||R.abs(rx-mx)>0.2||R.abs(ry-my)>0.2)raf=requestAnimationFrame(loop);
  }
  raf=requestAnimationFrame(loop);
  D.addEventListener('mouseleave',function(){dot.style.opacity='0';ring.style.opacity='0';});
  D.addEventListener('mouseenter',function(){dot.style.opacity='1';ring.style.opacity='1';});
}

/* ═══ 10 — parallax du hero (rAF throttlé) ════════════════════════════ */
function initParallax(){
  var hero=QS('.hero');if(!hero)return;
  var on=throttleRAF(function(){
    if(!S.motion)return;
    var y=W.pageYOffset||D.documentElement.scrollTop;
    if(y>W.innerHeight*1.2){hero.style.transform='';return;}
    var k=R.min(y,900);
    hero.style.transform='translate3d(0,'+(k*0.085).toFixed(2)+'px,0)';
  });
  ON(W,'scroll',on,{passive:true});
  ON(W,'resize',on);
  on();
}

/* ═══ 11 — barre de progression + scroll-spy ══════════════════════════ */
function initScroll(){
  var bar=QS('.toc-h span');
  var crumb=QS('.crumb');
  var on=throttleRAF(function(){
    var st=W.pageYOffset||D.documentElement.scrollTop;
    var max=R.max(1,D.documentElement.scrollHeight-W.innerHeight);
    if(bar)bar.style.setProperty('--p',(clamp(st/max,0,1)*100).toFixed(2)+'%');
    var best=null,bd=1e9;
    QSA('section.sec:not([hidden])').forEach(function(s){
      var d=s.getBoundingClientRect().top-120;
      if(d<=0&&R.abs(d)<bd){bd=R.abs(d);best=s;}
    });
    if(best){
      QSA('.rail-link').forEach(function(a){
        if(a.getAttribute('data-sec')===best.getAttribute('id'))a.setAttribute('aria-current','true');
        else a.removeAttribute('aria-current');
      });
      if(crumb){
        crumb.textContent=best.getAttribute('data-num')+' — '+(best.getAttribute('data-title')||'');
        crumb.className='crumb on';
        crumb.style.top='calc(var(--top) + 12px)';
      }
    }else if(crumb)crumb.className='crumb';
  });
  ON(W,'scroll',on,{passive:true});
  ON(W,'resize',on);
  on();
}

/* ═══ 12 — recherche globale (filtre temps réel) ═════════════════════ */
function searchText(n){
  if(n.getAttribute('data-search'))return n.getAttribute('data-search');
  return n.textContent||'';
}
function runSearch(q){
  S.search=(q||'').trim().toLowerCase();
  var wrap=QS('.search'),cnt=QS('.search-count'),input=QS('.search input');
  var pool=QSA('[data-search]');
  var terms=S.search?S.search.split(/\s+/).filter(Boolean):[];
  var shown=0,total=0;
  pool.forEach(function(n){
    total++;
    var hay=searchText(n).toLowerCase();
    var hit=!terms.length||terms.every(function(t){return hay.indexOf(t)>=0;});
    if(hit)shown++;
    n.style.display=hit?'':'none';
    if(hit&&S.search){
      var sec=n.closest?n.closest('.sec'):null;
      if(sec&&terms.length)sec.setAttribute('data-hl','1');
    }
  });
  /* les sections sans résultat disparaissent */
  QSA('section.sec').forEach(function(s){
    var items=QSA('[data-search]',s);
    var vis=items.some(function(n){return n.style.display!=='none';});
    if(S.search)s.className=s.className.replace(/\bnone-match\b/,'')+(!vis?' none-match':'');
  });
  if(wrap)wrap.className='search'+(S.search?' on':'');
  if(cnt)cnt.textContent=shown+' sur '+total+(total===1?' résultat':' résultats');
  if(input)input.setAttribute('aria-label',S.search?(shown+' sur '+total+' résultats'):'Recherche globale');
  return {shown:shown,total:total};
}
function clearSearch(){
  var input=QS('.search input');
  if(input)input.value='';
  runSearch('');
}
function initSearch(){
  var input=QS('.search input');if(!input)return;
  var go=debounce(function(){runSearch(input.value);},110);
  ON(input,'input',go);
  ON(input,'keydown',function(e){
    if(e.key==='Escape'){clearSearch();input.blur();}
    if(e.key==='Enter'){e.preventDefault();runSearch(input.value);
      var first=QS('[data-search]:not([style*="display: none"])');if(first&&S.search)flashRow(first);}
  });
  var c=QS('.search-clear');
  ON(c,'click',function(){clearSearch();input.focus();});
}
function flashRow(n){
  var r=n.closest?n.closest('tr,.card,.lg-i'):null;
  if(!r)return;
  r.className+=' hl';
  setTimeout(function(){r.className=r.className.replace(/\bhl\b/,'').trim();},1500);
}

/* ═══ 13 — panneaux personnalisables : drag & drop, repli, masquage ════ */
function currentOrder(){
  return QSA('section.sec').map(function(s){return s.getAttribute('id');});
}
function applyLayout(){
  var L=ST.get(K.layout,null);
  if(!L)return;
  S.hidden=L.hidden||{};S.folded=L.folded||{};
  var host=QS('.dash');
  if(!host)return;
  if(L.order&&L.order.length){
    L.order.forEach(function(id){
      var s=D.getElementById(id);
      if(s&&s.parentNode===host)host.appendChild(s);
    });
    /* les sections apparues depuis ne sont plus à la fin */
    QSA('section.sec').forEach(function(s){
      var id=s.getAttribute('id');
      if(L.order.indexOf(id)<0)host.appendChild(s);
    });
  }
  Object.keys(S.hidden).forEach(function(id){
    var s=D.getElementById(id);
    if(s&&S.hidden[id])s.className+=' hidden-sec';
  });
  Object.keys(S.folded).forEach(function(id){
    var s=D.getElementById(id);
    if(s&&S.folded[id])s.className+=' folded';
  });
  refreshSheet();
}
function toggleFold(sec){
  var id=sec.getAttribute('id'),on=sec.className.indexOf(' folded ')>=0||/\bfolded\b/.test(sec.className);
  sec.className=on?sec.className.replace(/\bfolded\b/,'').trim():sec.className+' folded';
  S.folded[id]=!on;
  var b=QS('[data-fold]',sec);
  if(b)b.setAttribute('aria-expanded',on?'false':'true');
  saveLayout();
}
function toggleHide(sec){
  var id=sec.getAttribute('id'),on=/\bhidden-sec\b/.test(sec.className);
  sec.className=on?sec.className.replace(/\bhidden-sec\b/,'').trim():sec.className+' hidden-sec';
  S.hidden[id]=!on;
  refreshSheet();
  saveLayout();
}
function moveSec(sec,dir){
  var host=sec.parentNode;
  if(dir<0&&sec.previousElementSibling)host.insertBefore(sec,sec.previousElementSibling);
  if(dir>0&&sec.nextElementSibling)host.insertBefore(sec.nextElementSibling,sec);
  saveLayout();
  sec.scrollIntoView({block:'nearest'});
}
function resetLayout(){
  ST.del(K.layout);
  S.hidden={};S.folded={};
  QSA('section.sec').forEach(function(s){
    s.className=s.className.replace(/\b(hidden-sec|folded)\b/,'').replace(/\s+/g,' ').trim();
  });
  var order=QS('.dash')?QS('.dash').getAttribute('data-order'):null;
  if(order){
    var host=QS('.dash');
    order.split(',').forEach(function(id){var s=D.getElementById(id);if(s)host.appendChild(s);});
  }
  refreshSheet();saveLayout();
  toast('Mise en page','Ordre, visibilité et repli réinitialisés.','ok');
}
function initDnD(){
  var host=QS('.dash');if(!host)return;
  var drag=null;
  QSA('section.sec').forEach(function(sec){
    var h=QS('.sec-h',sec);if(!h)return;
    h.setAttribute('draggable','true');
    ON(h,'dragstart',function(e){
      drag=sec;sec.className+=' dragging';
      try{e.dataTransfer.effectAllowed='move';e.dataTransfer.setData('text/plain',sec.getAttribute('id'));}catch(err){}
    });
    ON(h,'dragend',function(){
      sec.className=sec.className.replace(/\bdragging\b/,'').trim();
      QSA('.sec').forEach(function(s){s.className=s.className.replace(/\bdrop-(before|after)\b/,'').trim();});
      drag=null;saveLayout();
    });
    ON(sec,'dragover',function(e){
      if(!drag||drag===sec)return;
      e.preventDefault();
      try{e.dataTransfer.dropEffect='move';}catch(err){}
      var r=sec.getBoundingClientRect(),after=(e.clientY-r.top)>r.height/2;
      QSA('.sec').forEach(function(s){s.className=s.className.replace(/\bdrop-(before|after)\b/,'').trim();});
      sec.className+=' drop-'+(after?'after':'before');
    });
    ON(sec,'drop',function(e){
      if(!drag||drag===sec)return;
      e.preventDefault();
      var r=sec.getBoundingClientRect(),after=(e.clientY-r.top)>r.height/2;
      sec.className=sec.className.replace(/\bdrop-(before|after)\b/,'').trim();
      if(after)sec.parentNode.insertBefore(drag,sec.nextElementSibling);
      else sec.parentNode.insertBefore(drag,sec);
      drag.className=drag.className.replace(/\bdragging\b/,'').trim();
      drag=null;saveLayout();
    });
  });
}

/* ═══ 14 — menu de personnalisation (sheet) ═══════════════════════════ */
function sheetNode(){
  var s=QS('.sheet');
  if(!s){
    s=el('aside','sheet');
    s.setAttribute('role','dialog');
    s.setAttribute('aria-label','Personnaliser le tableau de bord');
    D.body.appendChild(s);
  }
  return s;
}
function refreshSheet(){
  var s=QS('.sheet');if(!s)return;
  var secs=QSA('section.sec');
  s.innerHTML='<header class="sheet-h"><h2 class="sheet-t">Mise en page</h2>'+
    '<button class="mo-x" type="button" data-sheet-close="1" aria-label="Fermer">✕</button></header>'+
    '<div class="sheet-b">'+
    '<p class="sheet-g lbl">Thème</p>'+
    THEMES.map(function(t){
      return '<button class="opt'+(S.theme===t[0]?' on':'')+'" type="button" data-theme-opt="'+t[0]+'">'+
      '<span class="opt-sw" style="--sw:'+t[2]+'"></span><span class="opt-t">'+esc(t[1])+'</span>'+
      '<span class="opt-s">'+esc(t[0])+'</span></button>';}).join('')+
    '<p class="sheet-g lbl">Police</p>'+
    FONTS.map(function(f){
      return '<button class="opt'+(S.font===f[0]?' on':'')+'" type="button" data-font-opt="'+f[0]+'">'+
      '<span class="opt-t">'+esc(f[1])+'</span><span class="opt-s">'+esc(f[2])+'</span></button>';}).join('')+
    '<p class="sheet-g lbl">Lecture</p>'+
    '<div class="row-sw"><span class="row-t">Mode noob</span>'+
    '<label class="sw"><input type="checkbox" data-pref="noob"'+(S.noob?' checked':'')+'>'+
    '<span class="sw-track"></span><span class="sw-l">aide</span></label></div>'+
    '<div class="row-sw"><span class="row-t">Animations</span>'+
    '<label class="sw"><input type="checkbox" data-pref="motion"'+(S.motion?' checked':'')+'>'+
    '<span class="sw-track"></span><span class="sw-l">on</span></label></div>'+
    '<div class="row-sw"><span class="row-t">Curseur</span>'+
    '<label class="sw"><input type="checkbox" data-pref="cursor"'+(S.cursor?' checked':'')+'>'+
    '<span class="sw-track"></span><span class="sw-l">ambre</span></label></div>'+
    '<p class="sheet-g lbl">Sections (glisser pour réordonner)</p>'+
    secs.map(function(sec){
      var id=sec.getAttribute('id'),num=sec.getAttribute('data-num')||'';
      var t=sec.getAttribute('data-title')||id;
      var hid=/\bhidden-sec\b/.test(sec.className),fold=/\bfolded\b/.test(sec.className);
      return '<div class="row-sw" data-sec-row="'+id+'">'+
      '<span class="row-t" draggable="true" data-row-drag="'+id+'">'+esc(num)+' '+esc(t)+'</span>'+
      '<button class="btn btn-xs" type="button" data-fold="'+id+'" aria-pressed="'+(fold?'true':'false')+'">'+
      (fold?'déplier':'replier')+'</button>'+
      '<button class="btn btn-xs'+(hid?' on':'')+'" type="button" data-hide="'+id+'" aria-pressed="'+(hid?'true':'false')+'">'+
      (hid?'montrer':'masquer')+'</button>'+
      '<button class="btn btn-xs btn-ico" type="button" data-move="'+id+'|-1" aria-label="Monter">↑</button>'+
      '<button class="btn btn-xs btn-ico" type="button" data-move="'+id+'|1" aria-label="Descendre">↓</button>'+
      '</div>';}).join('')+
    '<p class="sheet-g"></p>'+
    '<button class="btn btn-acc" type="button" data-reset="1" style="width:100%;justify-content:center;margin:8px 0">'+
    'Réinitialiser la mise en page</button>'+
    '<p class="tiny dim" style="padding:6px 11px 10px">Ordre, repli et visibilité sont mémorisés '+
    'dans ce navigateur (clé <span class="mono">dash.layout.v1</span>).</p>'+
    '</div>';
  /* le delegate est posé UNE seule fois : innerHTML est remplace a chaque refresh */
  if(s.getAttribute('data-bound')!=='1'){
    s.setAttribute('data-bound','1');
    ON(s,'click',onSheetClick);
  }
  QSA('[data-pref]',s).forEach(function(cb){
    ON(cb,'change',function(){
      var k=cb.getAttribute('data-pref');
      if(k==='noob')applyNoob(cb.checked);
      if(k==='motion')applyMotion(cb.checked);
      if(k==='cursor')applyCursor(cb.checked);
    });
  });
  initRowDnD();
}
function onSheetClick(e){
  var t=e.target.closest?e.target.closest('[data-theme-opt],[data-font-opt],[data-fold],[data-hide],[data-move],[data-reset],[data-sheet-close]'):null;
  if(!t)return;
  if(t.hasAttribute('data-sheet-close')){QS('.sheet').className='sheet';return;}
  if(t.hasAttribute('data-theme-opt')){applyTheme(t.getAttribute('data-theme-opt'));refreshSheet();
    toast('Thème','« '+t.textContent.trim()+' » appliqué.','ok',2200);return;}
  if(t.hasAttribute('data-font-opt')){applyFont(t.getAttribute('data-font-opt'));refreshSheet();return;}
  if(t.hasAttribute('data-fold')){var s1=D.getElementById(t.getAttribute('data-fold'));if(s1)toggleFold(s1);refreshSheet();return;}
  if(t.hasAttribute('data-hide')){var s2=D.getElementById(t.getAttribute('data-hide'));if(s2)toggleHide(s2);refreshSheet();return;}
  if(t.hasAttribute('data-move')){
    var p=t.getAttribute('data-move').split('|'),s3=D.getElementById(p[0]);
    if(s3)moveSec(s3,parseInt(p[1],10));
    refreshSheet();return;
  }
  if(t.hasAttribute('data-reset')){resetLayout();return;}
}
function initRowDnD(){
  var dragId=null;
  QSA('[data-row-drag]').forEach(function(h){
    ON(h,'dragstart',function(e){
      dragId=h.getAttribute('data-row-drag');
      try{e.dataTransfer.effectAllowed='move';e.dataTransfer.setData('text/plain',dragId);}catch(err){}
    });
    ON(h,'dragend',function(){dragId=null;});
    ON(h.parentNode,'dragover',function(e){if(dragId)e.preventDefault();});
    ON(h.parentNode,'drop',function(e){
      if(!dragId)return;
      e.preventDefault();
      var from=D.getElementById(dragId),to=h.parentNode.getAttribute('data-sec-row');
      var target=D.getElementById(to);
      if(!from||!target||from===target){dragId=null;return;}
      target.parentNode.insertBefore(from,target);
      dragId=null;saveLayout();refreshSheet();
    });
  });
}
function toggleSheet(){
  var s=sheetNode();
  refreshSheet();
  var on=s.className.indexOf(' on')>=0;
  s.className=on?'sheet':'sheet on';
  var sc=D.getElementById('scrim');
  if(!on&&sc){sc.hidden=false;requestAnimationFrame(function(){sc.className='on';});}
  if(on&&sc){sc.className='';setTimeout(function(){if(!QSA('.mo.on').length&&!QSA('.pal.on').length)sc.hidden=true;},240);}
}

/* ═══ 15 — palette de commandes (Ctrl+K) ══════════════════════════════ */
var PAL={node:null,items:[],idx:0,prev:null};
function cmds(){
  var list=[];
  QSA('section.sec').forEach(function(s){
    list.push({g:'Navigation',t:(s.getAttribute('data-num')||'')+' — '+(s.getAttribute('data-title')||s.id),
      ico:s.getAttribute('data-num')||'§',k:'goto',run:function(){goSec(s.id);}});
  });
  THEMES.forEach(function(t){
    list.push({g:'Apparence',t:'Thème : '+t[1],ico:'◐',k:'theme '+t[0],run:function(){applyTheme(t[0]);refreshSheet();}});
  });
  FONTS.forEach(function(f){
    list.push({g:'Apparence',t:'Police : '+f[1],ico:'Aa',k:'font '+f[0],run:function(){applyFont(f[0]);refreshSheet();}});
  });
  list.push({g:'Lecture',t:'Mode noob : '+(S.noob?'désactiver':'activer'),ico:'?',k:'noob',
    run:function(){applyNoob(!S.noob);refreshSheet();}});
  list.push({g:'Lecture',t:'Animations : '+(S.motion?'couper':'rétablir'),ico:'≈',k:'motion',
    run:function(){applyMotion(!S.motion);refreshSheet();}});
  list.push({g:'Lecture',t:'Curseur ambre : '+(S.cursor?'couper':'activer'),ico:'◎',k:'cursor',
    run:function(){applyCursor(!S.cursor);}});
  list.push({g:'Données',t:'Rafraîchir les données',ico:'↻',k:'refresh',run:function(){load();}});
  list.push({g:'Données',t:'Exporter le JSON',ico:'↓',k:'export json',run:exportJSON});
  list.push({g:'Données',t:'Ouvrir /api/overview',ico:'↗',k:'api overview',run:function(){W.open('/api/overview','_blank','noopener');}});
  list.push({g:'Données',t:'Lancer un scan',ico:'▶',k:'scan start',run:openScanModal});
  if(S.liveOn)list.push({g:'Données',t:'Arrêter le scan en cours',ico:'■',k:'scan stop',run:stopScan});
  list.push({g:'Scans',t:'Afficher / masquer les scans en direct',ico:'◉',k:'live',run:function(){toggleLive();}});
  list.push({g:'Mise en page',t:'Ouvrir le menu de personnalisation',ico:'☰',k:'layout',run:toggleSheet});
  list.push({g:'Mise en page',t:'Tout déplier',ico:'▽',k:'expand',run:function(){QSA('.sec').forEach(function(s){s.className=s.className.replace(/\bfolded\b/,'').trim();S.folded[s.id]=false;});refreshSheet();saveLayout();}});
  list.push({g:'Mise en page',t:'Tout replier (sauf le hero)',ico:'△',k:'collapse',run:function(){
    QSA('.sec').forEach(function(s){if(s.id!=='hero'){s.className+=' folded';S.folded[s.id]=true;}});refreshSheet();saveLayout();}});
  list.push({g:'Mise en page',t:'Réinitialiser la mise en page',ico:'⟲',k:'reset layout',run:resetLayout});
  list.push({g:'Aide',t:'Réinitialiser la recherche',ico:'⌫',k:'clear search',run:function(){clearSearch();}});
  list.push({g:'Aide',t:'Glossaire : qu’est-ce que ça veut dire ?',ico:'?',k:'glossary',run:openGlossary});
  return list;
}
function buildPal(){
  if(PAL.node)return;
  PAL.node=el('div','pal');
  PAL.node.setAttribute('role','dialog');
  PAL.node.setAttribute('aria-modal','true');
  PAL.node.setAttribute('aria-label','Palette de commandes');
  PAL.node.innerHTML='<div class="pal-box">'+
    '<div class="pal-in"><span class="mono">❯</span>'+
    '<input type="text" placeholder="Commande ou section…" autocomplete="off" spellcheck="false" aria-label="Commande">'+
    '<span class="pal-kbd">ESC</span></div>'+
    '<div class="pal-list" role="listbox" aria-label="Résultats"></div>'+
    '<div class="pal-f"><span><span class="pal-kbd">↑</span><span class="pal-kbd">↓</span> naviguer</span>'+
    '<span><span class="pal-kbd">⏎</span> valider</span><span><span class="pal-kbd">ESC</span> fermer</span></div>'+
    '</div>';
  D.body.appendChild(PAL.node);
  var input=QS('input',PAL.node);
  ON(input,'input',function(){paintPal(input.value);});
  ON(input,'keydown',palKeys);
  ON(PAL.node,'mousedown',function(e){if(e.target===PAL.node)closePal();});
  ON(QS('.pal-list',PAL.node),'click',function(e){
    var it=e.target.closest?e.target.closest('.pal-i'):null;
    if(it){PAL.idx=parseInt(it.getAttribute('data-i'),10)||0;runPal();}
  });
  ON(PAL.node,'mousemove',function(e){
    var it=e.target.closest?e.target.closest('.pal-i'):null;
    if(!it)return;
    var i=parseInt(it.getAttribute('data-i'),10);
    if(i!==PAL.idx){PAL.idx=i;paintSel();}
  });
}
function highlight(text,q){
  if(!q)return esc(text);
  var out='',i=0,l=text.toLowerCase();
  q.split(/\s+/).filter(Boolean).forEach(function(t){
    var at=l.indexOf(t,i);
    while(at>=0){
      out+=esc(text.slice(i,at))+'<mark>'+esc(text.slice(at,at+t.length))+'</mark>';
      i=at+t.length;at=l.indexOf(t,i);
    }
  });
  return out+esc(text.slice(i));
}
function paintPal(q){
  q=(q||'').trim().toLowerCase();
  var list=QS('.pal-list',PAL.node);
  var all=cmds();
  PAL.items=q?all.filter(function(c){
    return (c.t+' '+c.k+' '+c.g).toLowerCase().indexOf(q)>=0;}):all;
  PAL.idx=0;
  if(!PAL.items.length){
    list.innerHTML='<p class="pal-empty">Aucune commande ne correspond à « '+esc(q)+' ».</p>';
    return;
  }
  var out='',g=null;
  PAL.items.forEach(function(c,i){
    if(c.g!==g){g=c.g;out+='<p class="pal-g lbl">'+esc(g)+'</p>';}
    out+='<button class="pal-i" type="button" role="option" data-i="'+i+'" aria-selected="false">'+
      '<span class="pal-ico">'+esc(c.ico)+'</span>'+
      '<span class="pal-t">'+highlight(c.t,q)+'</span>'+
      '<span class="cmd-k">'+esc(c.k)+'</span></button>';
  });
  list.innerHTML=out;
  paintSel();
}
function paintSel(){
  var items=QSA('.pal-i',PAL.node);
  items.forEach(function(n,i){
    var on=i===PAL.idx;
    n.setAttribute('aria-selected',on?'true':'false');
    if(on&&n.scrollIntoView)n.scrollIntoView({block:'nearest'});
  });
}
function palKeys(e){
  var k=e.key;
  if(k==='ArrowDown'){e.preventDefault();PAL.idx=(PAL.idx+1)%R.max(1,PAL.items.length);paintSel();}
  else if(k==='ArrowUp'){e.preventDefault();PAL.idx=(PAL.idx-1+PAL.items.length)%R.max(1,PAL.items.length);paintSel();}
  else if(k==='Home'){e.preventDefault();PAL.idx=0;paintSel();}
  else if(k==='End'){e.preventDefault();PAL.idx=R.max(0,PAL.items.length-1);paintSel();}
  else if(k==='Enter'){e.preventDefault();runPal();}
  else if(k==='Escape'){e.preventDefault();closePal();}
  else if(k==='Tab'){
    var n=QSA('button,input,[href]',PAL.node).length;
    if(e.shiftKey&&D.activeElement===PAL.node.firstElementChild)PAL.node.lastElementChild.focus();
    else if(!e.shiftKey&&D.activeElement===PAL.node.lastElementChild)PAL.node.firstElementChild.focus();
    e.preventDefault();
    return;
  }
}
function runPal(){
  var c=PAL.items[PAL.idx];if(!c)return;
  closePal();
  setTimeout(function(){try{c.run();}catch(err){toast('Erreur','Commande impossible.', 'err');}},10);
}
function openPal(){
  buildPal();
  PAL.prev=D.activeElement;
  var input=QS('input',PAL.node);
  input.value='';paintPal('');
  PAL.node.className='pal on';
  var sc=D.getElementById('scrim');
  if(sc){sc.hidden=false;requestAnimationFrame(function(){sc.className='on';});}
  input.focus();
}
function closePal(){
  if(!PAL.node)return;
  PAL.node.className='pal';
  var sc=D.getElementById('scrim');
  if(sc){sc.className='';setTimeout(function(){if(!QSA('.mo.on').length)sc.hidden=true;},240);}
  if(PAL.prev&&PAL.prev.focus)PAL.prev.focus();
}
function palOpen(){return PAL.node&&/\bon\b/.test(PAL.node.className);}

function goSec(id){
  var s=D.getElementById(id);if(!s)return;
  var t=s.getAttribute('data-title')||id;
  s.scrollIntoView({behavior:S.motion?'smooth':'auto',block:'start'});
  s.className=s.className.replace(/\bhidden-sec\b/,'').trim();
  s.setAttribute('tabindex','-1');
  try{s.focus({preventScroll:true});}catch(e){}
  toast('Section',t,'' ,1600);
}

/* ═══ 16 — tri de tableau ════════════════════════════════════════════ */
function sortTable(tbl,col,dir){
  var body=QS('tbody',tbl);if(!body)return;
  var rows=QSA('tr',body);
  rows.sort(function(a,b){
    var x=(a.children[col]?a.children[col].getAttribute('data-v'):null),
        y=(b.children[col]?b.children[col].getAttribute('data-v'):null);
    if(x==null)x=a.children[col]?a.children[col].textContent:'';
    if(y==null)y=b.children[col]?b.children[col].textContent:'';
    var xn=parseFloat(String(x).replace(',','.'));
    var yn=parseFloat(String(y).replace(',','.'));
    var res;
    if(!isNaN(xn)&&!isNaN(yn))res=xn-yn;
    else res=String(x).localeCompare(String(y),'fr',{numeric:true});
    return dir==='desc'?-res:res;
  });
  rows.forEach(function(r){body.appendChild(r);});
}
function initSort(){
  QSA('th.sortable').forEach(function(th){
    ON(th,'click',function(){
      var tbl=th.closest('table');if(!tbl)return;
      var col=Array.prototype.indexOf.call(th.parentNode.children,th);
      var cur=th.getAttribute('aria-sort');
      var dir=cur==='ascending'?'descending':'ascending';
      QSA('th',tbl).forEach(function(o){o.removeAttribute('aria-sort');});
      th.setAttribute('aria-sort',dir);
      sortTable(tbl,col,dir);
    });
  });
}

/* ═══ 17 — helpers de rendu ═══════════════════════════════════════════ */
function gl(word,tip){
  return '<span class="gloss-b" data-gloss="'+esc(tip)+'">'+esc(word)+'</span>';
}
function lbl(t){return '<span class="lbl">'+esc(t)+'</span>';}
function kpi(key,label,v,unit,tip,toneCls){
  return '<article class="kpi'+(toneCls?' '+toneCls:'')+'" data-kpi="'+esc(key)+'" '+
    'data-search="'+esc(key+' '+label)+'" data-tip="'+esc(tip)+'" data-tip-title="'+esc(label)+'">'+
    lbl(label)+
    '<p class="kpi-v"><span class="num" data-count="'+esc(v)+'">'+esc(v)+'</span>'+
    (unit?'<small>'+esc(unit)+'</small>':'')+'</p>'+
    '<span class="kpi-ghost" aria-hidden="true">'+esc(String(v).charAt(0))+'</span></article>';
}
function chartBox(title,svg,legend,tip,id){
  return '<figure class="chart rv" data-chart="'+esc(id||'')+'" data-tip="'+esc(tip||title)+'">'+
    '<figcaption class="chart-h"><span class="chart-t">'+esc(title)+'</span></figcaption>'+
    '<div class="chart-body">'+svg+'</div>'+
    (legend?'<div class="chart-lg">'+legend+'</div>':'')+'</figure>';
}
function legendOf(buckets,unit){
  var mx=0;
  (buckets||[]).forEach(function(b){mx=R.max(mx,Number(b.value)||0);});
  if(!mx)mx=1;
  return '<div class="legend">'+buckets.map(function(b){
    var v=Number(b.value)||0,p=clamp(v/mx*100,0,100);
    return '<div class="lg-i" data-search="'+esc(b.label)+'" data-tone="'+esc(b.tone)+'" role="button" tabindex="0" '+
      'data-tip="'+esc(b.label+' : '+(unit?unit+' ':'')+nfmt(v)+' élément(s).')+'" '+
      'style="--sw:var(--'+tone(b.tone)+')">'+
      '<span class="lg-sw"></span><span class="lg-l">'+esc(b.label)+'</span>'+
      '<span class="lg-v">'+nfmt(v)+'</span></div>'+
      '<div class="lg-bar" style="--sw:var(--'+tone(b.tone)+')" aria-hidden="true"><span style="--c:'+p+'"></span></div>';
  }).join('')+'</div>';
}
function tblHead(cols,sortable){
  return '<thead><tr>'+cols.map(function(c){
    return '<th class="'+(c[2]||'')+(sortable?' sortable':'')+'" scope="col" tabindex="'+(sortable?'0':'-1')+'">'+
      esc(c[0])+(sortable?'<span class="arrow">↕</span>':'')+'</th>';
  }).join('')+'</tr></thead>';
}
function tblWrap(head,rows,foot){
  if(!rows.length)return '';
  return '<div class="tw"><table class="tbl">'+head+'<tbody>'+rows.join('')+'</tbody></table></div>'+
    (foot?'<footer class="tbl-foot"><span>'+esc(foot.l||'')+'</span>'+
      '<span class="pager"><button class="btn btn-xs" type="button" data-page="-1">←</button>'+
      esc(foot.r||'')+'<button class="btn btn-xs" type="button" data-page="1">→</button></span></footer>':'');
}
function emptyState(icon,title,hint){
  return '<div class="empty"><span class="empty-i" aria-hidden="true">'+esc(icon)+'</span>'+
    '<p class="empty-t">'+esc(title)+'</p><p class="empty-h">'+esc(hint)+'</p></div>';
}
function accHead(id,title,count,open){
  return '<button class="acc-h" type="button" aria-expanded="'+(open?'true':'false')+'" aria-controls="'+esc(id)+'">'+
    (count!=null?'<span class="acc-c">'+esc(count)+'</span>':'')+
    '<span class="acc-t">'+esc(title)+'</span><span class="acc-sign" aria-hidden="true"></span></button>';
}
function secHead(num,id,title,lead,tip){
  return '<header class="sec-h">'+
    '<span class="sec-num" aria-hidden="true">'+esc(num)+'</span>'+
    '<h2 class="sec-t">'+title+'</h2>'+
    '<p class="sec-lead">'+esc(lead||'')+'</p>'+
    '<span class="sec-acts">'+
    '<button class="btn btn-xs" type="button" data-sec-fold="'+esc(id)+'" aria-expanded="true" '+
    'aria-label="Replier la section '+esc(title)+'">replier</button>'+
    '<button class="btn btn-xs" type="button" data-sec-hide="'+esc(id)+'" aria-pressed="false" '+
    'aria-label="Masquer la section '+esc(title)+'">masquer</button>'+
    '</span></header>';
}

/* ═══ 18 — rendu des sections ══════════════════════════════════════════ */
var TIPS={
  score:'Note globale de sécurité du site, de 0 (très mauvais) à 100 (excellent). C’est un résumé : un score élevé ne veut pas dire qu’il n’y a aucun problème.',
  kpi:'Les chiffres clés en un coup d’œil : combien de scans, de cibles, de problèmes trouvés, de ports ouverts.',
  crit:'Constat critique : une faille sérieuse, à corriger en priorité. Ne l’ignorez pas.',
  high:'Constat important : à traiter rapidement, mais moins grave que le critique.',
  modules:'Chaque case est un module du scanner (un type de test). Le nombre indique ce qu’il a trouvé sur la cible affichée.',
  coverage:'La couverture dit si le module a pu analyser la cible : 0 = rien, 1 = à moitié, 2 = complet. Un module à 0 n’a rien analysé du tout.',
  machine:'L’état de la machine qui fait tourner le scanner : processeur, mémoire, disque, réseau, services. Si le CPU ou la RAM sont saturés, les scans ralentissent.',
  scans:'L’historique des scans : cible analysée, date, score obtenu, ports trouvés, problèmes détectés, durée.',
  findings:'Les problèmes de sécurité, du plus grave au moins grave. Chaque ligne dit ce qu’il faut faire.',
  impact:'La preuve qu’un problème est réellement exploitable, pas juste théorique. C’est la partie qui compte pour un rapport.',
  tools:'Les outils externes utilisés par le scanner (nmap, httpx…), leur état et le nombre d’éléments collectés.',
  surface:'La surface visible depuis l’extérieur : ports, hôtes, enregistrements DNS, certificats, en-têtes HTTP, fichiers récupérés.',
  loot:'Les fichiers qui ont pu être téléchargés depuis la cible. Le nombre entre parenthèses est la taille.',
  live:'Ce qui se passe en ce moment sur le scanner : scans en cours, dernière ligne de journal, durée écoulée.',
  tls:'Le certificat de chiffrement du site. Un certificat expiré ou un vieux protocole (TLS 1.0) dégrade la note.',
  dns:'Les enregistrements DNS du domaine : adresses IP, serveurs de courriel, etc. Un SPF ou DKIM manquant facilite le hameçonnage.',
  headers:'Les en-têtes de sécurité renvoyés par le site. 강화 ihre présence est gratuit et efficace.',
  hosts:'Les sous-domaines et machines trouvés. Chacun est une porte d’entrée possible.',
  banner:'La bannière : le petit texte qu’un service renvoie quand on se connecte. Elle révèle souvent la version du logiciel.',
  verdict:'Le verdict d’impact : PROVABLE = on a vraiment pu l’exploiter, PARTIEL = promising mais pas confirmé, BLOQUÉ = l’attaque a été arrêtée.',
  scoreSeries:'L’évolution de la note de sécurité dans le temps. Si la courbe monte, vous réparez.',
  findingsSeries:'Le nombre de problèmes trouvés scan après scan. Une courbe qui descend est une bonne nouvelle.',
  histo:'La répartition des ports ouverts par tranche (1-1024, 1025-49151…).',
  radar:'Un profil radar des grands domaines de sécurité : réseau, web, certificats, etc. Plus une branche est longue, mieux c’est.',
  gauge:'La jauge de score : de 0 à 100.',
  ring:'Anneau de progression : modules actifs sur modules installés.',
  don:'La répartition des constats par gravité (critique, important, moyen, faible).',
  area:'Les scores dans le temps, en aire. Sert à voir la tendance.',
  hbars:'Les catégories de constats les plus fréquentes.',
  heat:'La densité des constats dans le temps (carte de chaleur).',
  stack:'Les constats empilés par gravité au fil des scans.',
  spark:'La minuscule tendance propre au module.',
  uptime:'Depuis combien de temps la machine tourne sans redémarrer.',
  scanBtn:'Démarrer un nouveau scan sur une cible.'
};
function slot(svg){return svg||'';}

function secHero(d){
  var k=d.kpis||{};
  var crit=Number(k.crit)||0,high=Number(k.high)||0;
  var score=Number(d.score)||0;
  var toneCls=score>=80?'ok':score>=55?'':(crit>0?'crit':'high');
  return '<section class="sec" id="hero" data-num="00" data-title="Hero">'+
    '<div class="hero rv" data-tip="'+esc(TIPS.score)+'" data-tip-title="Score de sécurité">'+
    '<div class="hero-top"><div>'+
    '<p class="hero-eyebrow"><span class="rule"></span><span class="lbl">Rapport d’audit</span></p>'+
    '<h1 class="hero-t">Évaluation <em>de surface</em><span class="br">et d’impact</span></h1>'+
    '<p class="hero-sub">Lecture du dernier scan sur <b>'+esc(d.target||'—')+'</b> — '+
    esc(d.scan_date||'date inconnue')+'. Chaque section est déplaçable, repliable et commentée '+
    'en français simple.</p>'+
    '<div class="hero-tag">'+
    '<span class="chip on"><i class="chip-dot"></i>'+esc(d.db_name||'base locale')+'</span>'+
    '<span class="chip">scan #'+esc(d.current_scan||0)+'</span>'+
    '<span class="chip">généré '+esc(d.generated_at||'—')+'</span>'+
    '<span class="chip'+(crit?' sev-crit':'')+'">'+esc(crit)+' critique'+(crit>1?'s':'')+'</span>'+
    '<span class="chip'+(high?' sev-high':'')+'">'+esc(high)+' important'+(high>1?'s':'')+'</span>'+
    '</div></div>'+
    '<div class="hero-score" data-tip="'+esc(TIPS.score)+'">'+
    '<span class="hero-score-v num" data-count="'+score+'">'+score+'</span>'+
    '<span class="hero-score-u">/ 100</span></div>'+
    '</div>'+
    '<div class="hero-meta">'+
    '<div><b>cible</b><span>'+esc(d.target||'—')+'</span></div>'+
    '<div><b>scans</b><span class="num" data-count="'+esc(k.scans||0)+'">'+esc(k.scans||0)+'</span></div>'+
    '<div><b>cibles distinctes</b><span class="num" data-count="'+esc(k.targets||0)+'">'+esc(k.targets||0)+'</span></div>'+
    '<div><b>problèmes</b><span class="num" data-count="'+esc(k.findings||0)+'">'+esc(k.findings||0)+'</span></div>'+
    '<div><b>base</b><span>'+nfmt(Number(k.db_size_mb)||0)+' Mo</span></div>'+
    '</div></div>'+
    '<div class="grid grid-6">'+
    kpi('scans','Scans',k.scans||0,'','Nombre de scans enregistrés depuis le début.','ok')+
    kpi('targets','Cibles',k.targets||0,'','Combien de machines ou sites différents ont été analysés.')+
    kpi('findings','Constats',k.findings||0,'','Total de problèmes de sécurité actuellement connus.','high')+
    kpi('crit','Critiques',crit,'','Les pires problèmes : à corriger aujourd’hui.','crit')+
    kpi('high','Importants',high,'','Problèmes sérieux mais pas immédiats.','high')+
    kpi('ports','Ports',k.ports||0,'','Nombre de portes ouvertes trouvées sur la cible.')+
    kpi('hosts','Hôtes',k.hosts||0,'','Sous-domaines et machines découverts.')+
    kpi('loot','Fichiers',k.loot||0,'','Fichiers récupérables depuis la cible.')+
    kpi('modules','Modules actifs',(k.modules_active||0)+'/'+(k.modules_total||0),'',
      'Combien de modules du scanner ont tourné sur ce scan, sur combien sont installés.')+
    kpi('purged','Constats purgés',k.findings_purged||0,'','Anciens constats archivés pour alléger la base.','')+
    kpi('db','Taille base',nfmt(Number(k.db_size_mb)||0),'Mo','Poids du fichier de base de données sur le disque.')+
    kpi('up','Uptime',dur((d.machine||{}).uptime_s),'','Depuis combien de temps la machine du scanner tourne sans redémarrer.')+
    '</div>'+
    '<div class="grid grid-side">'+
    chartBox('Score de sécurité',slot(SVG.donut),'','TIPS_DON','don')+
    chartBox('Jauge et anneau','<div class="grid grid-2" style="gap:12px">'+
      '<div>'+slot(SVG.gauge)+'</div><div>'+slot(SVG.ring)+'</div></div>','','TIPS_GAUGE','gauge')+
    '</div></section>';
}

function secPosition(d){
  var m=d.machine||{},k=d.kpis||{};
  return '<section class="sec" id="position" data-num="01" data-title="Position">'+
    secHead('01','position','Position <em>de la cible</em>','Ce que l’on sait de la cible avant même de tester.',
      'Récapitulatif : cible, surface observée, répartition des constats, profil de sécurité.')+
    '<div class="sec-b">'+
    '<div class="grid grid-side">'+
    '<div class="grid grid-2">'+
    chartBox('Score',slot(SVG.gauge),'','TIPS_GAUGE','gauge')+
    chartBox('Modules actifs',slot(SVG.ring),'','TIPS_RING','ring')+
    '</div>'+
    '<div class="grid grid-2">'+
    chartBox('Gravité des constats',slot(SVG.donut),'','TIPS_DON','donut')+
    chartBox('Profil de sécurité',slot(SVG.radar),'','TIPS_RADAR','radar')+
    '</div></div>'+
    '<div class="grid grid-6">'+
    kpi('p-score','Score',d.score||0,'/ 100','TIPS_SCORE',(Number(d.score)>=80?'ok':''))+
    kpi('p-crit','Critiques',k.crit||0,'','TIPS_CRIT','crit')+
    kpi('p-high','Importants',k.high||0,'','TIPS_HIGH','high')+
    kpi('p-ports','Ports ouverts',k.ports||0,'','Nombre de services qui répondent sur la machine.')+
    kpi('p-hosts','Hôtes trouvés',k.hosts||0,'','TIPS_HOSTS')+
    kpi('p-target','Cible',esc(d.target||'—'),'','La machine ou le site analysé en ce moment.')+
    '</div>'+
    '<div class="grid grid-2">'+
    chartBox('Catégories de constats',legendOf(d.categories||[],'constat(s)'),'TIPS_HBARS','cat')+
    chartBox('En-têtes HTTP évalués',legendOf(d.header_eval||[],'test(s)'),'','Évaluation de chaque en-tête de sécurité du site.')+
    '</div>'+
    '<div class="card rv" data-tip="'+esc(TIPS.area)+'">'+
    '<div class="tbl-cap"><h3>Évolution dans le temps</h3>'+lbl('scores & constats')+'</div>'+
    '<div class="grid grid-2">'+
    chartBox('Scores',slot(SVG.area),'','TIPS_AREA','area')+
    chartBox('Constats par scan',slot(SVG.stacked),'','TIPS_STACK','stacked')+
    '</div></div>'+
    '<div class="card rv" data-tip="'+esc(TIPS.heat)+'">'+
    '<div class="tbl-cap"><h3>Densité dans le temps</h3>'+lbl('carte de chaleur')+'</div>'+
    chartBox('Quand les problèmes apparaissent',slot(SVG.heatmap),'','TIPS_HEAT','heatmap')+
    '</div>'+
    '</div></section>';
}

function secModules(d){
  var mods=d.modules||[];
  if(!mods.length)return '<section class="sec" id="modules" data-num="02" data-title="Cartographie">'+
    secHead('02','modules','Cartographie <em>des modules</em>','Aucun module n’a tourné sur ce scan.','')+
    '<div class="sec-b">'+emptyState('◌','Aucun module','Lancez un scan pour peupler cette section.')+'</div></section>';
  var groups={},order=[];
  mods.forEach(function(m){
    var g=m.group||'autre';
    if(!groups[g]){groups[g]=[];order.push(g);}
    groups[g].push(m);
  });
  var html='<section class="sec" id="modules" data-num="02" data-title="Cartographie">'+
    secHead('02','modules','Cartographie <em>des modules</em>',
      mods.length+' module(s) répartis en '+order.length+' groupe(s). Glissez les cartes pour les réordonner.',
      'TIPS_MODULES')+
    '<div class="sec-b">';
  order.forEach(function(g,gi){
    html+='<div class="grid grid-mod">'+
      '<header class="grp-h" style="grid-column:1/-1">'+lbl(g)+' — '+groups[g].length+' module(s)</header>';
    groups[g].forEach(function(m,mi){
      html+='<article class="card mod rv rv-'+clamp(mi+1,1,8)+'" data-mod="'+esc(m.key)+'" data-search="'+esc(m.key+' '+m.label+' '+m.group+' '+m.tool)+'" '+
        'data-tip="'+esc(m.blurb||'')+'" data-tip-title="'+esc(m.label)+'" draggable="true">'+
        '<span class="card-drag" aria-hidden="true"></span>'+
        '<header class="card-h"><h3 class="card-t">'+esc(m.label)+'</h3>'+
        (m.severity_max?sev(m.severity_max):'<span class="sev sev-mute"><i class="dot"></i>aucun</span>')+'</header>'+
        '<p class="card-meta">'+esc(m.key)+' · '+esc(m.group)+' · '+esc(m.tool)+'</p>'+
        '<figure class="card-spark">'+(m.spark&&m.spark.length?slot(SVG.spark):'')+'</figure>'+
        '<p class="card-count"><span class="num" data-count="'+esc(m.count)+'">'+esc(m.count)+'</span>'+
        '<span class="card-unit">élément(s)</span></p>'+
        '<p class="card-blurb">'+esc(m.blurb||'Pas de description.')+'</p>'+
        '<footer class="card-f">'+
        '<div class="cover" data-cover="'+esc(m.coverage||0)+'" role="img" aria-label="Couverture '+
        esc(m.coverage||0)+' sur 2" data-tip="'+esc(TIPS.coverage)+'"><span style="--c:'+
        clamp(Number(m.coverage)||0,0,2)+'"></span></div>'+
        '<button class="btn btn-ghost btn-xs" type="button" data-act="detail" data-mod="'+esc(m.key)+'" '+
        'aria-label="Détail du module '+esc(m.label)+'">détail</button>'+
        '</footer></article>';
    });
    html+='</div>';
  });
  html+='</div></section>';
  return html;
}

function gauge(labelTxt,pct,valText,note,toneCls){
  var w=clamp(Number(pct)||0,0,100);
  return '<div class="gauge" data-search="'+esc(labelTxt)+'"'+
    (note?' data-tip="'+esc(note)+'" data-tip-title="'+esc(labelTxt)+'"':'')+'>'+
    '<div class="gauge-t"><span class="gauge-l">'+esc(labelTxt)+'</span>'+
    '<span class="gauge-v">'+esc(valText)+'</span></div>'+
    '<div class="gauge-b'+(toneCls?' '+toneCls:'')+'"><span style="--w:'+w+'%"></span></div></div>';
}
function secMachines(d){
  var m=d.machine||{};
  var ramTotal=Number(m.ram_total_mb)||0,ramUsed=Number(m.ram_used_mb)||0;
  var ramPct=ramTotal?ramUsed/ramTotal*100:0;
  var cpu=Number(m.cpu_pct)||0;
  var disk=Number(m.disk_used_pct)||0;
  var svc=m.services||[];
  return '<section class="sec" id="machines" data-num="03" data-title="Machines">'+
    secHead('03','machines','Machines <em>de travail</em>','L’état de la machine qui fait tourner le scanner.',
      'TIPS_MACHINE')+
    '<div class="sec-b">'+
    '<div class="mach rv" data-tip="'+esc(TIPS.machine)+'" data-tip-title="Machine">'+
    '<div class="mach-h"><div>'+
    '<p class="mach-host">'+esc(m.host||'hôte inconnu')+'</p>'+
    '<p class="mach-os">'+esc(m.os||'')+' · '+esc(m.cores||0)+' cœurs</p></div>'+
    '<div style="display:flex;gap:6px;flex-wrap:wrap">'+
    '<span class="chip'+(m.scanner_running?' sev-crit on':'')+'"><i class="chip-dot"></i>'+
    (m.scanner_running?'scanner en activité':'scanner inactif')+'</span>'+
    '<span class="chip">'+esc(m.active_scans||0)+' scan(s) actif(s)</span>'+
    '<span class="chip" data-tip="'+esc(TIPS.uptime)+'" data-tip-title="Uptime">uptime '+esc(dur(m.uptime_s))+'</span>'+
    '</div></div>'+
    '<div class="gauges">'+
    gauge('CPU',cpu,nfmt(cpu)+' %','Charge du processeur. Au-dessus de 80 %, les scans ralentissent.',
      cpu>=85?'crit':cpu>=60?'high':'ok')+
    gauge('Mémoire',ramPct,nfmt(ramUsed)+' / '+nfmt(ramTotal)+' Mo',
      'Mémoire vive utilisée. Si elle est pleine, le scanner peut planter.',ramPct>=90?'crit':ramPct>=75?'high':'ok')+
    gauge('Swap',ramTotal?(Number(m.swap_used_mb)||0)/ramTotal*100:0,nfmt(m.swap_used_mb)+' Mo',
      'Mémoire d’échange : le disque utilisé quand la RAM est pleine. Une swap élevée ralentit tout.',
      (Number(m.swap_used_mb)||0)>1024?'high':'ok')+
    gauge('Disque',disk,nfmt(Number(m.disk_total_gb)||0)+' Go / '+nfmt(Number(m.disk_free_gb)||0)+' Go libres',
      'Espace disque utilisé. Un disque plein bloque les écritures de base de données.',
      disk>=90?'crit':disk>=75?'high':'ok')+
    gauge('Réseau ↓',clamp(Number(m.net_rx_mb)||0,0,100)*10,nfmt(Number(m.net_rx_mb)||0)+' Mo',
      'Données téléchargées depuis la cible pendant ce scan.')+
    gauge('Réseau ↑',clamp(Number(m.net_tx_mb)||0,0,100)*10,nfmt(Number(m.net_tx_mb)||0)+' Mo',
      'Données envoyées vers la cible pendant ce scan.')+
    '</div>'+
    (m.load&&m.load.length?'<div class="chart" style="margin-top:15px"><p class="chart-t">Charge moyenne (1/5/15 min)</p>'+
      '<div style="display:flex;align-items:flex-end;gap:4px;height:56px;margin-top:10px">'+
      m.load.slice(-40).map(function(l){
        var h=clamp(Number(l)||0,0,4)/4*100;
        return '<span style="flex:1;min-width:3px;height:'+h+'%;background:var(--accent);opacity:'+
          (0.35+clamp(h/100,0,0.65)).toFixed(2)+';border-radius:1px 1px 0 0" title="'+esc(l)+'"></span>';
      }).join('')+'</div></div>':'')+
    '<div class="svc-list" data-tip="Les services surveillés sur la machine. Un service en échec peut couper le scanner." '+
    'data-tip-title="Services">'+
    (svc.length?svc.map(function(s){
      var st=(s.state||'').toLowerCase();
      var cls=/active|running|ok|true|started/.test(st)?' svc-active':/fail|down|dead|error|inactive/.test(st)?' svc-fail':'';
      return '<span class="svc'+cls+'" data-search="'+esc(s.name+' '+s.state)+'" '+
        'data-tip="'+esc(s.name+' : '+s.state+(s.since?' depuis '+s.since:''))+'">'+esc(s.name)+' <b>'+esc(s.state)+'</b><i></i></span>';
    }).join(''):'<span class="tiny dim">Aucun service surveillé.</span>')+
    '</div></div></div></section>';
}

function secScans(d){
  var scans=d.scans||[];
  var rows=scans.map(function(s){
    var sc=Number(s.score)||0;
    return '<tr data-search="'+esc(s.target+' '+(s.created_at||''))+'">'+
      '<td class="mono-c">#'+esc(s.id)+'</td>'+
      '<td>'+esc(s.target||'—')+'</td>'+
      '<td class="mono-c">'+esc(s.created_at||'—')+'</td>'+
      '<td class="r serif" data-v="'+sc+'"><span class="sev sev-'+(sc>=80?'ok':sc>=50?'med':'crit')+'">'+sc+'</span></td>'+
      '<td class="r" data-v="'+esc(s.ports)+'">'+esc(s.ports)+'</td>'+
      '<td class="r" data-v="'+esc(s.findings)+'">'+(Number(s.findings)?sev('med'):'<span class="sev sev-ok"><i class="dot"></i>0</span>')+'</td>'+
      '<td class="r mono-c" data-v="'+esc(s.duration)+'">'+esc(Number(s.duration||0).toFixed(1))+' s</td></tr>';
  });
  var ss=d.score_series||{};
  return '<section class="sec" id="scans" data-num="04" data-title="Scans">'+
    secHead('04','scans','Historique <em>des scans</em>',scans.length+' scan(s) enregistré(s).',
      'TIPS_SCANS')+
    '<div class="sec-b">'+
    '<div class="grid grid-side">'+
    '<div class="rv"><div class="tbl-cap"><h3>Scores dans le temps</h3>'+lbl('tendance')+'</div>'+
    chartBox('Score par scan',slot(SVG.area),axisLegend(ss.labels),'TIPS_AREA','area')+
    (ss.labels&&ss.labels.length?'<p class="tiny dim" style="margin-top:8px">Premier : '+esc(ss.labels[0])+
      ' · dernier : '+esc(ss.labels[ss.labels.length-1])+'</p>':'')+
    '</div>'+
    '<div class="rv" data-tip="'+esc(TIPS.histo)+'">'+
    '<div class="tbl-cap"><h3>Ports par tranche</h3>'+lbl('distribution')+'</div>'+
    chartBox('Histogramme des ports',slot(SVG.histogram),'','TIPS_HISTO','histogram')+
    legendOf(d.port_histogram||[],'port(s)')+
    '</div></div>'+
    '<div class="rv">'+
    (rows.length?tblWrap(tblHead([['#',''],['cible',''],['date',''],['score','r'],['ports','r'],
      ['constats','r'],['durée','r']],true),rows,{l:rows.length+' scan(s)',r:'1–'+rows.length}):
      emptyState('◷','Aucun scan','Lancez un premier scan pour remplir cet historique.'))+
    '</div></div></section>';
}
function axisLegend(labels){
  if(!labels||!labels.length)return'';
  return labels.slice(-10).map(function(l){return '<i>'+esc(l)+'</i>';}).join('');
}

function secFindings(d){
  var f=d.findings||[];
  var bySev={};
  f.forEach(function(x){var t=tone(x.severity);bySev[t]=(bySev[t]||0)+1;});
  var chips=['crit','high','med','low','info'].filter(function(t){return bySev[t];}).map(function(t){
    return '<button class="chip'+(S.filt===t?' on':'')+'" type="button" data-sev-filt="'+t+'" '+
      'aria-pressed="'+(S.filt===t?'true':'false')+'"><i class="chip-dot" style="background:var(--'+t+')"></i>'+
      esc(t)+' · '+bySev[t]+'</button>';
  }).join('');
  var list=f.filter(function(x){return !S.filt||tone(x.severity)===S.filt;});
  var rows=list.map(function(x,i){
    return '<tr data-search="'+esc(x.title+' '+x.category+' '+x.severity)+'">'+
      '<td class="c mono-c">'+(i+1)+'</td>'+
      '<td>'+sev(x.severity)+'</td>'+
      '<td class="mono-c">'+esc(x.category||'—')+'</td>'+
      '<td class="wrap-c" title="'+esc(x.title)+'">'+esc(x.title||'—')+'</td>'+
      '<td class="wrap-c" title="'+esc(x.recommendation)+'">'+esc(x.recommendation||'—')+'</td>'+
      '<td class="c"><button class="btn btn-xs" type="button" data-finding="'+esc(x.title)+'" '+
      'aria-label="Détail du constat">voir</button></td></tr>';
  });
  return '<section class="sec" id="findings" data-num="05" data-title="Constats">'+
    secHead('05','findings','Les <em>constats</em>',f.length+' constat(s). Filtrez par gravité.',
      'TIPS_FINDINGS')+
    '<div class="sec-b">'+
    '<div class="grid grid-side">'+
    '<div class="rv"><div class="tbl-cap"><h3>Répartition par gravité</h3>'+lbl('donut')+'</div>'+
    chartBox('Gravité',slot(SVG.donut),'','TIPS_DON','donut')+
    '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:12px">'+(chips||
      '<span class="tiny dim">Aucun constat.</span>')+'</div></div>'+
    '<div class="rv"><div class="tbl-cap"><h3>Par catégorie</h3>'+lbl('barres')+'</div>'+
    chartBox('Catégories',slot(SVG.hbars),'','TIPS_HBARS','hbars')+
    legendOf(d.categories||[],'constat(s)')+
    '</div></div>'+
    '<div class="rv">'+
    (rows.length?tblWrap(tblHead([['#','c'],['gravité',''],['catégorie',''],['constat',''],
      ['recommandation',''],['','c']],false),rows,
      {l:list.length+' / '+f.length+' constat(s) affiché(s)',r:S.filt?('filtre : '+S.filt):'tous'}):
      emptyState('◇',S.filt?'Aucun constat pour ce filtre':'Aucun constat',
        S.filt?'Retirez le filtre pour tout revoir.':'Rien à signaler sur ce scan.'))+
    '</div></div></section>';
}

function verdict(v){
  var s=String(v||'').toLowerCase();
  var c=/provable|confirmed|exploitable|preuve|oui|yes/.test(s)?'provable':
    /partial|partiel|pending|candidate/.test(s)?'partial':
    /blocked|bloque|no|none|aucun/.test(s)?'blocked':'none';
  return '<span class="verdict verdict-'+c+'">'+esc(v||'—')+'</span>';
}
function secImpact(d){
  var im=d.impacts||[];
  var rows=im.map(function(x){
    return '<tr data-search="'+esc(x.module+' '+x.verdict+' '+(x.detail||''))+'">'+
      '<td class="mono-c">'+esc(x.module)+'</td>'+
      '<td>'+verdict(x.verdict)+'</td>'+
      '<td class="wrap-c" title="'+esc(x.detail)+'">'+esc(x.detail||'—')+'</td>'+
      '<td class="wrap-c mono-c" title="'+esc(x.evidence)+'">'+esc(x.evidence||'—')+'</td>'+
      '<td class="mono-c">'+esc(x.created_at||'—')+'</td></tr>';
  });
  var provable=im.filter(function(x){
    return /provable|confirmed|exploitable|preuve|oui|yes/i.test(String(x.verdict));}).length;
  return '<section class="sec" id="impact" data-num="06" data-title="Impact">'+
    secHead('06','impact','Preuve <em>d’impact</em>','Ce qui est réellement exploitable, pas seulement théorique.',
      'TIPS_IMPACT')+
    '<div class="sec-b">'+
    '<div class="grid grid-4">'+
    kpi('i-all','Verdicts',im.length,'','TIPS_VERDICT')+
    kpi('i-prov','Prouvables',provable,'','Constats où l’exploitation a été confirmée en vrai.','crit')+
    kpi('i-part','Partiels',im.length-provable,'','Verdicts prometteurs mais non confirmés.','high')+
    kpi('i-rate','Taux',im.length?R.round(provable/im.length*100):0,'%',
      'Part des verdicts qui sont prouvables. Un taux élevé est grave.')+
    '</div>'+
    '<div class="rv">'+
    (rows.length?tblWrap(tblHead([['module',''],['verdict',''],['détail',''],['preuve',''],['date','']],true),
      rows,{l:rows.length+' verdict(s)',r:provable+' prouvable(s)'}):
      emptyState('◎','Aucune preuve','Aucun module n’a encore vérifié l’exploitabilité sur ce scan.'))+
    '</div></div></section>';
}

function secTools(d){
  var t=d.tools||[];
  var rows=t.map(function(x){
    var st=(x.status||'').toLowerCase();
    return '<tr data-search="'+esc(x.name+' '+x.status)+'">'+
      '<td class="mono-c">'+esc(x.name)+'</td>'+
      '<td>'+sev(st||'inconnu')+'</td>'+
      '<td class="r" data-v="'+esc(x.runs)+'">'+esc(x.runs)+'</td>'+
      '<td class="r" data-v="'+esc(x.items)+'">'+esc(x.items)+'</td>'+
      '<td class="r mono-c" data-v="'+esc(x.avg_secs)+'">'+esc(Number(x.avg_secs||0).toFixed(2))+' s</td>'+
      '<td class="c"><div class="cover" style="width:70px" data-tip="Relativité des éléments collectés par cet outil.">'+
      '<span style="--c:'+clamp((Number(x.items)||0),0,2)+'"></span></div></td></tr>';
  });
  var totR=t.reduce(function(a,b){return a+(Number(b.runs)||0);},0);
  var totI=t.reduce(function(a,b){return a+(Number(b.items)||0);},0);
  var avg=t.length?totR?totR/t.length:0:0;
  return '<section class="sec" id="tools" data-num="07" data-title="Outils">'+
    secHead('07','tools','Les <em>outils</em>',t.length+' outil(s) externe(s) mobilisé(s).','TIPS_TOOLS')+
    '<div class="sec-b">'+
    '<div class="grid grid-4">'+
    kpi('t-n','Outils',t.length,'','Combien d’outils externes sont utilisés par le scanner.')+
    kpi('t-runs','Exécutions',totR,'','Combien de fois les outils ont tourné au total.')+
    kpi('t-items','Éléments',totI,'','Total d’informations récupérées par les outils.','ok')+
    kpi('t-avg','Moyenne',nfmt(avg),'s','Durée moyenne d’une exécution d’outil.')+
    '</div>'+
    '<div class="rv">'+
    (rows.length?tblWrap(tblHead([['outil',''],['état',''],['runs','r'],['éléments','r'],['durée moy.','r'],['','c']],true),
      rows,{l:rows.length+' outil(s)',r:totI+' élément(s)'}):
      emptyState('⌘','Aucun outil enregistré','Les outils externes n’ont pas encore tourné.'))+
    '</div></div></section>';
}

function acc(id,title,count,inner,open,tip){
  return '<div class="acc'+(open?' on':'')+'" data-acc="'+esc(id)+'"'+(tip?' data-tip="'+esc(tip)+'"':'')+'>'+
    accHead(id,title,count,open)+'<div class="acc-b" id="'+esc(id)+'">'+inner+'</div></div>';
}
function secSurface(d){
  var ports=d.ports||[],hosts=d.hosts||[],dns=d.dns||[],tls=d.tls||[],hdrs=d.headers||[],loot=d.loot||[];
  var openPorts=ports.filter(function(p){return !/closed|filtered/i.test(p.state||'');}).length;
  var alive=hosts.filter(function(h){return h.alive;}).length;
  var insecureDns=dns.filter(function(x){return !x.secure;}).length;
  var badTls=tls.filter(function(t){return !t.valid||t.tls10||t.tls11;}).length;
  var badHdr=hdrs.filter(function(h){return /missing|absent|fail|ko|non|absent/i.test(h.evaluation||'');}).length;
  var totalBytes=loot.reduce(function(a,b){return a+(Number(b.size_bytes)||0);},0);

  var portRows=ports.map(function(p){
    return '<tr data-search="'+esc(p.port+' '+p.service+' '+p.state+' '+(p.banner||''))+'">'+
      '<td class="r serif" data-v="'+esc(p.port)+'">'+esc(p.port)+'</td>'+
      '<td>'+esc(p.service||'—')+'</td>'+
      '<td>'+sev(p.state||'unknown')+'</td>'+
      '<td class="wrap-c mono-c" title="'+esc(p.banner)+'">'+esc(p.banner||'—')+'</td></tr>';
  });
  var hostRows=hosts.map(function(h){
    return '<tr data-search="'+esc(h.host+' '+(h.ip||'')+' '+(h.title||'')+' '+(h.tech||''))+'">'+
      '<td>'+(h.alive?'<span class="sev sev-ok"><i class="dot"></i>vivant</span>':
        '<span class="sev sev-mute"><i class="dot"></i>inactif</span>')+'</td>'+
      '<td>'+esc(h.host||'—')+'</td>'+
      '<td class="mono-c">'+esc(h.ip||'—')+'</td>'+
      '<td>'+(h.status?esc(h.status):'—')+'</td>'+
      '<td class="wrap-c" title="'+esc(h.title)+'">'+esc(h.title||'—')+'</td>'+
      '<td class="mono-c">'+esc(h.tech||'—')+'</td>'+
      '<td class="mono-c">'+esc(h.server||'—')+'</td></tr>';
  });
  var dnsRows=dns.map(function(x){
    return '<tr data-search="'+esc(x.rtype+' '+x.value)+'">'+
      '<td class="mono-c">'+esc(x.rtype||'—')+'</td>'+
      '<td class="wrap-c mono-c" title="'+esc(x.value)+'">'+esc(x.value||'—')+'</td>'+
      '<td>'+(x.secure?'<span class="sev sev-ok"><i class="dot"></i>sécurisé</span>':
        '<span class="sev sev-high"><i class="dot"></i>à durcir</span>')+'</td></tr>';
  });
  var tlsRows=tls.map(function(t){
    var dr=t.days_remaining;
    return '<tr data-search="'+esc(t.protocol+' '+t.cipher+' '+(t.issuer||''))+'">'+
      '<td class="mono-c">'+esc(t.protocol||'—')+'</td>'+
      '<td class="mono-c">'+esc(t.cipher||'—')+'</td>'+
      '<td class="wrap-c" title="'+esc(t.issuer)+'">'+esc(t.issuer||'—')+'</td>'+
      '<td class="r" data-v="'+esc(dr)+'">'+(dr==null?'—':(dr<0?
        '<span class="sev sev-crit"><i class="dot"></i>expiré</span>':
        '<span class="sev sev-'+(dr<15?'high':dr<30?'med':'ok')+'"><i class="dot"></i>'+esc(dr)+' j</span>'))+'</td>'+
      '<td class="c">'+(t.tls13?'<span class="chip on">1.3</span>':
        '<span class="chip">'+(t.tls12?'1.2':'—')+'</span>')+'</td>'+
      '<td class="c">'+(t.tls10?'<span class="chip sev-crit">1.0</span>':
        '<span class="chip sev-mute">1.0 off</span>')+'</td></tr>';
  });
  var hdrRows=hdrs.map(function(h){
    return '<tr data-search="'+esc(h.name+' '+h.value+' '+h.evaluation)+'">'+
      '<td class="mono-c">'+esc(h.name||'—')+'</td>'+
      '<td class="wrap-c mono-c" title="'+esc(h.value)+'">'+esc(h.value||'—')+'</td>'+
      '<td>'+sev(h.evaluation||'unknown')+'</td></tr>';
  });
  var lootRows=loot.map(function(x){
    return '<tr data-search="'+esc(x.url+' '+(x.content_type||'')+' '+(x.local_path||''))+'">'+
      '<td>'+sev(x.severity||'info')+'</td>'+
      '<td class="wrap-c mono-c" title="'+esc(x.url)+'">'+esc(x.url||'—')+'</td>'+
      '<td class="r" data-v="'+esc(x.size_bytes)+'">'+bytes(x.size_bytes)+'</td>'+
      '<td class="mono-c">'+esc(x.content_type||'—')+'</td>'+
      '<td class="r" data-v="'+esc(x.status)+'">'+esc(x.status||'—')+'</td>'+
      '<td class="wrap-c mono-c" title="'+esc(x.sha256)+'">'+esc(String(x.sha256||'').slice(0,16))+'…</td>'+
      '<td class="mono-c wrap-c" title="'+esc(x.local_path)+'">'+esc(x.local_path||'—')+'</td></tr>';
  });

  return '<section class="sec" id="surface" data-num="08" data-title="Surface">'+
    secHead('08','surface','La <em>surface</em> vue de l’extérieur',
      'Ports, hôtes, DNS, TLS, en-têtes et fichiers récupérés.','TIPS_SURFACE')+
    '<div class="sec-b">'+
    '<div class="grid grid-6">'+
    kpi('s-ports','Ports ouverts',openPorts+'/'+ports.length,'','TIPS_PORTS')+
    kpi('s-hosts','Hôtes vivants',alive+'/'+hosts.length,'','TIPS_HOSTS')+
    kpi('s-dns','DNS à durcir',insecureDns,'/'+dns.length,'TIPS_DNS',insecureDns?'high':'ok')+
    kpi('s-tls','TLS douteux',badTls,'/'+tls.length,'TIPS_TLS',badTls?'crit':'ok')+
    kpi('s-hdr','En-têtes absents',badHdr,'/'+hdrs.length,'TIPS_HEADERS',badHdr?'high':'ok')+
    kpi('s-loot','Fichiers',loot.length,bytes(totalBytes),'TIPS_LOOT')+
    '</div>'+
    '<div class="grid grid-2">'+
    '<div class="rv" data-tip="'+esc(TIPS.histo)+'">'+chartBox('Ports par tranche',
      slot(SVG.histogram),'','TIPS_HISTO','histogram')+legendOf(d.port_histogram||[],'port(s)')+'</div>'+
    '<div class="rv" data-tip="'+esc(TIPS.don)+'">'+chartBox('En-têtes évalués',
      slot(SVG.donut),'','Évaluation de chaque en-tête de sécurité renvoyé par le site.')+
      legendOf(d.header_eval||[],'test(s)')+'</div>'+
    '</div>'+
    acc('acc-ports','Ports détectés',ports.length,
      (portRows.length?tblWrap(tblHead([['port','r'],['service',''],['état',''],['bannière','']],true),
        portRows,{l:ports.length+' port(s)',r:openPorts+' ouvert(s)'}):
        emptyState('⊘','Aucun port','Le scan n’a trouvé aucun port ouvert.')),
      false,'TIPS_PORTS')+
    acc('acc-hosts','Hôtes & sous-domaines',hosts.length,
      (hostRows.length?tblWrap(tblHead([['état',''],['hôte',''],['ip',''],['code',''],
        ['titre',''],['tech',''],['serveur','']],true),hostRows,{l:hosts.length+' hôte(s)',r:alive+' vivant(s)'}):
        emptyState('⊘','Aucun hôte','Aucun sous-domaine découvert.')),
      false,'TIPS_HOSTS')+
    acc('acc-dns','Enregistrements DNS',dns.length,
      (dnsRows.length?tblWrap(tblHead([['type',''],['valeur',''],['durcissement','']],true),
        dnsRows,{l:dns.length+' enregistrement(s)',r:insecureDns+' à durcir'}):
        emptyState('⊘','Aucun enregistrement DNS','Aucune donnée DNS collectée.')),
      false,'TIPS_DNS')+
    acc('acc-tls','Certificats & protocoles TLS',tls.length,
      (tlsRows.length?tblWrap(tblHead([['protocole',''],['chiffrement',''],['émetteur',''],
        ['jours restants','r'],[' moderne','c'],['legacy','c']],true),tlsRows,{l:tls.length+' certificat(s)',r:badTls+' douteux'}):
        emptyState('⊘','Aucun certificat','Le site ne semble pas utiliser HTTPS.')),
      false,'TIPS_TLS')+
    acc('acc-headers','En-têtes de sécurité HTTP',hdrs.length,
      (hdrRows.length?tblWrap(tblHead([['en-tête',''],['valeur',''],['évaluation','']],true),
        hdrRows,{l:hdrs.length+' en-tête(s)',r:badHdr+' absent(s)'}):
        emptyState('⊘','Aucun en-tête','Aucun en-tête HTTP collecté.')),
      false,'TIPS_HEADERS')+
    acc('acc-loot','Fichiers récupérés',loot.length,
      (lootRows.length?tblWrap(tblHead([['gravité',''],['url',''],['taille','r'],['type',''],
        ['http','r'],['sha256',''],['fichier local','']],true),lootRows,
        {l:loot.length+' fichier(s)',r:bytes(totalBytes)}):
        emptyState('⊘','Aucun fichier','Rien n’a pu être téléchargé depuis la cible.')),
      false,'TIPS_LOOT')+
    '</div></section>';
}

// Scans REELLEMENT en cours. `live` conserve l'historique du registre : un scan
// arrete y reste avec state="stopped"/"done". Tester live.length>0 ferait dire
// « scan en cours » pour un processus mort — ce que la section Machines
// contredit (scanner_running=false). On filtre donc sur l'etat.
function liveRunning(list){return (list||[]).filter(function(j){return (j.state||'')==='running';});}

function secLive(d){
  var live=d.live||[],m=d.machine||{};
  var act=liveRunning(live);
  var running=m.scanner_running||act.length>0;
  var items=live.length?live:[{pid:0,target:d.target,profile:'—',started_at:d.scan_date,
    elapsed_s:0,state:m.scanner_running?'running':'idle',last_line:'—',log_path:''}];
  var tl=items.map(function(x){
    var st=(x.state||'').toLowerCase();
    var cls=/run|progress|active/.test(st)?' run':/done|end|finish|ok/.test(st)?' done':'';
    return '<li class="tl'+cls+'" data-search="'+esc(x.target+' '+x.profile+' '+(x.state||''))+'">'+
      '<span class="tl-i" aria-hidden="true"></span><div class="tl-b">'+
      '<span class="tl-name">'+esc(x.profile||'scan')+' · pid '+esc(x.pid||0)+'</span>'+
      '<p class="tl-x">'+esc(x.target||'—')+'</p>'+
      '<p class="tl-meta">'+esc(x.started_at||'')+' · '+esc(dur(x.elapsed_s))+
      ' · '+esc(x.state||'')+(x.log_path?' · <span class="mono">'+esc(x.log_path)+'</span>':'')+'</p>'+
      (x.last_line&&x.last_line!=='—'?'<pre class="logbox" style="margin-top:8px">'+esc(x.last_line)+'</pre>':'')+
      '</div></li>';
  }).join('');
  return '<section class="sec" id="live" data-num="09" data-title="Live">'+
    secHead('09','live','Scans <em>en direct</em>',
      running?'Un scan tourne en ce moment.':'Aucun scan en cours. Rafraîchissement toutes les 3 s.','TIPS_LIVE')+
    '<div class="sec-b">'+
    '<div class="grid grid-4">'+
    kpi('l-state','État',running?'actif':'inactif','',running?'Un scan est en cours.':'Le scanner attend.',running?'high':'ok')+
    kpi('l-cnt','Scans actifs',m.active_scans||0,'','Nombre de scans lancés depuis l’interface.')+
    kpi('l-pid','PID',items[0].pid||0,'','Le numéro de processus du scanner (utilisable pour l’arrêter).')+
    kpi('l-elapsed','Écoulé',dur(items[0].elapsed_s),'','Temps écoulé depuis le lancement du scan.')+
    '</div>'+
    '<div class="card rv" data-tip="'+esc(TIPS.live)+'" data-tip-title="Direct">'+
    '<div class="tbl-cap"><h3>Flux des scans</h3>'+lbl('temps réel')+
    '<button class="btn btn-xs" type="button" data-live-toggle="1" style="margin-left:auto">'+
    (S.liveOn?'couper le direct':'activer le direct')+'</button>'+
    '<button class="btn btn-xs btn-danger" type="button" data-scan-stop="1"'+(running?'':' disabled')+'>arrêter</button>'+
    '</div>'+
    '<ul class="timeline">'+tl+'</ul>'+
    '<div class="prog indet" style="margin-top:14px"'+(running?'':' hidden')+'><span></span></div>'+
    '</div></div></section>';
}

/* ═══ 19 — chrome : topbar, rail, livebar, glossaire ══════════════════ */
function buildChrome(){
  var tb=D.getElementById('topbar');
  if(!tb){
    tb=el('header','topbar');
    tb.id='topbar';
    tb.innerHTML=
      '<button class="btn btn-ico rail-burger" type="button" data-rail-toggle="1" aria-label="Ouvrir la navigation">☰</button>'+
      '<a class="brand" href="#hero"><span class="brand-mark">MCP-Intruder<em>.</em>dash</span>'+
      '<span class="brand-sub">security surface</span></a>'+
      '<div class="search">'+
      '<span class="search-i" aria-hidden="true">⌕</span>'+
      '<input type="search" placeholder="Rechercher partout…" autocomplete="off" spellcheck="false" '+
      'aria-label="Recherche globale sur les tableaux et cartes">'+
      '<span class="search-kbd" aria-hidden="true">/</span>'+
      '<span class="search-count" role="status" aria-live="polite">0 sur 0 résultats</span></div>'+
      '<div class="topbar-sp"></div>'+
      '<span class="tb-live"><i class="pulse" id="tb-pulse"></i><b id="tb-state">inactif</b></span>'+
      '<div class="tb-group">'+
      '<button class="btn btn-ico" type="button" data-pal-open="1" aria-label="Commandes (Ctrl+K)" title="Commandes · Ctrl+K">⌘</button>'+
      '<button class="btn btn-ico" type="button" data-noob-toggle="1" aria-pressed="true" '+
      'aria-label="Mode noob : afficher les explications" title="Mode noob">?</button>'+
      '<button class="btn btn-ico" type="button" data-sheet-open="1" aria-label="Personnaliser la mise en page" '+
      'title="Personnaliser">☰</button>'+
      '<button class="btn btn-xs" type="button" data-scan-open="1" aria-label="Lancer un scan" '+
      'data-tip="'+esc(TIPS.scanBtn)+'" data-tip-title="Nouveau scan">lancer un scan</button>'+
      '</div>';
    D.body.insertBefore(tb,D.body.firstChild);
  }
  var rail=D.getElementById('rail');
  if(!rail){
    rail=el('aside','rail');
    rail.id='rail';
    D.body.insertBefore(rail,tb.nextSibling);
  }
  var lb=D.getElementById('livebar');
  if(!lb){
    lb=el('div','livebar');
    lb.id='livebar';
    lb.setAttribute('role','status');
    lb.setAttribute('aria-live','polite');
    D.body.appendChild(lb);
  }
  var toc=QS('.toc-h');
  if(!toc){toc=el('div','toc-h','<span></span>');D.body.insertBefore(toc,tb);}
  if(!QS('.crumb')){var cr=el('div','crumb');cr.setAttribute('aria-hidden','true');D.body.insertBefore(cr,tb.nextSibling);}
}
function paintRail(){
  var rail=D.getElementById('rail');if(!rail)return;
  var secs=QSA('section.sec');
  rail.innerHTML='<div class="rail-block"><span class="rail-s">Navigation</span></div>'+
    '<nav class="rail-nav" aria-label="Sections du tableau de bord">'+
    secs.map(function(s){
      var id=s.getAttribute('id'),num=s.getAttribute('data-num')||'',t=s.getAttribute('data-title')||id;
      return '<a class="rail-link" href="#'+esc(id)+'" data-sec="'+esc(id)+'">'+
        '<span class="n" aria-hidden="true">'+esc(num)+'</span>'+esc(t)+'</a>';
    }).join('')+'</nav>'+
    '<div class="rail-f">'+
    '<label class="sw"><input type="checkbox" data-pref="noob"'+(S.noob?' checked':'')+'>'+
    '<span class="sw-track"></span><span class="sw-l">mode noob</span></label>'+
    '<label class="sw"><input type="checkbox" data-pref="cursor"'+(S.cursor?' checked':'')+'>'+
    '<span class="sw-track"></span><span class="sw-l">curseur</span></label>'+
    '<p class="rail-meta" id="rail-meta">'+esc((S.data&&S.data.db_name)||'mcp-intruder')+'</p>'+
    '<button class="btn btn-xs" type="button" data-reset="1" style="justify-content:center">réinitialiser</button>'+
    '</div>';
  QSA('.rail-link',rail).forEach(function(a){
    ON(a,'click',function(e){
      e.preventDefault();
      goSec(a.getAttribute('data-sec'));
      rail.className='rail';
    });
  });
  QSA('[data-pref]',rail).forEach(function(cb){
    ON(cb,'change',function(){
      var k=cb.getAttribute('data-pref');
      if(k==='noob')applyNoob(cb.checked);
      if(k==='cursor')applyCursor(cb.checked);
    });
  });
}
function paintLiveBar(){
  var lb=D.getElementById('livebar');if(!lb)return;
  var live=S.live||[],m=(S.data&&S.data.machine)||{};
  var act=liveRunning(live);
  var running=m.scanner_running||act.length>0;
  // On affiche le scan en cours s'il existe, sinon le plus recent de l'historique.
  var x=act[0]||live[0]||{};
  lb.className='livebar'+(running?' show':'');
  lb.innerHTML=
    '<span class="livebar-k"><i class="pulse'+(running?' on':'')+'"></i>'+
    (running?'scan en cours':'au repos')+'</span>'+
    '<span class="livebar-t">'+(running?esc(x.target||(S.data&&S.data.target)||'cible inconnue'):
      'aucun scan actif')+(running?' · '+esc(dur(x.elapsed_s||0)):'')+'</span>'+
    '<span class="livebar-log">'+(running?
      '<b>'+esc(x.profile||'scan')+'</b> · '+esc(x.last_line||'en attente de la première ligne de log…'):
      'Ctrl+K pour les commandes · « / » pour chercher')+'</span>'+
    '<span class="livebar-a">'+
    (running?'<button class="btn btn-xs btn-danger" type="button" data-scan-stop="1">stop</button>':'')+
    '<button class="btn btn-xs" type="button" data-refresh="1">rafraîchir</button>'+
    '<button class="btn btn-xs" type="button" data-live-toggle="1">'+(S.liveOn?'direct ▮▮':'direct ▶')+'</button>'+
    '</span>';
  var p=D.getElementById('tb-pulse'),st=D.getElementById('tb-state');
  if(p)p.className='pulse'+(running?' on':'');
  if(st)st.textContent=running?('live '+esc(dur(x.elapsed_s||0))):'inactif';
}
function openGlossary(){
  var keys=Object.keys(TIPS);
  var body='<p class="tiny dim" style="margin-bottom:14px">Passage de la souris sur un terme '+
    'souligné affiche cette explication. Le mode noob ajoute aussi un point d’interrogation '+
    'sur chaque bloc.</p>'+
    '<dl class="kv">'+keys.map(function(k){
      return '<dt>'+esc(k)+'</dt><dd>'+esc(TIPS[k])+'</dd>';}).join('')+'</dl>';
  openModal('Glossaire — en clair',body,
    '<button class="btn" type="button" data-noob-modal="1">mode noob : '+(S.noob?'désactivé':'activé')+'</button>'+
    '<button class="btn btn-acc" type="button" data-close="1">Fermer</button>');
}

/* ═══ 20 — capture des SVG rendus par le serveur (placeholders) ═══════ */
/* Les SVG arrivent déjà rendus dans #prefill (charts.rs côté serveur).
   On les stocke en mémoire avant de reconstruire la page, puis on les
   réinjecte dans les figures correspondantes. */
var SVG={};
var SLOTS=['donut','gauge','hbars','area','stacked','radar','heatmap','histogram','ring','spark'];
function captureSlots(){
  var pf=D.getElementById('prefill');
  if(!pf)return;
  SLOTS.forEach(function(k){
    var n=pf.querySelector('[data-slot="'+k+'"]');
    if(!n)return;
    var raw=n.innerHTML.trim();
    if(!raw||raw.indexOf('@@SVG_')>=0)return;
    if(raw.charAt(0)!=='<')raw='<div>'+raw+'</div>';
    SVG[k]=raw;
  });
  /* sparklines par module : data-slot="spark" data-mod="clé" */
  QSA('[data-slot="spark"][data-mod]',pf).forEach(function(n){
    var key=n.getAttribute('data-mod'),raw=n.innerHTML.trim();
    if(!raw||raw.charAt(0)!=='<')return;
    SPARK[key]=raw;
  });
}
var SPARK={};
function sparkFor(key){return SPARK[key]||SVG.spark||'';}

/* ═══ 21 — résolution des tips « TIPS_XXX » ═══════════════════════════ */
function tipOf(v){
  if(!v)return'';
  if(v.charAt(0)==='T'){
    var k=v.slice(5).toLowerCase();
    var map={module:'modules',machine:'machine',scan:'scans',scanbtn:'scanbtn',
      histo:'histo',radar:'radar',don:'don',donut:'don',area:'area',heat:'heat',
      hbars:'hbars',stack:'stack',spark:'spark',ring:'ring',gauge:'gauge'};
    var key=map[k]||k;
    return TIPS[key]||'';
  }
  return v;
}
function resolveTips(root){
  QSA('[data-tip]',root||D).forEach(function(n){
    var v=n.getAttribute('data-tip');
    if(v&&v.charAt(0)==='T'){
      var t=tipOf(v);
      if(t)n.setAttribute('data-tip',t);
      else n.removeAttribute('data-tip');
    }
  });
}

/* ═══ 22 — rendu complet ═════════════════════════════════════════════ */
function bootSkeleton(){
  var b=D.getElementById('boot');if(!b)return;
  var bars=function(n){return Array.apply(null,Array(n||5)).map(function(){
    return '<span class="skl-l" style="width:'+(40+R.round(R.random()*55))+'%"></span>';}).join('');};
  b.innerHTML='<div class="hero" style="padding-top:10px;padding-bottom:30px">'+
    '<div class="skl-l" style="width:120px;height:10px"></div>'+
    '<div class="skl-l" style="width:min(560px,80%);height:44px;margin:16px 0 12px"></div>'+
    '<div class="skl-l" style="width:min(420px,64%);height:12px"></div>'+
    '<div style="display:flex;gap:10px;margin-top:20px"><span class="skl-l" style="width:90px"></span>'+
    '<span class="skl-l" style="width:110px"></span><span class="skl-l" style="width:70px"></span></div></div>'+
    '<div class="grid grid-6">'+bars(6).replace(/<span class="skl-l"/g,
      '<div class="skl-b">').replace(/<\/span>/g,'</div>')+'</div>'+
    '<div class="grid grid-side" style="margin-top:16px">'+
    '<div class="skl-b" style="min-height:260px"><span class="spin spin-lg" style="margin:40px auto"></span></div>'+
    '<div class="skl-b" style="min-height:260px">'+bars(6)+'</div></div>'+
    '<p class="tiny dim" style="margin-top:18px;text-align:center">Chargement de /api/overview…</p>';
}
/* ─────────────────────────────────────────────────── mode application ── */
/* Un onglet = un <section> masqué sauf celui qui est actif. On ne démonte
   jamais le DOM : les onglets déjà visités gardent leur état (tri, filtres,
   scroll), ce qu'un re-render complet à chaque poll détruirait. */
function pane(d,key,html){
  return '<section class="pane" data-pane="'+key+'"'+(S.tab===key?'':' hidden')+'>'+html+'</section>';
}

/* Barre d'onglets. Rôle tablist ARIA + flèches gauche/droite. */
function paintTabs(){
  var host=QS('.tabs');
  /* Le libelle du bandeau est ecrit ICI : paintTabs s'execute a chaque
     changement d'onglet et a chaque rafraichissement, c'est donc le seul
     point ou l'affichage est garanti coherent avec l'onglet surligne. */
  if(!host){
    var lab0=QS('[data-tablabel]');
    if(lab0)lab0.textContent=(TABS.filter(function(t){return t.key===S.tab;})[0]||{}).label||'';
    return;
  }
  host.innerHTML=TABS.map(function(t){
    var n=t.key==='findings'?(d_findings_count()):t.key==='impact'?(d_impact_count()):t.key==='live'?(liveRunning().length||0):0;
    var badge=n>0?'<b class="tab-n">'+esc(n)+'</b>':'';
    return '<button class="tab'+(S.tab===t.key?' on':'')+'" role="tab" data-tab="'+t.key+'"'+
      ' aria-selected="'+(S.tab===t.key)+'" title="'+esc(t.tip||'')+'">'+
      esc(t.label)+badge+'</button>';
  }).join('');
  var lab=QS('[data-tablabel]');
  if(lab)lab.textContent=(TABS.filter(function(t){return t.key===S.tab;})[0]||{}).label||'';
}

function d_findings_count(){return ((S.data&&S.data.findings)||[]).length;}
function d_impact_count(){return ((S.data&&S.data.impacts)||[]).length;}

/* Compteurs pour la barre d'onglets, sans toucher au DOM des sections. */
function refreshTabBadges(){
  var host=QS('.tabs');if(!host)return;
  QSA('.tab',host).forEach(function(b){
    var k=b.getAttribute('data-tab'),n=0;
    if(k==='findings')n=d_findings_count();
    else if(k==='impact')n=d_impact_count();
    else if(k==='live')n=liveRunning().length;
    var old=QS('.tab-n',b);
    if(n>0){if(!old){old=el('b','tab-n');b.appendChild(old);}old.textContent=n;}
    else if(old)old.remove();
  });
}

/* Bascule d'onglet : masque le pane actif, affiche le nouveau. */
function setTab(k){
  if(!TABS.some(function(t){return t.key===k;}))k='findings';
  S.tab=k;ST.set(K.tab,k);
  QSA('.pane').forEach(function(p){
    p.hidden=p.getAttribute('data-pane')!==k;
  });
  paintTabs();
  var p=QS('.pane[data-pane="'+k+'"]');
  if(p){p.classList.remove('in');R.requestAnimationFrame(function(){p.classList.add('in');});}
  /* Le libelle d'onglet dans la barre de statut est ecrit ici, localement et
     immediatement. Compter sur paintStatus introduisait un retard d'un cycle :
     le bandeau affichait le nom de l'onglet precedent jusqu'au polling suivant. */
  var lbl=(TABS.filter(function(t){return t.key===k;})[0]||{}).label||'';
  var node=QS('[data-tablabel]');
  if(node)node.textContent=lbl;
  var wrap=QS('[data-tablabel-wrap]');
  if(wrap)wrap.setAttribute('data-active',k);
  if(S.data) paintStatus(S.data);
  /* paintStatus reecrit le bandeau : on reapplique le libelle s'il l'a perdu. */
  var n2=QS('[data-tablabel]');
  if(n2)n2.textContent=lbl;
  refreshTabBadges();
}

/* ── barre de statut (bas d'ecran) : hero + position + modules + machine
   + outils, en lecture seule. C'est ICI que vit l'information que le
   dashboard affichait en sections pleine page. ───────────────────────────── */
function statusbarInner(d){
  return '<div class="sb-items">'+
    '<div class="sb-group" data-tip="'+esc(TIPS.target)+'"><span class="sb-k">cible</span>'+
      '<span class="sb-v">'+esc(d.target||'—')+'</span></div>'+
    '<div class="sb-group" data-tablabel-wrap><span class="sb-k">onglet</span>'+
      '<span class="sb-v" data-tablabel>'+esc((TABS.filter(function(t){return t.key===S.tab;})[0]||{}).label||'')+'</span></div>'+
    '<div class="sb-group" data-tip="'+esc(TIPS.modules)+'"><span class="sb-k">modules</span>'+
      '<span class="sb-v">'+esc(d.kpis.modules_active)+' / '+esc(d.kpis.modules_total)+'</span></div>'+
    sbGauge('score',(d.score||0),100,''+esc(d.score||0),d.score>=70?'ok':d.score>=40?'med':'crit')+
    sbGauge('constats',(d.kpis.findings||0),Math.max(1,(d.kpis.findings||0)),
      nfmt(d.kpis.findings),d.kpis.crit>0?'crit':d.kpis.high>0?'high':'med')+
    sbGauge('cpu',(d.machine&&d.machine.cpu_pct)||0,100,
      Math.round((d.machine&&d.machine.cpu_pct)||0)+' %',cpuTone((d.machine&&d.machine.cpu_pct)||0))+
    sbGauge('ram',(d.machine&&d.machine.ram_used_mb)||0,(d.machine&&d.machine.ram_total_mb)||1,
      nfmt(d.machine&&d.machine.ram_used_mb)+' Mo',(d.machine&&(d.machine.ram_used_mb/(d.machine.ram_total_mb||1))>0.85)?'high':'ok')+
    '<div class="sb-group" data-tip="'+esc(TIPS.machine)+'"><span class="sb-k">hote</span>'+
      '<span class="sb-v">'+esc((d.machine&&d.machine.host)||'—')+'</span></div>'+
    '<div class="sb-group" data-tip="'+esc(TIPS.scans)+'"><span class="sb-k">scans</span>'+
      '<span class="sb-v">'+esc(d.kpis.scans)+'</span></div>'+
    '<div class="sb-group" data-tip="'+esc(TIPS.tools)+'"><span class="sb-k">outils</span>'+
      '<span class="sb-v">'+esc(((d.tools||[]).length))+'</span></div>'+
    '<div class="sb-group sb-grow"></div>'+
    '<div class="sb-group sb-live" data-tip="'+esc(TIPS.live)+'">'+
      '<i class="pulse'+(liveRunning().length?' on':'')+'"></i>'+
      '<span class="sb-v">'+esc(liveRunning().length?liveRunning().length+' actif(s)':'au repos')+'</span></div>'+
    '</div>';
}

function cpuTone(v){return v>=85?'crit':v>=60?'med':'ok';}

/* Petit widget barre + valeur pour la barre de statut. */
function sbGauge(k,v,max,txt,tone){
  var pct=max>0?clamp(Math.round(v/max*100),0,100):0;
  return '<div class="sb-group sb-gauge" data-k="'+esc(k)+'">'+
    '<span class="sb-k">'+esc(k)+'</span>'+
    '<span class="sb-bar"><i class="'+tone+'" style="width:'+pct+'%"></i></span>'+
    '<span class="sb-v">'+txt+'</span></div>';
}

/* Mise a jour de la barre de statut sans re-rendre les panes. */
/* Monte la barre de statut comme enfant DIRECT du body, juste apres la zone
   de vue. Etre dans .dash la ferait defiler avec le contenu ; etre dans le body
   lui donne la ligne `status` de la grille d'application. */
function mountStatusBar(d){
  var bar=QS('.statusbar');
  if(!bar){
    bar=el('footer','statusbar');
    bar.setAttribute('role','contentinfo');
    var view=D.getElementById('view');
    if(view&&view.parentNode) view.parentNode.insertBefore(bar,view.nextSibling);
    else D.body.appendChild(bar);
  }
  bar.innerHTML=statusbarInner(d);
  resolveTips(bar);rebuildTips();
}
function paintStatus(d){
  var bar=QS('.statusbar');
  if(!bar||!d)return;
  /* Remplacement du contenu seul : on garde l'element pour ne pas perdre sa
     place dans la grille (un replaceWith le recreerait au meme endroit, mais
     resterait fragile si l'ordre du DOM changeait). */
  bar.innerHTML=statusbarInner(d);
  resolveTips(bar);rebuildTips();
}

/* Les 5 onglets, dans l'ordre de la barre. `tip` alimente le tooltip. */
var TABS=[
  {key:'findings',label:'Constats',tip:'Les problemes de securite trouves, filtres par gravite.'},
  {key:'surface', label:'Surface',  tip:'Ports, hotes, DNS, TLS, en-tetes et fichiers recuperes.'},
  {key:'scans',   label:'Scans',    tip:'L historique des scans et l evolution des scores.'},
  {key:'impact',  label:'Impact',   tip:'Ce qui est reellement exploitable, pas seulement theorique.'},
  {key:'live',    label:'Live',     tip:'Les scans en cours et leurs logs.'}
];

/* ══════════════════════════════ chrome applicatif ══════════════════════════ */
/* Branchement du header, des onglets et du statut au DOM. */
function initAppChrome(){
  /* onglets : delegation d'evenement (les boutons sont re-crees a chaque paint) */
  D.addEventListener('click',function(e){
    var t=e.target.closest?e.target.closest('.tab'):null;
    if(t&&t.hasAttribute('data-tab')){setTab(t.getAttribute('data-tab'));return;}
  });

  /* boutons du header */
  var bs=function(id){return D.getElementById(id);};
  var on=function(id,fn){var n=bs(id); if(n) n.addEventListener('click',fn);};
  on('btn-search',function(){var s=QS('.search-open'); if(s){s.focus();s.select();}});
  on('btn-cmd',function(){openPal('');});
  on('btn-noob',function(){applyNoob(!S.noob); paintNoob(); toast('Mode noob',S.noob?'Explications affichees':'Explications masquees');});
  on('btn-refresh',function(){load(true);});
  on('btn-scan',function(){openScan();});

  /* horloge dans la barre d'onglets */
  var tickClock=function(){
    var c=bs('clock'); if(!c)return;
    try{c.textContent=new Date().toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});}catch(e){}
  };
  tickClock(); setInterval(tickClock,1000);

  /* raccourcis globaux */
  D.addEventListener('keydown',function(e){
    if(e.target&&/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName))return;
    /* Ctrl+1..5 : aller a l'onglet N */
    if((e.ctrlKey||e.metaKey)&&e.key>='1'&&e.key<='5'){
      var i=Number(e.key)-1; if(TABS[i]){e.preventDefault();setTab(TABS[i].key);}
      return;
    }
    /* fleches dans la barre d'onglets : navigation clavier */
    if((e.key==='ArrowRight'||e.key==='ArrowLeft')&&D.activeElement&&D.activeElement.classList.contains('tab')){
      e.preventDefault();
      var idx=TABS.findIndex(function(t){return t.key===S.tab;});
      idx=e.key==='ArrowRight'?(idx+1)%TABS.length:(idx-1+TABS.length)%TABS.length;
      setTab(TABS[idx].key);
      var nb=QS('.tab.on'); if(nb)nb.focus();
    }
  });

  /* au premier rendu, applique l'onglet memorise */
  setTab(S.tab);
}

function paintNoob(){
  var n=D.getElementById('btn-noob');
  if(n)n.classList.toggle('on',!!S.noob);
}

/* Titre de l'app = cible courante + n° de scan. */
function paintAppTitle(d){
  var n=D.getElementById('apptitle'); if(!n||!d)return;
  n.textContent=(d.target||'—')+'  ·  scan #'+d.current_scan+'  ·  score '+(d.score||0)+'/100';
}

function render(d){
  var host=QS('.dash');
  if(!host){
    host=el('main','dash');
    host.id='dash';
    host.setAttribute('data-mode','app');
    host.setAttribute('data-order','findings,surface,scans,impact,live');
    /* En mode application le body est une GRILLE (header / onglets / vue /
       statut) : un enfant pose a la racine deviendrait un sixieme item et
       casserait la mise en page. On insere donc dans #view, puis dans le
       placeholder statique, et seulement en dernier recours sur le body. */
    var view=D.getElementById('view');
    if(view){view.appendChild(host);}
    else{
      var pf=D.getElementById('prefill');
      if(pf)pf.parentNode.insertBefore(host,pf.nextSibling);
      else D.body.appendChild(host);
    }
  }
  S.data=d;
  S.live=d.live||[];
  /* Mode application : UNE seule vue a la fois (l'onglet actif), plus la
     barre d'onglets et la barre de statut du bas. Plus de defilement continu
     a travers dix sections. */
  /* Le host ne porte QUE les vues. La barre de statut est un enfant direct du
     body (voir mountStatusBar) : c'est ce qui lui donne sa ligne dans la
     grille au lieu de defiler avec la vue. */
  host.innerHTML='<div class="panes">'+pane(d,'findings',secFindings(d))+
    pane(d,'surface',secSurface(d))+pane(d,'scans',secScans(d))+
    pane(d,'impact',secImpact(d))+pane(d,'live',secLive(d))+'</div>';
  mountStatusBar(d);
  paintTabs();
  paintStatus(d);
  paintAppTitle(d);
  /* les sparklines propres à chaque module */
  QSA('[data-mod]',host).forEach(function(card){
    if(!card.className||card.className.indexOf('card mod')<0)return;
    var key=card.getAttribute('data-mod'),fig=QS('.card-spark',card);
    if(fig&&!fig.innerHTML.trim()){
      var s=sparkFor(key);
      if(s)fig.innerHTML=s;
    }
  });
  resolveTips(host);
  rebuildTips();
  animateCounters(host);
  anchorCharts(host);
  stagger(host);
  initReveal();
  initSort();
  initDnD();
  initAcc();
  initModDnd();
  paintRail();
  paintLiveBar();
  applyLayout();
  if(S.search)runSearch(S.search);
  if(QS('.crumb')){
    var c=QS('.crumb');
    c.style.top='calc(var(--top) + 12px)';
  }
  D.body.className=D.body.className.replace(/\bloading\b/,'').trim();
  if(!D.body.className)D.body.className='ready';
}
function initAcc(){
  QSA('.acc-h').forEach(function(h){
    if(h.getAttribute('data-bound')==='1')return;
    h.setAttribute('data-bound','1');
    ON(h,'click',function(){
      var a=h.parentNode,on=a.className.indexOf(' on')>=0;
      a.className=on?'acc':'acc on';
      h.setAttribute('aria-expanded',on?'false':'true');
    });
  });
}
function initModDnd(){
  QSA('.card.mod').forEach(function(c){
    if(c.getAttribute('data-drag-bound')==='1')return;
    c.setAttribute('data-drag-bound','1');
    var drag=null;
    ON(c,'dragstart',function(e){
      drag=c;c.className+=' dragging';
      try{e.dataTransfer.effectAllowed='move';e.dataTransfer.setData('text/plain',c.getAttribute('data-mod'));}catch(err){}
    });
    ON(c,'dragend',function(){
      if(drag)drag.className=drag.className.replace(/\bdragging\b/,'').trim();
      drag=null;saveLayout();
    });
    ON(c,'dragover',function(e){if(drag&&drag!==c)e.preventDefault();});
    ON(c,'drop',function(e){
      if(!drag||drag===c)return;
      e.preventDefault();
      var r=c.getBoundingClientRect();
      if((e.clientX-r.left)>r.width/2)c.parentNode.insertBefore(drag,c.nextElementSibling);
      else c.parentNode.insertBefore(drag,c);
      drag.className=drag.className.replace(/\bdragging\b/,'').trim();
      drag=null;saveLayout();
    });
  });
}

/* ═══ 23 — chargement des données ════════════════════════════════════ */
function load(silent){
  if(S.busy&&silent)return Promise.resolve();
  S.busy=true;
  if(!silent){
    D.body.classList.add('loading');
    bootSkeleton();
  }
  return fetch('/api/overview',{headers:{'Accept':'application/json'},cache:'no-store'})
    .then(function(r){
      if(!r.ok)throw new Error('HTTP '+r.status);
      return r.json();
    })
    .then(function(d){
      S.lastGood=d;
      render(d);
      startLive();
      return d;
    })
    .catch(function(err){
      if(S.lastGood){render(S.lastGood);if(!silent)toast('Réseau','Données de secours affichées.','err');}
      else{
        D.body.className=D.body.className.replace(/\bloading\b/,'').trim();
        var b=D.getElementById('boot');
        if(b)b.innerHTML='<div class="empty"><span class="empty-i">⚠</span>'+
          '<p class="empty-t">Impossible de charger les données</p>'+
          '<p class="empty-h">L’API /api/overview n’a pas répondu ('+esc(err.message)+').</p>'+
          '<button class="btn btn-acc" type="button" data-refresh="1">Réessayer</button></div>';
        if(!silent)toast('Erreur','Chargement impossible : '+err.message,'err',7000);
      }
      return null;
    })
    .then(function(d){S.busy=false;return d;});
}

/* ═══ 24 — direct : polling /api/stream toutes les 3 s ════════════════ */
var LIVE_TIMER=null;
function startLive(){
  if(!S.liveOn||LIVE_TIMER)return;
  poll();
  LIVE_TIMER=setInterval(poll,3000);
}
function stopLive(){
  if(LIVE_TIMER){clearInterval(LIVE_TIMER);LIVE_TIMER=null;}
}
function toggleLive(){
  S.liveOn=!S.liveOn;
  if(S.liveOn){
    toast('Direct','Flux activé — rafraîchissement toutes les 3 secondes.','ok');
    startLive();
  }else{
    stopLive();
    toast('Direct','Flux suspendu.','');
  }
  paintLiveBar();
  var sec=QS('#live');
  if(sec&&S.data){
    var b=QS('.card',sec);
    if(b){
      var t=QS('[data-live-toggle]',b);
      if(t)t.textContent=S.liveOn?'couper le direct':'activer le direct';
    }
  }
}
function poll(){
  if(!S.liveOn||document.hidden)return;
  fetch('/api/stream',{headers:{'Accept':'application/json'},cache:'no-store'})
    .then(function(r){return r.ok?r.json():null;})
    .then(function(j){
      if(!j)return;
      if(j.live)S.live=j.live;
      if(j.machine&&S.data)S.data.machine=j.machine;
      if(j.kpis&&S.data)S.data.kpis=j.kpis;
      paintLiveBar();
      var sec=QS('#live');
      if(sec&&S.data){
        var old=QS('.timeline',sec);
        if(old){
          var fresh=el('div');
          fresh.innerHTML=secLive(S.data);
          var nt=QS('.timeline',fresh);
          if(nt)old.parentNode.replaceChild(nt,old);
          var kp=QSA('#live .kpi-v .num');
          kp.forEach(function(n){n.removeAttribute('data-done');});
          animateCounters(sec);
        }
      }
      var hb=QS('#hero .hero-score-v');
      if(hb&&j.score!=null)setCounter(hb,j.score);
    })
    .catch(function(){/* le direct ne doit jamais spammer de toasts */});
}

/* ═══ 25 — scan : lancement / arrêt / export ══════════════════════════ */
function post(url,body){
  return fetch(url,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},
    body:body?JSON.stringify(body):undefined})
    .then(function(r){
      if(!r.ok)throw new Error('HTTP '+r.status);
      return r.json().catch(function(){return {};});
    });
}
function openScanModal(){
  var target=S.data&&S.data.target?S.data.target:'';
  var profiles=['quick','standard','deep'];
  var body='<form id="scan-form"><dl class="kv">'+
    '<dt>cible</dt><dd><input id="scan-target" name="target" type="text" value="'+esc(target)+'" '+
    'style="width:100%;height:36px;padding:0 10px;background:var(--void);border:1px solid var(--line);'+
    'border-radius:var(--r);font-family:var(--mono);font-size:12px" required aria-label="Cible à scanner"></dd>'+
    '<dt>profil</dt><dd><div style="display:flex;gap:6px;flex-wrap:wrap">'+
    profiles.map(function(p,i){
      return '<button class="chip'+(i===1?' on':'')+'" type="button" data-profile="'+p+'">'+esc(p)+'</button>';
    }).join('')+'</div><p class="tiny dim" style="margin-top:7px">quick = rapide · standard = équilibré · '+
    'deep = exhaustif (long).</p></dd></dl></form>'+
    '<p class="tiny dim" style="margin-top:16px">Un POST est envoyé sur <span class="mono">/api/scan/start</span>. '+
    'Un seul scan tourne à la fois.</p>';
  openModal('Lancer un scan',body,
    '<button class="btn" type="button" data-close="1">Annuler</button>'+
    '<button class="btn btn-acc" type="button" id="scan-go">Démarrer</button>');
  var chosen='standard';
  QSA('[data-profile]',MO.node).forEach(function(b){
    ON(b,'click',function(){
      chosen=b.getAttribute('data-profile');
      QSA('[data-profile]',MO.node).forEach(function(x){x.className='chip';});
      b.className='chip on';
    });
  });
  ON(QS('#scan-go',MO.node),'click',function(){
    var t=QS('#scan-target',MO.node);
    var v=t?t.value.trim():'';
    if(!v){toast('Scan','Indiquez une cible.','err');return;}
    this.disabled=true;
    this.textContent='Démarrage…';
    post('/api/scan/start',{target:v,profile:chosen})
      .then(function(){closeModal();toast('Scan','Scan « '+v+' » ('+chosen+') lancé.','ok');
        S.liveOn=true;startLive();poll();})
      .catch(function(e){toast('Scan','Démarrage impossible : '+e.message,'err',7000);
        this.disabled=false;this.textContent='Démarrer';});
  });
}
function stopScan(){
  var x=(S.live&&S.live[0])||{};
  if(!confirm('Arrêter le scan sur '+(x.target||'la cible')+' ?'))return;
  post('/api/scan/stop',{pid:x.pid||0})
    .then(function(){toast('Scan','Signal d’arrêt envoyé.','ok');setTimeout(function(){load(true);poll();},900);})
    .catch(function(e){toast('Scan','Arrêt impossible : '+e.message,'err');});
}
function exportJSON(){
  if(!S.data){toast('Export','Aucune donnée à exporter.','err');return;}
  var blob=new Blob([JSON.stringify(S.data,null,2)],{type:'application/json'});
  var a=el('a');
  a.href=URL.createObjectURL(blob);
  a.download='mcp-intruder-overview-'+(new Date()).toISOString().slice(0,10)+'.json';
  D.body.appendChild(a);a.click();
  setTimeout(function(){URL.revokeObjectURL(a.href);if(a.parentNode)a.parentNode.removeChild(a);},600);
  toast('Export','JSON téléchargé.','ok');
}

/* ═══ 26 — délégation d’événements globale ═══════════════════════════ */
function wire(){
  D.addEventListener('click',function(e){
    var t=e.target;
    /* ripple */
    var b=t.closest?t.closest('.btn,.card,.chip,.opt,.rail-link,.lg-i,.acc-h'):null;
    if(b&&S.motion&&!t.closest('.ripple')){
      var r=b.getBoundingClientRect(),d=R.max(r.width,r.height)*2;
      var s=el('i','ripple');
      s.style.width=s.style.height=d+'px';
      s.style.left=((e.clientX||r.left+r.width/2)-r.left-d/2)+'px';
      s.style.top=((e.clientY||r.top+r.height/2)-r.top-d/2)+'px';
      b.appendChild(s);
      setTimeout(function(){if(s.parentNode)s.parentNode.removeChild(s);},640);
    }
    var hit=t.closest?t.closest('[data-sec-fold],[data-sec-hide],[data-sec-nav],[data-pal-open],'+
      '[data-sheet-open],[data-noob-toggle],[data-rail-toggle],[data-refresh],[data-reset],'+
      '[data-live-toggle],[data-scan-stop],[data-scan-open],[data-sev-filt],[data-act],'+
      '[data-finding],[data-close],[data-noob-modal],[data-pref]'):null;
    if(!hit)return;
    if(hit.hasAttribute('data-sec-fold')){var s1=hit.closest('section.sec');if(s1)toggleFold(s1);return;}
    if(hit.hasAttribute('data-sec-hide')){var s2=hit.closest('section.sec');if(s2)toggleHide(s2);return;}
    if(hit.hasAttribute('data-sec-nav')){goSec(hit.getAttribute('data-sec-nav'));return;}
    if(hit.hasAttribute('data-pal-open')){openPal();return;}
    if(hit.hasAttribute('data-sheet-open')){toggleSheet();return;}
    if(hit.hasAttribute('data-noob-toggle')){applyNoob(!S.noob);
      var nb=QS('[data-noob-toggle]');
      if(nb)nb.setAttribute('aria-pressed',S.noob?'true':'false');
      paintRail();return;}
    if(hit.hasAttribute('data-rail-toggle')){
      var rail=D.getElementById('rail');if(rail)rail.className='rail on';return;}
    if(hit.hasAttribute('data-refresh')){load(true);return;}
    if(hit.hasAttribute('data-reset')){resetLayout();return;}
    if(hit.hasAttribute('data-live-toggle')){toggleLive();return;}
    if(hit.hasAttribute('data-scan-stop')){stopScan();return;}
    if(hit.hasAttribute('data-scan-open')){openScanModal();return;}
    if(hit.hasAttribute('data-sev-filt')){
      var f=hit.getAttribute('data-sev-filt');
      S.filt=S.filt===f?'':f;
      if(S.data){var fs=QS('#findings');
        if(fs){
          var tmp=el('div');tmp.innerHTML=secFindings(S.data);
          var nb2=QS('.sec-b',tmp);var ob=QS('.sec-b',fs);
          if(nb2&&ob)ob.parentNode.replaceChild(nb2,ob);
          resolveTips(fs);rebuildTips();animateCounters(fs);initSort();initReveal();
        }}
      return;
    }
    if(hit.getAttribute('data-act')==='detail'){openModDetail(hit.getAttribute('data-mod'));return;}
    if(hit.hasAttribute('data-finding')){openFinding(hit.getAttribute('data-finding'));return;}
    if(hit.hasAttribute('data-noob-modal')){applyNoob(!S.noob);closeModal();
      setTimeout(openGlossary,120);return;}
    if(hit.hasAttribute('data-close')){closeModal();return;}
  });
  D.addEventListener('change',function(e){
    var cb=e.target;
    if(!cb||!cb.hasAttribute)return;
    var k=cb.getAttribute('data-pref');
    if(k==='noob'){applyNoob(cb.checked);
      var nb=QS('[data-noob-toggle]');if(nb)nb.setAttribute('aria-pressed',S.noob?'true':'false');}
    if(k==='motion')applyMotion(cb.checked);
    if(k==='cursor')applyCursor(cb.checked);
  });
  D.addEventListener('keydown',function(e){
    var tag=(e.target&&e.target.tagName||'').toLowerCase();
    var typing=tag==='input'||tag==='textarea'||tag==='select'||e.target.isContentEditable;
    if((e.ctrlKey||e.metaKey)&&(e.key==='k'||e.key==='K')){
      e.preventDefault();palOpen()?closePal():openPal();return;
    }
    if(e.key==='/'&&!typing){
      e.preventDefault();var si=QS('.search input');if(si)si.focus();return;
    }
    if(e.key==='Escape'){
      if(palOpen()){closePal();return;}
      if(MO.node&&/\bon\b/.test(MO.node.className)){closeModal();return;}
      var sh=QS('.sheet');
      if(sh&&/\bon\b/.test(sh.className)){sh.className='sheet';return;}
      var rl=D.getElementById('rail');
      if(rl&&/\bon\b/.test(rl.className)){rl.className='rail';return;}
      return;
    }
    if(typing)return;
    if(e.key==='r'||e.key==='R'){load(true);return;}
    if(e.key==='n'||e.key==='N'){applyNoob(!S.noob);return;}
    if(e.key==='l'||e.key==='L'){toggleLive();return;}
    if(e.key>='1'&&e.key<='9'){
      var secs=QSA('section.sec');
      var ix=parseInt(e.key,10)-1;
      if(secs[ix])goSec(secs[ix].getAttribute('id'));
    }
  });
  ON(D,'visibilitychange',function(){if(!document.hidden&&S.liveOn)poll();});
  ON(W,'beforeunload',saveLayout);
  ON(D.getElementById('scrim'),'click',function(){
    closePal();closeModal();
    var sh=QS('.sheet');if(sh)sh.className='sheet';
  });
  /* tri au clavier */
  D.addEventListener('keydown',function(e){
    if((e.key==='Enter'||e.key===' ')&&e.target.classList&&e.target.classList.contains('sortable')){
      e.preventDefault();e.target.click();
    }
  });
}
function openModDetail(key){
  var m=(S.data&&S.data.modules||[]).filter(function(x){return x.key===key;})[0];
  if(!m){toast('Module','Aucune fiche pour « '+key+' ».','err');return;}
  var spark=m.spark||[];
  var body='<dl class="kv">'+
    '<dt>clé</dt><dd class="mono-v">'+esc(m.key)+'</dd>'+
    '<dt>libellé</dt><dd>'+esc(m.label)+'</dd>'+
    '<dt>groupe</dt><dd>'+esc(m.group)+'</dd>'+
    '<dt>outil</dt><dd class="mono-v">'+esc(m.tool)+'</dd>'+
    '<dt>éléments</dt><dd>'+esc(m.count)+'</dd>'+
    '<dt>gravité max</dt><dd>'+(m.severity_max?sev(m.severity_max):'—')+'</dd>'+
    '<dt>couverture</dt><dd>'+esc(m.coverage)+' / 2 — '+
    (m.coverage===2?'complet':m.coverage===1?'partiel':'aucune donnée')+'</dd>'+
    '<dt>tendance</dt><dd>'+(spark.length?'<span class="mono-v">'+esc(spark.join(' · '))+'</span>':'—')+'</dd>'+
    '<dt>explication</dt><dd>'+esc(m.blurb||'—')+'</dd>'+
    '</dl>'+(spark.length?'<div style="margin-top:14px">'+sparkFor(key)+'</div>':'');
  openModal('Module · '+m.label,body,
    '<button class="btn" type="button" data-sec-jump="modules">voir la carte</button>'+
    '<button class="btn btn-acc" type="button" data-close="1">Fermer</button>');
}
function openFinding(title){
  var f=(S.data&&S.data.findings||[]).filter(function(x){return x.title===title;})[0];
  if(!f)return;
  openModal('Constat · '+title,
    '<dl class="kv"><dt>gravité</dt><dd>'+sev(f.severity)+'</dd>'+
    '<dt>catégorie</dt><dd>'+esc(f.category||'—')+'</dd>'+
    '<dt>constat</dt><dd>'+esc(f.title)+'</dd>'+
    '<dt>recommandation</dt><dd>'+esc(f.recommendation||'—')+'</dd></dl>'+
    '<p class="tiny dim" style="margin-top:16px">Ce que ça veut dire : '+
    esc(tipOf(TIPS[f.category])||'Ce constat est décrit tel quel dans le tableau.')+
    ' Cliquez sur la ligne du constat pour revenir ici.</p>',
    '<button class="btn btn-acc" type="button" data-close="1">Fermer</button>');
}

/* ═══ 27 — démarrage ═════════════════════════════════════════════════ */
/* Une etape d'initialisation qui echoue ne doit pas tuer l'application :
   on la signale et on continue. Le probleme est visible (bandeau console)
   sans empecher le chargement des donnees. */
function safe(name,fn){
  try{ return fn(); }
  catch(e){
    var msg=(e&&e.message)||String(e);
    D.body.setAttribute('data-init-error',name+' : '+msg);
    var box=D.getElementById('toasts');
    if(box){ var t=el('div','toast bad'); t.textContent='Module « '+name+' » indisponible : '+msg; box.appendChild(t); }
    return null;
  }
}

function start(){
  /* La classe `app` porte la grille d'application : on ne l'ecrase JAMAIS,
     meme pendant le chargement. */
  D.body.classList.add('app');

  safe('initAppChrome',initAppChrome);
  safe('loadPref',loadPref);
  safe('captureSlots',captureSlots);
  safe('buildChrome',buildChrome);
  safe('wire',wire);
  safe('initTips',initTips);
  safe('initGloss',initGloss);
  safe('initSearch',initSearch);
  safe('initCursor',initCursor);
  safe('initParallax',initParallax);
  safe('initScroll',initScroll);

  D.body.classList.add('loading');
  bootSkeleton();

  load().then(function(){
    safe('initParallax',initParallax);
    var pr=QS('#prefill');
    if(pr&&pr.parentNode)pr.parentNode.removeChild(pr);
    D.body.classList.remove('loading','boot');
    D.body.classList.add('ready');
    safe('startLive',startLive);
  }).catch(function(e){
    D.body.classList.remove('loading','boot');
    var box=D.getElementById('toasts');
    if(box){ var t=el('div','toast bad'); t.textContent='Chargement impossible : '+(e&&e.message||e); box.appendChild(t); }
  });

  W.__mcp-intruder={state:S,load:load,refresh:function(){return load(true);},search:runSearch,
    palette:openPal,layout:toggleSheet,reset:resetLayout,exportJSON:exportJSON};
}
if(D.readyState==='loading')ON(D,'DOMContentLoaded',start);else start();
})();
"##;
