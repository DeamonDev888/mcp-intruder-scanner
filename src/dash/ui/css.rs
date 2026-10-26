// src/dash/ui/css.rs — Design system CSS du tableau de bord (extrait de ui.rs v0.5.8).

// ───────────────────────────────────── design system ────────────────────────

pub const CSS: &str = r##"

/* ═══════════════════════════════════════════════════════════════════════
   MODE APPLICATION — chrome d'une application, pas d'une page web.
   Tokens Hermes en priorite, Ermitage en repli.
   ═══════════════════════════════════════════════════════════════════════ */
:root{
  --app-bg:       var(--background, #0d0a07);
  --app-fg:       var(--foreground, #ece5d8);
  --app-muted:    var(--muted-foreground, #948d7c);
  --app-accent:   var(--accent, #d9a24e);
  --app-border:   var(--border, rgba(236,229,216,.12));
  --app-card:     var(--card, #16120d);
  --tabbar-h: 40px;
  --status-h: 34px;
}

/* Le corps devient une grille d'application : header / onglets / vue / statut.
   Aucun defilement global : seule la vue Defile. */
body.app{
  height:100dvh; margin:0; padding:0;
  display:grid;
  grid-template-rows:auto auto minmax(0,1fr) auto;
  grid-template-areas:"head" "tabs" "view" "status";
  overflow:hidden;
  background:var(--app-bg); color:var(--app-fg);
  font-family:var(--font-sans, "Switzer", Inter, system-ui, -apple-system, "Segoe UI", sans-serif);
  font-size:14px; line-height:1.5;
}

/* — header : une seule ligne, titre + actions — */
.app-head{
  grid-area:head;
  display:flex; align-items:center; gap:.75rem;
  height:44px; padding:0 1rem;
  background:var(--app-card);
  border-bottom:1px solid var(--app-border);
  min-width:0;
}
.app-brand{
  font-family:var(--font-display, "Zodiak", Georgia, serif);
  font-size:1.05rem; letter-spacing:-.02em; white-space:nowrap;
}
.app-brand i{font-style:normal; color:var(--app-accent);}
.app-title{
  font-family:var(--font-mono, "Fragment Mono", ui-monospace, monospace);
  font-size:.68rem; letter-spacing:.06em; color:var(--app-muted);
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  flex:1 1 auto; min-width:0;
}
.app-actions{display:flex; align-items:center; gap:.35rem; flex:0 0 auto;}
.app-btn{
  display:inline-flex; align-items:center; justify-content:center; gap:.35rem;
  height:28px; padding:0 .6rem;
  background:transparent; color:var(--app-muted);
  border:1px solid var(--app-border); border-radius:6px;
  font-family:var(--font-mono, monospace); font-size:.68rem; letter-spacing:.04em;
  cursor:pointer; transition:color .12s, border-color .12s, background .12s;
  white-space:nowrap;
}
.app-btn:hover{color:var(--app-fg); border-color:var(--app-accent);}
.app-btn:focus-visible{outline:2px solid var(--app-accent); outline-offset:1px;}
.app-btn.primary{color:#1a1509; background:var(--app-accent); border-color:var(--app-accent);}
.app-btn.primary:hover{filter:brightness(1.08);}
.app-btn.icon{width:28px; padding:0;}

/* — barre d'onglets — */
.tabbar{
  grid-area:tabs;
  display:flex; align-items:stretch; justify-content:space-between;
  height:var(--tabbar-h);
  background:var(--app-card);
  border-bottom:1px solid var(--app-border);
  min-width:0;
}
.tabs{display:flex; align-items:stretch; overflow-x:auto; scrollbar-width:none;}
.tabs::-webkit-scrollbar{display:none;}
.tab{
  position:relative;
  display:inline-flex; align-items:center; gap:.4rem;
  padding:0 .95rem; height:100%;
  background:transparent; color:var(--app-muted);
  border:0; border-right:1px solid var(--app-border);
  font-family:var(--font-mono, monospace); font-size:.74rem; letter-spacing:.03em;
  cursor:pointer; white-space:nowrap;
  transition:color .12s, background .12s;
}
.tab:hover{color:var(--app-fg); background:color-mix(in srgb, var(--app-fg) 4%, transparent);}
.tab.on{color:var(--app-fg); background:color-mix(in srgb, var(--app-accent) 10%, transparent);}
/* le marqueur d'onglet actif : un trait ambre en bas, comme un vrai editor */
.tab.on::after{
  content:""; position:absolute; left:0; right:0; bottom:0; height:2px;
  background:var(--app-accent);
}
.tab:focus-visible{outline:2px solid var(--app-accent); outline-offset:-2px;}
.tab-n{
  min-width:1.15em; padding:0 .3em;
  background:color-mix(in srgb, var(--app-fg) 10%, transparent);
  border-radius:9px; font-size:.66rem; font-weight:400; text-align:center;
}
.tab.on .tab-n{background:var(--app-accent); color:#1a1509;}
.tabbar-right{display:flex; align-items:center; gap:.6rem; padding:0 .75rem; flex:0 0 auto;}
.clock{font-family:var(--font-mono, monospace); font-size:.68rem; color:var(--app-muted);}

/* — zone de vue : SEULE zone qui Defile — */
.app-view{
  grid-area:view;
  overflow-y:auto; overflow-x:hidden;
  min-height:0; min-width:0;
  scroll-behavior:smooth;
}
.pane{padding:1.25rem 1.5rem 2rem;}
.pane[hidden]{display:none;}
.pane.in{animation:paneIn .22s cubic-bezier(.16,1,.3,1) both;}
@keyframes paneIn{from{opacity:0; transform:translateY(6px);} to{opacity:1; transform:none;}}
/* a l'interieur d'un onglet, une grille d'application sobre */
.pane .dash{display:grid; gap:1.1rem;}
.pane h2{font-family:var(--font-display, Georgia, serif); font-size:1.15rem; font-weight:400; letter-spacing:-.01em;}
.pane .sec{border:0; padding:0; margin:0;}
.pane .sec-b{padding:0;}

/* — barre de statut — */
.statusbar{
  grid-area:status;
  display:block; min-height:var(--status-h);
  padding:0;
  background:var(--app-card);
  border-top:1px solid var(--app-border);
  font-family:var(--font-mono, monospace); font-size:.68rem;
  color:var(--app-muted);
}
.sb-items{overflow-x:auto; scrollbar-width:none; padding:0 .85rem;}
.statusbar::-webkit-scrollbar{display:none;}
.sb-items{display:flex; align-items:center; gap:.9rem; height:var(--status-h); white-space:nowrap;}
.sb-group{display:inline-flex; align-items:center; gap:.35rem; white-space:nowrap;}
.sb-grow{flex:1 1 auto;}
.sb-k{color:var(--app-muted); opacity:.75; text-transform:uppercase; letter-spacing:.1em; font-size:.62rem;}
.sb-v{color:var(--app-fg);}
.sb-gauge{gap:.4rem;}
.sb-bar{width:44px; height:3px; background:color-mix(in srgb, var(--app-fg) 12%, transparent); border-radius:2px; overflow:hidden;}
.sb-bar i{display:block; height:100%; background:var(--app-accent); transition:width .3s cubic-bezier(.16,1,.3,1);}
.sb-bar i.ok{background:#8fae7d;} .sb-bar i.med{background:#c8b48a;}
.sb-bar i.high{background:var(--app-accent);} .sb-bar i.crit{background:#e0654f;}
.sb-live{margin-left:auto;}

/* — mode etroit : barre d'onglets defilante, statut reduit — */
@media (max-width:900px){
  .statusbar .sb-hide-sm{display:none;}
  .pane{padding:1rem .9rem 1.5rem;}
  .app-title{display:none;}
}

/* Respect strict des preferences systeme : plus aucune animation. */
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms !important; transition-duration:.001ms !important;}
  .app-view{scroll-behavior:auto;}
}

/* 00 — tokens ------------------------------------------------------------ */
:root{
  --void:#0d0a07; --surface:#16120d; --surface-2:#1d1811; --surface-3:#241e15;
  --paper:#ece5d8; --muted:#948d7c; --dim:#6b6455;
  --accent:#d9a24e; --accent-soft:rgba(217,162,78,.14); --accent-line:rgba(217,162,78,.38);
  --line:rgba(236,229,216,.12); --line-2:rgba(236,229,216,.06); --line-3:rgba(236,229,216,.20);
  --crit:#e0564b; --high:#d9883c; --med:#d9a24e; --low:#8ea87c; --info:#7f95b8; --ok:#77b58a; --mute:#7b7568;
  --t:cubic-bezier(.16,1,.3,1); --t-fast:cubic-bezier(.16,1,.3,1);
  --d:520ms; --d-s:220ms; --d-l:900ms;
  --serif:'Zodiak','Iowan Old Style','Georgia','Times New Roman',serif;
  --sans:'Inter','Switzer','-apple-system','Segoe UI',system-ui,sans-serif;
  --mono:'JetBrains Mono','IBM Plex Mono','SFMono-Regular','Consolas',monospace;
  --font:var(--sans);
  --rail:266px; --top:58px; --pad:clamp(16px,3.2vw,44px);
  --r:2px; --r-l:4px;
  --sh:0 1px 0 rgba(236,229,216,.04),0 18px 48px -24px rgba(0,0,0,.9);
  --focus:0 0 0 1px var(--void),0 0 0 3px var(--accent);
}
/* 00b — thèmes ----------------------------------------------------------- */
html[data-theme="amber"]{
  --void:#120c05; --surface:#1c140a; --surface-2:#241a0d; --surface-3:#2d2110;
  --accent:#e8b05c; --accent-soft:rgba(232,176,92,.15); --accent-line:rgba(232,176,92,.42);
  --paper:#f0e7d5; --muted:#9d947f;
}
html[data-theme="term"]{
  --void:#060a07; --surface:#0b130e; --surface-2:#101b14; --surface-3:#15251b;
  --paper:#d7e6d6; --muted:#7e9184; --accent:#7ee08a; --accent-soft:rgba(126,224,138,.12);
  --accent-line:rgba(126,224,138,.38); --crit:#e2645a; --high:#d3a53f; --med:#8fc97a; --low:#6fa8b8;
  --info:#79a2bd; --ok:#7ee08a; --mute:#67766b; --line:rgba(215,230,214,.12);
  --line-2:rgba(215,230,214,.06); --line-3:rgba(215,230,214,.2);
}
/* 00c — choix de police -------------------------------------------------- */
html[data-font="serif"]{--font:var(--serif)}
html[data-font="sans"]{--font:var(--sans)}
html[data-font="mono"]{--font:var(--mono)}

/* 01 — reset ------------------------------------------------------------- */
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{
  margin:0;background:var(--void);color:var(--paper);font-family:var(--font);
  font-size:15px;line-height:1.55;font-feature-settings:"kern" 1,"liga" 1;
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
  overflow-x:hidden;min-height:100vh;
}
body::before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(1100px 620px at 76% -8%,rgba(217,162,78,.07),transparent 62%),
    radial-gradient(760px 520px at 4% 104%,rgba(217,162,78,.045),transparent 60%),
    linear-gradient(180deg,rgba(236,229,216,.028),transparent 42%);
}
h1,h2,h3,h4{font-family:var(--serif);font-weight:400;letter-spacing:-.015em;margin:0;line-height:1.1}
p{margin:0}
button,input,select,textarea{font:inherit;color:inherit}
button{background:none;border:0;cursor:pointer}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline;text-underline-offset:3px}
table{border-collapse:collapse;width:100%}
ul,ol{margin:0;padding:0;list-style:none}
svg{display:block;max-width:100%}
figure{margin:0}
:focus-visible{outline:none;box-shadow:var(--focus);border-radius:var(--r)}
::selection{background:var(--accent-soft);color:var(--paper)}
:focus:not(:focus-visible){outline:none}
.skip{
  position:fixed;left:12px;top:-64px;z-index:400;background:var(--accent);color:#1a1206;
  padding:10px 16px;border-radius:var(--r);font:600 12px/1 var(--mono);letter-spacing:.1em;
  text-transform:uppercase;transition:top var(--d-s) var(--t);
}
.skip:focus{top:12px;text-decoration:none}

/* 02 — grain + scrollbar ------------------------------------------------- */
.grain{
  position:fixed;inset:-50%;z-index:9998;pointer-events:none;opacity:.035;
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='180' height='180'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='.82' numOctaves='4' stitchTiles='stitch'/><feColorMatrix type='saturate' values='0'/></filter><rect width='180' height='180' filter='url(%23n)'/></svg>");
  animation:grainShift 7.2s steps(6) infinite;
}
@keyframes grainShift{
  0%{transform:translate(0,0)}20%{transform:translate(-3%,2%)}40%{transform:translate(2%,-3%)}
  60%{transform:translate(-2%,-2%)}80%{transform:translate(3%,1%)}100%{transform:translate(0,0)}
}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:var(--void)}
::-webkit-scrollbar-thumb{background:var(--line-3);border:3px solid var(--void);border-radius:9px}
::-webkit-scrollbar-thumb:hover{background:var(--accent-line)}

/* 03 — typo utilitaire --------------------------------------------------- */
.lbl,.mono,.kpi-h,.grp-h,.sec-num,.livebar-k,.cmd-k,.tl-name,.tbl th,.chip,.field-l,.rail-s{
  font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;
}
.mono{color:var(--muted);letter-spacing:.1em}
.ital{font-family:var(--serif);font-style:italic;letter-spacing:0;text-transform:none;font-size:1.02em}
.dim{color:var(--muted)}
.tiny{font-size:11.5px;line-height:1.45}
.num{font-family:var(--serif);font-variant-numeric:tabular-nums lining-nums}

/* 04 — topbar ------------------------------------------------------------ */
.topbar{
  position:fixed;top:0;left:0;right:0;height:var(--top);z-index:120;
  display:flex;align-items:center;gap:14px;padding:0 var(--pad);
  background:color-mix(in srgb,var(--void) 84%,transparent);
  backdrop-filter:blur(18px) saturate(1.3);-webkit-backdrop-filter:blur(18px) saturate(1.3);
  border-bottom:1px solid var(--line);
}
.brand{display:flex;align-items:baseline;gap:9px;white-space:nowrap;flex:0 0 auto}
.brand-mark{font-family:var(--serif);font-size:17px;letter-spacing:.01em}
.brand-mark em{font-style:italic;color:var(--accent)}
.brand-sub{font-family:var(--mono);font-size:9.5px;letter-spacing:.22em;text-transform:uppercase;color:var(--dim)}
.topbar-sp{flex:1 1 auto}
.search{position:relative;flex:0 1 380px;min-width:150px}
.search input{
  width:100%;height:34px;padding:0 74px 0 32px;background:var(--surface);
  border:1px solid var(--line);border-radius:var(--r);color:var(--paper);
  font-family:var(--mono);font-size:11.5px;letter-spacing:.04em;transition:border-color var(--d-s) var(--t),background var(--d-s) var(--t);
}
.search input::placeholder{color:var(--dim);letter-spacing:.1em;text-transform:uppercase;font-size:10px}
.search input:focus{border-color:var(--accent-line);background:var(--surface-2);outline:none;box-shadow:none}
.search-i{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--dim);font-family:var(--mono);font-size:11px;pointer-events:none}
.search-kbd{
  position:absolute;right:8px;top:50%;transform:translateY(-50%);pointer-events:none;
  font-family:var(--mono);font-size:9.5px;letter-spacing:.1em;color:var(--dim);
  border:1px solid var(--line);border-radius:var(--r);padding:2px 5px;background:var(--surface-2);
}
.search-count{
  position:absolute;right:8px;top:calc(100% + 6px);z-index:5;display:none;
  font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--accent);
  background:var(--surface-2);border:1px solid var(--accent-line);border-radius:var(--r);padding:4px 8px;white-space:nowrap;
}
.search.on .search-count{display:block}
.tb-group{display:flex;align-items:center;gap:6px;flex:0 0 auto}
.tb-live{
  display:flex;align-items:center;gap:7px;font-family:var(--mono);font-size:9.5px;
  letter-spacing:.16em;text-transform:uppercase;color:var(--muted);
  padding:5px 10px;border:1px solid var(--line);border-radius:999px;
}
.tb-live b{color:var(--paper);font-weight:500}
.pulse{width:6px;height:6px;border-radius:50%;background:var(--mute);flex:0 0 auto}
.pulse.on{background:var(--crit);animation:pulse 1.5s var(--t) infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(224,86,75,.55)}70%{box-shadow:0 0 0 8px rgba(224,86,75,0)}100%{box-shadow:0 0 0 0 rgba(224,86,75,0)}}

/* 05 — boutons ----------------------------------------------------------- */
.btn{
  position:relative;overflow:hidden;display:inline-flex;align-items:center;gap:7px;
  height:34px;padding:0 14px;border:1px solid var(--line);border-radius:var(--r);
  background:var(--surface);color:var(--paper);
  font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;
  transition:border-color var(--d-s) var(--t),background var(--d-s) var(--t),color var(--d-s) var(--t),transform var(--d-s) var(--t);
}
.btn:hover{border-color:var(--accent-line);background:var(--surface-2);color:var(--paper)}
.btn:active{transform:translateY(1px)}
.btn[aria-pressed="true"],.btn.on{background:var(--accent-soft);border-color:var(--accent-line);color:var(--accent)}
.btn-ico{width:34px;padding:0;justify-content:center;font-size:13px;letter-spacing:0}
.btn-xs{height:26px;padding:0 10px;font-size:9.5px;letter-spacing:.12em}
.btn-acc{background:var(--accent);color:#1a1206;border-color:var(--accent);font-weight:600}
.btn-acc:hover{background:color-mix(in srgb,var(--accent) 86%,var(--paper));color:#1a1206}
.btn-danger{border-color:rgba(224,86,75,.4);color:var(--crit)}
.btn-danger:hover{background:rgba(224,86,75,.12);border-color:var(--crit)}
.btn:disabled{opacity:.4;pointer-events:none}
.ripple{position:absolute;border-radius:50%;transform:scale(0);background:currentColor;opacity:.28;pointer-events:none;animation:rip .62s var(--t) forwards}
@keyframes rip{to{transform:scale(2.6);opacity:0}}

/* 06 — switch / toggle --------------------------------------------------- */
.sw{position:relative;display:inline-flex;align-items:center;gap:9px;cursor:pointer;user-select:none}
.sw input{position:absolute;opacity:0;width:0;height:0}
.sw-track{width:34px;height:18px;border-radius:999px;background:var(--surface-3);border:1px solid var(--line);position:relative;transition:background var(--d-s) var(--t),border-color var(--d-s) var(--t);flex:0 0 auto}
.sw-track::after{content:"";position:absolute;top:2px;left:2px;width:12px;height:12px;border-radius:50%;background:var(--muted);transition:transform var(--d) var(--t),background var(--d-s) var(--t)}
.sw input:checked+.sw-track{background:var(--accent-soft);border-color:var(--accent-line)}
.sw input:checked+.sw-track::after{transform:translateX(16px);background:var(--accent)}
.sw input:focus-visible+.sw-track{box-shadow:var(--focus)}
.sw-l{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.sw input:checked~.sw-l{color:var(--paper)}

/* 07 — sidebar / rail ---------------------------------------------------- */
.rail{
  position:fixed;top:var(--top);left:0;bottom:0;width:var(--rail);z-index:110;
  display:flex;flex-direction:column;gap:20px;padding:22px 0 18px;
  background:linear-gradient(180deg,var(--surface),var(--void));
  border-right:1px solid var(--line);overflow-y:auto;overscroll-behavior:contain;
}
.rail-block{padding:0 20px}
.rail-s{display:block;color:var(--dim);margin-bottom:9px;padding-bottom:7px;border-bottom:1px solid var(--line-2)}
.rail-nav{display:flex;flex-direction:column;gap:1px}
.rail-link{
  display:flex;align-items:center;gap:10px;padding:7px 20px;color:var(--muted);
  font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;
  border-left:2px solid transparent;transition:color var(--d-s) var(--t),background var(--d-s) var(--t),border-color var(--d-s) var(--t);
}
.rail-link span.n{color:var(--dim);font-size:9px;width:16px;flex:0 0 auto}
.rail-link:hover{color:var(--paper);background:var(--surface-2);text-decoration:none}
.rail-link[aria-current="true"]{color:var(--accent);border-left-color:var(--accent);background:var(--accent-soft)}
.rail-link[aria-current="true"] span.n{color:var(--accent)}
.rail-f{margin-top:auto;display:flex;flex-direction:column;gap:8px;padding:0 20px}
.rail-meta{font-family:var(--mono);font-size:9.5px;letter-spacing:.1em;color:var(--dim);line-height:1.7}
.rail-burger{display:none}

/* 08 — layout principal -------------------------------------------------- */
.dash{position:relative;z-index:1;margin-left:var(--rail);padding:calc(var(--top) + 34px) var(--pad) 120px;max-width:1720px}
.wrap{width:100%}
.grid{display:grid;gap:16px}
.grid-2{grid-template-columns:repeat(2,minmax(0,1fr))}
.grid-3{grid-template-columns:repeat(3,minmax(0,1fr))}
.grid-4{grid-template-columns:repeat(4,minmax(0,1fr))}
.grid-6{grid-template-columns:repeat(6,minmax(0,1fr))}
.grid-8{grid-template-columns:repeat(8,minmax(0,1fr))}
.grid-mod{grid-template-columns:repeat(auto-fill,minmax(292px,1fr))}
.grid-side{grid-template-columns:minmax(0,1.6fr) minmax(0,1fr)}
.grid-side-r{grid-template-columns:minmax(0,1fr) minmax(0,1.6fr)}
.span-2{grid-column:span 2}
.span-3{grid-column:span 3}
.span-4{grid-column:span 4}
.span-6{grid-column:span 6}

/* 09 — sections ---------------------------------------------------------- */
.sec{position:relative;margin:0 0 clamp(38px,5vw,74px);scroll-margin-top:calc(var(--top) + 18px)}
.sec[hidden]{display:none}
.sec-h{
  display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;
  padding:0 0 14px;margin-bottom:20px;border-bottom:1px solid var(--line);cursor:grab;
}
.sec-h:active{cursor:grabbing}
.sec-num{color:var(--accent);flex:0 0 auto;font-size:10px}
.sec-t{font-size:clamp(20px,2.5vw,31px);flex:0 1 auto}
.sec-t em{font-style:italic;color:var(--accent)}
.sec-lead{color:var(--muted);font-size:12.5px;flex:1 1 240px;min-width:0}
.sec-acts{display:flex;gap:5px;opacity:.35;transition:opacity var(--d-s) var(--t)}
.sec:hover .sec-acts,.sec:focus-within .sec-acts{opacity:1}
.sec-b{display:grid;gap:16px}
.sec.folded .sec-b{display:none}
.sec.folded .sec-h{border-bottom-style:dashed}
.sec.dragging{opacity:.4}
.sec.drop-before{box-shadow:0 -2px 0 0 var(--accent)}
.sec.drop-after{box-shadow:0 2px 0 0 var(--accent)}
.drop-mark{height:1px;background:var(--accent);margin:8px 0;box-shadow:0 0 12px var(--accent)}

/* 10 — cartes ------------------------------------------------------------ */
.card{
  position:relative;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);
  padding:16px;overflow:hidden;transition:border-color var(--d-s) var(--t),transform var(--d) var(--t),background var(--d-s) var(--t);
}
.card::after{content:"";position:absolute;inset:0;pointer-events:none;opacity:0;transition:opacity var(--d) var(--t);background:radial-gradient(420px 220px at var(--mx,50%) var(--my,0%),rgba(217,162,78,.07),transparent 70%)}
.card:hover{border-color:var(--line-3);background:var(--surface-2);transform:translateY(-2px)}
.card:hover::after{opacity:1}
.card-h{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:7px}
.card-t{font-size:15.5px;flex:1 1 auto;min-width:0}
.card-meta{font-family:var(--mono);font-size:9.5px;letter-spacing:.1em;color:var(--dim);margin-bottom:12px;word-break:break-word}
.card-spark{margin:0 -2px 12px;height:44px;overflow:hidden}
.card-spark svg{width:100%;height:100%}
.card-count{display:flex;align-items:baseline;gap:6px;font-family:var(--serif);font-size:27px;line-height:1;margin-bottom:9px}
.card-count .num{font-size:inherit}
.card-unit{font-family:var(--mono);font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
.card-blurb{color:var(--muted);font-size:12.5px;line-height:1.5;margin-bottom:12px}
.card-f{display:flex;align-items:center;justify-content:space-between;gap:10px;padding-top:11px;border-top:1px solid var(--line-2)}
.card-drag{position:absolute;top:14px;right:13px;width:12px;height:12px;opacity:0;transition:opacity var(--d-s) var(--t);cursor:grab}
.card-drag::before{content:"";position:absolute;inset:0;background-image:radial-gradient(var(--dim) 1px,transparent 1px);background-size:4px 4px}
.card:hover .card-drag{opacity:.9}
.cover{position:relative;width:52px;height:3px;background:var(--surface-3);border-radius:2px;overflow:hidden;flex:0 0 auto}
.cover span{position:absolute;inset:0;width:calc(var(--c)*50%);background:var(--accent);border-radius:2px;transform-origin:left;animation:growX var(--d-l) var(--t) both}
@keyframes growX{from{transform:scaleX(0)}to{transform:scaleX(1)}}
.grp-h{grid-column:1/-1;color:var(--dim);padding:14px 0 2px;border-bottom:1px solid var(--line-2);margin-bottom:4px}

/* 11 — hero -------------------------------------------------------------- */
.hero{position:relative;padding:clamp(22px,3.4vw,44px) 0 clamp(26px,3vw,40px);will-change:transform}
.hero-top{display:flex;align-items:flex-end;justify-content:space-between;gap:26px;flex-wrap:wrap;margin-bottom:26px}
.hero-eyebrow{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.hero-eyebrow .rule{width:clamp(30px,5vw,72px);height:1px;background:var(--accent-line)}
.hero-t{font-size:clamp(34px,6.4vw,80px);line-height:.95;letter-spacing:-.03em;max-width:20ch}
.hero-t em{font-style:italic;color:var(--accent)}
.hero-t .br{display:block}
.hero-sub{max-width:60ch;color:var(--muted);font-size:14.5px;line-height:1.6;margin-top:16px}
.hero-tag{display:flex;flex-wrap:wrap;gap:6px;margin-top:18px}
.hero-score{flex:0 0 auto;display:flex;align-items:baseline;gap:8px;padding-left:22px;border-left:1px solid var(--line)}
.hero-score-v{font-family:var(--serif);font-size:clamp(44px,6vw,72px);line-height:.9;letter-spacing:-.03em}
.hero-score-u{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim)}
.hero-meta{display:flex;flex-wrap:wrap;gap:6px 22px;margin-top:22px;padding-top:16px;border-top:1px solid var(--line-2)}
.hero-meta div{display:flex;flex-direction:column;gap:3px}
.hero-meta b{font-family:var(--mono);font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim);font-weight:400}
.hero-meta span{font-size:13px;color:var(--paper)}

/* 12 — KPI --------------------------------------------------------------- */
.kpi{
  position:relative;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);
  padding:14px 15px 15px;overflow:hidden;
}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--accent);opacity:0;transition:opacity var(--d) var(--t)}
.kpi:hover::before{opacity:1}
.kpi-h{display:block;color:var(--dim);margin-bottom:9px}
.kpi-v{font-family:var(--serif);font-size:clamp(25px,2.7vw,36px);line-height:1;letter-spacing:-.02em;display:flex;align-items:baseline;gap:5px}
.kpi-v small{font-family:var(--mono);font-size:10px;letter-spacing:.12em;color:var(--dim);text-transform:uppercase}
.kpi-ghost{position:absolute;right:-6px;bottom:-14px;font-family:var(--serif);font-size:64px;line-height:1;color:var(--paper);opacity:.028;pointer-events:none;user-select:none}
.kpi.crit{border-color:rgba(224,86,75,.34)}
.kpi.crit .kpi-v{color:var(--crit)}
.kpi.high .kpi-v{color:var(--high)}
.kpi.ok .kpi-v{color:var(--ok)}

/* 13 — chips / badges ---------------------------------------------------- */
.chip{
  display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 9px;
  border:1px solid var(--line);border-radius:999px;color:var(--muted);background:var(--surface-2);
  font-size:9.5px;letter-spacing:.12em;white-space:nowrap;
}
.chip.on{border-color:var(--accent-line);color:var(--accent);background:var(--accent-soft)}
.chip-dot{width:5px;height:5px;border-radius:50%;background:currentColor;flex:0 0 auto}
.sev{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;white-space:nowrap}
.sev .dot{width:6px;height:6px;border-radius:50%;background:currentColor;flex:0 0 auto}
.sev-crit{color:var(--crit)}
.sev-high{color:var(--high)}
.sev-med{color:var(--med)}
.sev-low{color:var(--low)}
.sev-info{color:var(--info)}
.sev-ok{color:var(--ok)}
.sev-mute{color:var(--mute)}
.sev-crit .dot{box-shadow:0 0 0 3px rgba(224,86,75,.16)}
.sev-high .dot{box-shadow:0 0 0 3px rgba(217,136,60,.16)}
.sev-med .dot{box-shadow:0 0 0 3px rgba(217,162,78,.16)}
.pill{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;padding:3px 7px;border:1px solid var(--line-2);border-radius:var(--r);color:var(--dim)}
.verdict{font-family:var(--mono);font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;padding:3px 8px;border-radius:var(--r);border:1px solid currentColor}
.verdict-provable{color:var(--crit)}
.verdict-partial{color:var(--high)}
.verdict-blocked{color:var(--mute)}
.verdict-none{color:var(--dim)}

/* 14 — graphiques -------------------------------------------------------- */
.chart{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:15px;min-width:0}
.chart-h{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:13px}
.chart-t{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim)}
.chart-lg{margin-top:11px;padding-top:10px;border-top:1px solid var(--line-2);font-family:var(--mono);font-size:10px;letter-spacing:.08em;color:var(--muted);display:flex;flex-wrap:wrap;gap:3px 14px}
.chart-lg i{font-style:normal;display:inline-flex;align-items:center;gap:5px}
.chart-lg i::before{content:"";width:7px;height:7px;border-radius:1px;background:var(--sw,var(--accent))}
.chart svg{width:100%;height:auto;overflow:visible}
.chart-hero{grid-row:span 2;display:flex;flex-direction:column}
.chart-hero .chart-body{flex:1 1 auto;display:flex;align-items:center;justify-content:center}
.legend{display:flex;flex-direction:column;gap:7px}
.lg-i{display:flex;align-items:center;gap:9px;font-size:12px;cursor:pointer;transition:opacity var(--d-s) var(--t)}
.lg-i:hover{color:var(--paper)}
.lg-i.off{opacity:.34}
.lg-sw{width:9px;height:9px;border-radius:1px;background:var(--sw,var(--accent));flex:0 0 auto}
.lg-l{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lg-v{font-family:var(--mono);font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums}
.lg-bar{height:2px;background:var(--surface-3);border-radius:2px;overflow:hidden;margin-top:2px}
.lg-bar span{display:block;height:100%;background:var(--sw,var(--accent));transform-origin:left;animation:growX var(--d-l) var(--t) both}

/* 15 — tableaux ---------------------------------------------------------- */
.tw{overflow-x:auto;overflow-y:hidden;border:1px solid var(--line);border-radius:var(--r);background:var(--surface);-webkit-overflow-scrolling:touch}
.tbl{font-size:12.5px;min-width:100%}
.tbl th{
  text-align:left;padding:10px 13px;color:var(--dim);font-weight:400;white-space:nowrap;
  border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--surface-2);z-index:1;
}
.tbl th.sortable{cursor:pointer;transition:color var(--d-s) var(--t)}
.tbl th.sortable:hover{color:var(--accent)}
.tbl th .arrow{opacity:0;margin-left:5px;transition:opacity var(--d-s) var(--t)}
.tbl th[aria-sort] .arrow{opacity:1;color:var(--accent)}
.tbl td{padding:9px 13px;border-bottom:1px solid var(--line-2);vertical-align:middle}
.tbl tbody tr:last-child td{border-bottom:0}
.tbl tbody tr{transition:background var(--d-s) var(--t);animation:rowIn var(--d) var(--t) both}
.tbl tbody tr:hover{background:var(--surface-2)}
.tbl tbody tr.hl{background:var(--accent-soft)}
.tbl .r{text-align:right;font-variant-numeric:tabular-nums}
.tbl .c{text-align:center}
.tbl .wrap-c{max-width:38ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tbl .mono-c{font-family:var(--mono);font-size:10.5px;letter-spacing:.06em;color:var(--muted)}
.tbl .serif{font-family:var(--serif);font-size:15px}
@keyframes rowIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.tbl-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 13px;border-top:1px solid var(--line-2);background:var(--surface-2);font-family:var(--mono);font-size:10px;letter-spacing:.12em;color:var(--dim)}
.tbl-cap{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:11px}
.tbl-cap h3{font-size:15px}
.pager{display:flex;align-items:center;gap:5px}

/* 16 — accordéon --------------------------------------------------------- */
.acc{border:1px solid var(--line);border-radius:var(--r);background:var(--surface);overflow:hidden}
.acc+.acc{margin-top:10px}
.acc-h{display:flex;align-items:center;gap:12px;width:100%;padding:12px 14px;text-align:left;transition:background var(--d-s) var(--t)}
.acc-h:hover{background:var(--surface-2)}
.acc-h .acc-c{font-family:var(--mono);font-size:9.5px;letter-spacing:.12em;color:var(--dim);text-transform:uppercase}
.acc-h .acc-t{flex:1 1 auto;font-family:var(--serif);font-size:15px}
.acc-sign{width:13px;height:13px;position:relative;flex:0 0 auto;transition:transform var(--d) var(--t)}
.acc-sign::before,.acc-sign::after{content:"";position:absolute;background:var(--accent);transition:opacity var(--d-s) var(--t)}
.acc-sign::before{left:0;top:6px;width:13px;height:1px}
.acc-sign::after{left:6px;top:0;width:1px;height:13px}
.acc[open] .acc-sign,.acc.on .acc-sign{transform:rotate(135deg)}
.acc-b{padding:0 14px 14px;display:none;animation:accIn var(--d) var(--t) both}
.acc.on>.acc-b,.acc[open]>.acc-b{display:block}
@keyframes accIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.acc-h[aria-expanded="true"] .acc-c{color:var(--accent)}

/* 17 — états vides / skeleton / spinner --------------------------------- */
.empty{display:flex;flex-direction:column;align-items:center;gap:8px;padding:34px 20px;text-align:center;border:1px dashed var(--line);border-radius:var(--r);background:var(--surface)}
.empty-i{font-family:var(--serif);font-size:26px;color:var(--dim);line-height:1}
.empty-t{font-family:var(--serif);font-size:15px}
.empty-h{color:var(--dim);font-size:12px;max-width:44ch}
.skl{display:grid;gap:16px}
.skl-b{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:16px}
.skl-l{height:9px;background:linear-gradient(90deg,var(--surface-2),var(--surface-3),var(--surface-2));background-size:220% 100%;border-radius:2px;animation:shimmer 1.5s linear infinite}
@keyframes shimmer{from{background-position:120% 0}to{background-position:-120% 0}}
.spin{width:15px;height:15px;border:1.5px solid var(--line-3);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;flex:0 0 auto}
@keyframes spin{to{transform:rotate(360deg)}}
.spin-lg{width:26px;height:26px;border-width:2px}
.boot-skeleton{position:relative;z-index:1;margin-left:var(--rail);padding:calc(var(--top) + 34px) var(--pad) 120px;display:none}
body.loading .boot-skeleton{display:block}
body.loading .dash{display:none}
.prog{height:2px;background:var(--surface-3);border-radius:2px;overflow:hidden;position:relative}
.prog span{position:absolute;inset:0;width:var(--p,0%);background:var(--accent);border-radius:2px;transition:width var(--d-l) var(--t)}
.prog.indet span{width:34%;animation:indet 1.3s var(--t) infinite}
@keyframes indet{0%{transform:translateX(-110%)}100%{transform:translateX(330%)}}
.nojs{margin:calc(var(--top) + 34px) var(--pad);padding:18px;border:1px solid var(--accent-line);border-radius:var(--r);background:var(--surface);color:var(--muted);max-width:70ch}

/* 18 — machine ----------------------------------------------------------- */
.mach{display:grid;grid-template-columns:minmax(0,1fr);gap:16px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:17px}
.mach-h{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;flex-wrap:wrap;padding-bottom:13px;margin-bottom:15px;border-bottom:1px solid var(--line-2)}
.mach-host{font-family:var(--serif);font-size:22px;letter-spacing:-.01em}
.mach-os{font-family:var(--mono);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);margin-top:4px}
.gauges{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:14px}
.gauge{display:flex;flex-direction:column;gap:7px}
.gauge-t{display:flex;align-items:baseline;justify-content:space-between;gap:8px}
.gauge-l{font-family:var(--mono);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
.gauge-v{font-family:var(--serif);font-size:17px;font-variant-numeric:tabular-nums}
.gauge-b{height:4px;background:var(--surface-3);border-radius:3px;overflow:hidden;position:relative}
.gauge-b span{position:absolute;inset:0;width:var(--w,0%);background:var(--accent);border-radius:3px;transform-origin:left;animation:growX var(--d-l) var(--t) both}
.gauge-b.crit span{background:var(--crit)}
.gauge-b.high span{background:var(--high)}
.gauge-b.ok span{background:var(--ok)}
.gauge-note{font-family:var(--mono);font-size:9.5px;letter-spacing:.06em;color:var(--dim)}
.svc-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:15px;padding-top:14px;border-top:1px solid var(--line-2)}
.svc{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:9.5px;letter-spacing:.1em;padding:4px 8px;border:1px solid var(--line-2);border-radius:var(--r);color:var(--muted)}
.svc b{font-weight:400;color:var(--paper)}
.svc-active{color:var(--ok);border-color:rgba(119,181,138,.3)}
.svc-fail{color:var(--crit);border-color:rgba(224,86,75,.3)}
.svc i{width:5px;height:5px;border-radius:50%;background:currentColor}

/* 19 — live bar ---------------------------------------------------------- */
.livebar{
  position:fixed;left:var(--rail);right:0;bottom:0;z-index:115;
  display:flex;align-items:center;gap:14px;padding:9px var(--pad);
  background:color-mix(in srgb,var(--void) 92%,transparent);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border-top:1px solid var(--line);
  transform:translateY(100%);transition:transform var(--d) var(--t);
}
.livebar.show{transform:none}
.livebar-k{color:var(--dim);flex:0 0 auto;display:flex;align-items:center;gap:8px}
.livebar-t{font-family:var(--serif);font-size:13.5px;flex:0 0 auto}
.livebar-log{
  flex:1 1 auto;min-width:0;font-family:var(--mono);font-size:10.5px;letter-spacing:.04em;color:var(--muted);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}
.livebar-log b{color:var(--accent);font-weight:400}
.livebar-a{display:flex;gap:6px;flex:0 0 auto}
.logbox{
  font-family:var(--mono);font-size:11px;line-height:1.7;color:var(--muted);
  background:var(--void);border:1px solid var(--line);border-radius:var(--r);padding:12px;
  max-height:280px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;
}
.logbox b{color:var(--accent);font-weight:400}
.timeline{display:flex;flex-direction:column;gap:0}
.tl{position:relative;display:grid;grid-template-columns:18px 1fr;gap:12px;padding:0 0 16px}
.tl:last-child{padding-bottom:0}
.tl::before{content:"";position:absolute;left:8px;top:16px;bottom:0;width:1px;background:var(--line)}
.tl:last-child::before{display:none}
.tl-i{width:9px;height:9px;margin-top:5px;border-radius:50%;background:var(--accent);position:relative;z-index:1;box-shadow:0 0 0 4px var(--surface)}
.tl.done .tl-i{background:var(--ok)}
.tl.run .tl-i{animation:pulse 1.5s var(--t) infinite}
.tl-b{min-width:0}
.tl-name{display:block;color:var(--dim);margin-bottom:4px}
.tl-x{font-size:12.5px;line-height:1.5}
.tl-meta{font-family:var(--mono);font-size:9.5px;letter-spacing:.08em;color:var(--dim);margin-top:4px}

/* 20 — palette de commandes (Ctrl+K) ------------------------------------ */
.pal{
  position:fixed;inset:0;z-index:300;display:flex;align-items:flex-start;justify-content:center;
  padding:clamp(60px,14vh,150px) 16px 16px;background:rgba(6,4,3,.72);
  backdrop-filter:blur(9px);-webkit-backdrop-filter:blur(9px);
  opacity:0;visibility:hidden;transition:opacity var(--d-s) var(--t),visibility var(--d-s) var(--t);
}
.pal.on{opacity:1;visibility:visible}
.pal-box{
  width:100%;max-width:620px;background:var(--surface);border:1px solid var(--line-3);border-radius:var(--r-l);
  box-shadow:0 40px 100px -30px rgba(0,0,0,.95);overflow:hidden;transform:translateY(-10px) scale(.99);
  transition:transform var(--d) var(--t);
}
.pal.on .pal-box{transform:none}
.pal-in{display:flex;align-items:center;gap:11px;padding:15px 17px;border-bottom:1px solid var(--line)}
.pal-in input{flex:1 1 auto;background:none;border:0;outline:none;font-family:var(--mono);font-size:14px;letter-spacing:.04em}
.pal-in input::placeholder{color:var(--dim)}
.pal-kbd{font-family:var(--mono);font-size:9.5px;letter-spacing:.1em;color:var(--dim);border:1px solid var(--line);border-radius:var(--r);padding:2px 6px}
.pal-list{max-height:min(52vh,440px);overflow-y:auto;padding:7px}
.pal-g{padding:9px 10px 5px;color:var(--dim)}
.pal-i{
  display:flex;align-items:center;gap:11px;width:100%;padding:9px 11px;border-radius:var(--r);
  text-align:left;transition:background var(--d-s) var(--t);scroll-margin:8px;
}
.pal-i .pal-ico{width:17px;text-align:center;color:var(--dim);flex:0 0 auto;font-family:var(--mono);font-size:12px}
.pal-i .pal-t{flex:1 1 auto;font-size:13.5px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pal-i .pal-t mark{background:var(--accent-soft);color:var(--accent);border-radius:1px;padding:0 1px}
.pal-i .cmd-k{color:var(--dim);flex:0 0 auto}
.pal-i .pal-sw{width:26px;height:15px;border-radius:999px;background:var(--surface-3);border:1px solid var(--line);position:relative;flex:0 0 auto;transition:background var(--d-s) var(--t)}
.pal-i .pal-sw::after{content:"";position:absolute;top:2px;left:2px;width:9px;height:9px;border-radius:50%;background:var(--muted);transition:transform var(--d) var(--t),background var(--d-s) var(--t)}
.pal-i[aria-selected="true"]{background:var(--accent-soft)}
.pal-i[aria-selected="true"] .pal-ico,.pal-i[aria-selected="true"] .pal-t{color:var(--accent)}
.pal-i[aria-selected="true"] .pal-sw::after{transform:translateX(11px);background:var(--accent)}
.pal-f{display:flex;align-items:center;gap:14px;padding:9px 17px;border-top:1px solid var(--line);color:var(--dim);flex-wrap:wrap}
.pal-f span{display:flex;align-items:center;gap:5px}
.pal-empty{padding:26px;text-align:center;color:var(--dim)}

/* 21 — modale ------------------------------------------------------------ */
.scrim{position:fixed;inset:0;z-index:240;background:rgba(6,4,3,.7);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px);opacity:0;transition:opacity var(--d-s) var(--t)}
.scrim.on{opacity:1}
.mo{position:fixed;inset:0;z-index:250;display:flex;align-items:center;justify-content:center;padding:16px;pointer-events:none}
.mo-box{
  width:100%;max-width:660px;max-height:84vh;overflow-y:auto;background:var(--surface);
  border:1px solid var(--line-3);border-radius:var(--r-l);box-shadow:0 40px 100px -30px rgba(0,0,0,.95);
  opacity:0;transform:translateY(12px) scale(.985);transition:opacity var(--d-s) var(--t),transform var(--d) var(--t);
  pointer-events:auto;
}
.mo.on .mo-box{opacity:1;transform:none}
.mo-h{display:flex;align-items:center;gap:12px;padding:15px 18px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--surface);z-index:2}
.mo-t{flex:1 1 auto;font-family:var(--serif);font-size:18px}
.mo-x{width:28px;height:28px;display:grid;place-items:center;border:1px solid var(--line);border-radius:var(--r);color:var(--muted);transition:color var(--d-s) var(--t),border-color var(--d-s) var(--t)}
.mo-x:hover{color:var(--crit);border-color:rgba(224,86,75,.4)}
.mo-b{padding:18px}
.mo-f{display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:13px 18px;border-top:1px solid var(--line);position:sticky;bottom:0;background:var(--surface)}
.kv{display:grid;grid-template-columns:minmax(120px,auto) minmax(0,1fr);gap:9px 18px}
.kv dt{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);padding-top:3px}
.kv dd{margin:0;font-size:13px;line-height:1.55;word-break:break-word}
.kv dd.mono-v{font-family:var(--mono);font-size:11.5px;word-break:break-all}

/* 22 — toasts ------------------------------------------------------------ */
.toasts{position:fixed;right:16px;bottom:16px;z-index:320;display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:min(400px,calc(100vw - 32px))}
.toast{
  display:flex;align-items:flex-start;gap:10px;padding:11px 14px;background:var(--surface-2);
  border:1px solid var(--line-3);border-left:2px solid var(--accent);border-radius:var(--r);
  box-shadow:var(--sh);pointer-events:auto;animation:toastIn var(--d) var(--t) both;
}
.toast.out{animation:toastOut var(--d-s) var(--t) both}
.toast-ok{border-left-color:var(--ok)}
.toast-err{border-left-color:var(--crit)}
.toast-i{font-family:var(--mono);font-size:12px;line-height:1.4;flex:0 0 auto}
.toast-b{flex:1 1 auto;min-width:0}
.toast-t{font-size:12.5px;line-height:1.45}
.toast-t b{display:block;font-family:var(--mono);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);font-weight:400;margin-bottom:3px}
@keyframes toastIn{from{opacity:0;transform:translateX(24px) scale(.98)}to{opacity:1;transform:none}}
@keyframes toastOut{to{opacity:0;transform:translateX(24px) scale(.98)}}

/* 23 — tooltips / mode noob ---------------------------------------------- */
[data-tip]{position:relative}
.tip{
  position:absolute;z-index:260;max-width:290px;padding:10px 12px;
  background:var(--surface-3);border:1px solid var(--line-3);border-left:2px solid var(--accent);
  border-radius:var(--r);box-shadow:0 22px 50px -18px rgba(0,0,0,.9);
  font-family:var(--sans);font-size:12px;line-height:1.5;letter-spacing:0;text-transform:none;
  color:var(--paper);opacity:0;visibility:hidden;transform:translateY(4px);
  transition:opacity var(--d-s) var(--t),transform var(--d-s) var(--t),visibility var(--d-s) var(--t);
  pointer-events:none;
}
.tip.on{opacity:1;visibility:visible;transform:none}
.tip b{display:block;font-family:var(--mono);font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);font-weight:400;margin-bottom:5px}
.tip-q{position:absolute;top:4px;right:5px;width:14px;height:14px;border-radius:50%;border:1px solid var(--line-3);color:var(--dim);font-family:var(--mono);font-size:9px;line-height:12px;text-align:center;opacity:0;transition:opacity var(--d-s) var(--t),color var(--d-s) var(--t)}
html[data-noob="1"] [data-tip]>.tip-q{opacity:1}
html[data-noob="1"] [data-tip]:hover>.tip-q{color:var(--accent);border-color:var(--accent-line)}
.gloss{display:none}
html[data-noob="1"] .gloss{display:inline}
.gloss-b{border-bottom:1px dotted var(--accent-line);cursor:help}
html[data-noob="0"] .gloss-b{border-bottom:0;cursor:inherit}
.noob-note{display:none;align-items:flex-start;gap:10px;padding:11px 14px;margin-bottom:18px;background:var(--accent-soft);border:1px solid var(--accent-line);border-radius:var(--r);font-size:12.5px;line-height:1.5;color:var(--paper)}
html[data-noob="1"] .noob-note{display:flex}

/* 24 — menu de personnalisation ------------------------------------------ */
.sheet{position:fixed;top:var(--top);right:16px;z-index:210;width:min(320px,calc(100vw - 32px));background:var(--surface);border:1px solid var(--line-3);border-radius:var(--r-l);box-shadow:0 34px 80px -28px rgba(0,0,0,.94);opacity:0;visibility:hidden;transform:translateY(-8px) scale(.99);transition:opacity var(--d-s) var(--t),transform var(--d-s) var(--t),visibility var(--d-s) var(--t)}
.sheet.on{opacity:1;visibility:visible;transform:none}
.sheet-h{display:flex;align-items:center;gap:10px;padding:13px 15px;border-bottom:1px solid var(--line)}
.sheet-t{flex:1 1 auto;font-family:var(--serif);font-size:16px}
.sheet-b{padding:6px;max-height:min(64vh,560px);overflow-y:auto}
.opt{display:flex;align-items:center;gap:10px;width:100%;padding:9px 11px;border-radius:var(--r);text-align:left;transition:background var(--d-s) var(--t)}
.opt:hover{background:var(--surface-2)}
.opt .opt-t{flex:1 1 auto;font-size:13px}
.opt .opt-s{font-family:var(--mono);font-size:9.5px;letter-spacing:.08em;color:var(--dim)}
.opt-sw{width:9px;height:9px;border-radius:50%;background:var(--sw,var(--accent));flex:0 0 auto;box-shadow:0 0 0 1px rgba(0,0,0,.4) inset}
.opt.on{background:var(--accent-soft)}
.opt.on .opt-t{color:var(--accent)}
.sheet-g{padding:11px 12px 5px}
.row-sw{display:flex;align-items:center;gap:10px;padding:7px 11px;border-radius:var(--r)}
.row-sw:hover{background:var(--surface-2)}
.row-sw .row-t{flex:1 1 auto;font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);cursor:grab}
.sec.hidden-sec{opacity:.32}
.sec.hidden-sec .sec-b{opacity:.3;filter:saturate(.2)}
.sec.hidden-sec .sec-t::after{content:" (masquée)";font-family:var(--mono);font-size:9.5px;letter-spacing:.12em;color:var(--dim)}

/* 25 — curseur custom ---------------------------------------------------- */
.cursor{position:fixed;inset:0;z-index:9999;pointer-events:none;display:none}
html[data-cursor="1"] .cursor{display:block}
html[data-cursor="1"],html[data-cursor="1"] a,html[data-cursor="1"] button{cursor:none}
.cursor i{position:absolute;left:0;top:0;border-radius:50%;will-change:transform}
.cursor-dot{width:5px;height:5px;margin:-2.5px 0 0 -2.5px;background:var(--accent)}
.cursor-ring{width:28px;height:28px;margin:-14px 0 0 -14px;border:1px solid var(--accent-line);transition:width var(--d-s) var(--t),height var(--d-s) var(--t),margin var(--d-s) var(--t),background var(--d-s) var(--t)}
.cursor-ring::after{content:"";position:absolute;inset:-5px;border:1px solid var(--line-2);border-radius:50%}
body.cur-hot .cursor-ring{width:44px;height:44px;margin:-22px 0 0 -22px;background:var(--accent-soft)}
body.cur-hot .cursor-dot{opacity:.5}

/* 26 — reveal / parallax ------------------------------------------------- */
.rv{opacity:0;transform:translateY(24px);transition:opacity var(--d-l) var(--t),transform var(--d-l) var(--t)}
.rv.in{opacity:1;transform:none}
.rv-2{transition-delay:40ms}
.rv-3{transition-delay:80ms}
.rv-4{transition-delay:120ms}
.rv-5{transition-delay:160ms}
.rv-6{transition-delay:200ms}
.rv-7{transition-delay:240ms}
.rv-8{transition-delay:280ms}
.draw{stroke-dasharray:var(--len,1400);stroke-dashoffset:var(--len,1400)}
.draw.in{animation:draw var(--d-l) var(--t) forwards}
@keyframes draw{to{stroke-dashoffset:0}}
.barg{transform:scaleY(0);transform-origin:bottom;animation:barg var(--d-l) var(--t) forwards}
@keyframes barg{to{transform:scaleY(1)}}
.ringp{opacity:0;transform:scale(.86);transform-origin:center;transition:opacity var(--d-l) var(--t),transform var(--d-l) var(--t)}
.ringp.in{opacity:1;transform:none}

/* 27 — scrollbar de progression + fil d'ariane ---------------------------- */
.toc-h{position:fixed;top:0;left:0;right:0;height:2px;z-index:130;background:transparent;pointer-events:none}
.toc-h span{display:block;height:100%;width:var(--p,0%);background:linear-gradient(90deg,var(--accent),color-mix(in srgb,var(--accent) 40%,var(--paper)));transition:width 90ms linear}
.crumb{position:fixed;left:var(--rail);z-index:104;pointer-events:none;font-family:var(--mono);font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);opacity:0;transition:opacity var(--d) var(--t)}
.crumb.on{opacity:1}

/* 28 — responsive -------------------------------------------------------- */
@media (max-width:1200px){
  .grid-6{grid-template-columns:repeat(3,minmax(0,1fr))}
  .grid-8{grid-template-columns:repeat(4,minmax(0,1fr))}
  .span-3,.span-4{grid-column:span 2}
}
@media (max-width:980px){
  :root{--rail:0px}
  .dash,.boot-skeleton,.nojs{margin-left:0}
  .rail{
    width:min(300px,86vw);transform:translateX(-102%);transition:transform var(--d) var(--t);
    box-shadow:0 0 90px rgba(0,0,0,.7);
  }
  .rail.on{transform:none}
  .rail-burger{display:inline-flex}
  .grid-3,.grid-4,.grid-6,.grid-8,.grid-side,.grid-side-r{grid-template-columns:repeat(2,minmax(0,1fr))}
  .span-2,.span-3,.span-4,.span-6{grid-column:span 2}
  .crumb{left:0}
  .livebar{left:0}
  .search{flex:1 1 auto;min-width:0}
  .search-kbd{display:none}
}
@media (max-width:640px){
  :root{--top:52px;--pad:14px}
  .grid-2,.grid-3,.grid-4,.grid-6,.grid-8,.grid-side,.grid-side-r,.grid-mod{grid-template-columns:minmax(0,1fr)}
  .span-2,.span-3,.span-4,.grid-hero-side{grid-column:span 1}
  .grid-hero-side{grid-row:auto!important}
  .hero-score{padding-left:0;border-left:0;border-top:1px solid var(--line);padding-top:14px;width:100%}
  .brand-sub{display:none}
  .sec-h{gap:9px}
  .sec-acts{opacity:1}
  .tbl th,.tbl td{padding:8px 10px}
  .tbl .wrap-c{max-width:20ch}
  .toasts{left:12px;right:12px;max-width:none}
  .livebar{flex-wrap:wrap;gap:8px}
  .livebar-log{order:3;flex-basis:100%}
}
@media (hover:none){
  html[data-cursor="1"] .cursor{display:none}
  .sec-acts{opacity:1}
  .card-drag{opacity:.6}
}
@media (prefers-contrast:more){
  :root{--line:rgba(236,229,216,.32);--muted:#c3bca9;--dim:#a49c8a}
  .grain{display:none}
}
@media print{
  .topbar,.rail,.livebar,.sec-acts,.cursor,.grain,.toasts,.boot-skeleton{display:none!important}
  .dash{margin-left:0;padding:0}
  .sec{break-inside:avoid;margin-bottom:24px}
  body{background:#fff;color:#111}
  .card,.chart,.tw{background:#fff;border-color:#ccc}
}
/* 29 — mouvement réduit : TOUT est désactivé ------------------------------ */
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{
    animation-duration:.001ms!important;animation-iteration-count:1!important;
    transition-duration:.001ms!important;scroll-behavior:auto!important;
  }
  .grain{display:none}
  .rv{opacity:1;transform:none}
  .draw{stroke-dasharray:none;stroke-dashoffset:0}
  .barg{transform:none}
  .ringp{opacity:1;transform:none}
  .cover span,.lg-bar span,.gauge-b span{transform:none;width:var(--w,100%)}
  .livebar{transform:none}
  .pal,.mo-box,.sheet,.tip,.scrim{transition:none}
  .cursor{display:none!important}
}
html[data-motion="0"] *{animation-duration:.001ms!important;transition-duration:.001ms!important}
html[data-motion="0"] .rv{opacity:1;transform:none}
html[data-motion="0"] .cursor{display:none!important}
"##;
