// src/wizard/ui.rs — Interface de l'assistant (page unique, autonome).
//
// Aucune dependance externe : le CSS et le JS sont inline dans le binaire.
// L'interface suit le meme registre visuel que le tableau de bord (fond
// sombre, ambre, typo monospace) pour que l'ensemble forme un seul outil.

/// Page complete de l'assistant.
pub fn page() -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="fr" data-theme="void">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="generator" content="intruder.wizard">
<title>MCP Intruder · assistant de configuration</title>
<style>{CSS}</style>
</head>
<body class="wiz">
<div class="wrap">
  <header class="head">
    <div class="brand">intruder<i>.</i></div>
    <h1>Assistant de configuration</h1>
    <p class="lede">
      Le moteur de scan s'appuie sur l'outillage Kali (nmap, nuclei, nikto,
      wafw00f, whatweb, sslscan, ffuf, dnsrecon&hellip;). Sur une machine qui
      n'est pas un Kali natif, cet assistant installe le runtime de conteneur
      puis l'image Kali officielle.
    </p>
  </header>

  <section class="card" id="diag">
    <div class="card-head">
      <h2>Diagnostic</h2>
      <button class="btn ghost" id="btn-refresh">Rafraichir</button>
    </div>
    <div class="banner" id="headline">Analyse en cours&hellip;</div>
    <ul class="steps" id="steps"></ul>
    <dl class="facts" id="facts"></dl>
  </section>

  <section class="card">
    <div class="card-head"><h2>Actions</h2></div>
    <div class="actions">
      <button class="btn" id="btn-install">
        <span class="btn-t">Installer le runtime de conteneur</span>
        <span class="btn-s" id="cmd-install"></span>
      </button>
      <button class="btn" id="btn-pull">
        <span class="btn-t">Telecharger l'image Kali officielle</span>
        <span class="btn-s" id="cmd-pull"></span>
      </button>
      <button class="btn" id="btn-verify">
        <span class="btn-t">Verifier l'outillage</span>
        <span class="btn-s" id="cmd-verify">nmap, nuclei, nikto, wafw00f&hellip;</span>
      </button>
    </div>
    <div class="out" id="out" hidden></div>
  </section>

  <section class="card" id="next" hidden>
    <div class="card-head"><h2>Suite</h2></div>
    <p class="lede" id="next-text"></p>
    <pre class="cmd" id="next-cmd"></pre>
  </section>

  <footer class="foot">
    <span>mcp_intruder &middot; image officielle <code>kalilinux/kali-rolling:latest</code></span>
    <span id="ver"></span>
  </footer>
</div>
<script>{JS}</script>
</body>
</html>"#
    )
}

/// Feuille de style de l'assistant.
pub const CSS: &str = r#"
:root{
  --bg:#0d0a07; --bg2:#14100b; --card:#171309; --line:#2a2116;
  --fg:#e8e2d6; --muted:#9a8f7d; --amber:#d9a24e; --amber-dim:#8a6a33;
  --ok:#5fbf7f; --warn:#d9a24e; --ko:#d96459; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body.wiz{
  margin:0; background:radial-gradient(1200px 700px at 18% -10%,#1d1509 0%,var(--bg) 62%);
  color:var(--fg); font-family:var(--mono); font-size:14px; line-height:1.55;
  min-height:100vh;
}
.wrap{max-width:880px;margin:0 auto;padding:40px 20px 64px}
.head{margin-bottom:28px}
.brand{font-size:12px;letter-spacing:.22em;color:var(--amber);text-transform:uppercase}
.brand i{color:var(--amber-dim);font-style:normal}
h1{font-size:26px;margin:10px 0 8px;letter-spacing:-.01em}
h2{font-size:14px;margin:0;letter-spacing:.12em;text-transform:uppercase;color:var(--amber)}
.lede{color:var(--muted);margin:0 0 4px;font-size:13px}
.card{background:linear-gradient(180deg,var(--card),#120e08);border:1px solid var(--line);
  border-radius:10px;padding:20px;margin-bottom:18px;box-shadow:0 12px 40px rgba(0,0,0,.35)}
.card-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.banner{border:1px solid var(--line);border-left:3px solid var(--amber);background:#15110a;
  padding:12px 14px;border-radius:6px;margin-bottom:16px;font-size:13px}
.banner.ok{border-left-color:var(--ok)} .banner.ko{border-left-color:var(--ko)} .banner.warn{border-left-color:var(--warn)}
.steps{list-style:none;margin:0 0 16px;padding:0}
.steps li{display:flex;gap:12px;align-items:flex-start;padding:11px 0;border-bottom:1px dashed #241c12}
.steps li:last-child{border-bottom:0}
.dot{width:9px;height:9px;border-radius:50%;margin-top:6px;flex:0 0 auto;background:var(--muted)}
.dot.done{background:var(--ok);box-shadow:0 0 9px rgba(95,191,127,.55)}
.dot.todo{background:var(--amber-dim)} .dot.ko{background:var(--ko)}
.dot.busy{background:var(--amber);animation:pulse 1s infinite}
@keyframes pulse{50%{opacity:.25}}
.step-t{font-size:13px;color:var(--fg)}
.step-d{font-size:12px;color:var(--muted);margin-top:2px;word-break:break-word}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin:0}
.facts div{background:#131007;border:1px solid var(--line);border-radius:6px;padding:9px 11px}
.facts dt{font-size:10px;letter-spacing:.13em;text-transform:uppercase;color:var(--muted)}
.facts dd{margin:3px 0 0;font-size:12px;color:var(--fg);word-break:break-all}
.actions{display:grid;gap:12px}
.btn{width:100%;text-align:left;background:#191308;border:1px solid var(--line);color:var(--fg);
  border-radius:8px;padding:13px 15px;cursor:pointer;font-family:inherit;transition:.15s}
.btn:hover:not(:disabled){border-color:var(--amber-dim);background:#1e1709;transform:translateY(-1px)}
.btn:disabled{opacity:.42;cursor:not-allowed}
.btn.ghost{width:auto;padding:6px 12px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.btn-t{display:block;font-size:13px}
.btn-s{display:block;font-size:11px;color:var(--muted);margin-top:4px;word-break:break-all}
.out{background:#0b0906;border:1px solid var(--line);border-radius:6px;padding:12px;margin-top:14px;
  font-size:11.5px;color:var(--muted);white-space:pre-wrap;word-break:break-word;max-height:280px;overflow:auto}
.cmd{background:#0b0906;border:1px solid var(--line);border-radius:6px;padding:13px;font-size:12px;
  color:var(--amber);overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.foot{display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;color:var(--muted);font-size:11px;padding-top:6px}
code{background:#0b0906;border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:11px}
@media (max-width:520px){.wrap{padding:24px 13px 48px}h1{font-size:21px}}
"#;

/// Script de l'assistant : diagnostic, actions, rafraichissement.
pub const JS: &str = r#"
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
  (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function post(url){
  const r = await fetch(url, {method:'POST'});
  return await r.json();
}

function renderSteps(steps){
  $('steps').innerHTML = steps.map(s => `
    <li>
      <span class="dot ${esc(s.state)}"></span>
      <span>
        <span class="step-t">${esc(s.title)}</span>
        <span class="step-d">${esc(s.detail)}</span>
      </span>
    </li>`).join('');
}

function renderFacts(d){
  const rows = [
    ['Systeme', d.os_label + (d.distro ? ' — ' + d.distro : '')],
    ['Kali natif', d.is_native_kali ? 'oui' : 'non'],
    ['Runtime', d.container_runtime ? d.container_runtime + ' ' + (d.container_version||'') : 'absent'],
    ['Image Kali', d.kali_image_present ? 'presente' : 'absente'],
    ['Outillage', d.tools_ready ? 'operationnel' : 'incomplet'],
  ];
  $('facts').innerHTML = rows.map(([k,v]) =>
    `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('');
  $('cmd-install').textContent = d.runtime_install.command;
  $('cmd-pull').textContent = d.image_pull.command;
  $('btn-install').disabled = d.is_native_kali || !!d.container_runtime;
  $('btn-pull').disabled = d.is_native_kali || !d.container_runtime || d.kali_image_present;
}

function renderDiag(d){
  renderSteps(d.steps || []);
  renderFacts(d);
  const h = $('headline');
  h.textContent = d.headline || '';
  h.className = 'banner ' + (d.tools_ready ? 'ok' : (d.container_runtime ? 'warn' : 'ko'));

  // Bloc "suite" : la commande a executer manuellement si l'action auto a echoue.
  const next = $('next');
  if (d.tools_ready){
    next.hidden = false;
    $('next-text').textContent = "Configuration terminee. Vous pouvez lancer un scan : " +
      "mcp_intruder <cible> --fast --json  ou  mcp_intruder tools pour l'etat de l'outillage.";
    $('next-cmd').textContent = 'mcp_intruder example.com --fast --json';
  } else if (d.container_runtime && !d.kali_image_present){
    next.hidden = false;
    $('next-text').textContent = "Runtime disponible. Telechargez l'image Kali officielle :";
    $('next-cmd').textContent = d.image_pull.command;
  } else if (!d.container_runtime && !d.is_native_kali){
    next.hidden = false;
    $('next-text').textContent = "Installez le runtime de conteneur (privileges administrateur requis) :";
    $('next-cmd').textContent = d.runtime_install.command;
  } else {
    next.hidden = true;
  }
}

async function refresh(){
  const r = await fetch('/api/diagnostic');
  renderDiag(await r.json());
}

function showOutput(title, text){
  const o = $('out');
  o.hidden = false;
  o.textContent = (title ? '### ' + title + '\n\n' : '') + (text || '');
}

async function act(url, label){
  const btns = document.querySelectorAll('.btn');
  btns.forEach(b => b.disabled = true);
  showOutput(label, 'Execution en cours...');
  try {
    const r = await post(url);
    showOutput(label + (r.ok ? ' — OK' : ' — ECHEC'),
      (r.message ? r.message + '\n\n' : '') + (r.output || ''));
    if (r.diagnostic) renderDiag(r.diagnostic);
  } catch (e) {
    showOutput(label + ' — ERREUR', String(e));
  } finally {
    btns.forEach(b => b.disabled = false);
    refresh();
  }
}

$('btn-refresh').onclick = refresh;
$('btn-install').onclick = () => act('/api/install', 'Installation du runtime');
$('btn-pull').onclick = () => act('/api/pull', 'Telechargement de l image');
$('btn-verify').onclick = () => act('/api/verify', 'Controle de l outillage');

fetch('/api/health').then(r=>r.json()).then(h=>{ $('ver').textContent = h.version || ''; }).catch(()=>{});
refresh();
"#;
