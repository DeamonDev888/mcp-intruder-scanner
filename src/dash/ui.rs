// src/dash/ui.rs — Design system 2026 du tableau de bord MCP-Intruder.
// -----------------------------------------------------------------------------
// Direction artistique « Ermitage Industries » : fond encre #0d0a07, surfaces
// #16120d, papier #ece5d8, accent ambre #d9a24e, filets hairline, grain
// filmique, serif display pour les titres, sans-serif pour le texte, mono
// capitalise pour les labels, transitions cubic-bezier(.16,1,.3,1).
//
// RÈGLE DE COMPILATION : ce module ne référence JAMAIS `charts::`. Les SVG
// arrivent déjà rendus par le serveur et sont injectés dans des placeholders
// (@@SVG_*) que `with_charts()` remplace. Voir `body_skeleton()` + `with_charts()`.
//
// API publique
//   CSS, JS, SHELL            — le design system et le squelette HTML
//   SLOT_*                    — placeholders de graphiques
//   page_shell()              — document complet (style + script inline)
//   page()                    — page_shell() avec le prefill des charts
//   body_skeleton()           — HTML des sections (version sans JS, charts)
//   with_charts()             — injection des SVG dans le squelette
//   module_card()             — carte module + sparkline
//   group_grid()              — grille de cartes par groupe fonctionnel
//   kpi_tile()                — tuile KPI (mode noob : data-tip)
//   table()/row()/cell()      — helpers de tableau statique
//   severity_badge()/tone()   — badges de sévérité
//   empty_state()             — état vide illustré
//   esc()                     — échappement HTML/attribut
// -----------------------------------------------------------------------------

use crate::dash::model::ModuleStat;

// ───────────────────────────── placeholders de graphiques ────────────────────
// Remplacés par dashboard.rs avec charts::donut(), charts::gauge(), …

pub const SLOT_DONUT: &str = "@@SVG_DONUT@@";
pub const SLOT_GAUGE: &str = "@@SVG_GAUGE@@";
pub const SLOT_HBARS: &str = "@@SVG_HBARS@@";
pub const SLOT_AREA: &str = "@@SVG_AREA@@";
pub const SLOT_STACKED: &str = "@@SVG_STACKED@@";
pub const SLOT_RADAR: &str = "@@SVG_RADAR@@";
pub const SLOT_HEATMAP: &str = "@@SVG_HEATMAP@@";
pub const SLOT_HISTOGRAM: &str = "@@SVG_HISTOGRAM@@";
pub const SLOT_RING: &str = "@@SVG_RING@@";
pub const SLOT_SPARK: &str = "@@SVG_SPARK@@";

/// Ordre canonique des sections : sert au scroll-spy, à la palette de
/// commandes et à la réinitialisation de la mise en page.
/// Les 5 ONGLETS de l'application. Les sections hero / position / cartographie /
/// machines / outils ne sont plus des onglets : leur information vit dans la
/// barre de statut du bas (voir `statusbar()`).
pub const SECTION_ORDER: [&str; 5] = ["findings", "surface", "scans", "impact", "live"];

/// Libelles des onglets (le JS les lit pour la barre).
pub const TAB_LABELS: [&str; 5] = ["Constats", "Surface", "Scans", "Impact", "Live"];

/// Les labels sont en mono capitalisé, séparés par un filet.
pub fn label(text: &str) -> String {
    format!("<span class=\"lbl\">{}</span>", esc(text))
}

/// Classe de couleur pour un ton (`crit`, `high`, `med`, `low`, `info`, `ok`, `mute`).
pub fn tone(tone_name: &str) -> String {
    let t = tone_name.trim().to_ascii_lowercase();
    let key = match t.as_str() {
        "crit" | "critical" | "critique" | "blocker" | "fatal" => "crit",
        "high" | "haut" | "eleve" | "élevé" => "high",
        "med" | "medium" | "moyen" | "moderate" | "modere" => "med",
        "low" | "faible" | "minor" | "info-low" => "low",
        "info" | "information" | "notice" => "info",
        "ok" | "pass" | "good" | "valid" | "valid_on" => "ok",
        _ => "mute",
    };
    key.to_string()
}

/// Badge de sévérité : pastille + mot, utilisé partout dans les tableaux.
pub fn severity_badge(sev: &str) -> String {
    let t = tone(sev);
    let word = if sev.trim().is_empty() {
        "inconnu"
    } else {
        sev.trim()
    };
    format!(
        "<span class=\"sev sev-{}\"><i class=\"dot\" aria-hidden=\"true\"></i>{}</span>",
        t,
        esc(word)
    )
}

/// Échappement HTML (texte et attributs).
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 24);
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Tuile KPI. `value` est le nombre déjà formaté côté serveur ; le JS anime
/// depuis `data-count` si le nombre est numérique.
pub fn kpi_tile(key: &str, label_text: &str, value: &str, tip: &str) -> String {
    format!(
        "<article class=\"kpi\" data-kpi=\"{k}\" data-search=\"{k} {l}\" data-tip=\"{t}\">\
         <header class=\"kpi-h\">{l}</header>\
         <p class=\"kpi-v\"><span class=\"num\" data-count=\"{v}\">{v}</span></p>\
         <span class=\"kpi-ghost\" aria-hidden=\"true\"></span></article>",
        k = esc(key),
        l = label(label_text),
        v = esc(value),
        t = esc(tip)
    )
}

/// Carte de module : identité, sparkline SVG injecté, compteur, blurb noob.
pub fn module_card(m: &ModuleStat, spark_svg: &str) -> String {
    let sev = m.severity_max.as_deref().unwrap_or("");
    let sevtxt = if sev.trim().is_empty() {
        "aucun"
    } else {
        sev.trim()
    };
    let cover = m.coverage.min(2);
    format!(
        "<article class=\"card mod\" data-mod=\"{key}\" data-group=\"{grp}\" draggable=\"true\" \
         data-search=\"{key} {lab} {grp} {tool}\" data-tip=\"{tip}\">\
         <span class=\"card-drag\" aria-hidden=\"true\" title=\"Glisser pour réordonner\"></span>\
         <header class=\"card-h\"><h3 class=\"card-t\">{lab}</h3>\
         <span class=\"sev sev-{tone}\"><i class=\"dot\" aria-hidden=\"true\"></i>{sevtxt}</span></header>\
         <p class=\"card-meta\"><span class=\"mono\">{key}</span> · {grp} · {tool}</p>\
         <figure class=\"card-spark\" data-slot-figure=\"spark\">{spark}</figure>\
         <p class=\"card-count\"><span class=\"num\" data-count=\"{count}\">{count}</span> \
         <span class=\"card-unit\">élément(s)</span></p>\
         <p class=\"card-blurb\">{blurb}</p>\
         <footer class=\"card-f\"><div class=\"cover\" data-cover=\"{cover}\" role=\"img\" \
         aria-label=\"Couverture {cover} sur 2\"><span style=\"--c:{cover}\"></span></div>\
         <button class=\"btn btn-ghost btn-xs\" type=\"button\" data-act=\"detail\" data-mod=\"{key}\" \
         aria-label=\"Détail du module {lab}\">détail</button></footer></article>",
        key = esc(&m.key),
        lab = esc(&m.label),
        grp = esc(&m.group),
        tool = esc(&m.tool),
        tip = esc(&m.blurb),
        blurb = esc(&m.blurb),
        spark = spark_svg,
        count = m.count,
        tone = tone(sev),
        sevtxt = esc(sevtxt)
    )
}

/// Grille de cartes pour un groupe fonctionnel.
pub fn group_grid(group: &str, cards: &[String]) -> String {
    if cards.is_empty() {
        return empty_state("◌", group, "Aucun module actif dans ce groupe.");
    }
    format!(
        "<div class=\"grid grid-mod\" data-group=\"{g}\"><header class=\"grp-h\">{l}</header>{body}</div>",
        g = esc(group),
        l = label(group),
        body = cards.join("")
    )
}

/// Cellule de tableau.
pub fn cell(value: &str, cls: &str) -> String {
    if cls.is_empty() {
        format!("<td>{}</td>", value)
    } else {
        format!("<td class=\"{}\">{}</td>", esc(cls), value)
    }
}

/// Ligne de tableau.
pub fn row(cells: &[String]) -> String {
    format!("<tr>{}</tr>", cells.join(""))
}

/// Tableau statique : `(titre, classe)` par colonne.
pub fn table(columns: &[(&str, &str)], rows: &[String], empty: &str) -> String {
    if rows.is_empty() {
        return empty.to_string();
    }
    let head: String = columns
        .iter()
        .map(|(t, c)| format!("<th class=\"{}\" scope=\"col\">{}</th>", esc(c), esc(t)))
        .collect();
    format!(
        "<div class=\"tw\"><table class=\"tbl\"><thead><tr>{}</tr></thead><tbody>{}</tbody></table></div>",
        head,
        rows.join("")
    )
}

/// État vide illustré.
pub fn empty_state(icon: &str, title: &str, hint: &str) -> String {
    format!(
        "<div class=\"empty\"><span class=\"empty-i\" aria-hidden=\"true\">{i}</span>\
         <p class=\"empty-t\">{t}</p><p class=\"empty-h\">{h}</p></div>",
        i = esc(icon),
        t = esc(title),
        h = esc(hint)
    )
}

/// Injecte les SVG déjà rendus dans le squelette, via `with_charts(&body, &[(SLOT_DONUT, &svg), …])`.
pub fn with_charts(body: &str, charts: &[(&str, &str)]) -> String {
    let mut out = body.to_string();
    for (slot, svg) in charts {
        if !svg.is_empty() {
            out = out.replace(slot, svg);
        }
    }
    out
}

/// Squelette HTML des sections, version « sans JavaScript ».
/// Le JS lit les SVG dans `#prefill` via `[data-slot]`, les mémorise, puis
/// reconstruit la page dynamiquement. Sans JS, les graphiques restent lisibles.
pub fn body_skeleton() -> String {
    let figure = |slot: &str, svg: &str| -> String {
        format!(
            "<figure class=\"chart\" data-slot=\"{}\">{}</figure>",
            esc(slot),
            svg
        )
    };
    let prefill = format!(
        "<div id=\"prefill\" hidden>{h}{p}{m}</div>",
        h = figure("donut", SLOT_DONUT),
        p = figure("gauge", SLOT_GAUGE)
            + &figure("ring", SLOT_RING)
            + &figure("radar", SLOT_RADAR)
            + &figure("area", SLOT_AREA)
            + &figure("stacked", SLOT_STACKED)
            + &figure("heatmap", SLOT_HEATMAP)
            + &figure("histogram", SLOT_HISTOGRAM)
            + &figure("hbars", SLOT_HBARS)
            + &figure("spark", SLOT_SPARK),
        m = String::new()
    );
    format!(
        "{p}<noscript><div class=\"nojs\"><p>Ce tableau de bord a besoin de JavaScript pour \
         animer les données et les compteurs. Les graphiques statiques ci-dessus restent \
         lisibles, sans interaction.</p></div></noscript>",
        p = prefill
    )
}

/// Comme [`body_skeleton`] mais en injectant une sparkline par module.
/// `cards` reçoit `(clé de module, svg déjà rendu par charts::sparkline)`.
pub fn body_skeleton_with_sparks(sparks: &[(&str, &str)]) -> String {
    let mut per = String::new();
    for (key, svg) in sparks {
        per.push_str(&format!(
            "<figure class=\"chart\" data-slot=\"spark\" data-mod=\"{}\">{}</figure>",
            esc(key),
            svg
        ));
    }
    body_skeleton().replace(
        "<div id=\"prefill\" hidden>",
        &format!("<div id=\"prefill\" hidden>{}", per),
    )
}

/// Document complet : doctype, head, style inline, script inline, body vide.
pub fn page_shell(title: &str, meta: &str, body: &str) -> String {
    let mut out = SHELL.to_string();
    out = out.replace("@@TITLE@@", &esc(title));
    out = out.replace("@@META@@", &esc(meta));
    out = out.replace("@@CSS@@", CSS);
    out = out.replace("@@JS@@", JS);
    out = out.replace("@@BODY@@", body);
    out
}

/// Raccourci : document complet avec le prefill des graphiques statiques.
pub fn page(title: &str) -> String {
    page_shell(title, "tableau de bord de sécurité", &body_skeleton())
}

/// Le squelette HTML : uniquement des placeholders, pas de format! a accolades.
pub const SHELL: &str = r##"<!DOCTYPE html>
<html lang="fr" data-theme="void" data-font="sans">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark">
<meta name="description" content="@@META@@">
<meta name="generator" content="mcp-intruder.dash">
<title>@@TITLE@@</title>
<style>@@CSS@@</style>
</head>
<body class="app boot">
<a class="skip" href="#dash">Aller au contenu principal</a>
<div class="grain" aria-hidden="true"></div>
<div class="cursor" aria-hidden="true"><i class="cursor-dot"></i><i class="cursor-ring"></i></div>
<div class="scrim" id="scrim" hidden></div>
<div class="toasts" id="toasts" role="status" aria-live="polite"></div>
<div class="boot-skeleton" id="boot" aria-hidden="true"></div>
<header class="app-head">
  <div class="app-brand">mcp-intruder<i>.</i></div>
  <div class="app-title" id="apptitle">tableau de bord</div>
  <div class="app-actions">
    <button class="app-btn" id="btn-scan" title="Lancer un scan sur une cible">LANCER UN SCAN</button>
    <button class="app-btn icon" id="btn-search" title="Recherche globale (/)" aria-label="Recherche">/</button>
    <button class="app-btn icon" id="btn-cmd" title="Commandes (Ctrl+K)" aria-label="Commandes">&#8984;</button>
    <button class="app-btn icon" id="btn-noob" title="Mode noob : explications" aria-label="Mode noob">?</button>
    <button class="app-btn icon" id="btn-refresh" title="Rafraichir" aria-label="Rafraichir">&#8635;</button>
  </div>
</header>
<div class="tabbar" role="tablist" aria-label="Sections du tableau de bord">
  <div class="tabs" role="presentation"></div>
  <div class="tabbar-right"><span class="clock" id="clock"></span></div>
</div>
<div class="app-view" id="view" tabindex="-1">
@@BODY@@
</div>
<script>@@JS@@</script>
</body>
</html>
"##;
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
