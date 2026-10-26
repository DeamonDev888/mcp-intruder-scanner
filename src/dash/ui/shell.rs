// src/dash/ui/shell.rs — Squelette HTML du document (extraits de ui.rs v0.5.8).
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
