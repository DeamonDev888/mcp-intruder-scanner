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

// Squelette HTML, CSS et JS extraits dans des sous-modules (ex-ui.rs, 3 432 l.).
mod css;
mod js;
mod shell;

pub use css::CSS;
pub use js::JS;
pub use shell::SHELL;
