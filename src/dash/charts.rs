// src/dash/charts.rs — bibliothèque de graphiques SVG rendus côté serveur.
//
// Zéro dépendance (rien d'autre que `std`), zéro JavaScript de graphing :
// chaque fonction `pub` renvoie un `<svg>` inline prêt à injecter dans le HTML
// du tableau de bord, avec `viewBox` + `preserveAspectRatio` (donc responsive)
// et un `<title>` accessible.
//
// Deux invariants non négociables :
// - tout texte venant de la base passe par [`esc`] (labels arbitraires) ;
// - toute coordonnée passe par [`san`] (NaN/Inf -> 0.0) et [`cx`] (arrondi
//   à 2 décimales : jamais `NaN`, jamais `-0` dans un attribut).

use std::fmt::Write;

use super::model::{Bucket, Series};

// ───────────────────────────── Palette ─────────────────────────────

/// Fond de page, jamais en fill direct (sert de base aux mélanges).
const VOID: &str = "#0d0a07";
/// Fond des cartes.
const SURFACE: &str = "#16120d";
/// Texte principal.
const PAPER: &str = "#ece5d8";
/// Texte secondaire.
const MUTED: &str = "#948d7c";
/// Filet discret (grilles, cases vides).
const LINE: &str = "#ece5d81f";
/// Filet marqué (pistes, anneaux vides).
const LINE_STRONG: &str = "#ece5d83d";
/// Accent principal.
const AMBER: &str = "#d9a24e";
/// Critique / haut.
const CRIT: &str = "#e0654f";
/// Moyen.
const MED: &str = "#c8b48a";
/// Ok.
const OK: &str = "#8fae7d";

/// Pile monospace : cohérente avec le reste du tableau de bord.
const FONT: &str = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";

/// Message affiché quand une série est vide.
const NO_DATA: &str = "aucune donnée";

/// Compteur d'identifiants pour les `<defs>` : plusieurs SVG inline sur une
/// même page ne doivent jamais partager l'`id` d'un dégradé.
static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Écrit dans le buffer SVG. Un `String` ne peut pas échouer : le résultat est
/// ignoré, ce qui évite de threading un `Result` partout.
macro_rules! svg {
    ($buf:expr, $($arg:tt)*) => {{
        let _ = write!($buf, $($arg)*);
    }};
}

// ───────────────────────────── Primitives ─────────────────────────────

/// u32 -> f64 (aucun `From<u32> for f64` en std).
fn fw(v: u32) -> f64 {
    f64::from(v)
}

/// u8 -> f64 (aucun `From<u8> for f64` en std).
fn fw_val(v: u8) -> f64 {
    f64::from(v)
}

/// Échappe `& < > " '` pour un contexte XML/HTML (texte ET attribut).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Neutralise les flottants corrompus : NaN et +/-Inf deviennent 0.0.
fn san(v: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        0.0
    }
}

/// Ramène une valeur dans 0..1 ; série plate (span nul) -> 0.5.
fn norm(v: f64, lo: f64, sp: f64) -> f64 {
    if san(sp) > 1e-9 {
        ((san(v) - san(lo)) / san(sp)).clamp(0.0, 1.0)
    } else {
        0.5
    }
}

/// Identifiant unique pour les `<defs>` (`vg7`).
fn uid(prefix: &str) -> String {
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{prefix}{n}")
}

/// Coordonnée : 2 décimales max, jamais `NaN`, jamais `-0`.
fn cx(v: f64) -> String {
    let raw = format!("{:.2}", san(v));
    let trimmed = raw.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "-" {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Valeur lisible dans un `<title>` ou à côté d'une barre : entière si ça
/// l'est, 2 décimales sinon.
fn fmt_val(v: f64) -> String {
    let v = san(v);
    if v.abs() >= 10_000.0 || (v - v.trunc()).abs() < 1e-9 {
        format!("{v:.0}")
    } else {
        cx(v)
    }
}

/// Tronque sur `max` caractères sans jamais couper un `char` UTF-8 en deux
/// (le piège `&name[..24]`).
fn clip_label(s: &str, max: usize) -> String {
    let max = max.max(1);
    let head: String = s.chars().take(max).collect();
    if s.chars().nth(max).is_some() {
        format!("{head}…")
    } else {
        head
    }
}

/// Nombre de caractères qui tiennent dans `px` à la taille de police donnée
/// (approximation monospace 0.62em, bornée à 3).
fn chars_in(px: f64, font: f64) -> usize {
    let n = (san(px) / (san(font) * 0.62)).floor();
    if n.is_finite() && n > 0.0 {
        (n as usize).max(3)
    } else {
        3
    }
}

/// Borne `Bucket.tone` -> couleur de la palette.
fn tone_color(tone: &str) -> &'static str {
    match tone {
        "crit" | "high" => CRIT,
        "med" => MED,
        "ok" => OK,
        _ => MUTED,
    }
}

/// Couleur d'une jauge d'après son ratio 0..1.
fn ratio_color(t: f64) -> &'static str {
    if t >= 0.75 {
        OK
    } else if t >= 0.5 {
        AMBER
    } else if t >= 0.25 {
        MED
    } else {
        CRIT
    }
}

/// Min et max d'une série normalisée (vide -> (0,0)).
fn bounds(vals: &[f64]) -> (f64, f64) {
    let mut lo = f64::INFINITY;
    let mut hi = f64::NEG_INFINITY;
    for v in vals {
        let v = san(*v);
        if v < lo {
            lo = v;
        }
        if v > hi {
            hi = v;
        }
    }
    (san(lo), san(hi))
}

/// Écart min->max utilisable en division (0 quand la série est plate).
fn span(lo: f64, hi: f64) -> f64 {
    let d = san(hi) - san(lo);
    if d > 1e-9 {
        d
    } else {
        0.0
    }
}

/// Abscisse du point `i` sur `n`, dans `[pad, w-pad]`.
fn x_of(i: usize, n: usize, w: u32, pad: f64) -> f64 {
    let inner = (fw(w) - 2.0 * pad).max(1.0);
    if n > 1 {
        pad + i as f64 / (n - 1) as f64 * inner
    } else {
        pad
    }
}

/// Ordonnée d'une valeur normalisée `t` (0 = bas, 1 = haut) dans une zone de
/// tracé de hauteur `ih`.
fn y_of(t: f64, pad: f64, ih: f64) -> f64 {
    pad + ih - norm(t, 0.0, 1.0) * ih.max(1.0)
}

/// Point polaire : `deg` en degrés, 0 = 3 h, 90 = 6 h (repère SVG, y vers le
/// bas), sens horaire.
fn polar(cx: f64, cy: f64, r: f64, deg: f64) -> (f64, f64) {
    let rad = deg.to_radians();
    (cx + r * rad.cos(), cy + r * rad.sin())
}

/// `d` d'une polyligne ouverte.
fn line_path(pts: &[(f64, f64)]) -> String {
    let mut d = String::new();
    for (i, (x, y)) in pts.iter().enumerate() {
        if i == 0 {
            svg!(d, "M {} {}", cx(*x), cx(*y));
        } else {
            svg!(d, " L {} {}", cx(*x), cx(*y));
        }
    }
    d
}

/// `d` d'une aire refermée sur la ligne de base.
fn area_path(pts: &[(f64, f64)], base: f64) -> String {
    let Some((x0, _)) = pts.first() else {
        return String::new();
    };
    let mut d = format!("M {} {}", cx(*x0), cx(base));
    for (x, y) in pts {
        svg!(d, " L {} {}", cx(*x), cx(*y));
    }
    if let Some((lx, _)) = pts.last() {
        svg!(d, " L {} {} Z", cx(*lx), cx(base));
    }
    d
}

/// `d` d'un arc circulaire (drapeau grand-arc calculé sur l'amplitude).
fn arc_path(ccx: f64, ccy: f64, r: f64, a0: f64, a1: f64) -> String {
    let (x0, y0) = polar(ccx, ccy, r, a0);
    let (x1, y1) = polar(ccx, ccy, r, a1);
    let large = if (a1 - a0).abs() > 180.0 { 1 } else { 0 };
    let sweep = if a1 >= a0 { 1 } else { 0 };
    format!(
        "M {} {} A {} {} 0 {large} {sweep} {} {}",
        cx(x0),
        cx(y0),
        cx(r),
        cx(r),
        cx(x1),
        cx(y1)
    )
}

/// Mélange deux couleurs hexadécimales `#rrggbb`, `t` = 0 -> a, 1 -> b.
fn mix_hex(a: &str, b: &str, t: f64) -> String {
    let t = norm(t, 0.0, 1.0);
    let mut out = String::with_capacity(7);
    out.push('#');
    for ch in 0..3_usize {
        let lo = 1 + ch * 2;
        let av = u8::from_str_radix(&a[lo..lo + 2], 16).unwrap_or(0);
        let bv = u8::from_str_radix(&b[lo..lo + 2], 16).unwrap_or(0);
        let mixed = (fw_val(av) + (fw_val(bv) - fw_val(av)) * t).round();
        if mixed < 0.0 {
            svg!(out, "00");
        } else if mixed > 255.0 {
            svg!(out, "ff");
        } else {
            svg!(out, "{:02x}", mixed as u8);
        }
    }
    out
}

/// Ouvre le `<svg>` racine + son `<title>` accessible (ratio préservé).
fn open(w: u32, h: u32, title: &str) -> String {
    let mut s = String::new();
    svg!(s, "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {w} {h}\" preserveAspectRatio=\"xMidYMid meet\" role=\"img\" focusable=\"false\" class=\"vchart\"><title>{}</title>", esc(title));
    s
}

/// Comme [`open`] mais étiré : une sparkline épouse la largeur de son
/// conteneur CSS au lieu d'un carré (le trait reste fin grâce à
/// `vector-effect="non-scaling-stroke"`).
fn open_wide(w: u32, h: u32, title: &str) -> String {
    let mut s = String::new();
    svg!(s, "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {w} {h}\" preserveAspectRatio=\"none\" role=\"img\" focusable=\"false\" class=\"vchart\"><title>{}</title>", esc(title));
    s
}

/// Ferme le `<svg>` racine.
fn close() -> &'static str {
    "</svg>"
}

/// SVG de repli : cadre aux dimensions demandées + message centré.
fn empty(w: u32, h: u32, msg: &str) -> String {
    let mut s = open(w, h, msg);
    svg!(s, "<rect x=\"0.5\" y=\"0.5\" width=\"{}\" height=\"{}\" fill=\"{SURFACE}\" stroke=\"{LINE}\" rx=\"3\"/>", cx(fw(w) - 1.0), cx(fw(h) - 1.0));
    text_at(&mut s, fw(w) / 2.0, fw(h) / 2.0 + 4.0, 11.0, "middle", MUTED, msg);
    svg!(s, "{}", close());
    s
}

/// Élément `<text>` monospace, corps échappé.
fn text_at(s: &mut String, x: f64, y: f64, size: f64, anchor: &str, fill: &str, body: &str) {
    svg!(s, "<text x=\"{}\" y=\"{}\" font-family=\"{FONT}\" font-size=\"{}\" text-anchor=\"{anchor}\" fill=\"{fill}\">{}</text>", cx(x), cx(y), cx(size), esc(body));
}

// ───────────────────────────── Sparklines ─────────────────────────────

/// Micro-courbe sans aire : tendance d'une valeur (score, charge, latence).
/// `tone` est borné par [`tone_color`] (crit/high/med/ok/low/info/mute).
pub fn sparkline(values: &[f64], w: u32, h: u32, tone: &str) -> String {
    let (w, h) = (w.max(2), h.max(2));
    let vals: Vec<f64> = values.iter().copied().map(san).collect();
    if vals.is_empty() {
        return empty(w, h, NO_DATA);
    }
    let color = tone_color(tone);
    let pad = 2.0_f64;
    let n = vals.len();
    let ih = fw(h) - 2.0 * pad;
    let (lo, hi) = bounds(&vals);
    let sp = span(lo, hi);
    let pts: Vec<(f64, f64)> = (0..n)
        .map(|i| (x_of(i, n, w, pad), y_of(norm(vals[i], lo, sp), pad, ih)))
        .collect();

    let mut s = open_wide(w, h, "tendance");
    svg!(s, "<path d=\"{}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1.5\" stroke-linejoin=\"round\" stroke-linecap=\"round\" vector-effect=\"non-scaling-stroke\"/>", line_path(&pts));
    for (i, (x, y)) in pts.iter().enumerate() {
        svg!(s, "<circle cx=\"{}\" cy=\"{}\" r=\"2\" fill=\"{color}\"><title>point {} : {}</title></circle>", cx(*x), cx(*y), i + 1, fmt_val(vals[i]));
    }
    svg!(s, "{}", close());
    s
}

/// Comme [`sparkline`] mais avec une aire dégradée sous la courbe.
pub fn area_sparkline(values: &[f64], w: u32, h: u32, tone: &str) -> String {
    let (w, h) = (w.max(2), h.max(2));
    let vals: Vec<f64> = values.iter().copied().map(san).collect();
    if vals.is_empty() {
        return empty(w, h, NO_DATA);
    }
    let color = tone_color(tone);
    let pad = 2.0_f64;
    let n = vals.len();
    let ih = fw(h) - 2.0 * pad;
    let base = fw(h) - pad;
    let (lo, hi) = bounds(&vals);
    let sp = span(lo, hi);
    let pts: Vec<(f64, f64)> = (0..n)
        .map(|i| (x_of(i, n, w, pad), y_of(norm(vals[i], lo, sp), pad, ih)))
        .collect();

    let gid = uid("vg");
    let mut s = open_wide(w, h, "tendance");
    svg!(s, "<defs><linearGradient id=\"{gid}\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\"><stop offset=\"0\" stop-color=\"{color}\" stop-opacity=\"0.45\"/><stop offset=\"1\" stop-color=\"{color}\" stop-opacity=\"0.02\"/></linearGradient></defs>");
    svg!(s, "<path d=\"{}\" fill=\"url(#{gid})\"/>", area_path(&pts, base));
    svg!(s, "<path d=\"{}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1.5\" stroke-linejoin=\"round\" stroke-linecap=\"round\" vector-effect=\"non-scaling-stroke\"/>", line_path(&pts));
    for (i, (x, y)) in pts.iter().enumerate() {
        svg!(s, "<circle cx=\"{}\" cy=\"{}\" r=\"2\" fill=\"{color}\"><title>point {} : {}</title></circle>", cx(*x), cx(*y), i + 1, fmt_val(vals[i]));
    }
    svg!(s, "{}", close());
    s
}

// ────────────────────────────── Donut ──────────────────────────────

/// Anneau proportionnel + légende. Les parts sont tracées en
/// `stroke-dasharray` (une part à 100 % reste un cercle parfait) et démarrent
/// à midi. Le centre affiche le total.
pub fn donut(buckets: &[Bucket], size: u32) -> String {
    let size = size.max(40);
    let total: f64 = buckets.iter().map(|b| san(b.value).max(0.0)).sum();
    let visible: Vec<&Bucket> = buckets
        .iter()
        .filter(|b| san(b.value) > 0.0)
        .collect();
    if visible.is_empty() || total <= 0.0 {
        return empty(size, size, NO_DATA);
    }
    let stroke = (fw(size) * 0.12).clamp(6.0, 18.0);
    let cxy = fw(size) / 2.0;
    let r = (cxy - stroke / 2.0 - 2.0).max(2.0);
    let circ = std::f64::consts::TAU * r;
    let gap = if visible.len() > 1 { 1.5 } else { 0.0 };
    let font = (fw(size) * 0.055).clamp(8.0, 11.0);

    let mut s = open(size, size, "répartition");
    svg!(s, "<g transform=\"rotate(-90 {} {})\">", cx(cxy), cx(cxy));
    let mut acc = 0.0_f64;
    for b in &visible {
        let v = san(b.value).max(0.0);
        let len = v / total * circ;
        svg!(s, "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{}\" stroke-dasharray=\"{} {}\" stroke-dashoffset=\"{}\"><title>{} : {}</title></circle>", cx(cxy), cx(cxy), cx(r), tone_color(&b.tone), cx(stroke), cx(len.max(0.5)), cx((circ - len).max(0.0)), cx(-acc), esc(&b.label), fmt_val(v));
        acc += len + gap;
    }
    svg!(s, "</g>");
    text_at(&mut s, cxy, cxy + font * 0.35, font * 2.0, "middle", PAPER, &fmt_val(total));
    text_at(&mut s, cxy, cxy + font * 1.6, font, "middle", MUTED, "total");
    svg!(s, "{}", close());

    // Légende sous l'anneau (au plus 7 lignes).
    let rows = visible.len().min(7);
    if rows == 0 {
        return s;
    }
    let lh = 14.0_f64;
    let extra = (fw(rows as u32) * lh).round() as u32 + 4;
    let mut lg = open(size, size.saturating_add(extra), "répartition — légende");
    let chars = chars_in(fw(size) - 32.0, font);
    for (i, b) in visible.iter().take(rows).enumerate() {
        let y = fw(size) + 9.0 + fw(i as u32) * lh;
        svg!(lg, "<rect x=\"2\" y=\"{}\" width=\"8\" height=\"8\" rx=\"1.5\" fill=\"{}\"/>", cx(y - 6.0), tone_color(&b.tone));
        text_at(&mut lg, 14.0, y + 1.0, font, "start", MUTED, &format!("{} {}", clip_label(&b.label, chars), fmt_val(san(b.value))));
    }
    svg!(lg, "{}", close());
    lg
}

// ────────────────────────────── Jauge ──────────────────────────────

/// Jauge à arc de 240° (de 150° à 30°, ouverture vers le bas) avec aiguille,
/// graduations et valeur centrée. `max <= 0` ou NaN -> repli « aucune donnée ».
pub fn gauge(value: f64, max: f64, size: u32, label: &str) -> String {
    let size = size.max(40);
    let value = san(value);
    let top = san(max);
    if top <= 0.0 {
        return empty(size, size, NO_DATA);
    }
    let t = norm(value, 0.0, top);
    let cxy = fw(size) / 2.0;
    let stroke = (fw(size) * 0.06).clamp(5.0, 10.0);
    let r_arc = (cxy - stroke / 2.0 - 2.0).max(4.0);
    let a0 = 150.0_f64;
    let sweep = 240.0_f64;
    let color = ratio_color(t);
    let r_needle = (r_arc - stroke * 0.9).max(3.0);
    let font = (fw(size) * 0.2).clamp(10.0, 26.0);
    let lfont = (font * 0.42).clamp(8.0, 12.0);

    let mut s = open(size, size, if label.is_empty() { "jauge" } else { label });
    svg!(s, "<path d=\"{}\" fill=\"none\" stroke=\"{LINE_STRONG}\" stroke-width=\"{}\" stroke-linecap=\"round\"/>", arc_path(cxy, cxy, r_arc, a0, a0 + sweep), cx(stroke));
    svg!(s, "<path d=\"{}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"{}\" stroke-linecap=\"round\"><title>{} : {} / {}</title></path>", arc_path(cxy, cxy, r_arc, a0, a0 + sweep * t), cx(stroke), esc(label), fmt_val(value), fmt_val(top));
    for k in 0..=4_usize {
        let ang = a0 + sweep * (fw(k as u32) / 4.0);
        let (x0, y0) = polar(cxy, cxy, r_arc - stroke * 0.9, ang);
        let (x1, y1) = polar(cxy, cxy, r_arc + stroke * 0.4, ang);
        svg!(s, "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{LINE_STRONG}\" stroke-width=\"1\"/>", cx(x0), cx(y0), cx(x1), cx(y1));
    }
    let (nx, ny) = polar(cxy, cxy, r_needle, a0 + sweep * t);
    svg!(s, "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{PAPER}\" stroke-width=\"2\" stroke-linecap=\"round\"/>", cx(cxy), cx(cxy), cx(nx), cx(ny));
    svg!(s, "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"{PAPER}\"/>", cx(cxy), cx(cxy), cx((stroke * 0.6).max(2.0)));
    text_at(&mut s, cxy, cxy + font * 0.35, font, "middle", PAPER, &fmt_val(value));
    if !label.is_empty() {
        text_at(&mut s, cxy, cxy + font * 1.35, lfont, "middle", MUTED, &clip_label(label, chars_in(fw(size) - 6.0, lfont)));
    }
    svg!(s, "{}", close());
    s
}

// ─────────────────────── Barres horizontales ───────────────────────

/// Barres horizontales étiquetées : libellé à gauche, barre proportionnelle,
/// valeur à droite. `bar_h` = hauteur d'une barre, `gap` = interligne.
pub fn hbars(buckets: &[Bucket], w: u32, bar_h: u32, gap: u32) -> String {
    let w = w.max(60);
    let bar_h = bar_h.max(4);
    if buckets.is_empty() {
        return empty(w, 40, NO_DATA);
    }
    let step = bar_h + gap.max(1);
    let h = (buckets.len() as u32).saturating_mul(step).saturating_add(2);
    let label_w = (fw(w) * 0.32).clamp(38.0, 130.0);
    let val_w = (fw(w) * 0.16).clamp(30.0, 64.0);
    let x0 = label_w + 6.0;
    let track_w = (fw(w) - x0 - val_w).max(8.0);
    let vals: Vec<f64> = buckets.iter().map(|b| san(b.value)).collect();
    let (lo, hi) = bounds(&vals);
    let sp = span(lo.max(0.0), hi.max(0.0));
    let font = (fw(bar_h) * 0.6).clamp(8.0, 12.0);
    let ry = fw(bar_h) / 2.0;
    let mid = fw(bar_h) / 2.0 + font * 0.35;
    let chars = chars_in(label_w - 4.0, font);

    let mut s = open(w, h, "barres");
    for (i, b) in buckets.iter().enumerate() {
        let y = 1.0 + fw(i as u32) * fw(step);
        let frac = norm(san(b.value), 0.0, sp);
        svg!(s, "<g><title>{} : {}</title>", esc(&b.label), fmt_val(b.value));
        text_at(&mut s, label_w, y + mid, font, "end", MUTED, &clip_label(&b.label, chars));
        svg!(s, "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"{}\" fill=\"{LINE}\"/>", cx(x0), cx(y), cx(track_w), cx(fw(bar_h)), cx(ry.min(6.0)));
        svg!(s, "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"{}\" fill=\"{}\"/>", cx(x0), cx(y), cx((track_w * frac).max(1.0)), cx(fw(bar_h)), cx(ry.min(6.0)), tone_color(&b.tone));
        text_at(&mut s, x0 + track_w + 5.0, y + mid, font, "start", PAPER, &fmt_val(b.value));
        svg!(s, "</g>");
    }
    svg!(s, "{}", close());
    s
}

// ────────────────────── Courbe empilée (aire) ──────────────────────

/// Courbe temporelle : grille, aire pleine, ligne et repères min/max, avec
/// les libellés d'abscisse de la série. « Empilée » = la ligne est posée sur
/// son aire, elle-même sur la grille.
pub fn stacked_line(series: &Series, w: u32, h: u32, tone: &str) -> String {
    let w = w.max(40);
    let h = h.max(30);
    let vals: Vec<f64> = series.values.iter().copied().map(san).collect();
    if vals.is_empty() {
        return empty(w, h, NO_DATA);
    }
    let color = tone_color(tone);
    let pad = 4.0_f64;
    let bottom = 15.0_f64;
    let n = vals.len();
    let plot_h = (fw(h) - bottom - pad).max(1.0);
    let base = fw(h) - bottom;
    let (lo, hi) = bounds(&vals);
    let sp = span(lo, hi);
    let pts: Vec<(f64, f64)> = (0..n)
        .map(|i| (x_of(i, n, w, pad), y_of(norm(vals[i], lo, sp), pad, plot_h)))
        .collect();

    let mut s = open(w, h, "évolution");
    for k in 0..=2_usize {
        let y = pad + plot_h * (fw(k as u32) / 2.0);
        svg!(s, "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{LINE}\" stroke-width=\"1\"/>", cx(pad), cx(y), cx(fw(w) - pad), cx(y));
    }
    svg!(s, "<path d=\"{}\" fill=\"{color}\" fill-opacity=\"0.16\"/>", area_path(&pts, base));
    svg!(s, "<path d=\"{}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1.6\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>", line_path(&pts));
    for (i, (x, y)) in pts.iter().enumerate() {
        let label = series.labels.get(i).cloned().unwrap_or_default();
        svg!(s, "<circle cx=\"{}\" cy=\"{}\" r=\"2\" fill=\"{color}\"><title>{} : {}</title></circle>", cx(*x), cx(*y), esc(&label), fmt_val(vals[i]));
    }
    text_at(&mut s, 2.0, 9.0, 9.0, "start", MUTED, &format!("min {} · max {}", fmt_val(lo), fmt_val(hi)));

    // Libellés d'abscisse équidistants (6 au plus, le dernier toujours).
    let every = (n / 6).max(1);
    let show_labels = series.labels.len() > 1;
    for (i, (x, _)) in pts.iter().enumerate() {
        let show = (i % every == 0 || i + 1 == n) && show_labels;
        if let Some(label) = series.labels.get(i).filter(|_| show) {
            text_at(&mut s, *x, fw(h) - 3.0, 9.0, "middle", MUTED, &clip_label(label, 8));
        }
    }
    svg!(s, "{}", close());
    s
}

// ───────────────────────────── Radar ─────────────────────────────

/// Radar polaire : `axes` = (libellé, valeur) par axe, `max` = pleine échelle.
/// Premier axe à midi, le reste tourne horairement.
pub fn radial_radar(axes: &[(String, f64)], max: f64, size: u32) -> String {
    let size = size.max(60);
    if axes.is_empty() {
        return empty(size, size, NO_DATA);
    }
    let scale = if san(max) > 0.0 { san(max) } else { 1.0 };
    let cxy = fw(size) / 2.0;
    let r = (cxy - fw(size) * 0.22).max(4.0);
    let n = axes.len();
    let font = (fw(size) * 0.045).clamp(8.0, 11.0);
    let angle = |i: usize| -90.0 + 360.0 * (i as f64) / (n as f64);
    let poly = |frac: f64| -> String {
        let pts: Vec<(f64, f64)> = (0..n).map(|i| polar(cxy, cxy, r * frac, angle(i))).collect();
        format!("{} Z", line_path(&pts))
    };

    let mut s = open(size, size, "radar");
    for k in 1..=4_usize {
        svg!(s, "<path d=\"{}\" fill=\"none\" stroke=\"{LINE}\" stroke-width=\"1\"/>", poly(fw(k as u32) / 4.0));
    }
    for i in 0..n {
        let (x, y) = polar(cxy, cxy, r, angle(i));
        svg!(s, "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{LINE}\" stroke-width=\"1\"/>", cx(cxy), cx(cxy), cx(x), cx(y));
    }
    let data: Vec<(f64, f64)> = (0..n)
        .map(|i| polar(cxy, cxy, r * norm(san(axes[i].1), 0.0, scale), angle(i)))
        .collect();
    svg!(s, "<path d=\"{}\" fill=\"{AMBER}\" fill-opacity=\"0.22\" stroke=\"{AMBER}\" stroke-width=\"1.6\" stroke-linejoin=\"round\"/>", format!("{} Z", line_path(&data)));
    for i in 0..n {
        let (x, y) = data[i];
        svg!(s, "<circle cx=\"{}\" cy=\"{}\" r=\"2.5\" fill=\"{AMBER}\"><title>{} : {} / {}</title></circle>", cx(x), cx(y), esc(&axes[i].0), fmt_val(axes[i].1), fmt_val(scale));
        let (lx, ly) = polar(cxy, cxy, r + font * 1.6, angle(i));
        let anchor = if lx > cxy + 0.5 {
            "start"
        } else if lx < cxy - 0.5 {
            "end"
        } else {
            "middle"
        };
        let dy = if ly < cxy - 0.5 {
            font * 0.4
        } else if ly > cxy + 0.5 {
            -font * 0.9
        } else {
            font * 0.35
        };
        text_at(&mut s, lx, ly + dy, font, anchor, MUTED, &clip_label(&axes[i].0, 12));
    }
    svg!(s, "{}", close());
    s
}

// ─────────────────────────── Heatmap ───────────────────────────

/// Grille type GitHub : 7 lignes (jours) x `weeks` colonnes (semaines),
/// remplie dans l'ordre de `days`. Les cases au-delà de `days` restent au
/// filet (aucune activité).
pub fn heatmap(days: &[f64], weeks: u32) -> String {
    let weeks = weeks.clamp(1, 53);
    if days.is_empty() {
        return empty(60, 90, NO_DATA);
    }
    let cell = 10.0_f64;
    let gap = 2.0_f64;
    let left = 16.0_f64;
    let top = 12.0_f64;
    let rows = 7_usize;
    let cols = weeks as usize;
    let w = (left + fw(weeks) * cell - gap).ceil() as u32;
    let h = (top + fw(rows as u32) * cell - gap).ceil() as u32;
    let vals: Vec<f64> = days.iter().copied().map(san).map(|v| v.max(0.0)).collect();
    let (_, hi) = bounds(&vals);
    let sp = hi.max(1.0);
    const DAYS: [&str; 7] = ["L", "M", "M", "J", "V", "S", "D"];

    let mut s = open(w, h, "activité quotidienne");
    for (i, name) in DAYS.iter().enumerate() {
        text_at(&mut s, left - 3.0, top + fw(i as u32) * cell + cell * 0.78, 8.0, "end", MUTED, name);
    }
    for col in 0..cols {
        if col % 4 == 0 {
            text_at(&mut s, left + fw(col as u32) * cell, 8.0, 8.0, "start", MUTED, &format!("S{}", col + 1));
        }
        for (row, day) in DAYS.iter().enumerate().take(rows) {
            let x = left + fw(col as u32) * cell;
            let y = top + fw(row as u32) * cell;
            let (fill, body) = match vals.get(col * rows + row) {
                Some(v) => {
                    let t = norm(*v, 0.0, sp);
                    let level = if t <= 0.0 {
                        LINE.to_string()
                    } else if t < 0.25 {
                        mix_hex(SURFACE, AMBER, 0.3)
                    } else if t < 0.5 {
                        mix_hex(SURFACE, AMBER, 0.55)
                    } else if t < 0.75 {
                        mix_hex(SURFACE, AMBER, 0.8)
                    } else {
                        AMBER.to_string()
                    };
                    (
                        level,
                        format!("S{} {} : {}", col + 1, day, fmt_val(*v)),
                    )
                }
                None => (
                    VOID.to_string(),
                    format!("S{} {} : {}", col + 1, day, "—"),
                ),
            };
            svg!(s, "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"2\" fill=\"{fill}\"><title>{}</title></rect>", cx(x), cx(y), cx(cell - gap), cx(cell - gap), esc(&body));
        }
    }
    svg!(s, "{}", close());
    s
}

// ────────────────────────── Histogramme ──────────────────────────

/// Histogramme vertical : une colonne par bucket, couleur selon son tone,
/// graduations à gauche et libellés d'abscisse.
pub fn histogram(buckets: &[Bucket], w: u32, h: u32) -> String {
    let w = w.max(60);
    let h = h.max(40);
    if buckets.is_empty() {
        return empty(w, h, NO_DATA);
    }
    let n = buckets.len();
    let left = 30.0_f64;
    let bottom = 18.0_f64;
    let top = 6.0_f64;
    let plot_w = (fw(w) - left - 4.0).max(1.0);
    let plot_h = (fw(h) - bottom - top).max(1.0);
    let gap = if n > 1 { 2.0 } else { 0.0 };
    let bar_w = ((plot_w - gap * (n as f64 - 1.0)) / n as f64).max(1.0);
    let vals: Vec<f64> = buckets.iter().map(|b| san(b.value)).collect();
    let (_, hi) = bounds(&vals);
    let sp = hi.max(0.0);
    let font = 9.0_f64;
    let chars = chars_in(bar_w, font);

    let mut s = open(w, h, "histogramme");
    for k in 0..=2_usize {
        let frac = fw(k as u32) / 2.0;
        let y = top + plot_h - plot_h * frac;
        svg!(s, "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{LINE}\" stroke-width=\"1\"/>", cx(left), cx(y), cx(fw(w) - 4.0), cx(y));
        text_at(&mut s, left - 4.0, y + 3.0, 8.0, "end", MUTED, &fmt_val(sp * frac));
    }
    for (i, b) in buckets.iter().enumerate() {
        let x = left + fw(i as u32) * (bar_w + gap);
        let frac = if sp > 1e-9 { norm(san(b.value), 0.0, sp) } else { 0.0 };
        let bh = (plot_h * frac).max(1.0);
        let y = top + plot_h - bh;
        svg!(s, "<g><title>{} : {}</title>", esc(&b.label), fmt_val(b.value));
        svg!(s, "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"1.5\" fill=\"{}\"/>", cx(x), cx(y), cx(bar_w), cx(bh), tone_color(&b.tone));
        text_at(&mut s, x + bar_w / 2.0, fw(h) - 5.0, font, "middle", MUTED, &clip_label(&b.label, chars));
        svg!(s, "</g>");
    }
    svg!(s, "{}", close());
    s
}

// ────────────────────── Anneau de progression ──────────────────────

/// Anneau de progression : `pct` en pourcentage (borné à 0..=100 pour le
/// tracé ; la valeur réelle reste lisible dans le `<title>`), valeur et
/// libellé au centre.
pub fn ring_progress(pct: f64, size: u32, tone: &str, label: &str) -> String {
    let size = size.max(36);
    let raw = san(pct);
    let frac = norm(raw, 0.0, 100.0);
    let color = tone_color(tone);
    let cxy = fw(size) / 2.0;
    let stroke = (fw(size) * 0.09).clamp(4.0, 12.0);
    let r = (cxy - stroke / 2.0 - 1.0).max(2.0);
    let circ = std::f64::consts::TAU * r;
    let font = (fw(size) * 0.24).clamp(10.0, 28.0);
    let lfont = (font * 0.36).clamp(8.0, 12.0);
    let title = if label.is_empty() {
        format!("{}%", fmt_val(raw))
    } else {
        format!("{label} : {}%", fmt_val(raw))
    };

    let mut s = open(size, size, &title);
    svg!(s, "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"{SURFACE}\" stroke=\"{LINE_STRONG}\" stroke-width=\"{}\"/>", cx(cxy), cx(cxy), cx(r), cx(stroke));
    svg!(s, "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"{}\" stroke-linecap=\"round\" stroke-dasharray=\"{} {}\" transform=\"rotate(-90 {} {})\"><title>{}</title></circle>", cx(cxy), cx(cxy), cx(r), cx(stroke), cx(circ * frac), cx(circ * (1.0 - frac)), cx(cxy), cx(cxy), esc(&title));
    text_at(&mut s, cxy, cxy + font * 0.12, font, "middle", PAPER, &format!("{:.0}%", raw.clamp(-999.0, 999.0)));
    if !label.is_empty() {
        text_at(&mut s, cxy, cxy + font * 1.05, lfont, "middle", MUTED, &clip_label(label, chars_in(fw(size) - 6.0, lfont)));
    }
    svg!(s, "{}", close());
    s
}
