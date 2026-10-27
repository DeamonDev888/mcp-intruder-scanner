// src/dash/db.rs — Couche PostgreSQL du tableau de bord MCP Intruder.
//
// Toutes les valeurs affichées par le tableau de bord proviennent d'ici :
// aucune donnée simulée, aucun chiffre en dur. Les compteurs de modules sont
// lus dans les tables relationnelles du catalogue, les sévérités dans
// audit_findings, les preuves dans audit_impact, la surface dans
// audit_subdomains ∪ audit_surface.
//
// Deux invariants structurent le fichier :
//
//  1. TOUTES les valeurs passent par des paramètres liés ($1..$n). Aucun
//     format!() n'interpole une donnée dans une chaîne SQL. Les seuls
//     littéraux SQL sont des noms de tables/colonnes et des mots-clés,
//     choisis dans ce fichier, jamais issus d'une entrée utilisateur.
//     La cible, un nom d'outil, une bannière de port ou une preuve brute
//     ne peuvent donc pas injecter de SQL.
//
//  2. Toute lecture est tolérante : try_get / .ok().flatten() partout,
//     un Vec vide si la table n'a rien, jamais de panique. Une colonne dont
//     le type diffère (INT, TIMESTAMPTZ, BOOL, text[]) est castée en SQL
//     (`col::text`) AVANT d'être lue dans un Option<String> — sinon le
//     décodeur postgres lève « error retrieving column » et tue le process.
//     Les bools sont donc lus comme du texte 'true'/'false' et comparés en
//     Rust ; les tableaux text[] passent par array_to_string ; les
//     timestamptz par to_char.
//
// Piège d'ORDER BY documenté : quand la sortie caste une colonne
// (`id::text AS scan_id`), un `ORDER BY id` non qualifié résout la colonne
// de SORTIE (le texte) et trie lexicographiquement — 99, 97, 96, 9, 88….
// Tout ORDER BY de ce fichier qualifie donc explicitement `audit_scans.id`
// ou `table.colonne`.

use postgres::{Client, NoTls};
use std::time::Duration;

use crate::dash::model::{
    Bucket, DnsRow, Finding, HeaderRow, HostRow, ImpactVerdict, Kpis, LootRow, Machine, ModuleStat,
    Overview, PortRow, ScanRow, Series, ServiceState, TlsRow, ToolStat,
};

/// Nombre de points du graphique miniature d'un module (8 derniers scans).
const SPARK_POINTS: usize = 8;
/// Nombre de scans listés par défaut dans le sélecteur du tableau de bord.
const SCANS_WINDOW: i64 = 14;

/// Source de données d'un module : la table dont on lit le nombre de lignes
/// pour le scan affiché. `Tool` pointe une entrée d'audit_tool_outputs.
#[derive(Clone, Copy)]
enum Src {
    DnsRecords,
    DnsHardening,
    Ports,
    Headers,
    Subdomains,
    Tls,
    Tech,
    Geo,
    EmailSec,
    WebEndpoints,
    Loot,
    Findings,
    Impacts,
    Scans,
    /// Aucune table ne porte le résultat du module : il reste à 0 plutôt que
    /// d'emprunter les données d'un autre module (box_prober vit dans le
    /// payload JSONB du scan, pas dans une table relationnelle).
    None,
    Tool(&'static str),
}

/// Les 36 modules Rust du scanner, dans l'ordre du REGISTRY de
/// src/bin/dashboard.rs. `count` est lu dans la table pointée par `src`.
struct Mod {
    key: &'static str,
    label: &'static str,
    group: &'static str,
    tool: &'static str,
    blurb: &'static str,
    src: Src,
    /// Catégories de audit_findings rattachées au domaine du module ; la
    /// sévérité max du module est la plus haute parmi ces catégories.
    cats: &'static [&'static str],
}

const MODULES: &[Mod] = &[
    Mod {
        key: "dns",
        label: "DNS",
        group: "réseau",
        tool: "interne",
        blurb: "liste les enregistrements DNS du domaine (A, MX, TXT, SPF…)",
        src: Src::DnsRecords,
        cats: &["DNS"],
    },
    Mod {
        key: "dns_hardening",
        label: "Durcissement DNS",
        group: "réseau",
        tool: "interne",
        blurb: "vérifie si le serveur DNS répond trop permissivement",
        src: Src::DnsHardening,
        cats: &["DNS"],
    },
    Mod {
        key: "netdns",
        label: "Net DNS",
        group: "réseau",
        tool: "interne",
        blurb: "interroge les serveurs DNS du domaine en réseau",
        src: Src::DnsRecords,
        cats: &["DNS"],
    },
    Mod {
        key: "dnsrecon_audit",
        label: "dnsrecon",
        group: "réseau",
        tool: "dnsrecon",
        blurb: "cherche des sous-domaines oubliés avec l'outil dnsrecon",
        src: Src::Tool("dnsrecon"),
        cats: &["DNS"],
    },
    Mod {
        key: "ports",
        label: "Ports",
        group: "réseau",
        tool: "interne",
        blurb: "regarde quels ports sont ouverts sur la machine",
        src: Src::Ports,
        cats: &["PORT", "NMAP"],
    },
    Mod {
        key: "full_portscan",
        label: "Full portscan",
        group: "réseau",
        tool: "nmap",
        blurb: "balaie tous les ports avec nmap",
        src: Src::Ports,
        cats: &["PORT", "NMAP"],
    },
    Mod {
        key: "portscan_rustscan",
        label: "rustscan",
        group: "réseau",
        tool: "rustscan",
        blurb: "trouve les ports ouverts puis lance nmap dessus",
        src: Src::Tool("rustscan"),
        cats: &["PORT", "NMAP"],
    },
    Mod {
        key: "http",
        label: "HTTP",
        group: "web",
        tool: "interne",
        blurb: "lit les en-têtes renvoyés par le site web",
        src: Src::Headers,
        cats: &["HTTP", "COOKIE", "SRI"],
    },
    Mod {
        key: "http_probe",
        label: "HTTP probe",
        group: "web",
        tool: "interne",
        blurb: "teste si le site répond et avec quel code HTTP",
        src: Src::Ports,
        cats: &["PORT", "HTTP"],
    },
    Mod {
        key: "nethttp",
        label: "Net HTTP",
        group: "web",
        tool: "interne",
        blurb: "analyse les réponses HTTP en réseau",
        src: Src::Headers,
        cats: &["HTTP", "COOKIE", "SRI"],
    },
    Mod {
        key: "http_probe_budget",
        label: "Probe budget",
        group: "web",
        tool: "interne",
        blurb: "mesure le temps et le nombre de sondes HTTP autorisées",
        src: Src::Ports,
        cats: &["PORT", "HTTP"],
    },
    Mod {
        key: "web_endpoints",
        label: "Endpoints web",
        group: "web",
        tool: "interne",
        blurb: "regarde security.txt, robots.txt et les méthodes HTTP permises",
        src: Src::WebEndpoints,
        cats: &["WEB"],
    },
    Mod {
        key: "ffuf_audit",
        label: "ffuf",
        group: "web",
        tool: "ffuf",
        blurb: "regarde si le site laisse filtrer des fichiers secrets",
        src: Src::Tool("ffuf"),
        cats: &["WEB"],
    },
    Mod {
        key: "nikto_deep",
        label: "nikto",
        group: "web",
        tool: "nikto",
        blurb: "cherche des failles connues avec nikto",
        src: Src::Tool("nikto"),
        cats: &["NIKTO"],
    },
    Mod {
        key: "nuclei_deep",
        label: "nuclei",
        group: "web",
        tool: "nuclei",
        blurb: "teste des failles connues avec nuclei",
        src: Src::Tool("nuclei"),
        cats: &["NUCLEI"],
    },
    Mod {
        key: "vuln_audit",
        label: "Vuln audit",
        group: "web",
        tool: "nuclei",
        blurb: "cherche les vulnérabilités exploitables du site",
        src: Src::Tool("nuclei"),
        cats: &["NUCLEI"],
    },
    Mod {
        key: "sslscan_audit",
        label: "sslscan",
        group: "web",
        tool: "sslscan",
        blurb: "détaille les chiffrements et failles SSL/TLS",
        src: Src::Tool("sslscan"),
        cats: &["TLS"],
    },
    Mod {
        key: "obscura_audit",
        label: "obscura",
        group: "web",
        tool: "obscura",
        blurb: "cherche les fichiers oubliés dans les répertoires du site",
        src: Src::Tool("obscura"),
        cats: &["OBSCURA"],
    },
    Mod {
        key: "waf",
        label: "WAF",
        group: "détection",
        tool: "wafw00f",
        blurb: "détecte si un pare-feu applicatif protège le site",
        src: Src::Tool("wafw00f"),
        cats: &["WAF"],
    },
    Mod {
        key: "tech_stack",
        label: "Tech stack",
        group: "détection",
        tool: "whatweb",
        blurb: "devine les technologies utilisées par le site",
        src: Src::Tech,
        cats: &["HTTP"],
    },
    Mod {
        key: "scheme_detect",
        label: "Schéma",
        group: "détection",
        tool: "interne",
        blurb: "repère les sous-domaines qui exposent un schéma particulier",
        src: Src::Subdomains,
        cats: &["SUBDOMAIN"],
    },
    Mod {
        key: "brand_sec",
        label: "Marque",
        group: "détection",
        tool: "interne",
        blurb: "cherche des sites qui usurpent la marque",
        src: Src::Subdomains,
        cats: &["BRAND"],
    },
    Mod {
        key: "subdomains",
        label: "Sous-domaines",
        group: "surface",
        tool: "crt.sh",
        blurb: "trouve les sous-domaines via les certificats et le DNS",
        src: Src::Subdomains,
        cats: &["SUBDOMAIN"],
    },
    Mod {
        key: "crt_sh",
        label: "crt.sh",
        group: "surface",
        tool: "crt.sh",
        blurb: "liste les sous-domaines visibles dans les certificats TLS",
        src: Src::Subdomains,
        cats: &["SUBDOMAIN"],
    },
    Mod {
        key: "box_prober",
        label: "Box prober",
        group: "surface",
        tool: "interne",
        blurb: "teste si l'appareil est une box CSU/CPE accessible",
        src: Src::None,
        cats: &["BOX"],
    },
    Mod {
        key: "theharvester_audit",
        label: "theHarvester",
        group: "surface",
        tool: "theharvester",
        blurb: "récolte des mails et des noms liés au domaine",
        src: Src::Tool("theharvester"),
        cats: &["OSINT"],
    },
    Mod {
        key: "geo",
        label: "Géoloc / ASN",
        group: "surface",
        tool: "interne",
        blurb: "situe géographiquement les adresses IP du domaine",
        src: Src::Geo,
        cats: &["GEO"],
    },
    Mod {
        key: "tls",
        label: "TLS",
        group: "surface",
        tool: "interne",
        blurb: "lit les certificats et les versions TLS acceptées",
        src: Src::Tls,
        cats: &["TLS"],
    },
    Mod {
        key: "email_sec",
        label: "Email & anti-spoof",
        group: "surface",
        tool: "interne",
        blurb: "vérifie SPF, DKIM, DMARC, BIMI et MTA-STS",
        src: Src::EmailSec,
        cats: &["EMAIL"],
    },
    Mod {
        key: "whois_audit",
        label: "WHOIS",
        group: "surface",
        tool: "whois",
        blurb: "lit les informations d'enregistrement du domaine",
        src: Src::Tool("whois"),
        cats: &["WHOIS"],
    },
    Mod {
        key: "loot",
        label: "Loot",
        group: "preuve",
        tool: "interne",
        blurb: "récupère les fichiers trouvés avec leur empreinte sha256",
        src: Src::Loot,
        cats: &["SECRETS"],
    },
    Mod {
        key: "impact",
        label: "Impact",
        group: "preuve",
        tool: "interne",
        blurb: "prouve ou non un accès réel au service",
        src: Src::Impacts,
        cats: &[],
    },
    Mod {
        key: "findings",
        label: "Findings",
        group: "preuve",
        tool: "interne",
        blurb: "liste tous les constats de sécurité du scan",
        src: Src::Findings,
        cats: &[],
    },
    Mod {
        key: "progress",
        label: "Progression",
        group: "preuve",
        tool: "interne",
        blurb: "montre l'avancement du scan et ses constats",
        src: Src::Findings,
        cats: &[],
    },
    Mod {
        key: "db",
        label: "Catalogue DB",
        group: "preuve",
        tool: "interne",
        blurb: "montre le nombre de scans catalogués en base",
        src: Src::Scans,
        cats: &[],
    },
    Mod {
        key: "mod",
        label: "Dispatcher",
        group: "preuve",
        tool: "interne",
        blurb: "oriente le scan vers les modules utiles",
        src: Src::Impacts,
        cats: &[],
    },
];

// ─────────────────────────────────────────────────────────────── connexion ──

/// Ouvre une connexion PostgreSQL via socket Unix (auth peer de l'OS : aucun
/// mot de passe, aucun TCP exposé). Même logique que `DatabaseManager::connect`
/// de src/modules/db.rs, avec un `application_name` propre au tableau de bord
/// pour que les scans visibles dans pg_stat_activity se distinguent.
/// Le nom de base transite par l'API builder : jamais par une concaténation.
pub fn connect(db_name: &str) -> Result<Client, String> {
    let mut last_err = String::new();
    for dir in ["/var/run/postgresql", "/tmp"] {
        let mut cfg = postgres::Config::new();
        cfg.dbname(db_name)
            .host(dir)
            .application_name("mcp-intruder_dashboard")
            .connect_timeout(Duration::from_secs(10))
            .options("-c statement_timeout=55000");
        match cfg.connect(NoTls) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = format!("socket {dir} : {e}"),
        }
    }
    Err(format!(
        "PostgreSQL injoignable via socket locale ({last_err})"
    ))
}

// ───────────────────────────────────────────────────────────────── helpers ──

type P<'a> = &'a [&'a (dyn postgres::types::ToSql + Sync)];

/// Liste vide de paramètres : évite d'allouer un Vec à chaque appel sans arg.
const NO_PARAMS: P<'static> = &[];

fn row_i64(r: &postgres::Row, i: usize) -> i64 {
    r.try_get::<_, i64>(i).unwrap_or(0)
}

fn row_f64(r: &postgres::Row, i: usize) -> f64 {
    r.try_get::<_, f64>(i).unwrap_or(0.0)
}

/// Lit une colonne déjà castée en texte côté SQL (`col::text`). Le try_get
/// absorbs un type inattendu : on obtient None, pas une panique.
fn row_text(r: &postgres::Row, i: usize) -> String {
    r.try_get::<_, Option<String>>(i)
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn row_opt_text(r: &postgres::Row, i: usize) -> Option<String> {
    r.try_get::<_, Option<String>>(i).ok().flatten()
}

/// Les bools sont castés en texte (`col::text`) puis comparés ici : lire un
/// BOOL dans un Option<String> ferait échouer la récupération de la colonne.
fn row_bool(r: &postgres::Row, i: usize) -> bool {
    row_text(r, i).eq_ignore_ascii_case("true")
}

/// Exécute une requête et renvoie les lignes, ou un Vec vide si elle échoue.
/// Aucune erreur ne se propage : une section vide vaut mieux qu'une page morte.
fn rows(c: &mut Client, sql: &str, p: P<'_>) -> Vec<postgres::Row> {
    c.query(sql, p).unwrap_or_default()
}

/// Première colonne de la première ligne, ou 0.
fn scalar_i64(c: &mut Client, sql: &str, p: P<'_>) -> i64 {
    c.query_opt(sql, p)
        .ok()
        .flatten()
        .map(|r| row_i64(&r, 0))
        .unwrap_or(0)
}

fn scalar_f64(c: &mut Client, sql: &str, p: P<'_>) -> f64 {
    c.query_opt(sql, p)
        .ok()
        .flatten()
        .map(|r| row_f64(&r, 0))
        .unwrap_or(0.0)
}

fn text_opt(c: &mut Client, sql: &str, p: P<'_>) -> Option<String> {
    c.query_opt(sql, p)
        .ok()
        .flatten()
        .and_then(|r| row_opt_text(&r, 0))
}

/// Classe CSS de couleur d'une sévérité.
fn sev_tone(sev: &str) -> &'static str {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => "crit",
        "HIGH" => "high",
        "MEDIUM" => "med",
        "LOW" => "low",
        _ => "info",
    }
}

/// Classe CSS d'une évaluation d'en-tête HTTP.
fn eval_tone(ev: &str) -> &'static str {
    match ev.to_ascii_uppercase().as_str() {
        "PASS" => "ok",
        "WARNING" => "med",
        "MISSING" => "high",
        _ => "info",
    }
}

/// Rang de tri d'une sévérité (5 = la plus grave). 0 pour un texte inconnu.
fn sev_rank(sev: &str) -> i32 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 5,
        "HIGH" => 4,
        "MEDIUM" => 3,
        "LOW" => 2,
        "INFO" => 1,
        _ => 0,
    }
}

// ──────────────────────────────────────────────────────────────── overview ──

/// Résout le scan à afficher : l'id demandé s'il existe, sinon le plus
/// récent. Retourne (scan_id, target, date, score).
fn resolve_scan(c: &mut Client, wanted: Option<i64>) -> (i64, String, String, i32) {
    let id = match wanted {
        Some(id) if id > 0 => {
            let ok = scalar_i64(
                c,
                "SELECT count(*) FROM audit_scans WHERE audit_scans.id = $1",
                &[&id],
            );
            if ok > 0 {
                id
            } else {
                latest_scan_id(c)
            }
        }
        _ => latest_scan_id(c),
    };
    let head = rows(
        c,
        "SELECT audit_scans.target::text,
                to_char(audit_scans.created_at,'DD.MM.YYYY · HH24:MI'),
                COALESCE(audit_scans.overall_score::text,'0')
         FROM audit_scans
         WHERE audit_scans.id = $1",
        &[&id],
    );
    match head.first() {
        Some(r) => (
            id,
            row_text(r, 0),
            row_text(r, 1),
            row_text(r, 2).parse().unwrap_or(0),
        ),
        None => (id, "aucun scan".to_string(), "—".to_string(), 0),
    }
}

fn latest_scan_id(c: &mut Client) -> i64 {
    scalar_i64(
        c,
        "SELECT audit_scans.id FROM audit_scans ORDER BY audit_scans.id DESC LIMIT 1",
        NO_PARAMS,
    )
}

/// Charge tout le tableau de bord pour un scan. Les sections `live` et
/// `machine` ne viennent pas de PostgreSQL (processus et hôte) : elles sont
/// vides ici et l'appelant les remplit — le tableau de bord ne doit jamais
/// afficher de la donnée inventée.
pub fn fetch_overview(c: &mut Client, db: &str, scan: Option<i64>) -> Result<Overview, String> {
    let (id, target, date, score) = resolve_scan(c, scan);
    if id == 0 {
        return Err("aucun scan catalogué dans la base".to_string());
    }

    let kpis = fetch_kpis(c, id);
    let modules = fetch_modules(c, id);
    let (severity, categories, dns_types, header_eval) = fetch_buckets(c, id);

    Ok(Overview {
        generated_at: generated_at(c),
        db_name: db.to_string(),
        current_scan: id,
        target: target.clone(),
        scan_date: date,
        score,
        kpis,
        modules,
        severity,
        categories,
        dns_types,
        header_eval,
        tools: fetch_tools(c, id),
        impacts: fetch_impacts(c, &target),
        findings: fetch_findings(c, id, 20),
        scans: fetch_scans(c, SCANS_WINDOW),
        ports: fetch_ports(c, id),
        hosts: fetch_hosts(c, id),
        headers: fetch_headers(c, id),
        dns: fetch_dns(c, id),
        tls: fetch_tls(c, id),
        loot: fetch_loot(c, id),
        score_series: fetch_series(c, Some(target.clone())).0,
        findings_series: fetch_series(c, Some(target)).1,
        port_histogram: fetch_port_histogram(c, id),
        live: Vec::new(),
        machine: empty_machine(),
    })
}

/// Placeholder `Machine`. Le tableau de bord n'invente PAS de métriques
/// hôte : db.rs ne lit que PostgreSQL, donc il renvoie une structure vide que
/// l'appelant remplace par `machine::snapshot()` (voir server.rs). Zéros et
/// chaînes vides, jamais des valeurs(devinées).
fn empty_machine() -> Machine {
    Machine {
        host: String::new(),
        os: String::new(),
        cores: 0,
        cpu_pct: 0.0,
        load: Vec::new(),
        ram_total_mb: 0,
        ram_used_mb: 0,
        swap_used_mb: 0,
        disk_used_pct: 0.0,
        disk_total_gb: 0.0,
        disk_free_gb: 0.0,
        uptime_s: 0,
        net_rx_mb: 0.0,
        net_tx_mb: 0.0,
        services: Vec::<ServiceState>::new(),
        scanner_running: false,
        active_scans: 0,
    }
}

/// Timestamp de génération de la page, lu par le serveur (jamais l'horloge
/// du client) pour que l'horodatage reste celui du catalogue.
pub fn generated_at(c: &mut Client) -> String {
    text_opt(
        c,
        "SELECT to_char(now(),'DD.MM.YYYY · HH24:MI:SS')",
        NO_PARAMS,
    )
    .unwrap_or_default()
}

// Requetes par domaine (ex-fichier monolithique de 1 473 lignes) ; les
// re-exports preservent les chemins dash::db::fetch_* pour server.rs/scans.rs.
mod kpis;
mod modules;
mod scans;
mod series;
mod surface;

pub use kpis::{db_size_mb, fetch_findings, fetch_impacts, fetch_kpis, fetch_tools};
pub use modules::fetch_modules;
pub use scans::{fetch_scans, list_targets};
pub use series::{fetch_buckets, fetch_series};
pub use surface::{
    fetch_dns, fetch_headers, fetch_hosts, fetch_loot, fetch_port_histogram, fetch_ports, fetch_tls,
};
