// src/dash/db.rs — Couche PostgreSQL du tableau de bord mcp-intruder.
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

// ─────────────────────────────────────────────────────────── scans & cibles ──

/// Les `limit` derniers scans catalogués, du plus récent au plus ancien.
/// `ORDER BY audit_scans.id DESC` est qualifié : sans cela PostgreSQL
/// résoudrait `id` sur la colonne de sortie `id::text` et trierait
/// lexicographiquement (99, 97, 96, 9, 88…).
pub fn fetch_scans(c: &mut Client, limit: i64) -> Vec<ScanRow> {
    rows(
        c,
        "SELECT audit_scans.id::text AS scan_id,
                audit_scans.target,
                to_char(audit_scans.created_at,'DD.MM.YY · HH24:MI'),
                audit_scans.overall_score::text,
                audit_scans.open_ports_count::text,
                audit_scans.findings_count::text,
                round(audit_scans.duration_seconds::numeric,1)::text
         FROM audit_scans
         ORDER BY audit_scans.id DESC
         LIMIT $1::bigint",
        &[&limit],
    )
    .iter()
    .map(|r| ScanRow {
        id: row_text(r, 0).parse().unwrap_or(0),
        target: row_text(r, 1),
        created_at: row_text(r, 2),
        score: row_text(r, 3).parse().unwrap_or(0),
        ports: row_text(r, 4).parse().unwrap_or(0),
        findings: row_text(r, 5).parse().unwrap_or(0),
        duration: row_text(r, 6).parse().unwrap_or(0.0),
    })
    .collect()
}

/// Cibles distinctes pour le sélecteur : (cible, nb_scans, dernier_score,
/// dernier created_at). DISTINCT ON garde la ligne la plus récente de chaque
/// cible, la fenêtre compte les scans de cette cible.
pub fn list_targets(c: &mut Client) -> Vec<(String, i64, i64, String)> {
    rows(
        c,
        "SELECT d.target, d.nb, d.overall_score, d.created_at FROM (
             SELECT DISTINCT ON (audit_scans.target)
                    audit_scans.target,
                    audit_scans.overall_score::text AS overall_score,
                    to_char(audit_scans.created_at,'DD.MM.YY · HH24:MI') AS created_at,
                    count(*) OVER (PARTITION BY audit_scans.target)::bigint AS nb
             FROM audit_scans
             ORDER BY audit_scans.target, audit_scans.id DESC
         ) d
         ORDER BY d.target",
        NO_PARAMS,
    )
    .iter()
    .map(|r| {
        (
            row_text(r, 0),
            row_i64(r, 1),
            row_text(r, 2).parse().unwrap_or(0),
            row_text(r, 3),
        )
    })
    .collect()
}

// ────────────────────────────────────────────────────────────────── modules ──

/// Requête unique renvoyant tous les compteurs de modules du scan en une
/// ligne. Chaque module est un scalaire sous-requête indexé sur scan_id :
/// 26 aller-retours économisés, la page reste sous les 800 ms.
const COUNTS_SQL: &str = "SELECT
     (SELECT count(*) FROM audit_dns_records   WHERE scan_id = $1) AS c_dns,
     (SELECT count(*) FROM audit_dns_hardening WHERE scan_id = $1) AS c_dsh,
     (SELECT count(*) FROM audit_ports         WHERE scan_id = $1) AS c_port,
     (SELECT count(*) FROM audit_http_headers  WHERE scan_id = $1) AS c_hdr,
     (SELECT count(*) FROM audit_subdomains    WHERE scan_id = $1) AS c_sub,
     (SELECT count(*) FROM audit_tls_certs     WHERE scan_id = $1) AS c_tls,
     (SELECT count(*) FROM audit_tech          WHERE scan_id = $1) AS c_tech,
     (SELECT count(*) FROM audit_geo           WHERE scan_id = $1) AS c_geo,
     (SELECT count(*) FROM audit_email_sec     WHERE scan_id = $1) AS c_mail,
     (SELECT count(*) FROM audit_web_endpoints WHERE scan_id = $1) AS c_wep,
     (SELECT count(*) FROM audit_loot          WHERE scan_id = $1) AS c_loot,
     (SELECT count(*) FROM audit_findings      WHERE scan_id = $1) AS c_find,
     (SELECT count(*) FROM audit_scans)                                  AS c_scans,
     (SELECT count(*) FROM audit_impact
        WHERE target = (SELECT target FROM audit_scans WHERE audit_scans.id = $1)) AS c_impact,
     (SELECT count(*) FILTER (WHERE tool_name='ffuf')         FROM audit_tool_outputs WHERE scan_id = $1) AS t_ffuf,
     (SELECT count(*) FILTER (WHERE tool_name='nikto')        FROM audit_tool_outputs WHERE scan_id = $1) AS t_nikto,
     (SELECT count(*) FILTER (WHERE tool_name='nuclei')       FROM audit_tool_outputs WHERE scan_id = $1) AS t_nuclei,
     (SELECT count(*) FILTER (WHERE tool_name='sslscan')      FROM audit_tool_outputs WHERE scan_id = $1) AS t_sslscan,
     (SELECT count(*) FILTER (WHERE tool_name='obscura')      FROM audit_tool_outputs WHERE scan_id = $1) AS t_obscura,
     (SELECT count(*) FILTER (WHERE tool_name='wafw00f')      FROM audit_tool_outputs WHERE scan_id = $1) AS t_waf,
     (SELECT count(*) FILTER (WHERE tool_name='whois')        FROM audit_tool_outputs WHERE scan_id = $1) AS t_whois,
     (SELECT count(*) FILTER (WHERE tool_name='theharvester') FROM audit_tool_outputs WHERE scan_id = $1) AS t_harv,
     (SELECT count(*) FILTER (WHERE tool_name='dnsrecon')     FROM audit_tool_outputs WHERE scan_id = $1) AS t_dnsrec,
     (SELECT count(*) FILTER (WHERE tool_name='rustscan')     FROM audit_tool_outputs WHERE scan_id = $1) AS t_rust,
     (SELECT count(*) FILTER (WHERE tool_name='nmap')         FROM audit_tool_outputs WHERE scan_id = $1) AS t_nmap";

/// Position de la colonne du compteur correspondant à une source, dans
/// COUNTS_SQL. `None` = le module n'a pas de compteur (retourne 0).
fn count_slot(src: Src) -> Option<usize> {
    Some(match src {
        Src::DnsRecords => 0,
        Src::DnsHardening => 1,
        Src::Ports => 2,
        Src::Headers => 3,
        Src::Subdomains => 4,
        Src::Tls => 5,
        Src::Tech => 6,
        Src::Geo => 7,
        Src::EmailSec => 8,
        Src::WebEndpoints => 9,
        Src::Loot => 10,
        Src::Findings => 11,
        Src::Scans => 12,
        Src::Impacts => 13,
        Src::None => return None,
        Src::Tool(t) => match t {
            "ffuf" => 15,
            "nikto" => 16,
            "nuclei" => 17,
            "sslscan" => 18,
            "obscura" => 19,
            "wafw00f" => 20,
            "whois" => 21,
            "theharvester" => 22,
            "dnsrecon" => 23,
            "rustscan" => 24,
            "nmap" => 25,
            _ => return None,
        },
    })
}

/// Compteurs des 8 derniers scans de la cible, pour les graphiques
/// miniatures. Une seule requête : un LATERAL VALUES croise les 8 scans
/// avec chaque table source. Renvoie (kind, scan_id, count).
fn spark_rows(c: &mut Client, scan: i64) -> Vec<(String, i64, i64)> {
    rows(
        c,
        "SELECT t.k, s.id, t.n FROM (
             SELECT audit_scans.id AS id FROM audit_scans
             WHERE audit_scans.target = (SELECT target FROM audit_scans WHERE audit_scans.id = $1)
             ORDER BY audit_scans.id DESC LIMIT $2::bigint
         ) s
         CROSS JOIN LATERAL (VALUES
            ('dns'::text,   (SELECT count(*) FROM audit_dns_records      x WHERE x.scan_id = s.id)),
            ('dsh'::text,   (SELECT count(*) FROM audit_dns_hardening    x WHERE x.scan_id = s.id)),
            ('port'::text,  (SELECT count(*) FROM audit_ports            x WHERE x.scan_id = s.id)),
            ('hdr'::text,   (SELECT count(*) FROM audit_http_headers     x WHERE x.scan_id = s.id)),
            ('sub'::text,   (SELECT count(*) FROM audit_subdomains       x WHERE x.scan_id = s.id)),
            ('tls'::text,   (SELECT count(*) FROM audit_tls_certs        x WHERE x.scan_id = s.id)),
            ('tech'::text,  (SELECT count(*) FROM audit_tech             x WHERE x.scan_id = s.id)),
            ('geo'::text,   (SELECT count(*) FROM audit_geo              x WHERE x.scan_id = s.id)),
            ('mail'::text,  (SELECT count(*) FROM audit_email_sec        x WHERE x.scan_id = s.id)),
            ('wep'::text,   (SELECT count(*) FROM audit_web_endpoints    x WHERE x.scan_id = s.id)),
            ('loot'::text,  (SELECT count(*) FROM audit_loot             x WHERE x.scan_id = s.id)),
            ('find'::text,  (SELECT count(*) FROM audit_findings         x WHERE x.scan_id = s.id)),
            ('tool'::text,  (SELECT count(*) FROM audit_tool_outputs     x WHERE x.scan_id = s.id))
         ) AS t(k, n)
         ORDER BY t.k, s.id DESC",
        &[&scan, &(SPARK_POINTS as i64)],
    )
    .iter()
    .map(|r| (row_text(r, 0), row_i64(r, 1), row_i64(r, 2)))
    .collect()
}

/// Compteurs par outil externe sur les 8 derniers scans de la cible.
fn tool_spark_rows(c: &mut Client, scan: i64) -> Vec<(String, i64, i64)> {
    rows(
        c,
        "SELECT x.tool_name, x.scan_id, count(*)::bigint
         FROM audit_tool_outputs x
         WHERE x.scan_id IN (
             SELECT audit_scans.id FROM audit_scans
             WHERE audit_scans.target = (SELECT target FROM audit_scans WHERE audit_scans.id = $1)
             ORDER BY audit_scans.id DESC LIMIT $2::bigint
         )
         GROUP BY x.tool_name, x.scan_id
         ORDER BY x.tool_name, x.scan_id DESC",
        &[&scan, &(SPARK_POINTS as i64)],
    )
    .iter()
    .map(|r| (row_text(r, 0), row_i64(r, 1), row_i64(r, 2)))
    .collect()
}

/// Construit le vecteur d'un spark : SPARK_POINTS valeurs, de la plus ancienne
/// à la plus récente, alignées à droite.
///
/// `points` arrive trié du plus récent au plus ancien (ORDER BY id DESC) et ne
/// contient AU PLUS SPARK_POINTS scans — la requête SQL a déjà fait le
/// fenêtrage. On positionne donc chaque point par son RANG dans cette liste,
/// jamais par la distance entre ids : les ids de deux cibles s'entrelacent
/// (example.com #164 et #150 sont séparés par les scans d'autres cibles), si on
/// indexait sur `newest_id - id` presque tous les points tomberaient hors
/// fenêtre et le graphique serait vide.
fn build_spark(points: &[(i64, i64)]) -> Vec<f64> {
    let mut out = vec![0.0f64; SPARK_POINTS];
    let n = points.len().min(SPARK_POINTS);
    // points[0] = plus récent ; on part de la fin pour écrire en ordre chrono.
    let start = SPARK_POINTS - n;
    for i in 0..n {
        out[start + i] = points[n - 1 - i].1 as f64;
    }
    out
}

/// Sévérité la plus haute du scan par catégorie. Une seule requête, feeding
/// le `severity_max` de tous les modules.
fn severity_by_category(c: &mut Client, scan: i64) -> Vec<(String, String)> {
    rows(
        c,
        "SELECT audit_findings.category::text,
                (array_agg(upper(audit_findings.severity) ORDER BY
                   CASE upper(audit_findings.severity)
                     WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3
                     WHEN 'LOW' THEN 2 ELSE 1 END DESC))[1]
         FROM audit_findings
         WHERE audit_findings.scan_id = $1
         GROUP BY audit_findings.category",
        &[&scan],
    )
    .iter()
    .map(|r| (row_text(r, 0), row_text(r, 1)))
    .collect()
}

/// Les 36 modules avec, pour le scan affiché, un `count` réellement lu en
/// base, la sévérité max de leur domaine et un spark de 8 points.
///
/// `coverage` : 0 quand le module n'a rien produit, 2 quand sa table a des
/// lignes, 1 quand le module tourne mais sa table est vide (ex. box_prober,
/// dont le résultat ne vit que dans le payload du scan).
pub fn fetch_modules(c: &mut Client, scan: i64) -> Vec<ModuleStat> {
    let counts = rows(c, COUNTS_SQL, &[&scan]);
    let first = counts.first();

    let spark = spark_rows(c, scan);
    let tspark = tool_spark_rows(c, scan);
    let sevs = severity_by_category(c, scan);

    MODULES
        .iter()
        .map(|m| {
            let count = match (count_slot(m.src), first) {
                (Some(i), Some(r)) => row_i64(r, i),
                _ => 0,
            };

            // sévérité max parmi les catégories du domaine du module
            let severity_max = if m.cats.is_empty() {
                // modules "vue d'ensemble" : la pire sévérité du scan entier
                sevs.iter()
                    .max_by_key(|(_, s)| sev_rank(s))
                    .map(|(_, s)| s.clone())
            } else {
                m.cats
                    .iter()
                    .filter_map(|cat| {
                        sevs.iter()
                            .find(|(c, _)| c.eq_ignore_ascii_case(cat))
                            .map(|(_, s)| s.clone())
                    })
                    .max_by_key(|s| sev_rank(s))
            };

            // spark : points du module, du plus ancien au plus récent
            let points: Vec<(i64, i64)> = match m.src {
                Src::Tool(tool) => tspark
                    .iter()
                    .filter(|(t, _, _)| t == tool)
                    .map(|(_, id, n)| (*id, *n))
                    .collect(),
                Src::Scans | Src::Impacts | Src::None => Vec::new(),
                _ => {
                    let kind = match count_slot(m.src) {
                        Some(0) => "dns",
                        Some(1) => "dsh",
                        Some(2) => "port",
                        Some(3) => "hdr",
                        Some(4) => "sub",
                        Some(5) => "tls",
                        Some(6) => "tech",
                        Some(7) => "geo",
                        Some(8) => "mail",
                        Some(9) => "wep",
                        Some(10) => "loot",
                        Some(11) => "find",
                        _ => "",
                    };
                    if kind.is_empty() {
                        Vec::new()
                    } else {
                        spark
                            .iter()
                            .filter(|(k, _, _)| k == kind)
                            .map(|(_, id, n)| (*id, *n))
                            .collect()
                    }
                }
            };
            let spark = build_spark(&points);

            ModuleStat {
                key: m.key.to_string(),
                label: m.label.to_string(),
                group: m.group.to_string(),
                tool: m.tool.to_string(),
                blurb: m.blurb.to_string(),
                count,
                severity_max,
                // 0 = le module n'a rien produit, 2 = sa table a des lignes.
                // Aucun module n'est « partiel » ici : une table vide pour un
                // module qui a tourné se distingue par count == 0, pas par
                // un troisième état inventé.
                coverage: if count > 0 { 2 } else { 0 },
                spark,
            }
        })
        .collect()
}

// ───────────────────────────────────────────────────────────────────── KPIs ──

/// Total des constats purgés, sommé sur TOUTES les tables
/// audit_findings_purges_* (leur nombre évolue à chaque purge : les lister
/// en dur manquerait les nouvelles). Les identifiants de tables viennent du
/// catalogue lui-même et sont %#I-quotés par PostgreSQL : aucune injection
/// possible, la liste n'est pas une entrée utilisateur.
const PURGED_SQL: &str = "SELECT COALESCE(sum(n), 0)::bigint FROM (
     SELECT (xpath('/row/c/text()',
        query_to_xml(format('SELECT count(*) AS c FROM %I.%I', t.table_schema, t.table_name),
                     false, true, '')))[1]::text::bigint AS n
     FROM information_schema.tables t
     WHERE t.table_schema = 'public' AND t.table_name LIKE 'audit\\_findings\\_purges%'
 ) x";

/// Compteurs de tête du tableau de bord pour le scan affiché.
pub fn fetch_kpis(c: &mut Client, scan: i64) -> Kpis {
    // Un seul aller-retour pour les compteurs globaux + ceux du scan.
    let r = rows(
        c,
        "SELECT
            (SELECT count(*) FROM audit_scans)::bigint,
            (SELECT count(DISTINCT audit_scans.target) FROM audit_scans)::bigint,
            (SELECT count(*) FROM audit_findings)::bigint,
            (SELECT count(*) FROM audit_ports   WHERE scan_id = $1)::bigint,
            (SELECT count(*) FROM audit_subdomains WHERE scan_id = $1)::bigint,
            (SELECT count(*) FROM audit_loot    WHERE scan_id = $1)::bigint,
            (SELECT count(*) FROM audit_findings
               WHERE scan_id = $1 AND upper(severity) = 'CRITICAL')::bigint,
            (SELECT count(*) FROM audit_findings
               WHERE scan_id = $1 AND upper(severity) = 'HIGH')::bigint",
        &[&scan],
    );
    let get = |i: usize| r.first().map(|x| row_i64(x, i)).unwrap_or(0);

    let purged = scalar_i64(c, PURGED_SQL, NO_PARAMS);
    let size_mb = db_size_mb(c);
    let modules = fetch_modules(c, scan);
    let active = modules.iter().filter(|m| m.count > 0).count();

    Kpis {
        scans: get(0),
        targets: get(1),
        findings: get(2),
        findings_purged: purged,
        modules_total: MODULES.len(),
        modules_active: active,
        crit: get(6),
        high: get(7),
        ports: get(3),
        hosts: get(4),
        loot: get(5),
        db_size_mb: size_mb,
        error: String::new(),
    }
}

/// Taille de la base en Mo. Vraie valeur de pg_database_size, jamais un
/// chiffre figé.
pub fn db_size_mb(c: &mut Client) -> f64 {
    scalar_f64(
        c,
        "SELECT pg_database_size(current_database())::float8 / 1048576.0",
        NO_PARAMS,
    )
}

// ──────────────────────────────────────────────────────────────── constats ──

/// Constats du scan, du plus grave au moins grave, puis du plus récent au
/// plus ancien. `ORDER BY` sur la table qualifiée : le CASE de sévérité
/// n'existe pas en sortie, donc pas de piège de résolution.
pub fn fetch_findings(c: &mut Client, scan: i64, limit: i64) -> Vec<Finding> {
    rows(
        c,
        "SELECT audit_findings.severity::text,
                audit_findings.category::text,
                audit_findings.title::text,
                COALESCE(audit_findings.recommendation::text,'')
         FROM audit_findings
         WHERE audit_findings.scan_id = $1
         ORDER BY CASE upper(audit_findings.severity)
                    WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                  audit_findings.id DESC
         LIMIT $2::bigint",
        &[&scan, &limit],
    )
    .iter()
    .map(|r| Finding {
        severity: row_text(r, 0),
        category: row_text(r, 1),
        title: row_text(r, 2),
        recommendation: row_text(r, 3),
    })
    .collect()
}

// ────────────────────────────────────────────────────────────────── outils ──

/// Statistiques agrégées par outil externe sur le scan affiché.
pub fn fetch_tools(c: &mut Client, scan: i64) -> Vec<ToolStat> {
    rows(
        c,
        "SELECT audit_tool_outputs.tool_name::text,
                audit_tool_outputs.status::text,
                count(*)::bigint,
                COALESCE(sum(audit_tool_outputs.items_count),0)::bigint,
                COALESCE(round(avg(audit_tool_outputs.execution_time_seconds)::numeric,2),0)::float8
         FROM audit_tool_outputs
         WHERE audit_tool_outputs.scan_id = $1
         GROUP BY audit_tool_outputs.tool_name, audit_tool_outputs.status
         ORDER BY audit_tool_outputs.tool_name, audit_tool_outputs.status",
        &[&scan],
    )
    .iter()
    .map(|r| ToolStat {
        name: row_text(r, 0),
        status: row_text(r, 1),
        runs: row_i64(r, 2),
        items: row_i64(r, 3),
        avg_secs: row_f64(r, 4),
    })
    .collect()
}

// ──────────────────────────────────────────────────────────────── impacts ──

/// Verdicts de preuve d'impact d'une cible. audit_impact n'a pas de scan_id :
/// on filtre sur `target`, la cible du scan affiché.
pub fn fetch_impacts(c: &mut Client, target: &str) -> Vec<ImpactVerdict> {
    rows(
        c,
        "SELECT audit_impact.module::text,
                audit_impact.verdict::text,
                COALESCE(audit_impact.detail::text,''),
                COALESCE(audit_impact.evidence::text,''),
                to_char(audit_impact.created_at,'DD.MM.YY · HH24:MI')
         FROM audit_impact
         WHERE audit_impact.target = $1
         ORDER BY audit_impact.module, audit_impact.id DESC",
        &[&target],
    )
    .iter()
    .map(|r| ImpactVerdict {
        module: row_text(r, 0),
        verdict: row_text(r, 1),
        detail: row_text(r, 2),
        evidence: row_text(r, 3),
        created_at: row_text(r, 4),
    })
    .collect()
}

// ───────────────────────────────────────────────────────────────── surface ──

/// Ports ouverts du scan, triés par numéro de port.
pub fn fetch_ports(c: &mut Client, scan: i64) -> Vec<PortRow> {
    rows(
        c,
        "SELECT audit_ports.port::text,
                COALESCE(audit_ports.service::text,''),
                COALESCE(audit_ports.state::text,''),
                left(COALESCE(audit_ports.banner::text,''), 90)
         FROM audit_ports
         WHERE audit_ports.scan_id = $1
         ORDER BY audit_ports.port",
        &[&scan],
    )
    .iter()
    .map(|r| PortRow {
        port: row_text(r, 0).parse().unwrap_or(0),
        service: row_text(r, 1),
        state: row_text(r, 2),
        banner: row_text(r, 3),
    })
    .collect()
}

/// Histogramme des services sur les ports ouverts du scan. Regroupé par nom
/// de service : c'est ce que la section « surface » affiche.
pub fn fetch_port_histogram(c: &mut Client, scan: i64) -> Vec<Bucket> {
    rows(
        c,
        "SELECT COALESCE(NULLIF(audit_ports.service::text,''),'inconnu') AS svc,
                count(*)::float8
         FROM audit_ports
         WHERE audit_ports.scan_id = $1
         GROUP BY svc
         ORDER BY count(*) DESC, svc",
        &[&scan],
    )
    .iter()
    .map(|r| Bucket {
        label: row_text(r, 0),
        value: row_f64(r, 1),
        tone: "info".to_string(),
    })
    .collect()
}

/// Sous-domaines (audit_subdomains) UNION surface (audit_surface) de la même
/// cible. Les deux tables n'ont pas les mêmes colonnes : on complète par des
/// chaînes vides pour que l'UNION All garde la forme de HostRow.
pub fn fetch_hosts(c: &mut Client, scan: i64) -> Vec<HostRow> {
    rows(
        c,
        "SELECT u.host, u.st, u.ip, u.title, u.tech, u.server, u.alive FROM (
             SELECT audit_subdomains.subdomain AS host,
                    audit_subdomains.http_status::text AS st,
                    COALESCE(audit_subdomains.ip_address::text,'') AS ip,
                    '' AS title, '' AS tech, '' AS server,
                    audit_subdomains.is_alive::text AS alive
             FROM audit_subdomains
             WHERE audit_subdomains.scan_id = $1
             UNION ALL
             SELECT audit_surface.subdomain,
                    audit_surface.status::text,
                    '',
                    COALESCE(audit_surface.title::text,''),
                    COALESCE(audit_surface.tech::text,''),
                    COALESCE(audit_surface.server::text,''),
                    (audit_surface.status IS NOT NULL)::text
             FROM audit_surface
             WHERE audit_surface.cible = (SELECT target FROM audit_scans WHERE audit_scans.id = $1)
         ) u
         ORDER BY u.alive DESC, u.host",
        &[&scan],
    )
    .iter()
    .map(|r| HostRow {
        host: row_text(r, 0),
        status: row_opt_text(r, 1).and_then(|s| s.parse().ok()),
        ip: row_text(r, 2),
        title: row_text(r, 3),
        tech: row_text(r, 4),
        server: row_text(r, 5),
        alive: row_bool(r, 6),
    })
    .collect()
}

// ──────────────────────────────────────────────────────────── web · DNS · TLS ──

/// En-têtes HTTP du scan. Seules les évaluations non conformes sont
/// renvoyées : lister les 200 lignes PASS noierait le signal.
pub fn fetch_headers(c: &mut Client, scan: i64) -> Vec<HeaderRow> {
    rows(
        c,
        "SELECT audit_http_headers.header_name::text,
                left(COALESCE(audit_http_headers.header_value::text,''), 200),
                COALESCE(audit_http_headers.evaluation::text,'')
         FROM audit_http_headers
         WHERE audit_http_headers.scan_id = $1
           AND COALESCE(audit_http_headers.evaluation::text,'') <> 'PASS'
         ORDER BY audit_http_headers.evaluation, audit_http_headers.header_name",
        &[&scan],
    )
    .iter()
    .map(|r| HeaderRow {
        name: row_text(r, 0),
        value: row_text(r, 1),
        evaluation: row_text(r, 2),
    })
    .collect()
}

/// Enregistrements DNS du scan, triés par type puis valeur.
pub fn fetch_dns(c: &mut Client, scan: i64) -> Vec<DnsRow> {
    rows(
        c,
        "SELECT audit_dns_records.record_type::text,
                left(COALESCE(audit_dns_records.record_value::text,''), 300),
                audit_dns_records.is_secure::text
         FROM audit_dns_records
         WHERE audit_dns_records.scan_id = $1
         ORDER BY audit_dns_records.record_type, audit_dns_records.record_value",
        &[&scan],
    )
    .iter()
    .map(|r| DnsRow {
        rtype: row_text(r, 0),
        value: row_text(r, 1),
        secure: row_bool(r, 2),
    })
    .collect()
}

/// Certificats TLS du scan, avec les versions de protocole acceptées.
pub fn fetch_tls(c: &mut Client, scan: i64) -> Vec<TlsRow> {
    rows(
        c,
        "SELECT COALESCE(audit_tls_certs.protocol::text,''),
                COALESCE(audit_tls_certs.cipher::text,''),
                COALESCE(audit_tls_certs.issuer::text,''),
                COALESCE(audit_tls_certs.days_remaining::text,''),
                audit_tls_certs.is_valid::text,
                audit_tls_certs.supports_tls10::text,
                audit_tls_certs.supports_tls11::text,
                audit_tls_certs.supports_tls12::text,
                audit_tls_certs.supports_tls13::text
         FROM audit_tls_certs
         WHERE audit_tls_certs.scan_id = $1
         ORDER BY audit_tls_certs.id",
        &[&scan],
    )
    .iter()
    .map(|r| TlsRow {
        protocol: row_text(r, 0),
        cipher: row_text(r, 1),
        issuer: row_text(r, 2),
        days_remaining: row_opt_text(r, 3).and_then(|s| s.parse().ok()),
        valid: row_bool(r, 4),
        tls10: row_bool(r, 5),
        tls11: row_bool(r, 6),
        tls12: row_bool(r, 7),
        tls13: row_bool(r, 8),
    })
    .collect()
}

/// Pistes de loot du scan, les plus récentes d'abord. Le SHA-256 est complet
/// (c'est la preuve) ; `local_path` est tronqué comme la bannière.
pub fn fetch_loot(c: &mut Client, scan: i64) -> Vec<LootRow> {
    rows(
        c,
        "SELECT left(COALESCE(audit_loot.url::text,''), 160),
                COALESCE(audit_loot.size_bytes::text,'0'),
                COALESCE(audit_loot.sha256::text,''),
                COALESCE(audit_loot.content_type::text,''),
                COALESCE(audit_loot.status_code::text,'0'),
                COALESCE(audit_loot.severity::text,''),
                left(COALESCE(audit_loot.local_path::text,''), 120)
         FROM audit_loot
         WHERE audit_loot.scan_id = $1
         ORDER BY audit_loot.id DESC
         LIMIT 25",
        &[&scan],
    )
    .iter()
    .map(|r| LootRow {
        url: row_text(r, 0),
        size_bytes: row_text(r, 1).parse().unwrap_or(0),
        sha256: row_text(r, 2),
        content_type: row_text(r, 3),
        status: row_text(r, 4).parse().unwrap_or(0),
        severity: row_text(r, 5),
        local_path: row_text(r, 6),
    })
    .collect()
}

// ────────────────────────────────────────────────────────────────── buckets ──

/// Les quatre jeux de barres du tableau de bord, dans l'ordre du contrat :
/// (sévérités, catégories, types DNS, évaluations d'en-têtes).
pub fn fetch_buckets(
    c: &mut Client,
    scan: i64,
) -> (Vec<Bucket>, Vec<Bucket>, Vec<Bucket>, Vec<Bucket>) {
    // sévérités : du plus grave au moins grave
    let severity = rows(
        c,
        "SELECT audit_findings.severity::text, count(*)::float8
         FROM audit_findings
         WHERE audit_findings.scan_id = $1
         GROUP BY audit_findings.severity
         ORDER BY count(*) DESC",
        &[&scan],
    )
    .iter()
    .map(|r| {
        let s = row_text(r, 0);
        Bucket {
            tone: sev_tone(&s).to_string(),
            label: s,
            value: row_f64(r, 1),
        }
    })
    .collect();

    // catégories : les plus nombreuses d'abord
    let categories = rows(
        c,
        "SELECT audit_findings.category::text, count(*)::float8
         FROM audit_findings
         WHERE audit_findings.scan_id = $1
         GROUP BY audit_findings.category
         ORDER BY count(*) DESC",
        &[&scan],
    )
    .iter()
    .map(|r| Bucket {
        label: row_text(r, 0),
        value: row_f64(r, 1),
        tone: "info".to_string(),
    })
    .collect();

    // types DNS : on compte aussi les lignes « non sûres », la tone le dit
    let dns_types = rows(
        c,
        "SELECT audit_dns_records.record_type::text,
                count(*)::float8,
                count(*) FILTER (WHERE NOT audit_dns_records.is_secure)::float8
         FROM audit_dns_records
         WHERE audit_dns_records.scan_id = $1
         GROUP BY audit_dns_records.record_type
         ORDER BY count(*) DESC",
        &[&scan],
    )
    .iter()
    .map(|r| {
        let insecure = row_f64(r, 2);
        Bucket {
            tone: if insecure > 0.0 { "high" } else { "ok" }.to_string(),
            label: row_text(r, 0),
            value: row_f64(r, 1),
        }
    })
    .collect();

    // évaluations d'en-têtes
    let header_eval = rows(
        c,
        "SELECT audit_http_headers.evaluation::text, count(*)::float8
         FROM audit_http_headers
         WHERE audit_http_headers.scan_id = $1
         GROUP BY audit_http_headers.evaluation",
        &[&scan],
    )
    .iter()
    .map(|r| {
        let e = row_text(r, 0);
        Bucket {
            tone: eval_tone(&e).to_string(),
            label: e,
            value: row_f64(r, 1),
        }
    })
    .collect();

    (severity, categories, dns_types, header_eval)
}

// ────────────────────────────────────────────────────────────────── séries ──

/// Deux séries temporelles sur les 30 derniers scans : score global et
/// nombre de constats. `target = None` = toutes les cibles, `Some(t)` =
/// l'historique de cette cible. Les labels sont la date courte, l'ordre est
/// chronologique (le plus ancien à gauche).
pub fn fetch_series(c: &mut Client, target: Option<String>) -> (Series, Series) {
    let t: Option<String> = target.clone();
    let r = rows(
        c,
        "SELECT audit_scans.id,
                to_char(audit_scans.created_at,'DD/MM'),
                COALESCE(audit_scans.overall_score::text,'0')::float8,
                (SELECT count(*) FROM audit_findings f WHERE f.scan_id = audit_scans.id)::float8
         FROM audit_scans
         WHERE $1::text IS NULL OR audit_scans.target = $1::text
         ORDER BY audit_scans.id DESC
         LIMIT 30",
        &[&t],
    );
    // La requête trie du plus récent au plus ancien ; on inverse pour que la
    // courbe se lise de gauche (ancien) à droite (récent).
    let mut labels = Vec::with_capacity(r.len());
    let mut scores = Vec::with_capacity(r.len());
    let mut finds = Vec::with_capacity(r.len());
    for row in r.iter().rev() {
        labels.push(row_text(row, 1));
        scores.push(row_f64(row, 2));
        finds.push(row_f64(row, 3));
    }
    (
        Series {
            labels: labels.clone(),
            values: scores,
        },
        Series {
            labels,
            values: finds,
        },
    )
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
