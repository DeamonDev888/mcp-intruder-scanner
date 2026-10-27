// dash/db/modules.rs — compteurs de modules, sparklines, severites par categorie.

use super::*;

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
