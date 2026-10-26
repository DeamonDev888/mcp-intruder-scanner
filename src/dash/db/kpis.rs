// dash/db/kpis.rs — KPIs, taille DB, constats, outils, impacts.

use super::*;

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

