// dash/db/scans.rs — requetes scans & cibles du tableau de bord.

use super::*;

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

