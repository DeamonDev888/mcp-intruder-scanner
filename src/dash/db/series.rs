// dash/db/series.rs — buckets historiques et series temporelles.

use super::*;

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

