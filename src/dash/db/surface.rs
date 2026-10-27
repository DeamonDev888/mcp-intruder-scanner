// dash/db/surface.rs — surface d'attaque : ports, histogramme, hotes, headers, DNS, TLS, loot.

use super::*;

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
