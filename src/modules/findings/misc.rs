// findings/misc.rs — evaluateurs geo, sous-domaines et audit de vulnerabilites.

use super::*;

impl FindingsEngine {
    /// 8. Localisation géographique de l'hébergement (informationnel uniquement).
    pub(super) fn eval_geo(geo: &GeoResult, dns: &DnsAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let is_private_ip = geo
            .ip_address
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_private() || v4.is_loopback() || v4.is_link_local()
                }
                std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
            })
            .unwrap_or(false);
        if !is_private_ip {
            if let Some(ref ptr) = dns.reverse_ptr {
                findings.push(SecurityFinding {
                    severity: "INFO",
                    category: "GEO",
                    title: format!("Reverse PTR (hébergeur réel de l'IP) : {}", ptr),
                    recommendation:
                        "Information d'hébergeur issue du PTR : utile pour délimiter le périmètre réseau du fournisseur."
                            .into(),
                });
            }
        }
        if is_private_ip {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "GEO",
                title: format!("IP privée (réseau interne) : {}", geo.ip_address),
                recommendation:
                    "Cible sur un réseau privé — géolocalisation et whois non applicables.".into(),
            });
        } else if geo.is_canada {
            let region_info = geo.region.as_deref().unwrap_or("Canada");
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "GEO",
                title: format!(
                    "Hébergement détecté au {} ({}, {})",
                    region_info,
                    geo.org_name.as_deref().unwrap_or(""),
                    geo.city.as_deref().unwrap_or("")
                ),
                recommendation: "Information géographique issue du whois — aucune action requise."
                    .into(),
            });
        } else {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "GEO",
                title: format!("Hébergement hors Canada détecté : Pays '{}'", geo.country_code.as_deref().unwrap_or("Inconnu")),
                recommendation: "Information géographique issue du whois — utile pour délimiter le périmètre dhébergement et identifier les fournisseurs impliqués.".into(),
            });
        }
        findings
    }
    /// 9. Sous-domaines : inventaire vivants/morts + IPs d'infrastructure.
    pub(super) fn eval_subdomains(subdomains: &[SubdomainResult]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if !subdomains.is_empty() {
            let alive = subdomains.iter().filter(|s| s.is_alive).count();
            let dead: Vec<&str> = subdomains
                .iter()
                .filter(|s| !s.is_alive)
                .map(|s| s.subdomain.as_str())
                .take(4)
                .collect();
            let mut ips: Vec<&str> = Vec::new();
            for s in subdomains {
                if let Some(ip) = &s.ip_address {
                    for part in ip.split(',') {
                        let t = part.trim();
                        if !t.is_empty() && !ips.contains(&t) {
                            ips.push(t);
                        }
                    }
                }
            }
            let mut title = format!(
                "{} sous-domaines cartographiés : {} vivants, {} muets — infrastructure sur {} IP(s) ({})",
                subdomains.len(),
                alive,
                subdomains.len() - alive,
                ips.len(),
                ips.join(", ")
            );
            if !dead.is_empty() {
                title.push_str(&format!(" ; muets : {}", dead.join(", ")));
            }
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "SUBDOMAIN",
                title,
                recommendation:
                    "Les hôtes muets (DNS résolu, service HTTP absent) restent des actifs à surveiller : takeover CNAME et réactivation à contrôler."
                        .into(),
            });
        }
        findings
    }
    /// 10. Vulnérabilités Applicatives (CVEs, SRI, Mixed Content, CORS).
    pub(super) fn eval_vuln_audit(vuln_audit: &VulnAuditResult) -> Vec<SecurityFinding> {
        vuln_audit
            .findings
            .iter()
            .map(|v| SecurityFinding {
                severity: v.severity,
                category: v.category,
                title: v.title.clone(),
                recommendation: format!("{} (Réf: {})", v.fix, v.owasp),
            })
            .collect()
    }
}
