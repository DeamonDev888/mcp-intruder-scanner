use crate::modules::dns::DnsAuditResult;
use crate::modules::dns_hardening::DnsHardeningResult;
use crate::modules::email_sec::EmailSecurityResult;
use crate::modules::geo::GeoResult;
use crate::modules::http::HttpAuditResult;
use crate::modules::ports::PortScanResult;
use crate::modules::subdomains::SubdomainResult;
use crate::modules::tls::TlsAuditResult;
use crate::modules::vuln_audit::VulnAuditResult;
use crate::modules::web_endpoints::WebEndpointsResult;

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct SecurityFinding {
    pub severity: &'static str, // CRITICAL, HIGH, MEDIUM, LOW, INFO
    pub category: &'static str, // DNS, PORT, HTTP, TLS, COOKIE, SUBDOMAIN, EMAIL, WEB, CVE, SRI, CORS, GEO, OSINT, NMAP, NUCLEI, NIKTO, WAF, BRAND, SECRETS, MIXED_CONTENT, WHOIS, SUPPLY_CHAIN, FRONTEND, OBSCURA
    pub title: String,
    pub recommendation: String,
}

pub struct FindingsEngine;

/// La cible est-elle une IP nue ? Une IP n'a pas de zone DNS — SPF/DMARC/CAA/
/// DKIM/MTA-STS/BIMI seraient des faux positifs absurdes (bruit de score).
fn is_bare_ip_target(domain: &str) -> bool {
    domain.parse::<std::net::IpAddr>().is_ok()
}

impl FindingsEngine {
    /// Orchestrateur : délègue chaque domaine d'audit à un sous-évaluateur
    /// privé, dans un ordre fixe qui garantit un comportement identique au
    /// moteur monolithique historique (mêmes findings, même ordre, même score).
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        dns: &DnsAuditResult,
        ports: &[PortScanResult],
        http: &HttpAuditResult,
        tls: &TlsAuditResult,
        subdomains: &[SubdomainResult],
        geo: &GeoResult,
        email_sec: &EmailSecurityResult,
        web_endpoints: &WebEndpointsResult,
        dns_hardening: &DnsHardeningResult,
        vuln_audit: &VulnAuditResult,
    ) -> Vec<SecurityFinding> {
        let is_bare_ip = is_bare_ip_target(&dns.domain);

        let mut findings = Vec::new();
        findings.extend(Self::eval_dns(dns, is_bare_ip));
        findings.extend(Self::eval_ports(ports, &dns.domain));
        findings.extend(Self::eval_dns_hardening(dns_hardening));
        findings.extend(Self::eval_email(email_sec, is_bare_ip));
        findings.extend(Self::eval_http(http));
        findings.extend(Self::eval_web_endpoints(
            web_endpoints,
            http.http_status > 0,
        ));
        findings.extend(Self::eval_tls(tls));
        findings.extend(Self::eval_geo(geo, dns));
        findings.extend(Self::eval_subdomains(subdomains));
        findings.extend(Self::eval_vuln_audit(vuln_audit));
        findings
    }
}

// Evaluateurs par domaine d'audit (ex-impl monolithique de 1 210 lignes).
// Chaque sous-module ouvre son propre `impl FindingsEngine` : le dispatcher
// `evaluate` ci-dessus garde un ordre d'emission identique au monolithe.
mod dns;
mod email;
mod misc;
mod ports;
mod tls;
mod web;

#[cfg(test)]
mod tests;
