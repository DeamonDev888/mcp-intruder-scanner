use crate::modules::brand_sec::BrandSecResult;
use crate::modules::diag_exposure::DiagExposureResult;
use crate::modules::dns::DnsAuditResult;
use crate::modules::dns_hardening::DnsHardeningResult;
use crate::modules::dnsrecon_audit::DnsreconResult;
use crate::modules::email_sec::EmailSecurityResult;
use crate::modules::ffuf_audit::FfufAuditResult;
use crate::modules::findings::SecurityFinding;
use crate::modules::ftp_audit::FtpAuditResult;
use crate::modules::geo::GeoResult;
use crate::modules::http::HttpAuditResult;
use crate::modules::loot::LootResult;
use crate::modules::nikto_deep::NiktoAuditResult;
use crate::modules::nmap_deep::NmapAuditResult;
use crate::modules::nuclei_deep::NucleiAuditResult;
use crate::modules::obscura_audit::ObscuraResult;
use crate::modules::ports::PortScanResult;
use crate::modules::sslscan_audit::SslscanResult;
use crate::modules::subdomains::SubdomainResult;
use crate::modules::tech_stack::TechStackResult;
use crate::modules::theharvester_audit::TheHarvesterResult;
use crate::modules::tls::TlsAuditResult;
use crate::modules::vuln_audit::VulnAuditResult;
use crate::modules::waf::WafResult;
use crate::modules::web_endpoints::WebEndpointsResult;
use crate::modules::whois_audit::WhoisResult;
use serde::Serialize;

#[derive(Serialize)]
pub struct FullAuditReport {
    pub target: String,
    pub timestamp: String,
    pub duration_seconds: f32,
    pub dns: DnsAuditResult,
    pub ports: Vec<PortScanResult>,
    pub http: HttpAuditResult,
    pub tls: TlsAuditResult,
    pub subdomains: Vec<SubdomainResult>,
    pub geo: GeoResult,
    pub email_sec: EmailSecurityResult,
    pub web_endpoints: WebEndpointsResult,
    pub dns_hardening: DnsHardeningResult,
    pub vuln_audit: VulnAuditResult,
    pub diag_exposure: DiagExposureResult,
    pub nmap: Option<NmapAuditResult>,
    pub nuclei: Option<NucleiAuditResult>,
    pub nikto: Option<NiktoAuditResult>,
    pub waf: Option<WafResult>,
    pub tech_stack: Option<TechStackResult>,
    pub sslscan: Option<SslscanResult>,
    pub brand_sec: Option<BrandSecResult>,
    pub ftp_audit: Option<FtpAuditResult>,
    pub ffuf: Option<FfufAuditResult>,
    pub whois: Option<WhoisResult>,
    pub dnsrecon: Option<DnsreconResult>,
    pub theharvester: Option<TheHarvesterResult>,
    pub obscura: Option<ObscuraResult>,
    pub http_probe: Option<Vec<crate::modules::http_probe::HttpProbeResult>>,
    pub rustscan: Option<crate::modules::portscan_rustscan::RustScanResult>,
    pub sqli: Option<Vec<crate::modules::sqli_audit::SqliFinding>>,
    /// P1-1 : duree REELLE de l'outil, pas la duree totale du scan.
    pub http_probe_seconds: f32,
    pub sqli_seconds: f32,
    pub loot: Option<LootResult>,
    pub box_probe: Option<crate::modules::box_prober::BoxProbeResult>,
    pub smb_audit: Option<crate::modules::smb_audit::SmbAuditResult>,
    pub findings: Vec<SecurityFinding>,
    pub overall_score: u8,
}

impl FullAuditReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: String,
        timestamp: String,
        duration_seconds: f32,
        dns: DnsAuditResult,
        ports: Vec<PortScanResult>,
        http: HttpAuditResult,
        tls: TlsAuditResult,
        subdomains: Vec<SubdomainResult>,
        geo: GeoResult,
        email_sec: EmailSecurityResult,
        web_endpoints: WebEndpointsResult,
        dns_hardening: DnsHardeningResult,
        vuln_audit: VulnAuditResult,
        diag_exposure: DiagExposureResult,
        nmap: Option<NmapAuditResult>,
        nuclei: Option<NucleiAuditResult>,
        nikto: Option<NiktoAuditResult>,
        waf: Option<WafResult>,
        tech_stack: Option<TechStackResult>,
        sslscan: Option<SslscanResult>,
        brand_sec: Option<BrandSecResult>,
        ftp_audit: Option<FtpAuditResult>,
        ffuf: Option<FfufAuditResult>,
        whois: Option<WhoisResult>,
        dnsrecon: Option<DnsreconResult>,
        theharvester: Option<TheHarvesterResult>,
        obscura: Option<ObscuraResult>,
        http_probe: Option<Vec<crate::modules::http_probe::HttpProbeResult>>,
        rustscan: Option<crate::modules::portscan_rustscan::RustScanResult>,
        sqli: Option<Vec<crate::modules::sqli_audit::SqliFinding>>,
        http_probe_seconds: f32,
        sqli_seconds: f32,
        loot: Option<LootResult>,
        box_probe: Option<crate::modules::box_prober::BoxProbeResult>,
        smb_audit: Option<crate::modules::smb_audit::SmbAuditResult>,
        findings: Vec<SecurityFinding>,
    ) -> Self {
        let mut score: f32 = 100.0;

        for f in &findings {
            match f.severity {
                "CRITICAL" => score -= 25.0,
                "HIGH" => score -= 12.0,
                "MEDIUM" => score -= 5.0,
                "LOW" => score -= 2.0,
                _ => {}
            }
        }

        let overall_score = score.clamp(0.0, 100.0).round() as u8;

        Self {
            target,
            timestamp,
            duration_seconds,
            dns,
            ports,
            http,
            tls,
            subdomains,
            geo,
            email_sec,
            web_endpoints,
            dns_hardening,
            vuln_audit,
            diag_exposure,
            nmap,
            nuclei,
            nikto,
            waf,
            tech_stack,
            sslscan,
            brand_sec,
            ftp_audit,
            ffuf,
            whois,
            dnsrecon,
            theharvester,
            obscura,
            http_probe,
            rustscan,
            sqli,
            http_probe_seconds,
            sqli_seconds,
            loot,
            box_probe,
            smb_audit,
            findings,
            overall_score,
        }
    }

    /// Affichage formaté console exhaustif : une méthode privée par
    /// section, appelée dans l'ordre historique — aucune ligne affichée
    /// ne change (pure motion de code).
    pub fn print_console(&self) {
        println!(
            "================================================================================"
        );
        println!("        MCP-INTRUDER CYBERSCAN 360° — AUDIT DE SURFACE APPROFONDI ");
        println!(
            "================================================================================"
        );
        println!("  Cible auditée     : {}", self.target);
        println!("  Horodatage        : {}", self.timestamp);
        println!(
            "  Temps d'exécution : {:.2} secondes",
            self.duration_seconds
        );
        println!("  Score de sécurité : {} / 100", self.overall_score);
        println!(
            "--------------------------------------------------------------------------------\n"
        );

        self.print_geo_section();
        self.print_waf_section();
        self.print_email_section();
        self.print_dns_section();
        self.print_ports_section();
        self.print_http_section();
        self.print_tech_stack_section();
        self.print_tls_section();
        self.print_brand_sec_section();
        self.print_ftp_audit_section();
        self.print_ffuf_section();
        self.print_subdomains_section();
        self.print_vuln_section();
        self.print_diag_exposure_section();
        self.print_tools_section();
        self.print_findings_section();
    }
    /// Sérialisation JSON exhaustive du rapport complet (serde_json).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!(r#"{{"error": "serialization failed: {}"}}"#, e))
    }
}

// Sections du rapport (ex-impl monolithique de 1 054 lignes). Chaque
// sous-module ouvre son propre `impl FullAuditReport` ; print_console
// garde l'ordre historique d'affichage, aucune ligne ne change.
mod net;
mod osint;
mod tools;
mod web;
