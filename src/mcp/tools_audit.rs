// src/mcp/tools_audit.rs — Audits rapides lecture-seule exposes a l'unite.
//
// UN outil MCP par module moteur appelable DIRECTEMENT sur une simple
// cible (domaine, IP ou hote[:port]), sans scan complet orchestré :
// l'appel est synchrone, borne par les timeouts internes du module, et
// retourne le struct resultat du module sérialisé (raw_output tronqué).
//
// Modules moteur NON exposés ici, avec la raison (à réexposer si leur
// signature change) :
// - `ports::PortScanner` / `full_portscan::FullPortScanner` — balayage
//   réseau lourd, couvert par `scan_target` (profil infra) ;
// - `nmap_deep::NmapAuditor` / `sslscan_audit::SslscanAuditor` /
//   `sqli_audit` — exigent la liste des ports ouverts d'un scan préalable ;
// - `vuln_audit::VulnAuditor` / `ffuf_audit::FfufAuditor` /
//   `nikto_deep::NiktoAuditor` / `nuclei_deep::NucleiAuditor` /
//   `obscura_audit::ObscuraAuditor` — exigent le contexte complet du scan
//   (ports + budget réduit calculé par le garde WAF de l'orchestrateur) ;
// - `web_endpoints::WebEndpointsAuditor` / `box_prober::BoxProber` /
//   `smb_audit::SmbAuditor` — exigent la cible ET son IP résolue issue du
//   scan de ports (couverts par `scan_target`) ;
// - `brand_sec::BrandSecAuditor` (dnstwist) — typosquatting, exécution de
//   plusieurs minutes, réservé au profil web/full ;
// - `http_probe::probe_parallel` — attend une liste d'URLs à sonder ;
// - `loot::LootCollector` — ÉCRIT sur le disque (/var/lib/mcp-intruder/loot),
//   jamais exposé en lecture-seule.

use litemcp::prelude::*;
use serde_json::json;

use super::{guarded, resolve_first_ip, to_json_clipped, ToolResult};
use crate::modules::crt_sh::CrtShAuditor;
use crate::modules::dns::DnsAuditor;
use crate::modules::dns_hardening::DnsHardeningAuditor;
use crate::modules::dnsrecon_audit::DnsreconAuditor;
use crate::modules::email_sec::EmailSecAuditor;
use crate::modules::geo::GeoAuditor;
use crate::modules::http::HttpAuditor;
use crate::modules::subdomains::{ScanMode, SubdomainScanner};
use crate::modules::tech_stack::TechStackAuditor;
use crate::modules::tls::TlsAuditor;
use crate::modules::waf::WafAuditor;
use crate::modules::whois_audit::WhoisAuditor;

/// Enregistre les 12 audits rapides sur le builder.
pub(super) fn register(builder: ServerBuilder) -> ServerBuilder {
    builder
        // ------------------------------------------------------------------
        // dns_audit — modules/dns.rs : A/AAAA/MX/TXT/NS/SOA/CAA, DNSSEC,
        // SPF/DMARC, PTR, liste des problèmes.
        // ------------------------------------------------------------------
        .tool_parse(
            "dns_audit",
            "Audit DNS d'un domaine : enregistrements A/AAAA/MX/TXT/NS/SOA/CAA, DNSSEC, \
             SPF et DMARC (strictesse), reverse PTR et problèmes détectés.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                guarded("dns_audit", || {
                    Ok(to_json_clipped(&DnsAuditor::audit(&args.target)))
                })
            },
        )
        .annotate(
            "dns_audit",
            ToolAnnotations::new()
                .title("Audit DNS (SPF/DMARC/MX/DNSSEC)")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // tls_audit — modules/tls.rs : chaîne X.509, expiration, SAN,
        // protocoles TLS 1.0-1.3, auto-signé. La cible est résolue en IP
        // d'abord (le module audite l'IP effectivement résolue, SNI = hôte).
        // ------------------------------------------------------------------
        .tool_parse(
            "tls_audit",
            "Audit TLS d'un hôte : chaîne de certificat, dates de validité et jours restants, \
             SAN, protocoles TLS 1.0/1.1/1.2/1.3, auto-signature. Le port 443 est audité.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                let ip = resolve_first_ip(&args.target)?;
                guarded("tls_audit", move || {
                    Ok(to_json_clipped(&TlsAuditor::audit(&args.target, &ip)))
                })
            },
        )
        .annotate(
            "tls_audit",
            ToolAnnotations::new()
                .title("Audit TLS et certificat")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // http_audit — modules/http.rs : en-têtes de sécurité (HSTS, CSP,
        // X-Frame-Options...), cookies, redirection HTTPS, score.
        // ------------------------------------------------------------------
        .tool_parse(
            "http_audit",
            "Audit des en-têtes HTTP d'un hôte : HSTS, CSP, X-Frame-Options, cookies (Secure / \
             HttpOnly / SameSite), redirection vers HTTPS et score de configuration.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                guarded("http_audit", || {
                    Ok(to_json_clipped(&HttpAuditor::audit(&args.target, &[])))
                })
            },
        )
        .annotate(
            "http_audit",
            ToolAnnotations::new()
                .title("Audit des en-têtes HTTP")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // whois_audit — modules/whois_audit.rs : registre, dates,
        // verrou de transfert, serveurs de noms.
        // ------------------------------------------------------------------
        .tool_parse(
            "whois_audit",
            "Audit whois d'un domaine : registre, dates de création et d'expiration, statuts, \
             protection de la vie privée et verrou de transfert (binaire `whois` requis).",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                guarded("whois_audit", || {
                    Ok(to_json_clipped(&WhoisAuditor::audit(&args.target)))
                })
            },
        )
        .annotate(
            "whois_audit",
            ToolAnnotations::new()
                .title("Audit whois du domaine")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // geo_locate — modules/geo.rs : ASN, organisation, pays, région,
        // ville d'une IP (whois). La cible est résolue en IP d'abord.
        // ------------------------------------------------------------------
        .tool_parse(
            "geo_locate",
            "Géolocalisation et propriété d'une cible : adresse IP résolue, ASN, organisation, \
             pays, région et ville (via whois). Accepte un domaine ou une IP directe.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                let ip = resolve_first_ip(&args.target)?;
                guarded("geo_locate", move || {
                    Ok(to_json_clipped(&GeoAuditor::audit(&ip)))
                })
            },
        )
        .annotate(
            "geo_locate",
            ToolAnnotations::new()
                .title("Géolocalisation IP")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // email_sec_audit — modules/email_sec.rs : lookups SPF (RFC 7208),
        // sélecteurs DKIM, MTA-STS, SMTP TLS Reporting, BIMI, tags DMARC.
        // Les enregistrements SPF/DMARC bruts proviennent du module DNS,
        // même contrat que l'orchestrateur.
        // ------------------------------------------------------------------
        .tool_parse(
            "email_sec_audit",
            "Audit de sécurité messagerie d'un domaine : nombre de lookups SPF (limite RFC \
             7208), sélecteurs DKIM, MTA-STS, SMTP TLS Reporting, BIMI et tags DMARC avancés.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                guarded("email_sec_audit", move || {
                    let dns = DnsAuditor::audit(&args.target);
                    let res = EmailSecAuditor::audit(
                        &args.target,
                        dns.spf_record.as_deref(),
                        dns.dmarc_record.as_deref(),
                    );
                    Ok(to_json_clipped(&res))
                })
            },
        )
        .annotate(
            "email_sec_audit",
            ToolAnnotations::new()
                .title("Audit de sécurité messagerie")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // subdomains_audit — modules/subdomains.rs : énumération subfinder
        // (fallback liste statique), IP et statut HTTP par sous-domaine.
        // ------------------------------------------------------------------
        .tool_parse(
            "subdomains_audit",
            "Énumération de sous-domaines d'un domaine : subfinder si disponible (sinon liste \
             statique), avec IP résolue et statut HTTP par hôte trouvé.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                guarded("subdomains_audit", move || {
                    let subs = SubdomainScanner::scan_with_mode(&args.target, ScanMode::Auto);
                    Ok(json!({ "count": subs.len(), "subdomains": subs }))
                })
            },
        )
        .annotate(
            "subdomains_audit",
            ToolAnnotations::new()
                .title("Énumération de sous-domaines")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // crt_sh_lookup — modules/crt_sh.rs : sous-domaines historiques via
        // Certificate Transparency (passif, 1 requête GET vers crt.sh).
        // ------------------------------------------------------------------
        .tool_parse(
            "crt_sh_lookup",
            "Sous-domaines historiques d'un domaine via Certificate Transparency (crt.sh) : \
             hôtes invisibles pour subfinder mais présents dans les logs de certificats.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                guarded("crt_sh_lookup", || {
                    Ok(to_json_clipped(&CrtShAuditor::audit(&args.target)))
                })
            },
        )
        .annotate(
            "crt_sh_lookup",
            ToolAnnotations::new()
                .title("Sous-domaines via Certificate Transparency (crt.sh)")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // waf_detect — modules/waf.rs : détection de pare-feu applicatif
        // (wafw00f) + ports edge avec challenge (binaire `wafw00f` requis).
        // ------------------------------------------------------------------
        .tool_parse(
            "waf_detect",
            "Détection de pare-feu applicatif (WAF) devant un hôte : empreinte wafw00f, \
             fabricant, et ports edge avec challenge détectés (2083/2087/2096...).",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                guarded("waf_detect", || {
                    Ok(to_json_clipped(&WafAuditor::audit(&args.target)))
                })
            },
        )
        .annotate(
            "waf_detect",
            ToolAnnotations::new()
                .title("Détection de pare-feu applicatif (WAF)")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // tech_stack_audit — modules/tech_stack.rs : empreinte WhatWeb,
        // composants versionnés, emails exposés, technos tierces JS.
        // ------------------------------------------------------------------
        .tool_parse(
            "tech_stack_audit",
            "Empreinte technologique d'un hôte (WhatWeb) : CMS et librairies détectées, \
             composants versionnés (verdicts EOL), en-tête Server et emails exposés.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                guarded("tech_stack_audit", || {
                    Ok(to_json_clipped(&TechStackAuditor::audit(&args.target, &[])))
                })
            },
        )
        .annotate(
            "tech_stack_audit",
            ToolAnnotations::new()
                .title("Empreinte technologique (WhatWeb)")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // dnsrecon_audit — modules/dnsrecon_audit.rs : SRV, A-records des
        // hôtes du domaine, version Bind, AXFR (binaire `dnsrecon` requis).
        // ------------------------------------------------------------------
        .tool_parse(
            "dnsrecon_audit",
            "Énumération DNS avancée (dnsrecon) : enregistrements SRV, A-records des hôtes du \
             domaine (ftp./whm./autoconfig.), versions Bind et tentative de transfert de zone.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                guarded("dnsrecon_audit", || {
                    Ok(to_json_clipped(&DnsreconAuditor::audit(&args.target)))
                })
            },
        )
        .annotate(
            "dnsrecon_audit",
            ToolAnnotations::new()
                .title("Énumération DNS avancée (dnsrecon)")
                .read_only(true)
                .open_world(true),
        )
        // ------------------------------------------------------------------
        // dns_hardening_audit — modules/dns_hardening.rs : durcissement du
        // serveur DNS — résolveur ouvert, récursion, transfert de zone.
        // La cible est résolue en IP d'abord (le module sonde l'IP).
        // ------------------------------------------------------------------
        .tool_parse(
            "dns_hardening_audit",
            "Audit de durcissement du serveur DNS d'une cible : résolveur ouvert, récursion \
             refusée et transfert de zone (AXFR) refusé.",
            cible_schema(),
            |args: CibleArgs| -> ToolResult {
                let ip = resolve_first_ip(&args.target)?;
                guarded("dns_hardening_audit", move || {
                    Ok(to_json_clipped(&DnsHardeningAuditor::audit(
                        &ip,
                        &args.target,
                    )))
                })
            },
        )
        .annotate(
            "dns_hardening_audit",
            ToolAnnotations::new()
                .title("Durcissement DNS (récursion, AXFR)")
                .read_only(true)
                .open_world(true),
        )
}

// ==============================================================================
// ARGUMENTS PARTAGES
// ==============================================================================

/// Arguments des audits rapides : une seule cible (domaine ou IP).
#[derive(serde::Deserialize)]
struct CibleArgs {
    target: String,
}

/// Schéma zod commun : cible obligatoire, 1..=253 caractères, objet strict
/// (champ inconnu refusé en -32602).
fn cible_schema() -> litemcp::zod::Obj {
    zod::object()
        .field("target", zod::string().min(1).max(253))
        .strict()
}
