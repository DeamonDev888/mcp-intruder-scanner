// findings/ports.rs — evaluateur ports & services (bannieres, ports a risque, SGBD).

use super::*;

impl FindingsEngine {
    /// 2. Audit Ports & Services (bannières, ports à risque, bases de données).
    pub(super) fn eval_ports(ports: &[PortScanResult], target_domain: &str) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        // Artefacts d'edge uniforme : un UNIQUE finding INFO agrege (jamais
        // de HIGH fantomes — l'edge accepte TCP et parle HTTP partout, aucun
        // service reel n'est prouve). Meme principe que le downgrade loopback :
        // ne pas empoisonner le score avec des artefacts d'edge.
        let phantom: Vec<u16> = ports
            .iter()
            .filter(|p| p.is_phantom_edge)
            .map(|p| p.port)
            .collect();
        if !phantom.is_empty() {
            let shown: Vec<String> = phantom.iter().take(15).map(|p| p.to_string()).collect();
            let more = phantom.len() - shown.len();
            let listing = if more > 0 {
                format!("{} …(+{} autres)", shown.join(", "), more)
            } else {
                shown.join(", ")
            };
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "PORT",
                title: format!(
                    "{} port(s) sans service confirmé — l'edge répond uniformément (HTTP 4xx générique) : {}",
                    phantom.len(),
                    listing
                ),
                recommendation:
                    "L'edge/WAF accepte les connexions TCP et répond HTTP sur des ports non-HTTP : aucun service réel n'est prouvé derrière. Pour confirmer un service, sonder avec un client protocole dédié au-delà de l'edge (IP d'origine)."
                        .into(),
            });
        }
        for p in ports {
            if p.is_phantom_edge {
                continue;
            }
            // Bannière de service : version logicielle + empreinte OS divulgées
            if let Some(ref b) = p.banner {
                let b = b.trim();
                if b.len() > 8 {
                    let short: String = b.chars().take(64).collect();
                    findings.push(SecurityFinding {
                        severity: "LOW",
                        category: "PORT",
                        title: format!("Bannière de service divulgée sur le port {} : {}", p.port, short),
                        recommendation:
                            "Désactiver la bannière de version du service (ex. sshd 'DebianBanner no', nginx server_tokens off) pour limiter le CVE matching direct."
                                .into(),
                    });
                }
            }
            if p.port == 21 {
                findings.push(SecurityFinding {
                    severity: "HIGH",
                    category: "PORT",
                    title: "Port FTP 21/tcp ouvert en clair".into(),
                    recommendation:
                        "Désactiver le service FTP obsolète et privilégier SFTP sur SSH.".into(),
                });
            } else if p.port == 23 {
                findings.push(SecurityFinding {
                    severity: "CRITICAL",
                    category: "PORT",
                    title: "Port Telnet 23/tcp ouvert (non chiffré)".into(),
                    recommendation:
                        "Fermer immédiatement le port 23 et utiliser exclusivement SSH.".into(),
                });
            } else if p.port == 3389 {
                findings.push(SecurityFinding {
                    severity: "HIGH",
                    category: "PORT",
                    title: "Port RDP 3389/tcp exposé sur Internet".into(),
                    recommendation: "Restreindre l'accès RDP via un VPN ou un bastion avec authentification MFA.".into(),
                });
            } else if p.port == 3306 || p.port == 5432 || p.port == 6379 || p.port == 27017 {
                // Anti-faux-positif : sur une cible loopback (127.0.0.0/8 ou ::1),
                // le port DB n'est PAS exposé publiquement — service local uniquement.
                let is_loopback_target = target_domain
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false);
                if is_loopback_target {
                    findings.push(SecurityFinding {
                        severity: "INFO",
                        category: "PORT",
                        title: format!("Port de base de données {} ({}) en écoute — service local (loopback), non exposé publiquement", p.port, p.service_hint),
                        recommendation: "Service joignable uniquement en local : aucune exposition externe détectée.".into(),
                    });
                } else {
                    findings.push(SecurityFinding {
                        severity: "HIGH",
                        category: "PORT",
                        title: format!("Port de base de données {} ({}) exposé publiquement", p.port, p.service_hint),
                        recommendation: "Lier le service à localhost (127.0.0.1) ou filtrer l'accès via pare-feu (UFW).".into(),
                    });
                }
            }
        }
        findings
    }
}
