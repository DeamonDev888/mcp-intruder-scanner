// findings/dns.rs — evaluateurs DNS : zone, SPF/DMARC/CAA, durcissement (resolver ouvert).

use super::*;

impl FindingsEngine {
    /// 1. Audit DNS & SPF/DMARC/CAA/MX (spécifique à un domaine, pas une IP nue).
    pub(super) fn eval_dns(dns: &DnsAuditResult, is_bare_ip: bool) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if is_bare_ip {
            // Pas de zone DNS sur une IP : on saute tout le bloc email/DNS
        } else if !dns.spf_found {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "DNS",
                title: "Absence d'enregistrement SPF (Sender Policy Framework)".into(),
                recommendation: "Ajouter un enregistrement TXT 'v=spf1 ... -all' pour empêcher l'usurpation d'identité d'expéditeur.".into(),
            });
        } else if !dns.spf_strict {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "DNS",
                title: "Politique SPF permissive (~all ou ?all détecté)".into(),
                recommendation: "Basculer la terminaison SPF sur '-all' (Hard Fail) pour une protection maximale.".into(),
            });
        }

        if !is_bare_ip && !dns.dmarc_found {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "DNS",
                title: "Absence d'enregistrement DMARC sur _dmarc".into(),
                recommendation: "Créer l'enregistrement TXT '_dmarc' avec une politique 'p=quarantine' ou 'p=reject' et rua pour le suivi.".into(),
            });
        } else if let Some(ref pol) = dns.dmarc_policy {
            if pol == "none" {
                findings.push(SecurityFinding {
                    severity: "LOW",
                    category: "DNS",
                    title: "Politique DMARC en mode passif (p=none)".into(),
                    recommendation: "Passer progressivement à 'p=quarantine' puis 'p=reject' pour bloquer les faux emails.".into(),
                });
            } else if pol == "reject" || pol == "quarantine" {
                findings.push(SecurityFinding {
                    severity: "INFO",
                    category: "DNS",
                    title: format!("Contrôle DMARC actif et contraignant (p={}) — usurpation d'identité bloquée", pol),
                    recommendation:
                        "Contrôle attesté : la politique DMARC en place bloque ou met en quarantaine les messages non conformes."
                            .into(),
                });
            }
        }

        if !is_bare_ip && !dns.dnssec_active {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "DNS",
                title: "DNSSEC non déployé sur la zone (empoisonnement DNS possible)".into(),
                recommendation:
                    "Signer la zone (DNSSEC) et publier l'enregistrement DS au registrar pour garantir l'intégrité des réponses DNS."
                        .into(),
            });
        }

        // Attestation positive : CAA présents = émission de certificats encadrée
        if !is_bare_ip && !dns.caa_records.is_empty() {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "DNS",
                title: format!("Enregistrements CAA actifs ({} règle(s)) — émission de certificats restreinte", dns.caa_records.len()),
                recommendation:
                    "Contrôle attesté : seules les autorités listées dans les CAA peuvent émettre des certificats pour ce domaine."
                        .into(),
            });
        }

        // Cartographie email : le MX définit le périmètre d'envoi (cible spoofing/relais)
        if !is_bare_ip && !dns.mx_records.is_empty() {
            let mx: Vec<String> = dns.mx_records.iter().take(3).cloned().collect();
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "EMAIL",
                title: format!("Serveur(s) MX du domaine : {}", mx.join(", ")),
                recommendation:
                    "Périmètre d'envoi email identifié : auditer ce(s) serveur(s) (open relay, SMTP AUTH, TLS obligatoire)."
                        .into(),
            });
        }

        if !is_bare_ip && dns.caa_records.is_empty() {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "DNS",
                title: "Absence d'enregistrements CAA (Certification Authority Authorization)".into(),
                recommendation: "Définir des enregistrements CAA pour restreindre l'émission de certificats TLS aux autorités légitimes (ex: letsencrypt.org).".into(),
            });
        }

        findings
    }
    /// 3. Audit Durcissement DNS (Open Resolver check).
    pub(super) fn eval_dns_hardening(dns_hardening: &DnsHardeningResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if dns_hardening.is_open_resolver_risk {
            findings.push(SecurityFinding {
                severity: "CRITICAL",
                category: "DNS",
                title: "Serveur DNS agissant comme un résolveur récursif ouvert".into(),
                recommendation: "Désactiver la récursion dans Named/Knot/Bind ('recursion no;') pour éviter d'être exploité dans des attaques DDoS par amplification.".into(),
            });
        }
        findings
    }
}
