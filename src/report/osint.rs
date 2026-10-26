// report/osint.rs — sections OSINT du rapport : email, sous-domaines, FTP.

use super::*;

impl FullAuditReport {
    /// [3] DNS, sécurité courriel & anti-usurpation (MX, SPF, DMARC, MTA-STS, DKIM)
    pub(super) fn print_email_section(&self) {
        // 3. DNS & Messagerie
        println!("[3] DNS, SÉCURITÉ COURRIEL & ANTI-USURPATION");
        println!(
            "    • IPv4 (A)             : {}",
            if self.dns.a_records.is_empty() {
                "Aucune".into()
            } else {
                self.dns.a_records.join(", ")
            }
        );
        println!(
            "    • Reverse DNS (PTR)    : {}",
            self.dns.reverse_ptr.as_deref().unwrap_or("Non configuré")
        );
        println!(
            "    • Serveurs Mail (MX)   : {}",
            if self.dns.mx_records.is_empty() {
                "Aucun".into()
            } else {
                self.dns.mx_records.join("; ")
            }
        );
        println!(
            "    • DNSSEC               : {}",
            if self.dns.dnssec_active {
                "ACTIVÉ [OK]"
            } else {
                "NON SIGNÉ [INFO]"
            }
        );
        println!(
            "    • Enregistrements CAA  : {}",
            if self.dns.caa_records.is_empty() {
                "AUCUN [ATTENTION]".to_string()
            } else {
                self.dns.caa_records.join("; ")
            }
        );
        println!(
            "    • Politique SPF        : {}",
            if self.dns.spf_found {
                if self.dns.spf_strict {
                    "STRICTE (-all) [EXCELLENT]"
                } else {
                    "PERMISSIVE (~all) [ATTENTION]"
                }
            } else {
                "ABSENTE [ALERTE]"
            }
        );
        println!(
            "      Lookups SPF DNS      : {} / 10 (RFC 7208) [{}]",
            self.email_sec.spf_lookup_count,
            if self.email_sec.spf_lookup_valid {
                "CONFORME"
            } else {
                "DÉPASSÉ - ALERTE"
            }
        );
        println!(
            "    • Politique DMARC      : {}",
            if self.dns.dmarc_found {
                format!(
                    "PRÉSENTE (p={}) [OK]",
                    self.dns.dmarc_policy.as_deref().unwrap_or("inconnu")
                )
            } else {
                "ABSENTE [ALERTE]".into()
            }
        );
        println!(
            "    • MTA-STS (Anti-MITM)  : {}",
            if self.email_sec.mta_sts_present {
                "DÉPLOYÉ (_mta-sts) [EXCELLENT]"
            } else {
                "NON CONFIGURÉ [INFO]"
            }
        );
        println!(
            "    • SMTP TLS Reporting   : {}",
            if self.email_sec.smtp_tls_reporting {
                "ACTIF (_smtp._tls) [OK]"
            } else {
                "NON CONFIGURÉ"
            }
        );
        println!(
            "    • Sélecteurs DKIM      : {}",
            if self.email_sec.dkim_selectors_found.is_empty() {
                "Aucun sélecteur standard détecté".into()
            } else {
                self.email_sec.dkim_selectors_found.join(", ")
            }
        );
        println!();
    }
    /// [11] Sous-domaines & cartographie
    pub(super) fn print_subdomains_section(&self) {
        // 11. Sous-domaines
        println!("[11] SOUS-DOMAINES & CARTOGRAPHIE");
        if self.subdomains.is_empty() {
            println!("    • Aucun sous-domaine additionnel identifié parmi les noms courants.");
        } else {
            for sub in &self.subdomains {
                let http_info = sub
                    .http_status
                    .map(|c| format!("HTTP {}", c))
                    .unwrap_or_else(|| "Pas de réponse HTTP".into());
                println!(
                    "    • {:<32} -> {:<16} ({})",
                    sub.subdomain,
                    sub.ip_address.as_deref().unwrap_or("?"),
                    http_info
                );
            }
        }
        println!();
    }
    /// [9b] Audit FTP (port 21)
    pub(super) fn print_ftp_audit_section(&self) {
        if let Some(ref f) = self.ftp_audit {
            println!("[9b] AUDIT FTP (port 21)");
            println!("    • Cible                : {}", f.target);
            println!(
                "    • Banner               : {}",
                if f.banner.is_empty() {
                    "(aucun)".into()
                } else {
                    f.banner.clone()
                }
            );
            println!(
                "    • TLS supporté         : {}",
                if f.tls_supported { "OUI" } else { "NON" }
            );
            println!(
                "    • TLS exigé            : {}",
                if f.tls_required {
                    "OUI [OK]"
                } else {
                    "NON [RISQUE]"
                }
            );
            println!(
                "    • Anonymous FTP        : {}",
                if f.anonymous_allowed {
                    "AUTORISÉ [CRITIQUE]"
                } else {
                    "REFUSÉ"
                }
            );
            println!(
                "    • Loot attempté        : {}",
                if f.loot_attempted {
                    format!("OUI ({} fichier(s))", f.loot_files)
                } else {
                    "non".into()
                }
            );
            println!("    • Verdict              : {}", f.summary);
            println!();
        }
    }
}
