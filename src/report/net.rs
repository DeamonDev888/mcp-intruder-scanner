// report/net.rs — sections reseau du rapport : geo, DNS, ports, TLS.

use super::*;

impl FullAuditReport {
    /// [1] GéoIP & localisation
    pub(super) fn print_geo_section(&self) {
        // 1. GéoIP & Localisation
        println!("[1] GÉOIP & LOCALISATION");
        println!("    • Adresse IP Publique  : {}", self.geo.ip_address);
        println!(
            "    • Fournisseur / Org    : {}",
            self.geo.org_name.as_deref().unwrap_or("Inconnu")
        );
        println!(
            "    • Réseau / ASN         : {}",
            self.geo.asn.as_deref().unwrap_or("Inconnu")
        );
        println!(
            "    • Localisation         : {}, {} ({})",
            self.geo.city.as_deref().unwrap_or(""),
            self.geo.region.as_deref().unwrap_or(""),
            self.geo.country_code.as_deref().unwrap_or("")
        );
        println!(
            "    • Région détectée      : {}",
            if self.geo.is_quebec {
                "Québec (CA)"
            } else if self.geo.is_canada {
                "Canada (autre province)"
            } else {
                "Hors Canada"
            }
        );
        println!();
    }
    /// [4] Durcissement du serveur DNS (récursion ouverte, transfert AXFR)
    pub(super) fn print_dns_section(&self) {
        // 4. Durcissement DNS
        println!("[4] DURCISSEMENT DU SERVEUR DNS (Port 53)");
        println!(
            "    • Résolveur Récursif   : {}",
            if self.dns_hardening.recursion_denied {
                "Récursion désactivée (réponse standard)"
            } else {
                "RÉCURSIF OUVERT [CRITIQUE]"
            }
        );
        println!(
            "    • Transfert AXFR       : {}",
            if self.dns_hardening.zone_transfer_denied {
                "REFUSÉ [SÉCURISÉ]"
            } else {
                "AUTORISÉ [VULNÉRABILITÉ]"
            }
        );
        println!();
    }
    /// [5] Ports & services (scan étendu)
    pub(super) fn print_ports_section(&self) {
        // 5. Ports & Services
        println!("[5] MODULE PORTS & SERVICES (Scan étendu 75+ cibles)");
        if self.ports.is_empty() {
            println!("    • Aucun port standard ouvert détecté.");
        } else {
            for p in &self.ports {
                let banner_info = p.banner.as_deref().unwrap_or("Pas de bannière spontanée");
                println!(
                    "    • Port {:<5}/tcp : {:<15} (Service: {})",
                    p.port, "[OUVERT]", p.service_hint
                );
                if p.banner.is_some() {
                    println!("      Bannière: {}", banner_info);
                }
            }
        }
        println!();
    }
    /// [8] TLS / SSL & chiffrement (+ SSLScan)
    pub(super) fn print_tls_section(&self) {
        // 8. TLS & SSLScan
        println!("[8] MODULE TLS / SSL & CHIFFREMENT");
        println!(
            "    • Protocole négocié    : {}",
            self.tls.protocol.as_deref().unwrap_or("Inconnu")
        );
        println!(
            "    • Suite de chiffrement : {}",
            self.tls.cipher.as_deref().unwrap_or("Inconnue")
        );
        println!(
            "    • Émetteur (CA)        : {}",
            self.tls.issuer.as_deref().unwrap_or("Inconnu")
        );
        println!(
            "    • Jours restants       : {} jours",
            self.tls
                .days_remaining
                .map(|d| d.to_string())
                .unwrap_or_else(|| "Inconnu".into())
        );
        println!(
            "    • Noms alternatifs SAN : {}",
            if self.tls.sans.is_empty() {
                "Aucun".into()
            } else {
                self.tls.sans.join(", ")
            }
        );
        println!(
            "    • Support TLS 1.0 / 1.1: {}",
            if self.tls.supports_tls10 || self.tls.supports_tls11 {
                "DÉTECTÉ [VULNÉRABILITÉ]"
            } else {
                "DÉSACTIVÉ [CONFORME]"
            }
        );
        if let Some(ref ss) = self.sslscan {
            println!(
                "    • Heartbleed           : {}",
                if ss.heartbleed_vulnerable {
                    "VULNÉRABLE [CRITIQUE]"
                } else {
                    "NON VULNÉRABLE [OK]"
                }
            );
            println!(
                "    • Compression (CRIME)  : {}",
                if ss.compression_enabled {
                    "ACTIVÉE [VULNÉRABLE]"
                } else {
                    "DÉSACTIVÉE [SÉCURISÉ]"
                }
            );
            println!(
                "    • Renégociation        : {}",
                if ss.insecure_renegotiation {
                    "NON SÉCURISÉE [ATTENTION]"
                } else {
                    "SÉCURISÉE [OK]"
                }
            );
            println!(
                "    • Ciphers forts        : {} acceptés",
                ss.strong_ciphers_count
            );
            if !ss.weak_ciphers.is_empty() {
                println!(
                    "    • Ciphers faibles      : {} [ALERTE]",
                    ss.weak_ciphers.join(", ")
                );
            }
        }
        println!();
    }
}
