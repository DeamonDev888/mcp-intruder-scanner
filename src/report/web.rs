// report/web.rs — sections web du rapport : WAF, HTTP, tech stack, marque, ffuf, vulns, diag.

use super::*;

impl FullAuditReport {
    /// [2] Pare-feu applicatif (WAF / Wafw00f)
    pub(super) fn print_waf_section(&self) {
        // 2. WAF & Périmètre
        if let Some(ref w) = self.waf {
            println!("[2] PARE-FEU APPLICATIF (WAF / WAFW00F)");
            println!(
                "    • WAF Détecté          : {}",
                if w.waf_detected {
                    format!("OUI [{} - {}]", w.firewall_name, w.manufacturer)
                } else {
                    "NON (Exposition directe de l'infrastructure)".to_string()
                }
            );
            println!("    • Résumé               : {}", w.summary);
            println!();
        }
    }
    /// [6] Sécurité web, endpoints & en-têtes
    pub(super) fn print_http_section(&self) {
        // 6. Web & Endpoints
        println!("[6] SÉCURITÉ WEB, ENDPOINTS & HEADERS");
        println!("    • Statut HTTP HTTPS    : {}", self.http.http_status);
        println!(
            "    • Protocole ALPN       : {}",
            self.web_endpoints
                .alpn_negotiated
                .as_deref()
                .unwrap_or("http/1.1")
        );
        println!(
            "    • Redirection HTTPS    : {}",
            if self.http.redirects_to_https {
                "OUI [OK]"
            } else {
                "NON [ATTENTION]"
            }
        );
        println!(
            "    • Fichier security.txt : {}",
            if self.web_endpoints.security_txt_present {
                "PRÉSENT (RFC 9116) [EXCELLENT]"
            } else {
                "NON TROUVÉ"
            }
        );
        println!(
            "    • Fichier robots.txt   : {}",
            if self.web_endpoints.robots_txt_present {
                "PRÉSENT [OK]"
            } else {
                "NON TROUVÉ"
            }
        );
        println!(
            "    • Serveur divulgué     : {}",
            self.http.server_header.as_deref().unwrap_or("Masqué [OK]")
        );
        println!(
            "    • HSTS                 : {}",
            if self.http.hsts_present == Some(true) {
                "PRÉSENT [OK]"
            } else {
                "MANQUANT [ALERTE]"
            }
        );
        println!(
            "    • CSP                  : {}",
            if self.http.csp_present {
                "PRÉSENT [OK]"
            } else {
                "MANQUANT [ATTENTION]"
            }
        );
        println!(
            "    • X-Frame-Options      : {}",
            self.http.x_frame_options.as_deref().unwrap_or("MANQUANT")
        );
        println!(
            "    • X-Content-Type-Opt   : {}",
            self.http
                .x_content_type_options
                .as_deref()
                .unwrap_or("MANQUANT")
        );
        println!();
    }
    /// [7] Empreinte technologique & composants (WhatWeb)
    pub(super) fn print_tech_stack_section(&self) {
        // 7. Tech Stack (WhatWeb)
        if let Some(ref tw) = self.tech_stack {
            println!("[7] EMPREINTE TECHNOLOGIQUE & COMPOSANTS (WHATWEB)");
            println!(
                "    • Serveur web          : {}",
                tw.server.as_deref().unwrap_or("Non divulgué")
            );
            println!(
                "    • Composants détectés  : {}",
                if tw.detected_technologies.is_empty() {
                    "Aucun".into()
                } else {
                    tw.detected_technologies.join(", ")
                }
            );
            if !tw.js_third_party.is_empty() {
                println!(
                    "    • Technos JS tierces   : {}",
                    tw.js_third_party.join(", ")
                );
            }
            if !tw.versioned.is_empty() {
                println!("    • Composants versionnés :");
                for c in &tw.versioned {
                    println!("        - {} {}", c.name, c.version);
                }
                let verdicts =
                    crate::modules::tech_stack::TechStackAuditor::version_verdicts(&tw.versioned);
                if !verdicts.is_empty() {
                    println!("    • Branches non maintenues (EOL) :");
                    for v in verdicts {
                        println!(
                            "        ! {} {} < {} — {}",
                            v.name, v.detected, v.branch_min, v.recommendation
                        );
                    }
                }
            }
            if !tw.emails_exposed.is_empty() {
                println!(
                    "    • Courriels repérés    : {}",
                    tw.emails_exposed.join(", ")
                );
            }
            println!();
        }
    }
    /// [9] Protection de marque & typosquatting (Dnstwist)
    pub(super) fn print_brand_sec_section(&self) {
        // 9. Protection de Marque & Typosquatting
        if let Some(ref bs) = self.brand_sec {
            println!("[9] PROTECTION DE MARQUE & TYPOSQUATTING (DNSTWIST)");
            println!(
                "    • Domaines similaires  : {} actif(s) sur Internet",
                bs.registered_lookalikes.len()
            );
            for l in bs.registered_lookalikes.iter().take(6) {
                let ip_str = l.ip.as_deref().unwrap_or("Pas d'IP directe");
                println!("    • {:<24} ({}) -> {}", l.domain, l.fuzzer, ip_str);
            }
            if bs.registered_lookalikes.len() > 6 {
                println!(
                    "      ... (et {} autre(s) domaine(s))",
                    bs.registered_lookalikes.len() - 6
                );
            }
            println!();
        }
    }
    /// [10] Découverte de chemins & fichiers sensibles (Ffuf + SecLists)
    pub(super) fn print_ffuf_section(&self) {
        // 10. Ffuf / SecLists (si actif)
        if let Some(ref ffuf_res) = self.ffuf {
            println!("[10] DÉCOUVERTE DE CHEMINS & FICHIERS SENSIBLES (FFUF + SECLISTS)");
            println!(
                "    • Statut exécution     : {}",
                if ffuf_res.success {
                    "SUCCÈS"
                } else {
                    "ÉCHEC"
                }
            );
            println!("    • Résumé               : {}", ffuf_res.summary);
            if ffuf_res.endpoints.is_empty() {
                println!("    • Aucune fuite de fichier sensible (.git, .env, backup) détectée.");
            } else {
                for ep in &ffuf_res.endpoints {
                    println!(
                        "    • Route exposée        : /{} (HTTP {}, {} octets)",
                        ep.path, ep.status, ep.length
                    );
                }
            }
            println!();
        }
    }
    /// [12] Vulnérabilités applicatives & front-end
    pub(super) fn print_vuln_section(&self) {
        // 12. Vulnérabilités Applicatives & Front-end
        println!("[12] AUDIT DES VULNÉRABILITÉS APPLICATIVES & FRONT-END");
        println!(
            "    • Page HTML récupérée  : {}",
            if self.vuln_audit.html_retrieved {
                "OUI [200 OK]"
            } else {
                "NON"
            }
        );
        println!(
            "    • Scripts CDN détectés : {}",
            self.vuln_audit.cdn_scripts_count
        );
        println!(
            "    • Scripts sans SRI     : {}",
            if self.vuln_audit.missing_sri_count == 0 {
                "0 [SÉCURISÉ / INTÈGRE]".to_string()
            } else {
                format!("{} [ATTENTION]", self.vuln_audit.missing_sri_count)
            }
        );
        println!(
            "    • Contenu Mixte HTTP   : {}",
            if self.vuln_audit.mixed_content_count == 0 {
                "AUCUN [CONFORME]".to_string()
            } else {
                format!(
                    "{} ressource(s) en clair [ALERTE]",
                    self.vuln_audit.mixed_content_count
                )
            }
        );
        println!(
            "    • Configuration CORS   : {}",
            if self.vuln_audit.cors_misconfigured {
                "PERMISSIVE / VULNÉRABLE [ALERTE]"
            } else {
                "STRICTE / SÉCURISÉE [OK]"
            }
        );
        if !self.vuln_audit.detected_libraries.is_empty() {
            println!(
                "    • Bibliothèques JS     : {}",
                self.vuln_audit.detected_libraries.join(", ")
            );
        }
        println!();
    }
    /// Pages de diagnostic / fichiers sensibles exposes en clair.
    /// Affiche meme quand rien n'est trouve : l'absence de resultat est une
    /// information (le module a bien tourne).
    pub fn print_diag_exposure_section(&self) {
        let d = &self.diag_exposure;
        let exposed: Vec<_> = d.pages.iter().filter(|p| p.exposed).collect();
        let protected: Vec<_> = d
            .pages
            .iter()
            .filter(|p| p.signature == "protected")
            .collect();

        if exposed.is_empty() && protected.is_empty() {
            println!(
                "  [DIAG] {} chemin(s) teste(s) : aucune page de diagnostic exposee",
                d.checked
            );
            return;
        }

        if !exposed.is_empty() {
            println!(
                "  [DIAG] [1;31m{} page(s) de diagnostic EXPOSEE(S) en clair[0m",
                exposed.len()
            );
            for p in &exposed {
                println!(
                    "      [31mHTTP {} {} ({} octets, signature {})[0m",
                    p.status, p.path, p.size, p.signature
                );
            }
            if !d.php_disclosures.is_empty() {
                println!("      Configuration PHP divulguee :");
                for k in d.php_disclosures.iter().take(10) {
                    println!("        - {}", k);
                }
            }
        }
        if !protected.is_empty() {
            println!(
                "  [DIAG] {} chemin(s) existent mais sont proteges (403/401)",
                protected.len()
            );
            for p in &protected {
                println!("      {} -> HTTP {}", p.path, p.status);
            }
        }
        println!("      ({} chemin(s) teste(s) au total)", d.checked);
    }
}
