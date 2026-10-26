// report/tools.rs — sections orchestration : outils Kali [13]-[19] et constats [20].

use super::*;

impl FullAuditReport {
    /// [13] à [19] Outils d'orchestration Kali : Nmap, Nuclei, Nikto, Whois,
    pub(super) fn print_tools_section(&self) {
        // 13. Nmap (si actif)
        if let Some(ref nmap_res) = self.nmap {
            println!("[13] ORCHESTRATION KALI : NMAP SERVICE & NSE AUDIT");
            println!(
                "    • Statut exécution     : {}",
                if nmap_res.success {
                    "SUCCÈS"
                } else {
                    "ÉCHEC"
                }
            );
            println!("    • Résumé               : {}", nmap_res.summary);
            for srv in &nmap_res.services {
                let ver_str = srv.version.as_deref().unwrap_or("");
                let prod_str = srv.product.as_deref().unwrap_or(&srv.service);
                println!(
                    "    • Port {:<5}/{} : {:<10} {} {}",
                    srv.port, srv.protocol, srv.state, prod_str, ver_str
                );
                for (sc_id, _) in &srv.scripts {
                    println!("      - Script NSE validé  : {}", sc_id);
                }
            }
            println!();
        }

        // 14. Nuclei (si actif)
        if let Some(ref nuclei_res) = self.nuclei {
            println!("[14] ORCHESTRATION KALI : NUCLEI VULNERABILITY SCANNER");
            println!(
                "    • Statut exécution     : {}",
                if nuclei_res.success {
                    "SUCCÈS"
                } else {
                    "ÉCHEC"
                }
            );
            println!("    • Résumé               : {}", nuclei_res.summary);
            if nuclei_res.items.is_empty() {
                println!(
                    "    • Aucune vulnérabilité ou anomalie détectée par les templates Nuclei."
                );
            } else {
                for it in &nuclei_res.items {
                    println!(
                        "    • [{:<8}] {:<25} ({})",
                        it.severity, it.template_id, it.name
                    );
                }
            }
            println!();
        }

        // 15. Nikto (si actif)
        if let Some(ref nikto_res) = self.nikto {
            println!("[15] ORCHESTRATION KALI : NIKTO WEB SERVER AUDITOR");
            println!(
                "    • Statut exécution     : {}",
                if nikto_res.success {
                    "SUCCÈS"
                } else {
                    "ÉCHEC"
                }
            );
            println!("    • Résumé               : {}", nikto_res.summary);
            if nikto_res.vulnerabilities.is_empty() {
                println!("    • Aucun problème spécifique signalé par Nikto.");
            } else {
                for v in &nikto_res.vulnerabilities {
                    println!("    • [{}] Route {} : {}", v.id, v.url, v.msg);
                }
            }
            println!();
        }

        // 16. Whois (si actif)
        if let Some(ref wh) = self.whois {
            println!("[16] REGISTRE DE NOM DE DOMAINE & EXPIRATION (WHOIS)");
            println!(
                "    • Registrar            : {}",
                wh.registrar.as_deref().unwrap_or("Non identifié")
            );
            println!(
                "    • Date de création     : {}",
                wh.creation_date.as_deref().unwrap_or("Non renseignée")
            );
            println!(
                "    • Date d'expiration    : {}",
                wh.expiry_date.as_deref().unwrap_or("Non renseignée")
            );
            println!(
                "    • Verrou anti-transfert: {}",
                if wh.is_transfer_locked {
                    "ACTIF (ClientTransferProhibited) [SÉCURISÉ]"
                } else {
                    "INACTIF [ATTENTION: Risque de hijacking]"
                }
            );
            println!(
                "    • Masquage Privacy     : {}",
                if wh.is_privacy_protected {
                    "ACTIF (Données personnelles masquées) [CONFORME]"
                } else {
                    "NON DÉTECTÉ"
                }
            );
            println!();
        }

        // 17. Dnsrecon (si actif)
        if let Some(ref dr) = self.dnsrecon {
            println!("[17] RECONNAISSANCE DNS AVANCÉE (DNSRECON)");
            if dr.bind_versions.is_empty() {
                println!("    • Version DNS / BIND   : Masquée [SÉCURISÉ]");
            } else {
                for (srv, ver) in &dr.bind_versions {
                    println!("    • Version DNS sur {}   : {}", srv, ver);
                }
            }
            if dr.srv_records.is_empty() {
                println!("    • Services SRV         : Aucun service SRV standard exposé.");
            } else {
                for srv in &dr.srv_records {
                    println!(
                        "    • Service SRV trouvé   : {} -> {}:{} ({})",
                        srv.name, srv.target, srv.port, srv.address
                    );
                }
            }
            println!();
        }

        // 18. theHarvester (si actif)
        if let Some(ref th) = self.theharvester {
            println!("[18] RENSEIGNEMENT OSINT & FUITE DE DONNÉES (THEHARVESTER)");
            if th.emails.is_empty() {
                println!(
                    "    • Emails indexés OSINT : Aucun email public découvert dans les moteurs."
                );
            } else {
                println!("    • Emails indexés OSINT : {}", th.emails.join(", "));
            }
            if th.hosts.is_empty() {
                println!("    • Hôtes indexés OSINT  : Aucun hôte supplémentaire découvert.");
            } else {
                println!("    • Hôtes indexés OSINT  : {}", th.hosts.join(", "));
            }
            println!();
        }

        // 19. Obscura (si actif)
        if let Some(ref obs) = self.obscura {
            println!("[19] MOTEUR DE RENDU DYNAMIQUE JAVASCRIPT & DOM (OBSCURA)");
            println!(
                "    • Statut exécution     : {}",
                if obs.success { "SUCCÈS" } else { "ÉCHEC" }
            );
            println!("    • Titre rendu DOM      : {}", obs.page_title);
            println!(
                "    • Sous-ressources DOM  : {} totale(s), dont {} script(s) JS",
                obs.total_assets, obs.script_assets
            );
            if !obs.external_scripts.is_empty() {
                println!(
                    "    • Dépendances tierces  : {} domaine(s) externe(s) (ex: {})",
                    obs.external_scripts.len(),
                    obs.external_scripts
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if !obs.insecure_assets.is_empty() {
                println!(
                    "    • Contenu Mixte HTTP   : {} ressource(s) non sécurisée(s) [ALERTE]",
                    obs.insecure_assets.len()
                );
            }
            println!(
                "    • Alertes Console JS   : {}",
                if obs.console_warnings_count == 0 {
                    "0 [AUCUNE ERREUR]".to_string()
                } else {
                    format!("{} anomalie(s) interceptée(s)", obs.console_warnings_count)
                }
            );
            if let Some(ref sc_path) = obs.screenshot_path {
                println!(
                    "    • Capture visuelle PNG : {} ({} Ko)",
                    sc_path,
                    obs.screenshot_size_bytes / 1024
                );
            }
            println!();
        }
    }
    /// [20] Constatations & recommandations d'audit
    pub(super) fn print_findings_section(&self) {
        // 20. Constatations & Recommandations globales
        println!(
            "================================================================================"
        );
        println!(
            "             CONSTATATIONS & RECOMMANDATIONS D'AUDIT ({})                      ",
            self.findings.len()
        );
        println!(
            "================================================================================"
        );
        if self.findings.is_empty() {
            println!("  [EXCELLENT] Aucune faiblesse ou anomalie détectée sur la cible.");
        } else {
            for f in &self.findings {
                println!("  [{:<8}] [{:<9}] {}", f.severity, f.category, f.title);
                println!("    Action recommandée : {}\n", f.recommendation);
            }
        }
        println!(
            "--------------------------------------------------------------------------------\n"
        );
        println!();
        println!("Score global : {}/100", self.overall_score);
        println!();
    }
}
