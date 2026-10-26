// findings/tls.rs — evaluateur TLS : chaine, expiration, protocoles.

use super::*;

impl FindingsEngine {
    /// 7. Audit TLS.
    ///
    /// Unfinding si aucun certificat n'a pu être récupéré (443 fermé/filtré) :
    /// l'absence de service TLS n'est pas une faille.
    pub(super) fn eval_tls(tls: &TlsAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let tls_service_present = tls.subject.is_some() || tls.issuer.is_some();
        if !tls_service_present {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "TLS",
                title: "Aucun service TLS accessible sur le port 443".into(),
                recommendation:
                    "Le port 443 est fermé ou filtré : aucun certificat à auditer sur cette cible."
                        .into(),
            });
        } else if !tls.is_valid {
            // Discrimination des erreurs de vérification (fix faux positif
            // archambault.ca 2026-09-30) : « unable to get local issuer » /
            // « unable to verify the first certificate » = le serveur ne SERT
            // PAS l'intermédiaire (chaîne incomplète). Le certificat lui-même
            // se valide très bien avec l'intermédiaire récupéré (AIA) :
            // openssl verify -untrusted <inter> leaf -> OK. Ce n'est PAS une
            // chaîne « compromise » : downgrade MEDIUM config serveur.
            let incomplete_chain = tls.issues.iter().any(|i| {
                i.contains("unable to get local issuer")
                    || i.contains("unable to verify the first certificate")
            });
            if incomplete_chain {
                findings.push(SecurityFinding {
                    severity: "MEDIUM",
                    category: "TLS",
                    title:
                        "Chaîne TLS incomplète : le certificat intermédiaire n'est pas servi par le serveur"
                            .into(),
                    recommendation:
                        "Servir la chaîne complète (feuille + intermédiaires, ex. fullchain.pem) : les clients sans récupération AIA (curl, Python, certains SDK) échouent la validation."
                            .into(),
                });
            } else {
                findings.push(SecurityFinding {
                    severity: "CRITICAL",
                    category: "TLS",
                    title: "Chaîne de confiance du certificat TLS invalide ou compromise".into(),
                    recommendation:
                        "Renouveler immédiatement le certificat auprès d'une autorité reconnue."
                            .into(),
                });
            }
        }

        if tls.supports_tls10 || tls.supports_tls11 {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "TLS",
                title: "Support des protocoles obsolètes TLS 1.0 / TLS 1.1 actif".into(),
                recommendation: "Désactiver TLS 1.0 et 1.1 dans la configuration SSL et n'autoriser que TLS 1.2 et TLS 1.3.".into(),
            });
        }

        // Expiration : la détection days_remaining est désormais fonctionnelle
        if let Some(days) = tls.days_remaining {
            if days <= 0 {
                findings.push(SecurityFinding {
                    severity: "CRITICAL",
                    category: "TLS",
                    title: format!("Certificat TLS EXPIRÉ depuis {} jour(s)", -days),
                    recommendation:
                        "Renouveler immédiatement le certificat : les navigateurs bloquent le site."
                            .into(),
                });
            } else if days < 15 {
                findings.push(SecurityFinding {
                    severity: "HIGH",
                    category: "TLS",
                    title: format!("Certificat TLS expirant dans {} jour(s)", days),
                    recommendation:
                        "Planifier le renouvellement automatique du certificat (ACME/Let's Encrypt)."
                            .into(),
                });
            } else if days < 30 {
                findings.push(SecurityFinding {
                    severity: "MEDIUM",
                    category: "TLS",
                    title: format!("Certificat TLS expirant dans {} jour(s)", days),
                    recommendation: "Vérifier la chaîne de renouvellement du certificat.".into(),
                });
            } else if days < 45 {
                findings.push(SecurityFinding {
                    severity: "LOW",
                    category: "TLS",
                    title: format!(
                        "Certificat TLS à renouveler dans {} jour(s) (échéance : {})",
                        days,
                        tls.valid_until.as_deref().unwrap_or("?")
                    ),
                    recommendation:
                        "Vérifier que le renouvellement automatique ACME est opérationnel avant l'échéance."
                            .into(),
                });
            }
        }

        if tls.is_self_signed {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "TLS",
                title: "Certificat TLS auto-signé (confiance impossible côté clients)".into(),
                recommendation:
                    "Émettre un certificat via une autorité reconnue (Let's Encrypt / ACME)."
                        .into(),
            });
        }
        findings
    }
}
