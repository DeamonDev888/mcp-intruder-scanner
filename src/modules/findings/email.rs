// findings/email.rs — evaluateur messagerie : SPF lookups, DKIM, MTA-STS, BIMI.

use super::*;

impl FindingsEngine {
    /// 4. Audit Messagerie Avancée (SPF lookups, DKIM, MTA-STS, BIMI).
    pub(super) fn eval_email(email_sec: &EmailSecurityResult, is_bare_ip: bool) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if !is_bare_ip && !email_sec.spf_lookup_valid {
            findings.push(SecurityFinding {
                severity: "CRITICAL",
                category: "EMAIL",
                title: format!("Limite des 10 lookups DNS SPF dépassée ({} lookups détectés, RFC 7208)", email_sec.spf_lookup_count),
                recommendation: "Aplatir la politique SPF (utiliser des sous-réseaux IP au lieu de multiples 'include' ou 'a') pour éviter le rejet PermError.".into(),
            });
        }

        if !is_bare_ip
            && email_sec.dkim_selectors_tested > 0
            && email_sec.dkim_selectors_found.is_empty()
        {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "EMAIL",
                title: format!(
                    "Aucun sélecteur DKIM trouvé parmi les {} testés",
                    email_sec.dkim_selectors_tested
                ),
                recommendation:
                    "Publier un enregistrement DKIM (sélecteur par défaut) pour signer les messages sortants."
                        .into(),
            });
        }

        if !is_bare_ip && !email_sec.dkim_selectors_found.is_empty() {
            let sels: Vec<String> = email_sec
                .dkim_selectors_found
                .iter()
                .take(3)
                .cloned()
                .collect();
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "EMAIL",
                title: format!("Signature DKIM active ({} sélecteur(s) : {}) — messages signés", email_sec.dkim_selectors_found.len(), sels.join(", ")),
                recommendation:
                    "Contrôle attesté : les messages sortants sont signés cryptographiquement (intégrité + expéditeur vérifiables)."
                        .into(),
            });
        }

        if !is_bare_ip && email_sec.mta_sts_present && email_sec.mta_sts_mode.is_none() {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "EMAIL",
                title: "MTA-STS annoncé (TXT présent) mais politique HTTPS injoignable".into(),
                recommendation:
                    "Le DNS annonce MTA-STS mais https://mta-sts.<domaine>/.well-known/mta-sts.txt ne répond pas : les serveurs expéditeurs retomberont en SMTP opportuniste. Restaurer l'endpoint ou retirer l'enregistrement TXT."
                        .into(),
            });
        }

        if !is_bare_ip && !email_sec.mta_sts_present {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "EMAIL",
                title: "MTA-STS (RFC 8461) non configuré sur le domaine".into(),
                recommendation: "Configurer un enregistrement TXT '_mta-sts' et une politique HTTPS pour forcer le chiffrement TLS entre serveurs de messagerie.".into(),
            });
        }

        if !is_bare_ip && !email_sec.bimi_present {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "EMAIL",
                title: "Enregistrement BIMI (Brand Indicators) non détecté".into(),
                recommendation: "Optionnel : Configurer 'default._bimi' avec un logo SVG certifié pour afficher votre logo dans Gmail/Apple Mail.".into(),
            });
        }
        findings
    }
}
