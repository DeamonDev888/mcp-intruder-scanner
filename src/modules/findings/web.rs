// findings/web.rs — evaluateurs HTTP (headers, cookies) et endpoints web.

use super::*;

impl FindingsEngine {
    /// 5. Audit HTTP & Headers (redirection, HSTS, CSP, cookies).
    pub(super) fn eval_http(http: &HttpAuditResult) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        let http_service_present = http.http_status > 0;
        if !http_service_present {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "HTTP",
                title: "Aucun serveur HTTP/HTTPS accessible en tête de cible".into(),
                recommendation:
                    "Aucun port HTTP/HTTPS n'a répondu (80/443 ou ports spécifiés) : audit applicatif web non applicable."
                        .into(),
            });
        }
        if http_service_present && !http.redirects_to_https {
            findings.push(SecurityFinding {
                severity: "HIGH",
                category: "HTTP",
                title: "Pas de redirection forcée vers HTTPS".into(),
                recommendation: "Configurer une redirection 301 automatique du port 80 HTTP vers le port 443 HTTPS.".into(),
            });
        }

        // P1-3 : un attribut de TRANSPORT ne s'evalue que sur une reponse TLS.
        // Sur une reponse cleartext, l'absence de HSTS ne prouve rien (faux
        // positif mesure sur 100 scans, score moyen 30,6). Dans ce cas : INFO,
        // jamais HIGH.
        if http_service_present {
            match http.hsts_present {
                Some(true) => {}
                Some(false) => {
                    findings.push(SecurityFinding {
                        severity: "HIGH",
                        category: "HTTP",
                        title: "En-tête Strict-Transport-Security (HSTS) manquant".into(),
                        recommendation: "Ajouter 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.".into(),
                    });
                }
                None => {
                    findings.push(SecurityFinding {
                        severity: "INFO",
                        category: "HTTP",
                        title: "HSTS non évaluable : la réponse analysée était en cleartext".into(),
                        recommendation:
                            "Rejouer l'audit sur https://<cible>/ pour évaluer la présence de Strict-Transport-Security.".into(),
                    });
                }
            }
        }

        if http_service_present
            && http.csp_present
            && http
                .csp_value
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains("'unsafe-inline'")
        {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "HTTP",
                title: "CSP présente mais contournable : directive 'unsafe-inline' active".into(),
                recommendation:
                    "Remplacer 'unsafe-inline' par des nonces ou des hashes de scripts (CSP niveau 3) — la directive actuelle n'empêche pas l'injection de code inline."
                        .into(),
            });
        }

        if http_service_present && !http.csp_present {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "HTTP",
                title: "En-tête Content-Security-Policy (CSP) manquant".into(),
                recommendation:
                    "Définir une politique CSP stricte pour contrer les injections de scripts XSS."
                        .into(),
            });
        }

        if http_service_present && http.x_frame_options.is_none() {
            findings.push(SecurityFinding {
                severity: "MEDIUM",
                category: "HTTP",
                title: "En-tête X-Frame-Options manquant".into(),
                recommendation: "Définir 'X-Frame-Options: SAMEORIGIN' pour bloquer les attaques par Clickjacking.".into(),
            });
        }

        if http_service_present {
            if let Some(ref s) = http.server_header {
                findings.push(SecurityFinding {
                    severity: "LOW",
                    category: "HTTP",
                    title: format!("Divulgation du serveur Web : '{}'", s),
                    recommendation:
                        "Masquer la signature 'Server' (ex: server_tokens off dans Nginx).".into(),
                });
            }
        }

        // HSTS : évaluation du max-age réel (trop court = protection dégradée)
        if http_service_present {
            if let Some(ref v) = http.hsts_value {
                let max_age = v
                    .split(';')
                    .find_map(|p| p.trim().strip_prefix("max-age="))
                    .and_then(|s| s.trim().parse::<u64>().ok());
                if let Some(age) = max_age {
                    if age < 15_768_000 {
                        findings.push(SecurityFinding {
                            severity: "MEDIUM",
                            category: "HTTP",
                            title: format!(
                                "HSTS max-age trop court ({} s < 6 mois recommandés)",
                                age
                            ),
                            recommendation:
                                "Porter max-age à au moins 31536000 (1 an) avec includeSubDomains."
                                    .into(),
                        });
                    }
                }
            }
        }

        // Cookies : chaque cookie sans Secure/HttpOnly est signalé (l'ancien
        // moteur listait les cookies mais ne générait AUCUN finding)
        if http_service_present {
            for c in &http.cookies {
                if !c.secure || !c.http_only || c.same_site.is_none() {
                    let mut missing = Vec::new();
                    if !c.secure {
                        missing.push("Secure");
                    }
                    if !c.http_only {
                        missing.push("HttpOnly");
                    }
                    if c.same_site.is_none() {
                        missing.push("SameSite");
                    }
                    findings.push(SecurityFinding {
                        severity: "MEDIUM",
                        category: "COOKIE",
                        title: format!(
                            "Cookie '{}' émis sans attribut(s) de sécurité : {}",
                            c.name,
                            missing.join(", ")
                        ),
                        recommendation:
                            "Ajouter Secure, HttpOnly et SameSite=Lax/Strict sur tous les cookies."
                                .into(),
                    });
                }
            }
        }
        findings
    }
    /// 6. Audit Web Endpoints (robots.txt, security.txt, méthodes HTTP).
    pub(super) fn eval_web_endpoints(
        web_endpoints: &WebEndpointsResult,
        http_service_present: bool,
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        // robots.txt : les Disallow révèlent les chemins sensibles (recon passive)
        if http_service_present {
            let paths: Vec<&String> = web_endpoints
                .robots_disallowed_paths
                .iter()
                .filter(|p| !p.is_empty() && p.as_str() != "/")
                .take(6)
                .collect();
            if !paths.is_empty() {
                findings.push(SecurityFinding {
                    severity: "INFO",
                    category: "WEB",
                    title: format!(
                        "robots.txt révèle {} chemin(s) interne(s) : {}",
                        web_endpoints.robots_disallowed_paths.len(),
                        paths
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                    recommendation:
                        "Inventaire passif : ces chemins (API, backoffices, préprod) sont connus de tout visiteur — vérifier leur protection par authentification."
                            .into(),
                });
            }
        }

        if http_service_present && !web_endpoints.security_txt_present {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "WEB",
                title: "Fichier de signalement de vulnérabilités RFC 9116 (security.txt) manquant".into(),
                recommendation: "Publier un fichier /.well-known/security.txt pour orienter les chercheurs de failles légitimes.".into(),
            });
        }

        if web_endpoints.dangerous_methods_found {
            // TRACE annoncé mais non réfléchi (501/405) = annonce morte : LOW.
            // Exception PUT/DELETE : méthodes actives dangereuses, HIGH conservé.
            let trace_only_dead = web_endpoints.trace_reflected == Some(false)
                && !web_endpoints
                    .allowed_http_methods
                    .iter()
                    .any(|m| m == "PUT" || m == "DELETE" || m == "TRACK");
            let (sev, extra) = if trace_only_dead {
                (
                    "LOW",
                    " (TRACE annoncé dans Allow: mais non réfléchi par le serveur)",
                )
            } else {
                ("HIGH", "")
            };
            findings.push(SecurityFinding {
                severity: sev,
                category: "WEB",
                title: format!(
                    "Méthodes HTTP potentiellement dangereuses activées : {}{}",
                    web_endpoints.allowed_http_methods.join(", "),
                    extra
                ),
                recommendation: "Désactiver TRACE, TRACK, PUT, DELETE au niveau de la configuration du serveur Web.".into(),
            });
        }
        findings
    }
}
