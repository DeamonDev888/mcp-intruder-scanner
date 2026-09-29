//! Sous-domaines via Certificate Transparency (crt.sh).
//! Lecons bank8.example.com : blog.bank8.example.com (cert 2019-2020) etait invisible
//! pour subfinder + liste statique, mais present dans les logs CT.
//! Passif : 1 requete HTTPS GET, aucune interaction avec la cible.

use crate::modules::subdomains::SubdomainResult;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CrtShResult {
    pub success: bool,
    pub subdomains: Vec<SubdomainResult>,
    pub raw_output: String,
    pub summary: String,
    pub elapsed_seconds: f32,
}

pub struct CrtShAuditor;

impl CrtShAuditor {
    /// GET https://crt.sh/?q=%25.domaine&output=json puis parse serde_json.
    /// %25 = % (wildcard SQL de crt.sh) URL-encode.
    pub fn audit(domain: &str) -> CrtShResult {
        let start = std::time::Instant::now();
        let mut res = CrtShResult::default();

        let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
        let out = crate::utils::run_tool(
            "curl",
            &["-s", "--max-time", "25", "-H", "Accept: application/json", &url],
            30,
        );
        let body = out
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        res.raw_output = body.clone();

        if body.trim().is_empty() {
            res.summary = "crt.sh : reponse vide (timeout ou rate-limit)".into();
            return res;
        }
        let parsed: Vec<serde_json::Value> = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                res.summary = format!("crt.sh : JSON invalide ({e})");
                return res;
            }
        };

        let base = domain.trim_start_matches("www.").to_lowercase();
        let mut seen = std::collections::BTreeSet::new();
        for entry in &parsed {
            // name_value contient souvent plusieurs domaines separes par \n
            if let Some(nv) = entry.get("name_value").and_then(|x| x.as_str()) {
                for name in nv.split(['\n', ' ']) {
                    let n = name.trim().trim_end_matches('.').to_lowercase();
                    // Garde uniquement le domaine demande et ses sous-domaines
                    if n == base || n.ends_with(&format!(".{base}")) {
                        // Ignore les wildcards bruts *.domaine
                        if n.starts_with("*.") || n.is_empty() {
                            continue;
                        }
                        seen.insert(n);
                    }
                }
            }
        }

        res.subdomains = seen
            .into_iter()
            .map(|sub| SubdomainResult {
                subdomain: sub,
                source: "crt.sh".into(),
                ip_address: None,
                http_status: None,
                is_alive: false,
            })
            .collect();
        res.success = true;
        res.summary = format!(
            "crt.sh : {} sous-domaine(s) via Certificate Transparency en {:.1}s",
            res.subdomains.len(),
            start.elapsed().as_secs_f32()
        );
        res.elapsed_seconds = start.elapsed().as_secs_f32();
        res
    }

    /// Fusionne les hotes crt.sh dans la liste existante (dedup par nom).
    /// Retourne le nombre d'hotes nouvellement ajoutes.
    pub fn merge_into(subs: &mut Vec<crate::modules::subdomains::SubdomainResult>, crt: &CrtShResult) -> usize {
        let mut added = 0;
        for c in &crt.subdomains {
            if !subs.iter().any(|s| s.subdomain.eq_ignore_ascii_case(&c.subdomain)) {
                subs.push(c.clone());
                added += 1;
            }
        }
        added
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_crtsh_parse_filters_and_scopes() {
        let json = r#"[
          {"issuer_name":"Let's Encrypt","name_value":"*.bank8.example.com\nbank8.example.com","not_before":"2026-09-02"},
          {"issuer_name":"Let's Encrypt","name_value":"blog.bank8.example.com","not_before":"2019-11-04"},
          {"issuer_name":"Sectigo","name_value":"evilbank8.example.com\nother.com","not_before":"2020-01-01"}
        ]"#;
        let v: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        let base = "bank8.example.com";
        for entry in &v {
            if let Some(nv) = entry.get("name_value").and_then(|x| x.as_str()) {
                for name in nv.split(['\n', ' ']) {
                    let n = name.trim().trim_end_matches('.').to_lowercase();
                    if (n == base || n.ends_with(&format!(".{base}"))) && !n.starts_with("*.") && !n.is_empty() {
                        seen.insert(n);
                    }
                }
            }
        }
        let list: Vec<String> = seen.into_iter().collect();
        assert!(list.contains(&"bank8.example.com".to_string()));
        assert!(list.contains(&"blog.bank8.example.com".to_string()), "sous-domaine historique conservé");
        assert!(!list.iter().any(|x| x.contains("evilbank8")), "hors scope rejeté");
        assert!(!list.iter().any(|x| x.contains("other.com")), "hors scope rejeté");
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_lock_crtsh_merge_dedup() {
        let crt = CrtShResult {
            success: true,
            subdomains: vec![
                SubdomainResult { subdomain: "blog.bank8.example.com".into(), source: "crt.sh".into(), ip_address: None, http_status: None, is_alive: false },
                SubdomainResult { subdomain: "www.bank8.example.com".into(), source: "crt.sh".into(), ip_address: None, http_status: None, is_alive: false },
            ],
            ..Default::default()
        };
        let mut subs = vec![
            SubdomainResult { subdomain: "www.bank8.example.com".into(), source: "subfinder".into(), ip_address: None, http_status: Some(200), is_alive: true },
        ];
        let n = CrtShAuditor::merge_into(&mut subs, &crt);
        assert_eq!(n, 1, "seul blog.bank8.example.com est nouveau");
        assert_eq!(subs.len(), 2);
        assert!(subs.iter().any(|s| s.subdomain == "blog.bank8.example.com"));
        // Le www existant garde ses donnees vivantes (pas ecrase)
        let www = subs.iter().find(|s| s.subdomain == "www.bank8.example.com").unwrap();
        assert!(www.is_alive && www.http_status == Some(200));
    }
}
