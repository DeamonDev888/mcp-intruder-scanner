//! MCP Intruder — moteur de scan de surface offensif + serveur Model Context
//! Protocol (litemcp, Streamable HTTP).
//!
//! Principes NON NEGOCIABLES :
//! - lecture seule : HTTP GET et DNS exclusivement, jamais de POST/PUT/DELETE,
//!   jamais d'écriture sur la cible ;
//! - requête unique par objet (pas de brute-force : les chemins viennent du
//!   scanner) ;
//! - timeout dur sur chaque requête (curl --max-time) ;
//! - subprocess via args() uniquement, jamais `sh -c` ;
//! - secrets jamais affichés en clair : masqués avant affichage.
//!
//! Organisation :
//! - moteur de scan : config, modules, orchestrator, report, target_parser,
//!   utils (promus ici depuis l'ancien binaire main.rs, v0.5.x) ;
//! - preuve d'impact : net.rs, secrets.rs, dnsinfo.rs, gkeyx.rs ;
//! - `mcp.rs`        — serveur MCP (outils exposees au client) ;
//! - `dash/`         — tableau de bord web (serveur HTTP local).

/// Tableau de bord web : serveur HTTP local qui lit le catalogue
/// PostgreSQL et rend l'interface. Declare ici pour que le binaire
/// `src/bin/dashboard.rs` puisse l'importer via `mcp_intruder::dash`.
pub mod dash;

/// Serveur Model Context Protocol : expose le moteur de scan comme outils
/// MCP. Le binaire `src/bin/mcp_server.rs` construit et sert le serveur ;
/// `mcp::build_server()` est la seule porte d'entree.
pub mod mcp;

/// Moteur de scan (ex-cible binaire main.rs, promue en lib v0.6.0 pour que
/// le serveur MCP et le CLI partagent exactement le meme code).
pub mod config;
pub mod modules;
pub mod orchestrator;
pub mod platform;
pub mod report;
pub mod target_parser;
pub mod utils;
pub mod wizard;
//
// Organisation (ex-lib.rs monolithique de 900 lignes) :
//   net.rs      — HttpResponse + http_get/http_get_headers (curl, timeout dur)
//   secrets.rs  — masquage, .env, classification de cles, verification Google
//   dnsinfo.rs  — dig TXT, SPF, DMARC, verdict de spoofing
//   gkeyx.rs    — sondes de preuve d'impact cles Google (binaire gkeyx)
// Les re-exports ci-dessous preservent l'API publique historique : les bins
// `src/bin/*.rs` importent ces items depuis la racine du crate.

mod dnsinfo;
mod gkeyx;
mod net;
mod secrets;

pub use dnsinfo::{dig_txt, dmarc_policy, spf_all_qualifier, spoof_verdict};
pub use gkeyx::{
    extract_google_project, gemini_models, gkeyx_exploit, gkeyx_report, gkeyx_verdict,
    google_probe_classify, GProbe, GProbeStatus,
};
pub use net::{http_get, http_get_headers, HttpResponse};
pub use secrets::{
    check_google_key, classify_key, extract_emails, extract_remotes, is_high_signal,
    looks_like_env, mask_secret, parse_env, GoogleKeyVerdict, KeyKind,
};

/// Suite de tests du moteur (ex-main.rs, 123 tests) — compile dans la cible
/// lib depuis la promotion v0.6.0.
#[cfg(test)]
mod engine_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_secret_never_leaks_full_value() {
        let m = mask_secret("SUPERSECRET123456");
        assert!(!m.contains("SUPERSECRET123456"));
        assert!(m.contains("SUP"));
        assert!(m.contains("chars"));
        assert_eq!(mask_secret("abc"), "*** (3 chars)");
        assert_eq!(mask_secret(""), "(vide)");
    }

    #[test]
    fn parse_env_handles_comments_quotes() {
        let env = "# comment\nDB_HOST=localhost\nDB_PASSWORD=p@ss_w0rd!\nEMPTY=\n";
        let pairs = parse_env(env);
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], ("DB_HOST".to_string(), "localhost".to_string()));
        assert_eq!(pairs[1].1, "p@ss_w0rd!");
    }

    #[test]
    fn looks_like_env_rejects_html_soft404() {
        assert!(looks_like_env("A=1\nB=2\n"));
        assert!(!looks_like_env("<html><body>404</body></html>"));
    }

    #[test]
    fn high_signal_keys() {
        assert!(is_high_signal("DATABASE_PASSWORD"));
        assert!(is_high_signal("aws_secret_access_key"));
        assert!(is_high_signal("SMTP_TOKEN"));
        assert!(!is_high_signal("APP_NAME"));
        assert!(!is_high_signal("DEBUG"));
    }

    #[test]
    fn classify_key_formats() {
        let g = "AIzaSy123456789012345678901234567890123"; // 39 chars
        assert_eq!(classify_key(g), KeyKind::Google);
        assert_eq!(classify_key("sk_live_abc123"), KeyKind::StripeLive);
        assert_eq!(classify_key("sk_test_abc123"), KeyKind::StripeTest);
        assert_eq!(classify_key("SG.abc.def"), KeyKind::SendGrid);
        assert_eq!(classify_key("xoxb-123"), KeyKind::Slack);
        assert_eq!(classify_key("ghp_abc"), KeyKind::GitHub);
        assert_eq!(classify_key("sk-proj-xyz"), KeyKind::OpenAI);
        assert_eq!(classify_key("nimporte"), KeyKind::Unknown);
        assert!(!classify_key("sk_live_x").safely_checkable());
        assert!(classify_key(g).safely_checkable());
    }

    #[test]
    fn spf_qualifier_parsing() {
        assert_eq!(spf_all_qualifier("v=spf1 ip4:1.2.3.4 -all"), Some('-'));
        assert_eq!(spf_all_qualifier("v=spf1 ~all"), Some('~'));
        assert_eq!(spf_all_qualifier("v=spf1 all"), Some('+'));
        assert_eq!(spf_all_qualifier("v=spf1 ip4:1.2.3.4"), None);
    }

    #[test]
    fn dmarc_policy_parsing() {
        assert_eq!(
            dmarc_policy("v=DMARC1; p=reject; rua=mailto:x@y.z"),
            Some("reject".to_string())
        );
        assert_eq!(dmarc_policy("v=DMARC1; p=none"), Some("none".to_string()));
        assert_eq!(dmarc_policy("v=spf1 -all"), None);
    }

    #[test]
    fn spoof_verdict_matrix() {
        let (v, _) = spoof_verdict(None, None);
        assert_eq!(v, "USURPABLE");
        let (v, _) = spoof_verdict(Some("v=spf1 -all"), Some("reject"));
        assert_eq!(v, "PROTEGE");
        let (v, _) = spoof_verdict(Some("v=spf1 -all"), Some("none"));
        assert!(v.contains("PARTIEL"));
        let (v, _) = spoof_verdict(Some("v=spf1 -all"), None);
        assert_eq!(v, "PARTIEL");
    }

    #[test]
    fn extract_emails_and_remotes() {
        let log = "0000 1111 Alice <alice@corp.internal> 1700000000 +0000\tinit\n2222 3333 Bob <bob@corp.internal> 1700000001 +0000\tfix";
        assert_eq!(
            extract_emails(log),
            vec!["alice@corp.internal", "bob@corp.internal"]
        );
        let cfg = r#"[core]
	repositoryformatversion = 0
[remote "origin"]
	url = git@internal.git.corp:proj/web.git
"#;
        assert_eq!(
            extract_remotes(cfg),
            vec!["git@internal.git.corp:proj/web.git"]
        );
    }

    #[test]
    fn gkeyx_classify_real_signatures() {
        // Fixtures = reponses REELLES capturees des APIs Google (2026-09-26).
        // googleapis.com (gemini/youtube/translate) : HTTP 400 + message.
        let g400 = r#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}"#;
        assert_eq!(google_probe_classify(400, g400).0, GProbeStatus::Denied);
        // maps.googleapis.com : HTTP 200 + REQUEST_DENIED dans le corps.
        let maps_invalid = r#"{"candidates":[],"error_message":"The provided API key is invalid.","status":"REQUEST_DENIED"}"#;
        assert_eq!(
            google_probe_classify(200, maps_invalid).0,
            GProbeStatus::Denied
        );
        // Maps restreinte referrer : cle vive.
        let maps_ref = r#"{"error_message":"This API key is not authorized to be used from this site.","status":"REQUEST_DENIED"}"#;
        let (st, d) = google_probe_classify(200, maps_ref);
        assert_eq!(st, GProbeStatus::Constrained);
        assert!(d.contains("referrer"), "{d}");
        // API non activee : fuite du numero de projet.
        let not_used = r#"{"error":{"code":403,"message":"Google Maps JavaScript API error: RefererNotAllowedMapError ... has not been used in project 123456789012 before or it is disabled"}}"#;
        let (st, d) = google_probe_classify(403, not_used);
        assert_eq!(st, GProbeStatus::Constrained);
        assert!(d.contains("123456789012"), "{d}");
        // 200 net = acces prouve.
        assert_eq!(
            google_probe_classify(200, r#"{"models":[]}"#).0,
            GProbeStatus::Granted
        );
        // 429 = cle vive, rate-limitee.
        assert_eq!(
            google_probe_classify(429, r#"{"error":{"code":429}}"#).0,
            GProbeStatus::Constrained
        );
    }

    #[test]
    fn gkeyx_project_extraction() {
        assert_eq!(
            extract_google_project("has not been used in project 987654321234 before"),
            Some("987654321234".to_string())
        );
        // projects/ extrait aussi
        assert_eq!(
            extract_google_project("projects/555666777888/locations/global"),
            Some("555666777888".to_string())
        );
        assert_eq!(extract_google_project("rien ici"), None);
        // numero trop court = pas un projet
        assert_eq!(extract_google_project("project 123"), None);
    }

    #[test]
    fn gkeyx_gemini_models_parse() {
        let body =
            r#"{"models":[{"name":"models/gemini-2.0-flash"},{"name":"models/gemini-1.5-pro"}]}"#;
        assert_eq!(
            gemini_models(body),
            vec!["models/gemini-2.0-flash", "models/gemini-1.5-pro"]
        );
        assert!(gemini_models("{}").is_empty());
    }

    #[test]
    fn gkeyx_verdict_matrix() {
        let mk = |family: &'static str, service: &'static str, status: GProbeStatus| GProbe {
            family,
            service,
            status,
            detail: String::new(),
        };
        let probes = vec![
            mk("LLM", "gemini", GProbeStatus::Granted),
            mk("MAPS", "staticmap", GProbeStatus::Granted),
            mk("DATA", "youtube", GProbeStatus::Denied),
        ];
        let (v, d) = gkeyx_verdict(&probes);
        assert_eq!(v, "VALIDE");
        assert!(d.contains("gemini"), "{d}");
        assert!(d.contains("LLM"), "{d}");

        let constrained = vec![
            mk("MAPS", "staticmap", GProbeStatus::Constrained),
            mk("DATA", "youtube", GProbeStatus::Constrained),
        ];
        assert_eq!(gkeyx_verdict(&constrained).0, "VALIDE_RESTREINTE");

        let denied = vec![
            mk("LLM", "gemini", GProbeStatus::Denied),
            mk("MAPS", "staticmap", GProbeStatus::Denied),
        ];
        assert_eq!(gkeyx_verdict(&denied).0, "INVALIDE");

        let inc = vec![mk("LLM", "gemini", GProbeStatus::Inconclusive)];
        assert_eq!(gkeyx_verdict(&inc).0, "NON_VERIFIABLE");
    }
}
