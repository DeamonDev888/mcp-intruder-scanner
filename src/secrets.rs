// src/secrets.rs — analyse de secrets exposes : masquage, .env, classification de cles API.

use crate::net::http_get;

/// Masque un secret : 3 premiers caractères + longueur, jamais la valeur.
pub fn mask_secret(v: &str) -> String {
    let t = v.trim();
    let n = t.chars().count();
    if n == 0 {
        return String::from("(vide)");
    }
    if n <= 6 {
        return format!("{} ({n} chars)", "*".repeat(n));
    }
    let head: String = t.chars().take(3).collect();
    format!("{head}**** ({n} chars)")
}

/// Parse un contenu .env en paires clé/valeur (ignore commentaires et vides).
pub fn parse_env(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            l.split_once('=').map(|(k, v)| {
                (
                    k.trim().to_string(),
                    v.trim().trim_matches('"').trim_matches('\'').to_string(),
                )
            })
        })
        .collect()
}

/// Une réponse ressemble-t-elle à un vrai .env (anti soft-404) ?
pub fn looks_like_env(body: &str) -> bool {
    let pairs = parse_env(body);
    let low = body.to_lowercase();
    pairs.len() >= 2 && !low.contains("<html") && !low.contains("<!doctype")
}

/// Clé d'environnement à forte valeur (identifiants, secrets, DSN).
pub fn is_high_signal(key: &str) -> bool {
    const PATTERNS: [&str; 13] = [
        "PASSWORD",
        "PASSWD",
        "PWD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "PRIVATE",
        "DSN",
        "AWS_",
        "SMTP",
        "DATABASE_URL",
        "CREDENTIAL",
    ];
    let u = key.to_uppercase();
    PATTERNS.iter().any(|p| u.contains(p))
}

/// Type de clé API deviné depuis son format (classification seule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Google,
    StripeLive,
    StripeTest,
    SendGrid,
    Slack,
    GitHub,
    OpenAI,
    Unknown,
}

impl KeyKind {
    pub fn label(self) -> &'static str {
        match self {
            KeyKind::Google => "Google API",
            KeyKind::StripeLive => "Stripe LIVE",
            KeyKind::StripeTest => "Stripe test",
            KeyKind::SendGrid => "SendGrid",
            KeyKind::Slack => "Slack token",
            KeyKind::GitHub => "GitHub token",
            KeyKind::OpenAI => "OpenAI",
            KeyKind::Unknown => "inconnu",
        }
    }

    /// Seules certaines clés peuvent être vérifiées sans effet de bord.
    pub fn safely_checkable(self) -> bool {
        matches!(self, KeyKind::Google)
    }
}

pub fn classify_key(k: &str) -> KeyKind {
    let k = k.trim();
    if k.starts_with("AIza") && k.len() == 39 {
        KeyKind::Google
    } else if k.starts_with("sk_live") {
        KeyKind::StripeLive
    } else if k.starts_with("sk_test") {
        KeyKind::StripeTest
    } else if k.starts_with("SG.") && k.matches('.').count() == 2 {
        KeyKind::SendGrid
    } else if k.starts_with("xox") {
        KeyKind::Slack
    } else if k.starts_with("ghp_") || k.starts_with("github_pat_") {
        KeyKind::GitHub
    } else if k.starts_with("sk-") {
        KeyKind::OpenAI
    } else {
        KeyKind::Unknown
    }
}

/// Résultat de la vérification non destructive d'une clé Google Maps.
#[derive(Debug, Clone)]
pub struct GoogleKeyVerdict {
    pub valid: bool,
    pub detail: String,
}

/// Vérifie une clé Google via une requête staticmap minimale (1 requête GET,
/// gratuite, sans effet de bord). Détecte aussi les restrictions referrer/IP.
pub fn check_google_key(key: &str, timeout_secs: u64) -> Option<GoogleKeyVerdict> {
    let url =
        format!("https://maps.googleapis.com/maps/api/staticmap?center=0,0&size=16x16&key={key}");
    let r = http_get(&url, timeout_secs)?;
    let low = r.body.to_lowercase();
    if r.status == 200 {
        return Some(GoogleKeyVerdict {
            valid: true,
            detail: "clé ACCEPTÉE (200) — utilisable telle quelle".to_string(),
        });
    }
    if low.contains("request_denied") || low.contains("requestdenied") {
        if low.contains("referrer") || low.contains("http_referrer") {
            return Some(GoogleKeyVerdict {
                valid: true,
                detail: "clé VALIDE mais restreinte par referrer HTTP (contournable via spoofing Referer)".to_string(),
            });
        }
        if low.contains("ip") || low.contains("address") {
            return Some(GoogleKeyVerdict {
                valid: true,
                detail: "clé VALIDE mais restreinte par IP (utilisable depuis les IP autorisées)"
                    .to_string(),
            });
        }
        if low.contains("billing") || low.contains("quota") {
            return Some(GoogleKeyVerdict {
                valid: true,
                detail: "clé VALIDE mais quota/billing épuisé".to_string(),
            });
        }
        if low.contains("invalid") || low.contains("keyinvalid") {
            return Some(GoogleKeyVerdict {
                valid: false,
                detail: "clé INVALIDE (révoquée ou mal copiée)".to_string(),
            });
        }
        return Some(GoogleKeyVerdict {
            valid: false,
            detail: format!("REQUEST_DENIED ({}): {}", r.status, one_line(&r.body, 120)),
        });
    }
    Some(GoogleKeyVerdict {
        valid: false,
        detail: format!("HTTP {} inattendu: {}", r.status, one_line(&r.body, 120)),
    })
}

fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(max).collect()
}

/// Emails de développeurs extraits d'un git log exposé (preuve d'impact OSINT).
pub fn extract_emails(log: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in log.lines() {
        if let (Some(a), Some(b)) = (line.find('<'), line.find('>')) {
            if b > a {
                let mail = line[a + 1..b].to_string();
                if mail.contains('@') && !mail.contains(' ') && !out.contains(&mail) {
                    out.push(mail);
                }
            }
        }
    }
    out
}

/// URLs de remotes extraites d'un .git/config exposé.
pub fn extract_remotes(config: &str) -> Vec<String> {
    config
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("url =").map(|u| u.trim().to_string())
        })
        .collect()
}

// ============================================================
// gkeyx — enumeration des privileges d'une cle Google (AIza...)
// Sondes GET lecture-seule, une par service : ce que la cle ouvre.
// ============================================================
