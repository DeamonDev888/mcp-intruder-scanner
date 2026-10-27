// src/gkeyx.rs — preuve d'impact cles Google (probes, verdict, exploitation lecture-seule).

use crate::net::{http_get, http_get_headers};

/// Statut d'une sonde gkeyx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GProbeStatus {
    /// 200 avec donnees : acces PROUVE.
    Granted,
    /// Cle reconnue mais contrainte (API non activee, restriction referrer/IP, quota).
    Constrained,
    /// Cle refusee (invalide ou revokee).
    Denied,
    /// Sonde non concluante (reseau, reponse inattendue).
    Inconclusive,
}

impl GProbeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Granted => "ACCEPTE",
            Self::Constrained => "CONTRAINT",
            Self::Denied => "REFUSE",
            Self::Inconclusive => "NON_CONCLUANT",
        }
    }
}

/// Resultat d'une sonde GET vers un service Google.
#[derive(Debug, Clone)]
pub struct GProbe {
    pub family: &'static str,
    pub service: &'static str,
    pub status: GProbeStatus,
    pub detail: String,
}

/// Numero de projet Google fuite par un message d'erreur
/// ("... has not been used in project 123456789 before ...").
pub fn extract_google_project(body: &str) -> Option<String> {
    for pat in ["project ", "projects/"] {
        let mut from = 0usize;
        while let Some(pos) = body[from..].find(pat) {
            let rest = &body[from + pos + pat.len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 6 {
                return Some(digits);
            }
            from += pos + pat.len();
        }
    }
    None
}

/// Classifie la reponse d'une sonde Google (pure, testable sans reseau).
/// Signatures issue de reponses REELLES capturees le 2026-09-26.
pub fn google_probe_classify(status: u16, body: &str) -> (GProbeStatus, String) {
    let low = body.to_lowercase();
    // 1. cle invalide (googleapis HTTP 400, ou Maps HTTP 200 + REQUEST_DENIED)
    if low.contains("api key not valid")
        || low.contains("api_key_invalid")
        || low.contains("api key is invalid")
        || low.contains("keyinvalid")
    {
        return (GProbeStatus::Denied, "cle invalide".into());
    }
    // 2. Maps renvoie HTTP 200 avec REQUEST_DENIED dans le corps JSON
    if low.contains("request_denied") {
        if low.contains("referer") || low.contains("referrer") || low.contains("from this site") {
            return (
                GProbeStatus::Constrained,
                "cle VALIDE, restriction referrer".into(),
            );
        }
        if low.contains("ip address")
            || low.contains("this ip")
            || low.contains("site or ip")
            || low.contains("from this site")
            || low.contains("mobile application")
        {
            return (
                GProbeStatus::Constrained,
                "cle VALIDE, restriction site/IP".into(),
            );
        }
        if low.contains("billing") || low.contains("quota") {
            return (
                GProbeStatus::Constrained,
                "cle VALIDE, billing/quota non actif".into(),
            );
        }
        return (
            GProbeStatus::Constrained,
            "cle VALIDE, non autorisee sur ce service (restriction API)".into(),
        );
    }
    // 3. acces prouve
    if status == 200 {
        return (GProbeStatus::Granted, "acces PROUVE (200)".into());
    }
    // 4. rate limite
    if status == 429 || low.contains("quota exceeded") || low.contains("resource_exhausted") {
        return (
            GProbeStatus::Constrained,
            "rate-limitee (429) — cle vive, quota epuise".into(),
        );
    }
    // 5. API non activee dans le projet -> fuite du numero de projet
    if let Some(p) = extract_google_project(body) {
        return (
            GProbeStatus::Constrained,
            format!("cle VALIDE, API non activee (projet {p})"),
        );
    }
    if status == 403 {
        return (GProbeStatus::Constrained, "403 (restriction)".into());
    }
    (
        GProbeStatus::Inconclusive,
        format!("http {status} non concluant"),
    )
}

/// Noms de modeles extraits d'une reponse 200 de Generative Language
/// (cosmetique et tolerant : extrait au format, rien de critique dessus).
pub fn gemini_models(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(pos) = rest.find("\"name\"") {
        rest = &rest[pos + 6..];
        let Some(q1) = rest.find('"') else { break };
        let after = &rest[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        let val = &after[..q2];
        if val.starts_with("models/") {
            out.push(val.to_string());
            if out.len() >= 5 {
                break;
            }
        }
        rest = &after[q2..];
    }
    out
}

/// Enumere les privileges d'une cle Google : une sonde GET par service,
/// timeout dur sur chacune, jamais de POST.
pub fn gkeyx_report(key: &str, timeout_secs: u64) -> Vec<GProbe> {
    let probes: Vec<(&'static str, &'static str, String)> = vec![
        (
            "LLM",
            "gemini",
            format!(
                "https://generativelanguage.googleapis.com/v1beta/models?pageSize=50&key={key}"
            ),
        ),
        (
            "MAPS",
            "staticmap",
            format!("https://maps.googleapis.com/maps/api/staticmap?center=0,0&size=16x16&key={key}"),
        ),
        (
            "MAPS",
            "geocode",
            format!("https://maps.googleapis.com/maps/api/geocode/json?address=Montreal&key={key}"),
        ),
        (
            "MAPS",
            "streetview",
            format!("https://maps.googleapis.com/maps/api/streetview/metadata?location=45.5,-73.6&key={key}"),
        ),
        (
            "MAPS",
            "directions",
            format!("https://maps.googleapis.com/maps/api/directions/json?origin=Montreal&destination=Quebec&key={key}"),
        ),
        (
            "MAPS",
            "elevation",
            format!("https://maps.googleapis.com/maps/api/elevation/json?locations=45.5,-73.6&key={key}"),
        ),
        (
            "DATA",
            "youtube",
            format!("https://www.googleapis.com/youtube/v3/videos?part=id&chart=mostPopular&maxResults=1&key={key}"),
        ),
        (
            "DATA",
            "translate",
            format!("https://translation.googleapis.com/language/translate/v2?q=cat&target=fr&key={key}"),
        ),
        (
            "DATA",
            "customsearch",
            format!("https://www.googleapis.com/customsearch/v1?q=test&key={key}"),
        ),
    ];
    let mut out = Vec::new();
    for (family, service, url) in probes {
        let g = match http_get(&url, timeout_secs) {
            None => GProbe {
                family,
                service,
                status: GProbeStatus::Inconclusive,
                detail: "erreur reseau".into(),
            },
            Some(r) => {
                let (status, mut detail) = google_probe_classify(r.status, &r.body);
                if service == "gemini" && status == GProbeStatus::Granted {
                    let models = gemini_models(&r.body);
                    if !models.is_empty() {
                        detail = format!(
                            "{detail} — {} modele(s) : {}",
                            models.len(),
                            models
                                .iter()
                                .map(|m| m.trim_start_matches("models/").to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                }
                GProbe {
                    family,
                    service,
                    status,
                    detail,
                }
            }
        };
        out.push(g);
    }
    out
}

/// Verdict global : VALIDE (services accessibles), VALIDE_RESTREINTE,
/// INVALIDE (refusee partout) ou NON_VERIFIABLE.
pub fn gkeyx_verdict(probes: &[GProbe]) -> (&'static str, String) {
    let granted: Vec<&GProbe> = probes
        .iter()
        .filter(|p| p.status == GProbeStatus::Granted)
        .collect();
    let constrained = probes.iter().any(|p| p.status == GProbeStatus::Constrained);
    let denied = probes
        .iter()
        .filter(|p| p.status == GProbeStatus::Denied)
        .count();
    if !granted.is_empty() {
        let svcs: Vec<&str> = granted.iter().map(|p| p.service).collect();
        let mut fams: Vec<&str> = Vec::new();
        for p in &granted {
            if !fams.contains(&p.family) {
                fams.push(p.family);
            }
        }
        (
            "VALIDE",
            format!(
                "{} service(s) utilisable(s) [{}] : {}",
                granted.len(),
                fams.join("+"),
                svcs.join(", ")
            ),
        )
    } else if constrained {
        (
            "VALIDE_RESTREINTE",
            "cle vive mais aucun service pleinement ouvert (restrictions / API non activees)"
                .into(),
        )
    } else if denied == probes.len() {
        ("INVALIDE", "refusee sur tous les services sondes".into())
    } else {
        ("NON_VERIFIABLE", "sondes non concluantes (reseau?)".into())
    }
}

/// Phase d'exploitation post-verdict (toujours lecture seule) :
/// 1. fuites de numero de projet dans les details des sondes ;
/// 2. test de bypass de la restriction referrer (differential sans/avec
///    Referer) sur un service deja ouvert — prouve si la cle est consommable
///    en server-side pur (contournement de restriction).
pub fn gkeyx_exploit(key: &str, probes: &[GProbe], timeout_secs: u64) -> Vec<String> {
    let mut notes = Vec::new();
    // 1. fuite du numero de projet
    let mut projects: Vec<String> = Vec::new();
    for p in probes {
        if let Some(num) = extract_google_project(&p.detail) {
            if !projects.contains(&num) {
                projects.push(num);
            }
        }
    }
    if projects.is_empty() {
        if let Some(r) = http_get(
            &format!("https://www.googleapis.com/customsearch/v1?q=x&key={key}"),
            timeout_secs,
        ) {
            if let Some(num) = extract_google_project(&r.body) {
                projects.push(num);
            }
        }
    }
    if !projects.is_empty() {
        notes.push(format!(
            "RECON  : numero(s) de projet Google fuite(s) : {} (les 403 \"has not been used in project NNN\" identifient le projet proprietaire)",
            projects.join(", ")
        ));
    }
    // 2. bypass referrer : un service ouvert sans Referer + refuse avec Referer
    //    etranger = restriction non appliquee server-side.
    let open_probe = probes
        .iter()
        .find(|p| p.status == GProbeStatus::Granted && p.family == "MAPS");
    if let Some(op) = open_probe {
        let url = match op.service {
            "staticmap" => format!("https://maps.googleapis.com/maps/api/staticmap?center=45.5,-73.6&size=32x32&key={key}"),
            "geocode" => format!("https://maps.googleapis.com/maps/api/geocode/json?address=Montreal&key={key}"),
            "streetview" => format!("https://maps.googleapis.com/maps/api/streetview/metadata?location=45.5,-73.6&key={key}"),
            "directions" => format!("https://maps.googleapis.com/maps/api/directions/json?origin=Montreal&destination=Quebec&key={key}"),
            "elevation" => format!("https://maps.googleapis.com/maps/api/elevation/json?locations=45.5,-73.6&key={key}"),
            _ => return notes,
        };
        let with_ref = http_get_headers(
            &url,
            timeout_secs,
            &[("Referer", "https://attacker.example")],
        );
        match with_ref {
            Some(r) if r.status == 200 => notes.push(
                "BYPASS  : restriction referrer NON appliquee — la cle marche avec un Referer etranger (consommable depuis n'importe quel site/client)".to_string(),
            ),
            Some(_) => notes.push(
                "BYPASS  : restriction referrer appliquee sur les navigateurs (Referer etranger = 403) MAIS la cle repond 200 sans Referer -> consommable en server-side pur (curl/scripts) : vol de quota Maps possible".to_string(),
            ),
            None => notes.push("BYPASS  : test non concluant (reseau)".to_string()),
        }
    }
    notes
}
