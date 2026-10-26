// src/dnsinfo.rs — sondes DNS TXT lecture-seule : dig, SPF, DMARC, verdict de spoofing.

use std::process::{Command, Stdio};

/// Dig +short sur un enregistrement TXT.
pub fn dig_txt(domain: &str) -> Vec<String> {
    let out = Command::new("dig")
        .args(["+short", "TXT", domain, "+time=5", "+tries=1"])
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.trim().trim_matches('"').to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Qualificateur du mécanisme `all` d'un SPF (`-all`, `~all`, `?all`, `+all`).
pub fn spf_all_qualifier(spf: &str) -> Option<char> {
    let low = spf.to_lowercase();
    for mech in low.split([' ', '\t']) {
        let m = mech.trim();
        if m == "all" {
            return Some('+');
        }
        if let Some(rest) = m.strip_suffix("all") {
            let last = rest.chars().last()?;
            if matches!(last, '-' | '~' | '?' | '+') {
                return Some(last);
            }
        }
    }
    None
}

/// Politique DMARC (tag p=) depuis un TXT _dmarc.
pub fn dmarc_policy(txt: &str) -> Option<String> {
    for tag in txt.split(';') {
        let tag = tag.trim();
        if let Some(v) = tag.strip_prefix("p=").or_else(|| tag.strip_prefix("P=")) {
            return Some(v.trim().to_lowercase());
        }
    }
    None
}

/// Verdict d'usurpabilité d'un domaine (analyse seule, aucun envoi réel).
pub fn spoof_verdict(spf: Option<&str>, dmarc_p: Option<&str>) -> (&'static str, String) {
    let qualif = spf.and_then(spf_all_qualifier);
    match dmarc_p {
        None => match (spf, qualif) {
            (None, _) => (
                "USURPABLE",
                "aucun SPF ni DMARC : n'importe qui peut envoyer des mails au nom du domaine".to_string(),
            ),
            (Some(_), Some('-')) | (Some(_), Some('~')) => (
                "PARTIEL",
                "SPF restrictif mais DMARC absent : usurpation filtree uniquement par les destinataires SPF-strict".to_string(),
            ),
            (Some(_), _) => (
                "USURPABLE",
                "SPF permissif (qualificateur soft/pass) et DMARC absent".to_string(),
            ),
        },
        Some(p) => match (spf, p) {
            (_, "reject") => (
                "PROTEGE",
                "DMARC p=reject : usurpation bloquee par les boites conformes".to_string(),
            ),
            (None, "quarantine") | (None, "none") | (None, _) => (
                "PARTIEL",
                format!("DMARC p={p} sans SPF explicite (politique partielle)"),
            ),
            (_, "quarantine") => (
                "PARTIEL",
                "DMARC p=quarantine : usurpation mise en quarantaine (spam), pas bloquee".to_string(),
            ),
            (_, _) => (
                "PARTIEL",
                "DMARC p=none : monitorage seul, aucune action anti-usurpation".to_string(),
            ),
        },
    }
}

