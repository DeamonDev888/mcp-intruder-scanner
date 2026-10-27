// src/net.rs — HTTP GET minimal via curl, timeout dur (ex-lib.rs).

use std::process::{Command, Stdio};

/// Réponse HTTP minimale (via curl, zéro dépendance).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

/// GET HTTP avec timeout dur. Retourne None si curl échoue (DNS, réseau, TLS).
pub fn http_get(url: &str, timeout_secs: u64) -> Option<HttpResponse> {
    http_get_headers(url, timeout_secs, &[])
}

/// GET HTTP avec en-têtes supplémentaires (ex. Referer pour tester les
/// restrictions de clé), timeout dur. Retourne None si curl échoue.
pub fn http_get_headers(
    url: &str,
    timeout_secs: u64,
    headers: &[(&str, &str)],
) -> Option<HttpResponse> {
    let mut args: Vec<String> = [
        "-s",
        "-L",
        "--max-time",
        &timeout_secs.to_string(),
        "-w",
        "\n%{http_code}|%{content_type}",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (h, v) in headers {
        args.push("-H".to_string());
        args.push(format!("{h}: {v}"));
    }
    args.push(url.to_string());
    let out = Command::new("curl")
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout).to_string();
    let idx = raw.rfind('\n')?;
    let (body, meta) = (raw[..idx].to_string(), raw[idx + 1..].to_string());
    let mut parts = meta.split('|');
    let status: u16 = parts.next()?.trim().parse().ok()?;
    let content_type = parts.next().unwrap_or("").trim().to_string();
    Some(HttpResponse {
        status,
        content_type,
        body,
    })
}
