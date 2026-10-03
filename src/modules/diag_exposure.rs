//! Diagnostic pages and backup file exposure audit.
//!
//! Context: on 2026-10-02, a scan of `www.example.com` returned 0 findings while
//! `https://www.example.com/phpinfo.php` was serving 131 223 bytes of phpinfo in
//! cleartext, disclosing the exact PHP version, the install path
//! `/usr/local/php/5.5/`, `file_uploads=On`, `upload_max_filesize=128M`, and the
//! loaded extension list (Phar, curl, PDO...). None of the existing modules
//! covered it: the path is absent from every wordlist ffuf runs, and nuclei has
//! no template that matched it on that target.
//!
//! Every check here is proof-based, never name-based: a 200 on `/phpinfo.php`
//! that returns the site's own 404 page is NOT a finding. We require either a
//! positive content signature or an authoritative "not found" size comparison.

use crate::modules::nethttp;
use std::time::Duration;

/// Probe budget per request. Diagnostic pages are static; 6 s is plenty.
const PER_PROBE: u64 = 6;
/// Cap the body we fingerprint. phpinfo pages are ~130 KB; 400 KB is generous.
const MAX_BODY: usize = 400_000;

/// One probed path and what came back.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiagExposure {
    pub path: String,
    pub url: String,
    pub status: u16,
    /// True when the response body carries the signature for this path kind.
    pub exposed: bool,
    /// Which signature matched (empty when not exposed).
    pub signature: String,
    /// Body size in bytes (0 when empty).
    pub size: usize,
    /// True when the response looked like the site's generic 404/soft-404.
    pub soft_404: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DiagExposureResult {
    pub checked: usize,
    pub exposed_count: usize,
    pub pages: Vec<DiagExposure>,
    /// Names of the sensitive knobs a phpinfo page disclosed, when one matched.
    pub php_disclosures: Vec<String>,
    pub success: bool,
    pub elapsed_seconds: f32,
}

pub struct DiagExposureAuditor;

struct Probe {
    path: &'static str,
    kind: ProbeKind,
}

#[derive(Clone, Copy, PartialEq)]
enum ProbeKind {
    PhpInfo,
    EnvFile,
    ServerStatus,
    Git,
    Backup,
}

impl ProbeKind {
    /// Signatures proving the response IS the artifact, not a soft-404.
    fn signature(&self, body: &str) -> &'static str {
        match self {
            ProbeKind::PhpInfo => {
                if body.contains("phpinfo()")
                    || (body.contains("PHP Version") && body.contains("Server API"))
                    || body.contains("phpinfo()_PHPINFO_")
                {
                    "phpinfo_marker"
                } else {
                    ""
                }
            }
            ProbeKind::EnvFile => {
                // A real .env is key=value pairs; a 404 page rarely is.
                let hits = body
                    .lines()
                    .filter(|l| {
                        let t = l.trim();
                        t.contains('=')
                            && !t.starts_with('<')
                            && (t.contains("DB_")
                                || t.contains("APP_KEY")
                                || t.contains("SECRET")
                                || t.contains("PASSWORD")
                                || t.contains("_URL=")
                                || t.contains("TOKEN"))
                    })
                    .count();
                if hits >= 2 { "env_keyvalue" } else { "" }
            }
            ProbeKind::ServerStatus => {
                if body.contains("Apache Server Status")
                    || body.contains("apache2-server-status")
                {
                    "apache_server_status"
                } else {
                    ""
                }
            }
            ProbeKind::Git => {
                if body.contains("[core]")
                    && (body.contains("repositoryformatversion") || body.contains("bare ="))
                {
                    "git_config"
                } else {
                    ""
                }
            }
            ProbeKind::Backup => {
                // First line of a phpinfo-dump style backup, or a 7-zip/zip header.
                let t = body.trim_start();
                if t.starts_with("PK\u{3}\u{4}") || t.starts_with("7z") {
                    "archive_backup"
                } else {
                    ""
                }
            }
        }
    }

}

/// The probe set. Deliberately small and high-signal — no wordlist, no bruteforce.
const PROBES: &[Probe] = &[
    Probe { path: "/phpinfo.php", kind: ProbeKind::PhpInfo },
    Probe { path: "/info.php", kind: ProbeKind::PhpInfo },
    Probe { path: "/php_info.php", kind: ProbeKind::PhpInfo },
    Probe { path: "/i.php", kind: ProbeKind::PhpInfo },
    Probe { path: "/pi.php", kind: ProbeKind::PhpInfo },
    Probe { path: "/.env", kind: ProbeKind::EnvFile },
    Probe { path: "/.env.production", kind: ProbeKind::EnvFile },
    Probe { path: "/server-status", kind: ProbeKind::ServerStatus },
    Probe { path: "/server-info", kind: ProbeKind::ServerStatus },
    Probe { path: "/.git/config", kind: ProbeKind::Git },
    Probe { path: "/.git/HEAD", kind: ProbeKind::Git },
    Probe { path: "/backup.zip", kind: ProbeKind::Backup },
    Probe { path: "/backup.sql", kind: ProbeKind::Backup },
    Probe { path: "/site.tar.gz", kind: ProbeKind::Backup },
];

/// Knobs a phpinfo page discloses that materially raise the risk. Extracted for
/// the report so the operator sees WHY a phpinfo is worse than a stale header.
const INTERESTING_PHP_KEYS: &[&str] = &[
    "file_uploads",
    "upload_max_filesize",
    "expose_php",
    "allow_url_fopen",
    "allow_url_include",
    "disable_functions",
    "open_basedir",
    "Loaded Configuration File",
    "extension_dir",
];

/// Fetch a path and return `(status, body)`. `nethttp` speaks cleartext only,
/// so HTTPS falls back to curl through the central timeout helper. Both paths are
/// non-destructive GETs against a fixed, tiny probe list.
fn fetch(hostport: &str, host: &str, port: u16, path: &str) -> Option<(u16, String)> {
    // Cleartext first (no subprocess, faster).
    //
    // ATTENTION (bug corrige 2026-10-02) : une reponse non-2xx en clairtext
    // n'est PAS une reponse definitive. Le port 80 duplique presque toujours
    // l'acces HTTPS en renvoyant 301/308 : sur www.example.com les 14 sondes
    // partaient en http://:80, recevaient 301, et le repli HTTPS n'etait
    // jamais atteint -> /phpinfo.php (200 sur 443) passe inseen.
    // Seul 401/403 est traite comme definitif ici : ces codes prouvent que le
    // chemin existe et est protege, et le HTTPS renverrait la meme chose.
    if let Some((status, _h, body)) = nethttp::get(
        host,
        port,
        path,
        None,
        Duration::from_secs(PER_PROBE),
        MAX_BODY,
    ) {
        if (200..300).contains(&status) {
            return Some((status, String::from_utf8_lossy(&body).to_string()));
        }
        if status == 401 || status == 403 {
            return Some((status, String::new()));
        }
    }

    // HTTPS via curl (bounded by run_tool's deadline).
    let url = format!("https://{hostport}{path}");
    let out = crate::utils::run_tool(
        "curl",
        &[
            "-s",
            "-k",
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            "--max-time",
            "6",
            "-H",
            "User-Agent: mcp-intruder-scanner/0.5.8",
            &url,
        ],
        PER_PROBE,
    )?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, code) = match text.rsplit_once('\n') {
        Some((b, c)) => (b.to_string(), c.trim().parse::<u16>().unwrap_or(0)),
        None => (text.clone(), 0),
    };
    if code == 0 {
        return None;
    }
    if (200..300).contains(&code) {
        Some((code, body))
    } else {
        Some((code, String::new()))
    }
}

/// Variante HTTPS-premiere, pour les cibles dont le port 80 n'est pas le
/// point d'entree reel. Utilisee par le module pour ne dependre ni du port
/// par defaut ni du repli cleartext.
fn fetch_https_first(hostport: &str, path: &str) -> Option<(u16, String)> {
    let url = format!("https://{hostport}{path}");
    let out = crate::utils::run_tool(
        "curl",
        &[
            "-s",
            "-k",
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            "--max-time",
            "8",
            "-H",
            "User-Agent: mcp-intruder-scanner/0.5.8",
            &url,
        ],
        10,
    )?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, code) = match text.rsplit_once('\n') {
        Some((b, c)) => (b.to_string(), c.trim().parse::<u16>().unwrap_or(0)),
        None => (text.clone(), 0),
    };
    if code == 0 {
        return None;
    }
    if (200..300).contains(&code) {
        Some((code, body))
    } else {
        Some((code, String::new()))
    }
}

impl DiagExposureAuditor {
    /// Probe the diagnostic/backup surface of a host.
    pub fn audit(domain: &str, custom_ports: &[u16]) -> DiagExposureResult {
        let start = std::time::Instant::now();
        let mut res = DiagExposureResult {
            success: true,
            ..Default::default()
        };

        let hostport = crate::utils::host_with_port(domain, custom_ports);
        let (host, port) = match crate::utils::split_host_port(&hostport) {
            Some(hp) => hp,
            None => {
                res.success = false;
                res.elapsed_seconds = start.elapsed().as_secs_f32();
                return res;
            }
        };

        // Baseline: the site's response to a path that cannot exist. Used to
        // recognise soft-404 pages that answer 200 to everything (WAFs, CMS).
        let baseline = Self::baseline_signature(&hostport, &host, port);

        for probe in PROBES {
            res.checked += 1;
            let url = format!("https://{hostport}{}", probe.path);

            // HTTPS d'abord : les pages de diagnostic vivent derriere le TLS.
            // Le cleartext n'est qu'un repli (et 443 reste le defaut quand
            // aucun --ports n'est fourni).
            let https_port = if port == 80 { 443 } else { port };
            let https_hostport = if https_port == 443 {
                hostport.split(':').next().unwrap_or(&hostport).to_string()
            } else {
                hostport.clone()
            };
            let answer = fetch_https_first(&https_hostport, probe.path)
                .or_else(|| fetch(&hostport, &host, port, probe.path));

            let Some((status, body)) = answer else {
                res.pages.push(DiagExposure {
                    path: probe.path.to_string(),
                    url,
                    status: 0,
                    exposed: false,
                    signature: String::new(),
                    size: 0,
                    soft_404: false,
                });
                continue;
            };

            // Only 2xx/3xx bodies can carry an artifact. 403/401 mean "exists
            // but protected" — worth reporting separately from "exposed".
            if !(200..300).contains(&status) {
                res.pages.push(DiagExposure {
                    path: probe.path.to_string(),
                    url,
                    status,
                    exposed: false,
                    signature: if status == 403 || status == 401 {
                        "protected".to_string()
                    } else {
                        String::new()
                    },
                    size: 0,
                    soft_404: false,
                });
                continue;
            }

            // fetch() a deja renvoye le corps avec le statut : on analyse.

            let truncated: String = body.chars().take(MAX_BODY).collect();
            let text: &str = &truncated;
            let sig = probe.kind.signature(text);

            // Soft-404 guard: if the body matches the site's own "missing page"
            // shape, a signature alone is not enough to accuse.
            let soft_404 = baseline
                .as_ref()
                .map(|b| Self::looks_like_baseline(text, b))
                .unwrap_or(false);

            let exposed = !sig.is_empty() && !soft_404;
            if exposed {
                res.exposed_count += 1;
                if probe.kind == ProbeKind::PhpInfo {
                    Self::extract_php_disclosures(text, &mut res.php_disclosures);
                }
            }

            res.pages.push(DiagExposure {
                path: probe.path.to_string(),
                url,
                status,
                exposed,
                signature: sig.to_string(),
                size: body.len(),
                soft_404,
            });
        }

        res.elapsed_seconds = start.elapsed().as_secs_f32();
        res
    }

    /// Fetch a path that cannot exist, to learn the site's own 404 shape.
    fn baseline_signature(hostport: &str, host: &str, port: u16) -> Option<String> {
        let path = "/mcp-intruder-scanner-canary-9f3a2b.php";
        fetch(hostport, host, port, path).map(|(_s, b)| b)
    }

    /// Heuristic: does `body` look like the site's own not-found page?
    fn looks_like_baseline(body: &str, baseline: &str) -> bool {
        if baseline.is_empty() {
            return false;
        }
        // Strong signal: same length +/- 15% AND shares the baseline title.
        let bl = baseline.len();
        let bd = body.len();
        let bl_f = bl as f64;
        let similar_len = if bl_f == 0.0 {
            false
        } else {
            (bd as f64 - bl_f).abs() / bl_f < 0.15
        };
        let title_of = |s: &str| -> String {
            let low = s.to_lowercase();
            match (low.find("<title"), low.find("</title>")) {
                (Some(a), Some(b)) if b > a => low[a + 7..b].trim().to_string(),
                _ => String::new(),
            }
        };
        let tb = title_of(baseline);
        let tt = title_of(body);
        (!tb.is_empty() && tb == tt) || (similar_len && tb.is_empty())
    }

    fn extract_php_disclosures(text: &str, out: &mut Vec<String>) {
        for key in INTERESTING_PHP_KEYS {
            // phpinfo renders: <td class="e">KEY</td><td class="v">VALUE</td>
            if text.contains(key) && !out.iter().any(|o| o.starts_with(key)) {
                // Grab the value that follows the key when present.
                let value = extract_value_after(text, key).unwrap_or_default();
                out.push(if value.is_empty() {
                    key.to_string()
                } else {
                    format!("{key}={value}")
                });
            }
        }
    }

    /// Turn findings into canonical SecurityFinding entries.
    pub fn to_findings(r: &DiagExposureResult) -> Vec<crate::modules::findings::SecurityFinding> {
        let mut out = Vec::new();
        for p in &r.pages {
            if p.exposed {
                let (title, reco, sev) = match p.signature.as_str() {
                    "phpinfo_marker" => (
                        format!("Page de diagnostic PHP exposée en clair : {}", p.path),
                        format!(
                            "Supprimer {p} (ou le restreindre à localhost) : la page publie la version \
                             exacte de PHP, les chemins d'installation, file_uploads et la liste des \
                             extensions chargées. Sur une version hors support, c'est la carte \
                             permettant de choisir un RCE pré-authentification.",
                            p = p.path
                        ),
                        "HIGH",
                    ),
                    "env_keyvalue" => (
                        format!("Fichier d'environnement exposé en clair : {}", p.path),
                        format!(
                            "Supprimer {p} immédiatement et ROTATER tous les secrets qu'il contient : \
                             ils sont considérés comme compromis dès lors qu'ils sont publiés.",
                            p = p.path
                        ),
                        "CRITICAL",
                    ),
                    "git_config" => (
                        format!("Dépôt Git exposé : {}", p.path),
                        format!(
                            "Supprimer {p} et purger l'historique : .git/config et .git/HEAD \
                             donnent les chemins du serveur et l'URL du dépôt.",
                            p = p.path
                        ),
                        "CRITICAL",
                    ),
                    "apache_server_status" => (
                        format!("Page de statut Apache exposée : {}", p.path),
                        format!(
                            "Restreindre {p} à localhost via Require local : la page liste les \
                             requêtes en cours et les modules chargés.",
                            p = p.path
                        ),
                        "MEDIUM",
                    ),
                    "archive_backup" => (
                        format!("Archive de sauvegarde exposée : {}", p.path),
                        format!(
                            "Supprimer {p} : une archive en racine de site est régulièrement \
                             déposée par erreur et contient l'intégralité du code source.",
                            p = p.path
                        ),
                        "HIGH",
                    ),
                    _ => continue,
                };
                out.push(crate::modules::findings::SecurityFinding {
                    severity: sev,
                    category: "SECRETS",
                    title,
                    recommendation: reco,
                });
            } else if p.signature == "protected" {
                out.push(crate::modules::findings::SecurityFinding {
                    severity: "INFO",
                    category: "SECRETS",
                    title: format!("{} existe mais est protégé (HTTP {})", p.path, p.status),
                    recommendation:
                        "Confirmer que la protection couvre bien tous les cas (restriction IP, mot de passe, méthodes HTTP restreintes).".into(),
                });
            }
        }
        out
    }
}

/// Value sitting right after `key` in a phpinfo row, when extractable.
fn extract_value_after(text: &str, key: &str) -> Option<String> {
    let pos = text.find(key)?;
    let tail = &text[pos + key.len()..];
    // Skip the tag soup between the key cell and the value cell.
    let after_tags = match tail.find("class=\"v\"") {
        Some(i) => &tail[i + 8..],
        None => tail,
    };
    let start = match after_tags.find('>') {
        Some(i) => i + 1,
        None => return None,
    };
    let end = after_tags[start..].find('<').map(|i| start + i)?;
    let v = after_tags[start..end].trim();
    if v.is_empty() {
        None
    } else {
        Some(v.chars().take(48).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phpinfo_signature_detects_real_page() {
        let body = "<h1>phpinfo()</h1><table><tr><td class=\"e\">PHP Version</td><td class=\"v\">5.5.38</td></tr></table>";
        assert_eq!(ProbeKind::PhpInfo.signature(body), "phpinfo_marker");
    }

    #[test]
    fn test_phpinfo_signature_rejects_soft_404() {
        // A CMS 404 page that happens to mention "PHP Version" somewhere.
        let body = "<html><title>404</title><body>PHP Version not found</body></html>";
        assert_eq!(ProbeKind::PhpInfo.signature(body), "");
    }

    #[test]
    fn test_env_signature_needs_two_keys() {
        let one = "APP_KEY=x\n";
        assert_eq!(ProbeKind::EnvFile.signature(one), "");
        let two = "APP_KEY=x\nDB_PASSWORD=y\n";
        assert_eq!(ProbeKind::EnvFile.signature(two), "env_keyvalue");
    }

    #[test]
    fn test_git_config_signature() {
        let body = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n";
        assert_eq!(ProbeKind::Git.signature(body), "git_config");
    }

    #[test]
    fn test_extract_value_after_reads_phpinfo_cell() {
        let page = "<td class=\"e\">file_uploads</td><td class=\"v\">On</td>";
        assert_eq!(extract_value_after(page, "file_uploads"), Some("On".to_string()));
    }

    #[test]
    fn test_baseline_guard_detects_same_title() {
        let baseline = "<html><title>Page introuvable</title><body>404</body></html>";
        let same = "<html><title>Page introuvable</title><body>404 not found</body></html>";
        assert!(DiagExposureAuditor::looks_like_baseline(same, baseline));
        let other = "<html><title>Welcome</title><body>home</body></html>";
        assert!(!DiagExposureAuditor::looks_like_baseline(other, baseline));
    }

    #[test]
    fn test_probe_set_is_small_and_high_signal() {
        // No bruteforce: the set is fixed and tiny on purpose.
        assert!(PROBES.len() <= 16, "wordlist explosion: le module doit rester ciblé");
        assert!(PROBES.iter().any(|p| p.path == "/phpinfo.php"));
        assert!(PROBES.iter().any(|p| p.path == "/.env"));
    }
}
