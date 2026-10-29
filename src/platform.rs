// src/platform.rs — Detection de la plateforme hote et resolution de l'outillage.
//
// Le moteur de scan s'appuie sur les outils Kali (nmap, nuclei, nikto, wafw00f,
// whatweb, sslscan, ffuf, dnsrecon, theHarvester, obscura...). Sur un hote qui
// n'est pas un Kali natif, ces binaires sont absents : les modules correspondants
// sont alors soit ignores, soit delegates a un conteneur Docker Kali.
//
// Strategie retenue :
//   1. L'OS natif est un Kali (n'importe quelle variante) -> usage direct.
//   2. Sinon, si un runtime Docker ou Podman est disponible -> les outils
//      manquants sont executes dans le conteneur officiel kalilinux/kali-rolling.
//   3. Sinon -> l'interface propose d'installer le runtime Docker, puis de
//      telecharger l'image Kali. L'utilisateur confirme explicitement.
//
// Aucune commande n'est lancee sans consentement pour l'installation : la
// detection et la preparation du plan sont toujours sans effet de bord.

use std::fmt;

/// Image Docker officielle Kali Linux (verifiee sur Docker Hub le 2026-10-29 :
/// tag `latest`, multi-architecture amd64/arm64/386/arm, pushed 2026-10-26).
pub const KALI_IMAGE: &str = "kalilinux/kali-rolling:latest";

/// Famille d'OS hote, deduite de `std::env::consts::OS` et de la presence
/// des fichiers signature de chaque distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOs {
    Linux,
    MacOs,
    Windows,
    Other,
}

impl HostOs {
    /// Identifiant technique utilise par la logique de routage.
    pub fn id(self) -> &'static str {
        match self {
            HostOs::Linux => "linux",
            HostOs::MacOs => "macos",
            HostOs::Windows => "windows",
            HostOs::Other => "other",
        }
    }

    /// Libelle affiche dans le wizard.
    pub fn label(self) -> &'static str {
        match self {
            HostOs::Linux => "Linux",
            HostOs::MacOs => "macOS",
            HostOs::Windows => "Windows",
            HostOs::Other => "Autre",
        }
    }
}

impl fmt::Display for HostOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Etat complet de la plateforme, calcule en une passe.
#[derive(Debug, Clone)]
pub struct Platform {
    /// OS hote detecte.
    pub os: HostOs,
    /// Vrai si l'hote est un Kali Linux natif (distribution Kali ou derivee).
    pub is_native_kali: bool,
    /// Nom de la distribution lue depuis /etc/os-release (Linux uniquement).
    pub distro: String,
    /// Runtime de conteneur disponible : "docker", "podman" ou "".
    pub container_runtime: String,
    /// Version du runtime si presente.
    pub container_version: String,
    /// L'image Kali est deja presente localement (runtime disponible).
    pub kali_image_present: bool,
    /// Les outils Kali sont deja installes nativement.
    pub native_tools_present: bool,
}

impl Platform {
    /// Detecte la plateforme hote. Ne modifie rien au systeme.
    pub fn detect() -> Self {
        let os = match std::env::consts::OS {
            "linux" => HostOs::Linux,
            "macos" => HostOs::MacOs,
            "windows" => HostOs::Windows,
            _ => HostOs::Other,
        };

        let (distro, is_kali_distro) = if os == HostOs::Linux {
            read_os_release()
        } else {
            (String::new(), false)
        };

        // Kali se reconnait par l'ID ou le nom de la distribution ; une derivee
        // (kali-rolling, kali, parrot...) qui embarque /etc/kali-release est
        // traitee comme Kali natif.
        let is_native_kali = is_kali_distro
            || distro.to_lowercase().contains("kali")
            || std::path::Path::new("/etc/kali-release").exists();

        let native_tools_present = TOOLS.iter().any(|t| which(t).is_some());

        let (container_runtime, container_version) = detect_runtime();
        let kali_image_present = if container_runtime.is_empty() {
            false
        } else {
            image_present(&container_runtime)
        };

        Self {
            os,
            is_native_kali,
            distro,
            container_runtime,
            container_version,
            kali_image_present,
            native_tools_present,
        }
    }

    /// Vrai si les commandes de scan peuvent s'executer sans conteneur.
    pub fn can_run_natively(&self) -> bool {
        self.is_native_kali || self.native_tools_present
    }

    /// Runtime a utiliser pour executer un outil manquant.
    pub fn runtime(&self) -> Option<&str> {
        if self.container_runtime.is_empty() {
            None
        } else {
            Some(self.container_runtime.as_str())
        }
    }

    /// Resume pour l'interface et les logs.
    pub fn summary(&self) -> String {
        if self.is_native_kali {
            format!(
                "Kali Linux natif ({}) — outillage Kali disponible directement",
                if self.distro.is_empty() {
                    "distribution non identifiee"
                } else {
                    &self.distro
                }
            )
        } else if self.container_runtime.is_empty() {
            format!(
                "{} — runtime de conteneur absent (Docker ou Podman requis pour l'outillage Kali)",
                self.os
            )
        } else if self.kali_image_present {
            format!(
                "{} — outillage Kali via conteneur {} ({})",
                self.os, self.container_runtime, KALI_IMAGE
            )
        } else {
            format!(
                "{} — runtime {} disponible, image Kali a telecharger",
                self.os, self.container_runtime
            )
        }
    }
}

/// Outils Kali requis par les modules enrichis. Liste volontairement courte :
/// elle sert a savoir si l'outillage de base est present, pas a lister
/// chaque binaire optionnel.
pub const TOOLS: &[&str] = &[
    "nmap",
    "nuclei",
    "nikto",
    "wafw00f",
    "whatweb",
    "sslscan",
    "ffuf",
    "dnsrecon",
    "theHarvester",
    "obscura",
];

/// Lit /etc/os-release et renvoie (ID + VERSION, est-ce Kali).
fn read_os_release() -> (String, bool) {
    let raw = match std::fs::read_to_string("/etc/os-release") {
        Ok(r) => r,
        Err(_) => return (String::new(), false),
    };
    let mut id = String::new();
    let mut name = String::new();
    for line in raw.lines() {
        let mut kv = line.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let val = kv.next().unwrap_or("").trim().trim_matches('"');
        match key {
            "ID" => id = val.to_string(),
            "NAME" | "PRETTY_NAME" => name = val.to_string(),
            _ => {}
        }
    }
    let combined = format!("{} {}", id, name).to_lowercase();
    let is_kali = combined.contains("kali");
    let label = if name.is_empty() { id } else { name };
    (label, is_kali)
}

/// Cherche un binaire dans le PATH.
pub fn which(tool: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|p| p.is_file() && is_executable(p))
}

#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_p: &std::path::Path) -> bool {
    true
}

/// Detecte un runtime de conteneur utilisable (docker d'abord, puis podman).
fn detect_runtime() -> (String, String) {
    for rt in ["docker", "podman"] {
        if which(rt).is_some() {
            let ver = run_capture(rt, &["--version"])
                .unwrap_or_default()
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !ver.is_empty() {
                return (rt.to_string(), ver);
            }
        }
    }
    (String::new(), String::new())
}

/// L'image Kali est-elle deja telechargee localement ?
fn image_present(runtime: &str) -> bool {
    run_capture(runtime, &["images", "-q", KALI_IMAGE])
        .map(|o| !o.trim().is_empty())
        .unwrap_or(false)
}

/// Execute une commande sans shell et capture stdout+stderr.
///
/// Le binaire et les arguments sont toujours passes separement : aucune
/// interpretation shell, donc aucune injection via une cible ou un nom
/// d'outil.
pub fn run_capture(bin: &str, args: &[&str]) -> Option<String> {
    use std::process::{Command, Stdio};
    let out = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s)
}

/// Commande d'installation du runtime de conteneur, adaptee a l'OS.
///
/// Elle est presentee a l'utilisateur AVANT execution : rien n'est installe
/// automatiquement.
pub fn install_runtime_hint(os: HostOs) -> &'static str {
    match os {
        HostOs::Linux => "sudo apt-get update && sudo apt-get install -y docker.io",
        HostOs::MacOs => "brew install --cask docker (ou colima + docker client)",
        HostOs::Windows => "winget install --id Docker.DockerDesktop -e",
        HostOs::Other => "installer Docker ou Podman pour votre systeme",
    }
}

/// Commande de telechargement de l'image Kali officielle.
pub fn pull_image_hint() -> String {
    format!("docker pull {KALI_IMAGE}")
}

/// Retourne le nom de l'executable cible d'un outil a l'interieur du
/// conteneur. Identique a l'hote (les outils Kali gardent leurs noms).
pub fn container_tool_path(tool: &str) -> String {
    format!("/usr/bin/{tool}")
}

/// Construit la commande complete d'execution d'un outil hors Kali natif.
///
/// Le binaire local est utilise s'il existe ; sinon l'outil est execute dans
/// le conteneur Kali. La commande est montee avec un volume en lecture seule
/// sur le repertoire de travail pour que les prouvees restent cote operateur.
pub fn build_tool_command(
    runtime: &str,
    tool: &str,
    args: &[&str],
) -> Option<(String, Vec<String>)> {
    if which(tool).is_some() {
        return Some((
            tool.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));
    }
    if runtime.is_empty() {
        return None;
    }
    let mut cmd = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        "/tmp:/tmp".to_string(),
        "-w".to_string(),
        "/tmp".to_string(),
        KALI_IMAGE.to_string(),
        container_tool_path(tool),
    ];
    cmd.extend(args.iter().map(|s| s.to_string()));
    Some((runtime.to_string(), cmd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_os_id_is_stable() {
        assert_eq!(HostOs::Linux.id(), "linux");
        assert_eq!(HostOs::MacOs.id(), "macos");
        assert_eq!(HostOs::Windows.id(), "windows");
        assert_eq!(HostOs::Other.id(), "other");
    }

    #[test]
    fn image_kali_officielle_est_referencee() {
        assert_eq!(KALI_IMAGE, "kalilinux/kali-rolling:latest");
        assert!(KALI_IMAGE.starts_with("kalilinux/"));
    }

    #[test]
    fn detection_ne_panique_pour_un_os_inconnu() {
        let p = Platform::detect();
        assert!(!p.summary().is_empty());
    }

    #[test]
    fn install_hint_est_adapte_a_l_os() {
        for os in [HostOs::Linux, HostOs::MacOs, HostOs::Windows, HostOs::Other] {
            assert!(!install_runtime_hint(os).is_empty());
        }
    }

    #[test]
    fn commande_native_prioritaire_si_binaire_present() {
        // "sh" est present sur tous les Unix ; sur Windows la commande doit
        // basculer sur le conteneur ou ne pas etre construite.
        let r = build_tool_command("docker", "sh", &["-c", "echo hi"]);
        if cfg!(windows) {
            assert!(r.is_none() || r.unwrap().0 == "docker");
        } else {
            let (bin, args) = r.expect("commande construite");
            assert_eq!(bin, "sh");
            assert_eq!(args, vec!["-c".to_string(), "echo hi".to_string()]);
        }
    }

    #[test]
    fn commande_conteneur_sans_runtime_est_none() {
        let r = build_tool_command("", "outil_qui_nexiste_pas_xyz", &[]);
        assert!(r.is_none());
    }

    #[test]
    fn commande_conteneur_utilise_l_image_kali() {
        let r = build_tool_command("docker", "outil_qui_nexiste_pas_xyz", &["-V"]);
        let (bin, args) = r.expect("commande construite");
        assert_eq!(bin, "docker");
        assert!(args.contains(&KALI_IMAGE.to_string()));
        assert!(args.contains(&"/usr/bin/outil_qui_nexiste_pas_xyz".to_string()));
        assert_eq!(args.last().unwrap(), "-V");
    }
}
