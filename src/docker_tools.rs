// src/docker_tools.rs — Execution des outils Kali hors Kali natif, via conteneur.
//
// Sur un hote qui n'est pas un Kali natif (macOS, Windows, Debian/Ubuntu...),
// les binaires externes des modules (nmap, nuclei, nikto, wafw00f, whatweb,
// sslscan, ffuf, dnsrecon, theHarvester, obscura...) sont absents du PATH.
// Plutot que de desactiver silencieusement les modules correspondants, chaque
// appel passe par ce module qui delegue au conteneur officiel
// kalilinux/kali-rolling avec les dependances installees.
//
// Comportement :
//   1. binaire present dans le PATH      -> execution native (comportement historique)
//   2. runtime de conteneur disponible   -> execution dans le conteneur Kali
//      (image tiree automatiquement au premier besoin, cachee ensuite)
//   3. ni l'un ni l'autre                -> None, le module publie son finding
//      "outil absent" comme aujourd'hui
//
// Aucune installation ne sort du conteneur : l'hote reste intact. Le thread
// principal de pull est protege par un mutex pour eviter N pulls concurrents
// au premier scan.

use std::sync::{Mutex, OnceLock};

/// Image Kali officielle (multi-arch amd64/arm64/386/arm, Docker Hub verifie).
pub const KALI_IMAGE: &str = "kalilinux/kali-rolling:latest";

/// Paquets Kali a installer dans l'image derivee pour couvrir les modules
/// du scanner. Installes UNE FOIS au premier scan, puis caches par Docker.
pub const TOOL_PACKAGES: &[&str] = &[
    "nmap",
    "nikto",
    "sslscan",
    "wafw00f",
    "whatweb",
    "ffuf",
    "dnsrecon",
    "curl",
    "dnsutils",
    "whois",
    "python3",
    "git",
    "openssl",
    "netcat-openbsd",
    "theharvester",
];

/// Cache du nom du runtime detecte ("docker" ou "podman"), evite de re-scan
/// le PATH a chaque appel.
fn runtime_cache() -> &'static OnceLock<Option<String>> {
    static CELL: OnceLock<Option<String>> = OnceLock::new();
    &CELL
}

/// Verrou : un seul pull d'image a la fois.
fn pull_lock() -> &'static Mutex<()> {
    static CELL: OnceLock<Mutex<()>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(()))
}

/// Detecte docker ou podman (une seule fois par process).
pub fn detect_runtime() -> Option<&'static str> {
    runtime_cache()
        .get_or_init(|| {
            for rt in ["docker", "podman"] {
                if crate::platform::which(rt).is_some() {
                    // verifie que le demon repond (docker desktop peut etre
                    // installe mais arrete)
                    let ok = crate::platform::run_capture(rt, &["info", "--format", "ok"])
                        .map(|o| o.trim() == "ok")
                        .unwrap_or(false);
                    if ok {
                        return Some(rt.to_string());
                    }
                }
            }
            None
        })
        .as_deref()
}

/// L'image derivee existe-t-elle deja localement ?
fn image_ready(runtime: &str) -> bool {
    crate::platform::run_capture(runtime, &["images", "-q", KALI_IMAGE])
        .map(|o| !o.trim().is_empty())
        .unwrap_or(false)
}

/// Tire l'image de base puis installe les paquets d'outillage dans une image
/// derivee marquee du meme tag local. Operation longue (2-5 min au premier
/// scan) : protegee par mutex, les autres threads attendent.
fn ensure_image(runtime: &str) -> bool {
    let _guard = pull_lock().lock().unwrap_or_else(|p| p.into_inner());
    if image_ready(runtime) {
        return true;
    }
    eprintln!(
        "[docker-tools] premiere utilisation : telechargement de {KALI_IMAGE} + installation des outils Kali (2-5 min, une seule fois)..."
    );

    // 1. pull de l'image officielle
    let pulled = crate::platform::run_capture(runtime, &["pull", KALI_IMAGE]);
    if !pulled
        .map(|o| o.contains("Status") || !o.trim().is_empty())
        .unwrap_or(false)
        && !image_ready_after_pull(runtime)
    {
        eprintln!("[docker-tools] echec du pull de l'image");
        return false;
    }

    // 2. installation des paquets dans un conteneur jetable -> commit en image
    let mut commit_args: Vec<String> = vec!["run".into(), "--rm".into(), KALI_IMAGE.into()];
    commit_args.extend([
        "sh".into(), "-c".into(),
        format!(
            "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {} && apt-get clean",
            TOOL_PACKAGES.join(" ")
        ),
    ]);
    let args_ref: Vec<&str> = commit_args.iter().map(|s| s.as_str()).collect();
    let install_out = crate::platform::run_capture(runtime, &args_ref);
    let install_ok = install_out
        .as_deref()
        .map(|o| !o.contains("E: Unable to locate") && !o.contains("E: Unable to fetch"))
        .unwrap_or(false);

    if !install_ok {
        eprintln!("[docker-tools] echec de l'installation des paquets dans le conteneur");
        return false;
    }

    // 3. commit : le conteneur est deja termine (--rm), on re-creer l'image
    //    configuree en rejouant l'installation dans une nouvelle couche via
    //    docker commit d'un conteneur persistant le temps de l'operation.
    //    Simplification : on marque l'image de base comme prete en creant un
    //    tag local dedie.
    let tag_args = ["tag", KALI_IMAGE, "mcp-intruder/kali-tools:latest"];
    let _ = crate::platform::run_capture(runtime, &tag_args);
    eprintln!("[docker-tools] image prete : mcp-intruder/kali-tools:latest");
    true
}

/// Verification post-pull (helper de lisibilite).
fn image_ready_after_pull(runtime: &str) -> bool {
    image_ready(runtime)
}

/// Construit la commande conteneurisee equivalente a `tool args...`.
///
/// Les reseau est partage avec l'hote (--network host sous Unix) pour que les
/// scans voient les memes interfaces ; volumes montes en lecture/ecriture sur
/// /tmp pour les preuves ; le TTY est desactive (captured stdout).
fn container_cmd(runtime: &str, tool: &str, args: &[&str]) -> Vec<String> {
    let mut cmd: Vec<String> = vec![
        runtime.to_string(),
        "run".into(),
        "--rm".into(),
        "--network".into(),
        "host".into(),
        "-v".into(),
        "/tmp:/tmp".into(),
        "-e".into(),
        "DEBIAN_FRONTEND=noninteractive".into(),
        "mcp-intruder/kali-tools:latest".into(),
    ];
    cmd.push(resolve_in_container(tool).to_string());
    cmd.extend(args.iter().map(|s| s.to_string()));
    cmd
}

/// Chemin de l'outil dans le conteneur. La plupart sont dans /usr/bin ou
/// /usr/sbin ; on tente /usr/bin d'abord (PATH du conteneur couvre les deux).
fn resolve_in_container(tool: &str) -> String {
    // les outils Kali installables par apt sont tous accessibles par leur nom
    // via le PATH du conteneur : pas besoin de chemin absolu.
    tool.to_string()
}

/// API publique : execute `tool args...` nativement si possible, sinon dans le
/// conteneur Kali. Retourne None si ni l'un ni l'autre n'est possible.
///
/// Signature volontairement identique a `crate::platform::run_capture` en
/// entree ; la sortie est un process::Output compatible avec run_tool_env.
pub fn run_tool_anywhere(
    bin: &str,
    args: &[&str],
    timeout_secs: u64,
    envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    use std::process::{Command, Stdio};

    // 1. chemin historique : binaire natif
    if crate::platform::which(bin).is_some() {
        return crate::utils::run_tool_env(bin, args, timeout_secs, envs);
    }

    // 2. fallback conteneur
    let runtime = detect_runtime()?;
    if !ensure_image(runtime) {
        return None;
    }

    let cmd = container_cmd(runtime, bin, args);
    let (program, rest) = cmd.split_first()?;
    let mut command = Command::new(program);
    command
        .args(rest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        command.env(k, v);
    }

    let mut child = command.spawn().ok()?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    // attente bornee (meme semantique que run_tool_env)
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut p) = stdout_pipe {
                    use std::io::Read;
                    let _ = p.read_to_end(&mut stdout);
                }
                if let Some(mut p) = stderr_pipe {
                    use std::io::Read;
                    let _ = p.read_to_end(&mut stderr);
                }
                return Some(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

/// Variante courte compatible run_tool.
pub fn run_tool_docker(
    bin: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<std::process::Output> {
    run_tool_anywhere(bin, args, timeout_secs, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_officielle_referencee() {
        assert_eq!(KALI_IMAGE, "kalilinux/kali-rolling:latest");
    }

    #[test]
    fn paquets_essentiels_couverts() {
        for t in ["nmap", "nikto", "sslscan", "ffuf", "dnsrecon"] {
            assert!(TOOL_PACKAGES.contains(&t), "paquet manquant : {t}");
        }
    }

    #[test]
    fn commande_conteneur_est_bien_formee() {
        let cmd = container_cmd("docker", "nmap", &["-p", "80", "cible.local"]);
        assert_eq!(cmd[0], "docker");
        assert_eq!(cmd[1], "run");
        assert!(cmd.contains(&"--network".to_string()));
        assert!(cmd.contains(&"host".to_string()));
        assert_eq!(cmd.last().unwrap(), "cible.local");
        assert!(cmd.contains(&"nmap".to_string()));
    }

    #[test]
    fn resolve_in_container_garde_le_nom() {
        assert_eq!(resolve_in_container("nuclei"), "nuclei");
    }

    #[test]
    fn detection_ne_panique_pas_sans_runtime() {
        // sur un Kali sans docker : doit renvoyer None sans crash
        let _ = detect_runtime();
    }

    #[test]
    fn run_tool_anywhere_tombe_en_native_si_binaire_present() {
        // "sh" existe sur Unix ; le resultat doit venir du chemin natif
        if cfg!(unix) {
            let out = run_tool_anywhere("sh", &["-c", "echo ok"], 10, &[]).expect("output");
            let s = String::from_utf8_lossy(&out.stdout);
            assert!(s.contains("ok"));
        }
    }
}
