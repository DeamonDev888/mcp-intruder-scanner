// src/dash/machine.rs — Métriques temps réel de la machine hôte.
//
// Tout est lu depuis /proc, /sys et systemctl. Aucune dépendance externe :
// std uniquement. Aucune fonction ne renvoie Result et aucune ne panique sur
// une entrée machine absente ou tronquée (mac non-Linux, /proc masqué,
// fichier de jobs corrompu, systemctl qui bloque…). Chaque helper a un repli sûr.
//
// Piège connu et traité : `Command::output()` n'a pas de timeout. Un systemctl
// bloqué (D-Bus wedgé) gèle le tableau de bord entier. `run_with_timeout()`
// impose un délai dur et tue l'enfant si le temps est dépassé.

use std::fs;
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;

use crate::dash::model::{Machine, ServiceState};

/// Services interrogés à chaque refresh. `docker` n'est pas installé sur cette
/// machine : `inactive` est un résultat valide et s'affiche tel quel.
const TRACKED_SERVICES: [&str; 5] = ["postgresql", "ssh", "fail2ban", "ufw", "docker"];

/// Fichier de suivi écrit par le module scans.rs. Absent = aucun scan suivi.
const JOBS_PATH: &str = "/tmp/mcp-intruder-dash-jobs.json";

/// Délai dur maximal pour chaque sous-processus.
const CMD_TIMEOUT_SECS: u64 = 2;

// ---------------------------------------------------------------------------
// Sous-processus borné dans le temps
// ---------------------------------------------------------------------------

/// Lance `cmd` avec un timeout dur et renvoie sa sortie standard.
///
/// `Command` n'offre aucun mécanisme de délai : on délègue la lecture du pipe à
/// un thread dédié et on attend le résultat via `recv_timeout`. Si le délai
/// expire, l'enfant est tué et on renvoie `None` — le tableau de bord reste
/// alimenté même si `systemctl` est bloqué sur D-Bus.
///
/// `stderr` est jeté et `stdin` est fermé pour éviter qu'un service attendant
/// une entrée ne prolonge l'attente.
pub fn run_with_timeout(cmd: &mut Command, secs: u64) -> Option<String> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let mut stdout = child.stdout.take()?;

    let (tx, rx) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        use std::io::Read;
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });

    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(out) => {
            let _ = child.wait();
            Some(out)
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

/// Raccourci : exécute un binaire sans shell et renvoie sa sortie, bornée dans
/// le temps. Jamais de `sh -c` : les arguments sont passés directement au
/// processus, donc aucune interpretation possible.
fn run(prog: &str, args: &[&str]) -> Option<String> {
    run_with_timeout(Command::new(prog).args(args), CMD_TIMEOUT_SECS)
}

// ---------------------------------------------------------------------------
// Lecture de fichiers : toujours Option, jamais de panique
// ---------------------------------------------------------------------------

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Extrait la valeur d'un couple `clé: valeur` (mémoire, /proc).
fn proc_field(src: &str, key: &str) -> Option<u64> {
    for line in src.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.trim() != key {
            continue;
        }
        let mut it = v.split_whitespace();
        return it.next()?.parse::<u64>().ok();
    }
    None
}



// ---------------------------------------------------------------------------
// CPU
// ---------------------------------------------------------------------------

/// (jiffies totals, jiffies inactifs) de la ligne `cpu` agrégée.
fn cpu_times() -> Option<(u64, u64)> {
    let src = read_trimmed("/proc/stat")?;
    let line = src.lines().find(|l| {
        l.starts_with("cpu ")
            || l.starts_with("cpu\t")
    })?;
    // Champs : user nice system idle iowait irq softirq steal …
    let mut vals = [0u64; 8];
    let mut n = 0usize;
    for tok in line.split_whitespace().skip(1) {
        if n >= vals.len() {
            break;
        }
        match tok.parse::<u64>() {
            Ok(v) => {
                vals[n] = v;
                n += 1;
            }
            Err(_) => break,
        }
    }
    if n < 4 {
        return None;
    }
    let total: u64 = vals[..n].iter().sum();
    // idle + iowait : le temps d'attente disque n'est pas du travail CPU.
    let idle = vals[3].saturating_add(vals[4]);
    Some((total, idle))
}

/// Previous CPU sample : `(total, idle)` au dernier appel réussi.
static PREV_CPU: LazyLock<Mutex<Option<(u64, u64)>>> = LazyLock::new(|| Mutex::new(None));

/// Occupation CPU en pourcentage, calculée sur le delta entre deux lectures.
///
/// Le tout premier appel renvoie `0.0` (il n'existe pas de référence antérieure),
/// le second et les suivants renvoient le pourcentage réel. Si le mutex est
/// empoisonné par un panique antérieur, on repart d'un état propre au lieu de
/// propager le panique.
pub fn cpu_pct() -> f64 {
    let Some(cur) = cpu_times() else { return 0.0 };
    let Ok(mut guard) = PREV_CPU.lock() else { return 0.0 };
    let prev = guard.replace(cur);
    let Some((p_total, p_idle)) = prev else { return 0.0 };

    let d_total = cur.0.saturating_sub(p_total);
    let d_idle = cur.1.saturating_sub(p_idle);
    if d_total == 0 {
        return 0.0;
    }
    let busy = d_total.saturating_sub(d_idle);
    (busy as f64 / d_total as f64 * 100.0).clamp(0.0, 100.0)
}

fn cpu_cores() -> usize {
    if let Some(src) = read_trimmed("/proc/cpuinfo") {
        let n = src.lines().filter(|l| l.starts_with("processor")).count();
        if n > 0 {
            return n;
        }
    }
    // Repli : un répertoire cpuN par cœur sous /sys.
    fs::read_dir("/sys/devices/system/cpu")
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.starts_with("cpu") && n[3..].chars().all(char::is_numeric) && n.len() > 3)
                })
                .count()
        })
        .unwrap_or(1)
        .max(1)
}

// ---------------------------------------------------------------------------
// Mémoire
// ---------------------------------------------------------------------------

fn meminfo() -> (u64, u64, u64) {
    // (total Mo, utilisé Mo, swap utilisé Mo)
    let src = read_trimmed("/proc/meminfo").unwrap_or_default();
    let kb = |k: u64| k / 1024;
    let total_kb = proc_field(&src, "MemTotal").unwrap_or(0);
    // `Available` et non `Free` : le cache et les buffers sont de la mémoire
    // récupérable, `Free` surestimerait massivement la RAM utilisée.
    let avail_kb = proc_field(&src, "MemAvailable").or_else(|| proc_field(&src, "MemFree")).unwrap_or(0);
    let used_kb = total_kb.saturating_sub(avail_kb);
    let swap_total = proc_field(&src, "SwapTotal").unwrap_or(0);
    let swap_free = proc_field(&src, "SwapFree").unwrap_or(0);
    (kb(total_kb), kb(used_kb), kb(swap_total.saturating_sub(swap_free)))
}

// ---------------------------------------------------------------------------
// Load / uptime / identité
// ---------------------------------------------------------------------------

fn load_avg() -> Vec<f64> {
    read_trimmed("/proc/loadavg")
        .map(|s| {
            s.split_whitespace()
                .take(3)
                .filter_map(|t| t.parse::<f64>().ok())
                .collect()
        })
        .filter(|v: &Vec<f64>| v.len() == 3)
        .unwrap_or_default()
}

fn uptime_s() -> u64 {
    read_trimmed("/proc/uptime")
        .and_then(|s| s.split_whitespace().next().and_then(|t| t.parse::<f64>().ok()))
        .map(|f| if f.is_finite() && f > 0.0 { f as u64 } else { 0 })
        .unwrap_or(0)
}

fn hostname() -> String {
    read_trimmed("/proc/sys/kernel/hostname")
        .or_else(|| read_trimmed("/etc/hostname"))
        .or_else(|| run("hostname", &[]).map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "inconnu".to_string())
}

fn os_release() -> String {
    let src = read_trimmed("/etc/os-release").unwrap_or_default();
    for line in src.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            let name = v.trim().trim_matches('"').trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    "Linux".to_string()
}

// ---------------------------------------------------------------------------
// Réseau — octets cumulés depuis le boot
// ---------------------------------------------------------------------------

/// Somme `rx_bytes` / `tx_bytes` de toutes les interfaces hors loopback.
///
/// Ce sont des **cumulés depuis le boot**, pas un débit : le tableau de bord doit
/// les étiqueter « cumul » côté JS. Aucune dépendance externe, on lit /sys.
fn net_totals_mb() -> (f64, f64) {
    const MB: f64 = 1_048_576.0;
    let Ok(entries) = fs::read_dir("/sys/class/net") else { return (0.0, 0.0) };
    let (mut rx, mut tx) = (0u64, 0u64);
    for entry in entries.filter_map(std::result::Result::ok) {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        if name == "lo" {
            continue;
        }
        let base = format!("/sys/class/net/{name}/statistics");
        for (field, acc) in [("rx_bytes", &mut rx), ("tx_bytes", &mut tx)] {
            if let Some(v) = read_trimmed(&format!("{base}/{field}")).and_then(|s| s.parse::<u64>().ok()) {
                *acc = acc.saturating_add(v);
            }
        }
    }
    (rx as f64 / MB, tx as f64 / MB)
}

// ---------------------------------------------------------------------------
// Disque
// ---------------------------------------------------------------------------

/// Disque racine via `df -k /` : (utilisé %, total Go, libre Go).
///
/// Parsé à partir de la ligne dont le dernier champ est le point de montage `/`
/// (l'en-tête est ignoré). Aucun shell : `df` est appelé directement.
fn disk_root() -> (f64, f64, f64) {
    const KB_PER_GB: f64 = 1_048_576.0;
    let Some(out) = run("df", &["-k", "/"]) else { return (0.0, 0.0, 0.0) };

    let line = out
        .lines()
        .skip(1)
        .find(|l| l.split_whitespace().last() == Some("/"))
        .or_else(|| out.lines().rfind(|l| l.split_whitespace().count() >= 5));

    let Some(fields) = line.map(|l| l.split_whitespace().collect::<Vec<_>>()) else { return (0.0, 0.0, 0.0) };
    if fields.len() < 5 {
        return (0.0, 0.0, 0.0);
    }
    let total_kb: f64 = fields[1].parse().unwrap_or(0.0);
    let avail_kb: f64 = fields[3].parse().unwrap_or(0.0);
    let pct: f64 = match fields.get(4) {
        Some(p) => p.trim_end_matches('%').parse().unwrap_or(0.0),
        None => 0.0,
    };
    (pct.clamp(0.0, 100.0), total_kb / KB_PER_GB, avail_kb / KB_PER_GB)
}

// ---------------------------------------------------------------------------
// Services systemd
// ---------------------------------------------------------------------------

/// États des services suivis, en UN seul `systemctl show` borné dans le temps.
///
/// `show` accepte plusieurs unités et renvoie des blocs `Id=` / `ActiveState=` /
/// `ActiveEnterTimestamp=` séparés par une ligne vide, ce qui évite 5 appels.
/// L'ordre de sortie suit l'ordre des arguments ; on indexe donc par position
/// et on retombe sur le nom d'unité `Id=` si systemd réordonne.
fn services() -> Vec<ServiceState> {
    let mut args: Vec<&str> = vec!["show"];
    args.extend(TRACKED_SERVICES);
    args.extend(["--property=Id", "--property=ActiveState", "--property=ActiveEnterTimestamp"]);
    let Some(out) = run("systemctl", &args) else {
        return TRACKED_SERVICES.iter().map(|n| ServiceState { name: (*n).into(), state: "inconnu".into(), since: "—".into() }).collect();
    };

    let mut blocks: Vec<(String, String, String)> = Vec::new();
    let mut id = String::new();
    let mut state = String::new();
    let mut since = String::new();
    for line in out.lines() {
        if line.trim().is_empty() {
            if !id.is_empty() {
                blocks.push((std::mem::take(&mut id), std::mem::take(&mut state), std::mem::take(&mut since)));
            }
            continue;
        }
        match line.split_once('=') {
            Some(("Id", v)) => {
                if !id.is_empty() {
                    blocks.push((std::mem::take(&mut id), std::mem::take(&mut state), std::mem::take(&mut since)));
                }
                id = v.trim().to_string();
            }
            Some(("ActiveState", v)) => state = v.trim().to_string(),
            Some(("ActiveEnterTimestamp", v)) => since = v.trim().to_string(),
            _ => {}
        }
    }
    if !id.is_empty() {
        blocks.push((id, state, since));
    }

    TRACKED_SERVICES
        .iter()
        .enumerate()
        .map(|(i, name)| {
            // Position d'abord, puis correspondance par Id, puis repli neutre.
            let b = blocks
                .get(i)
                .filter(|(bid, _, _)| bid.trim_end_matches(".service") == *name)
                .or_else(|| blocks.iter().find(|(bid, _, _)| bid.trim_end_matches(".service") == *name));
            let (state, since) = match b {
                Some((_, s, t)) if !s.is_empty() => (s.clone(), if t.is_empty() { "—".to_string() } else { t.clone() }),
                _ => ("inconnu".to_string(), "—".to_string()),
            };
            ServiceState { name: (*name).into(), state, since }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Scanner et scans actifs
// ---------------------------------------------------------------------------

/// Vrai si un processus `mcp_intruder` tourne (`pgrep -x`, nom exact).
fn scanner_running() -> bool {
    match run("pgrep", &["-x", "mcp_intruder"]) {
        Some(out) => out.split_whitespace().any(|l| l.parse::<u32>().is_ok()),
        None => false,
    }
}

fn count_running_jobs(src: &str) -> u32 {
    let mut count = 0u32;
    // Découpe grossière mais sûre : chaque entrée est un objet contenant
    // "state": "<valeur>". On compte les occurrences de "state":"running".
    for entry in split_top_level_objects(src) {
        let running = entry
            .split("\"state\"")
            .nth(1)
            .and_then(|rest| {
                rest.split_once(':')
                    .map(|(_, v)| v.trim_start().trim_start_matches('"'))
            })
            .map(|v| v.split('"').next().unwrap_or("").trim() == "running")
            .unwrap_or(false);
        if running {
            count += 1;
        }
    }
    count
}

/// Découpe le JSON du registre en objets de premier niveau (le contenu de
/// chaque entrée), sans dépendance externe et sans jamais paniquer.
fn split_top_level_objects(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    let mut start = 0usize;
    let bytes: Vec<char> = src.chars().collect();
    let mut byte_idx = 0usize;
    for c in bytes {
        let width = c.len_utf8();
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else {
            match c {
                '"' => in_str = true,
                '{' => {
                    if depth == 1 {
                        start = byte_idx + width;
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 1 {
                        out.push(src[start..byte_idx].to_string());
                    }
                }
                _ => {}
            }
        }
        byte_idx += width;
    }
    out
}

/// Scans en cours : registre filtré sur l'état "running". Un registre absent ou
/// corrompu vaut 0 (et non 1), donc jamais de faux positif.
fn active_scans() -> u32 {
    read_trimmed(JOBS_PATH)
        .map(|s| count_running_jobs(&s))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// API publique
// ---------------------------------------------------------------------------

/// Lit l'intégralité des métriques machine et renvoie la struct prête à
/// sérialiser. Ne renvoie jamais `Result` et ne panique pas.
///
/// `db_name` n'est pas stocké dans `Machine` (il appartient à `Overview`) : il
/// est seulement accepté pour garder un point d'entrée unique côté API.
pub fn snapshot(db_name: &str) -> Machine {
    let _ = db_name;
    let (ram_total_mb, ram_used_mb, swap_used_mb) = meminfo();
    let (disk_used_pct, disk_total_gb, disk_free_gb) = disk_root();
    let (net_rx_mb, net_tx_mb) = net_totals_mb();

    Machine {
        host: hostname(),
        os: os_release(),
        cores: cpu_cores(),
        cpu_pct: cpu_pct(),
        load: load_avg(),
        ram_total_mb,
        ram_used_mb,
        swap_used_mb,
        disk_used_pct,
        disk_total_gb,
        disk_free_gb,
        uptime_s: uptime_s(),
        net_rx_mb,
        net_tx_mb,
        services: services(),
        scanner_running: scanner_running(),
        active_scans: active_scans(),
    }
}

/// Durée lisible : « 3 j 04 h 22 min », « 5 h 07 min » sous un jour.
pub fn uptime_human(s: u64) -> String {
    let d = s / 86_400;
    let h = (s % 86_400) / 3_600;
    let m = (s % 3_600) / 60;
    if d > 0 {
        format!("{d} j {h:02} h {m:02} min")
    } else {
        format!("{h} h {m:02} min")
    }
}

/// Taille lisible en unités binaires : « 1.42 Go ».
pub fn bytes_human(b: u64) -> String {
    const UNITS: [&str; 5] = ["o", "Ko", "Mo", "Go", "To"];
    let mut v = b as f64;
    let mut i = 0usize;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} o")
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_human_formats_days_and_hours() {
        assert_eq!(uptime_human(0), "0 h 00 min");
        assert_eq!(uptime_human(3600), "1 h 00 min");
        assert_eq!(uptime_human(3 * 86_400 + 4 * 3_600 + 22 * 60), "3 j 04 h 22 min");
    }

    #[test]
    fn bytes_human_scales_to_go() {
        assert_eq!(bytes_human(512), "512 o");
        assert_eq!(bytes_human(1_048_576), "1.00 Mo");
        assert_eq!(bytes_human(1_519_733_760), "1.42 Go");
    }

    #[test]
    fn active_scans_ignores_stopped_and_nested() {
        // Deux scans en cours => 2 actifs.
        let two_running = r#"{"1":{"state":"running","target":"a"},"2":{"state":"running","target":"b"}}"#;
        assert_eq!(count_running_jobs(two_running), 2);

        // Un scan arrêté ne compte PAS : c'est tout l'objet du correctif.
        let one_stopped =
            r#"{"1":{"state":"running","target":"a"},"2":{"state":"stopped","target":"b"}}"#;
        assert_eq!(count_running_jobs(one_stopped), 1);

        // Les objets imbriqués ne doivent pas créer de faux positif.
        let nested = r#"{"1":{"state":"running","meta":{"state":"stopped"}}}"#;
        assert_eq!(count_running_jobs(nested), 1);

        // États indéfinis => rien n'est compté comme actif.
        assert_eq!(count_running_jobs("{}"), 0);
        assert_eq!(count_running_jobs("not json"), 0);
        assert_eq!(count_running_jobs(""), 0);
        assert_eq!(count_running_jobs(r#"{"1":{"state":"done"}}"#), 0);
    }

    #[test]
    fn snapshot_is_plausible() {
        let m = snapshot("test");
        assert!(m.ram_used_mb <= m.ram_total_mb);
        assert!(m.cpu_pct >= 0.0 && m.cpu_pct <= 100.0);
        assert!(!m.host.is_empty());
        assert_eq!(m.services.len(), TRACKED_SERVICES.len());
    }
}