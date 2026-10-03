// src/dash/scans.rs — Gestionnaire des scans lancés depuis l'interface.
//
// Trois responsabilités :
//   1. démarrer un vrai processus `mcp_intruder` détaché, avec ses logs dans
//      un FICHIER (jamais un pipe : un pipe non lu bloque l'enfant dès que le
//      buffer est plein — c'est le piège classique du live-stream en HTTP) ;
//   2. le suivre en direct (état, elapsed, dernière ligne) sans jamais le
//      mettre en pause ;
//   3. l'arrêter proprement (SIGTERM d'abord : le scanner a un trap de
//      nettoyage, puis SIGKILL après 5 s) — uniquement s'il est dans NOTRE
//      registre (anti-BPIDF : on ne tue jamais un pid qui n'est pas à nous).
//
// Le registre est persisté en JSON (/tmp/mcp-intruder-dash-jobs.json, écriture
// atomique tmp+rename) pour survivre à un redémarrage du dashboard.
//
// Sécurité : la cible vient du GUI, donc d'un utilisateur. Jamais de shell —
// on utilise `Command::new(binaire).args([...])`, ce qui rend l'injection de
// commande structurellement impossible. La validation de la cible est une
// seconde barrière, en profondeur (défense en profondeur), pas la première.

use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::model::LiveScan;

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

/// Binaire réel du scanner (cf. `mcp_intruder --help`).
const SCAN_BIN: &str = "/usr/local/bin/mcp_intruder";
/// Registre persistant des jobs.
const JOBS_PATH: &str = "/tmp/mcp-intruder-dash-jobs.json";
/// Nombre maximal de scans simultanés.
const MAX_CONCURRENT: usize = 2;
/// Octets lus en fin de log pour trouver la dernière ligne.
const MAX_LOG_TAIL: u64 = 4096;
/// Lignes de log remontées dans `last_line` (tronquée pour le GUI).
const MAX_LAST_LINE: usize = 240;
/// Motifs de fin propre du scanner (cf. `Score global : 45/100`).
const DONE_MOTIFS: [&str; 2] = ["Score global :", "catalogué avec succès"];

/// Sérialise les lancements concurrents (limite MAX_CONCURRENT sans TOCTOU)
/// et sérialise le cycle lecture→écriture du registre.
static REGISTRY_LOCK: Mutex<()> = Mutex::new(());
/// Les enfants Lancés par CE processus, pourCHOIR les zombies sans bloquer.
/// Try_wait() non bloquant à chaque snapshot(). Après un redémarrage du
/// dashboard ils sont vides : on retombe alors sur /proc/<pid>.
static CHILDREN: Mutex<Vec<Child>> = Mutex::new(Vec::new());

/// Prend le verrou du registre, récupérant le poison au passage : on préfère
/// continuer à fonctionner sans verrou que paniquer (règle : jamais de panic).
fn registry_lock() -> MutexGuard<'static, ()> {
    match REGISTRY_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Pareil pour le registre des enfants.
fn children_lock() -> MutexGuard<'static, Vec<Child>> {
    match CHILDREN.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ---------------------------------------------------------------------------
// Profils — alignés sur la VRAIE sortie de `mcp_intruder --help`
// ---------------------------------------------------------------------------

/// Profils proposés par le GUI. Chaque libellé reprend les flags affichés par
/// `--help` (« PROFILS PRÊTS À L'EMPLOI ») :
///   -1/--fast, -2/--web, -3/--full, -4/--infra, -5/--vuln, -d/--discovery
/// plus le noyau seul et la sélection à la carte via `--modules`.
pub fn profiles() -> Vec<(&'static str, &'static str)> {
    vec![
        ("rapide", "Audit rapide Core Rust uniquement, aucun outil Kali (~1.5 s)  [-1/--fast]"),
        ("web", "Périmètre web : Wafw00f + WhatWeb + SSLScan + Dnstwist + Httpx  [-2/--web]"),
        ("full", "360° complet : tous les outils Kali (+ Obscura), SQLMap opt-in via --sqlmap  [-3/--full]"),
        ("infra", "Infrastructure : Nmap + SSLScan + RustScan  [-4/--infra]"),
        ("vuln", "Vulnérabilités : Nuclei + Nikto + Nmap + SQLMap  [-5/--vuln]"),
        ("decouverte", "Découverte d'endpoints : Ffuf + Nikto + Wafw00f  [-d/--discovery]"),
        ("custom", "Modules à la carte : --modules nmap,nuclei,...  [-m/--modules]"),
        ("core", "Noyau seul : aucune option, c'est-à-dire le strict minimum"),
    ]
}

/// Traduit un nom de profil en flags RÉELS de la CLI.
/// `None` = profil inconnu : on refuse plutôt que de retomber silencieusement
/// sur « aucun flag », ce qui ne lancerait que le noyau (piège documenté du
/// projet : `mcp_intruder <cible>` seul ne fait pas une couverture complète).
fn profile_flags(profile: &str) -> Option<Vec<&'static str>> {
    match profile.trim().to_ascii_lowercase().as_str() {
        "rapide" | "fast" | "1" => Some(vec!["-1"]),
        "web" | "2" => Some(vec!["-2"]),
        "full" | "360" | "3" => Some(vec!["-3"]),
        "infra" | "4" => Some(vec!["-4"]),
        "vuln" | "5" => Some(vec!["-5"]),
        "decouverte" | "discovery" | "d" => Some(vec!["-d"]),
        "custom" | "modules" | "core" | "" => Some(vec![]),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Validation de la cible (surface d'injection)
// ---------------------------------------------------------------------------

/// Caractères acceptés : alphanumériques, `.`, `_`, `-`, `:` (IPv6),
/// `/` (CIDR), `?` et `=` (chaîne de requête), `~`, `+`.
/// Tout le reste — espaces, `;`, `\`, quotes, `$(`, backtick, `|`, `&`, `>`,
/// `<`, `\0`… — est refusé.
fn target_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^[A-Za-z0-9._:/=?~+-]{1,253}$").unwrap_or_else(|_| {
            // Impossible en pratique (constante littérale) : on évite unwrap() et
            // on retombe sur une regex qui ne matche RIEN → tout sera refusé.
            regex::Regex::new(r"^$")
                .unwrap_or_else(|_| regex::Regex::new("$").unwrap_or_else(|_| unreachable!()))
        })
    })
}

/// Valide une cible saisie dans le GUI. Retourne la cible normalisée
/// (trim + minuscules) ou un message d'erreur clair en français.
pub fn validate_target(t: &str) -> Result<String, String> {
    let cleaned = t.trim().to_ascii_lowercase();
    if cleaned.is_empty() {
        return Err("cible invalide : cible vide".into());
    }
    if cleaned.len() > 253 {
        return Err(format!(
            "cible invalide : longueur {} > 253 caractères maximum",
            cleaned.len()
        ));
    }
    // Un « -foo » serait avalé par clap comme une option : on refuse en amont.
    if cleaned.starts_with('-') {
        return Err("cible invalide : ne doit pas commencer par '-'".into());
    }
    // `..` est legal au niveau caractères (`.` et `/`) mais c'est une
    // traversée de chemin : refus explicite.
    if cleaned.contains("..") {
        return Err("cible invalide : traversée de chemin interdite ('..')".into());
    }
    // Un URL porte son schema (`http://x/`) : le scanner attend un
    // hostname ou une IP nue. On refuse explicitement plutot que de
    // laisser passer une valeur qui echouerait de facon opaque en amont.
    // Attention : `www.exemple.ca` reste un hostname valide, seul le
    // schema est refuse.
    if cleaned.contains("://") {
        return Err(
            "cible invalide : fournissez un nom de domaine ou une IP nue, pas un URL".into(),
        );
    }
    if !target_re().is_match(&cleaned) {
        return Err(
            "cible invalide : caractère interdit (attendu : hostname, IP, CIDR — lettres, chiffres, . - _ : / ? =)"
                .into(),
        );
    }
    Ok(cleaned)
}

// ---------------------------------------------------------------------------
// Chemins (surchargeables par variables d'env pour les tests)
// ---------------------------------------------------------------------------

/// Binaire du scanner. `MCP-INTRUDER_DASH_SCAN_BIN` permet de tester le cycle
/// lancer→suivre→arrêter avec un binaire jetable sans toucher au scanner.
fn scan_bin() -> String {
    std::env::var("MCP-INTRUDER_DASH_SCAN_BIN").unwrap_or_else(|_| SCAN_BIN.to_string())
}

/// Fichier du registre.
fn jobs_path() -> String {
    std::env::var("MCP-INTRUDER_DASH_JOBS").unwrap_or_else(|_| JOBS_PATH.to_string())
}

/// Répertoire des logs : celui du registre (défaut /tmp).
fn log_dir() -> String {
    match Path::new(&jobs_path()).parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_string_lossy().to_string(),
        _ => "/tmp".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Temps
// ---------------------------------------------------------------------------

/// Secondes depuis l'époque Unix (0 si l'horloge est avant 1970, jamais paniqué).
fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Calendrier grégorien à partir d'un numéro de jour (algorithme de Hinnant) —
/// on n'a pas de dépendance chrono et on veut une chaîne stable à écrire.
fn civil_from_days(z0: i64) -> (i64, u32, u32) {
    let z = z0 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Horodatage ISO-8601 UTC, ex. `2026-10-02T14:31:07Z`.
fn iso8601(epoch: u64) -> String {
    let days = (epoch / 86_400) as i64;
    let sod = epoch % 86_400;
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

// ---------------------------------------------------------------------------
// Registre JSON
// ---------------------------------------------------------------------------

/// Lit le registre brut. Un fichier absent, illisible ou corrompu ⇒ objet
/// vide, jamais de panic.
fn read_jobs_raw() -> Map<String, Value> {
    let Ok(text) = std::fs::read_to_string(jobs_path()) else {
        return Map::new();
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

/// Écrit le registre de façon atomique (tmp + rename) : un dashboard arrêté
/// au mauvais moment ne laisse jamais un JSON tronqué.
fn write_jobs_raw(map: &Map<String, Value>) {
    let path = jobs_path();
    let tmp = format!("{path}.tmp");
    let Ok(text) = serde_json::to_string_pretty(map) else {
        return;
    };
    if std::fs::write(&tmp, text.as_bytes()).is_err() {
        return;
    }
    let _ = std::fs::rename(&tmp, &path);
}

/// Champ texte d'un enregistrement, tolérant au JSON incomplet.
fn jstr(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Champ entier d'un enregistrement.
fn ju64(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

// ---------------------------------------------------------------------------
// Processus
// ---------------------------------------------------------------------------

/// Envoie un signal sans shell : `kill -TERM <pid>` via exec direct.
/// Le drapeau doit être UN SEUL argument (`-TERM`), pas `-` puis `TERM` :
/// `kill - TERM 123` fait échouer l'analyse du binaire kill et ne tue rien.
fn kill_pid(pid: u32, sig: &str) -> bool {
    Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Le pid vit-il encore ? /proc en local (rapide, pas de fork), avec un repli
/// sur `kill -0` si /proc n'est pas monté.
///
/// Point important : un ZOMBIE a encore une entrée /proc/<pid> et répond
/// oui à `kill -0`, mais il est mort — c'est exactement l'état dans lequel on
/// se met après avoir envoyé un signal. Sans cette vérification, `stop()`
/// afficherait « sans effet » alors que le processus est déjà terminé.
fn pid_alive(pid: u32) -> bool {
    if Path::new("/proc/self").exists() {
        let stat = format!("/proc/{pid}/stat");
        let Ok(text) = std::fs::read_to_string(&stat) else {
            return false; // pas de /proc/<pid> => mort
        };
        // Format : "<pid> (<comm>) <state> ..." — comm peut contenir des
        // espaces ou parenthèses, donc on coupe après le dernier ')'.
        let Some(idx) = text.rfind(')') else {
            return false;
        };
        let Some(state) = text[idx + 1..].split_whitespace().next() else {
            return false;
        };
        return state != "Z";
    }
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Fait un `try_wait()` (NON bloquant) sur chaque enfant de CE processus et
/// retire ceux qui sont sortis : c'est ce qui évite les zombies. Retourne les
/// pids confirmés morts.
fn reap_children() -> HashSet<u32> {
    let mut dead = HashSet::new();
    let mut guard = children_lock();
    // try_wait() a besoin de &mut : on parcourt par index et on retire à
    // l'envers (swap_remove), ce qui préserve l'ordre des pids restants.
    let mut i = 0;
    while i < guard.len() {
        let finished = match guard[i].try_wait() {
            Ok(Some(_)) => true,
            Ok(None) => false,
            // Plus notre enfant (impossible sans double-fork) : on oublie.
            Err(_) => true,
        };
        if finished {
            dead.insert(guard.swap_remove(i).id());
        } else {
            i += 1;
        }
    }
    dead
}

// ---------------------------------------------------------------------------
// Lecture des logs
// ---------------------------------------------------------------------------

/// Nettoie une ligne pour l'affichage : on retire les séquences d'échappement
/// ANSI (le scanner colourise son spinner, sinon le GUI affiche `[38;5;198m`),
/// puis les caractères de contrôle, et on borne la longueur.
fn clean_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI (…[ … finale) : on saute jusqu'au caractère final 0x40..0x7E.
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    let trimmed = out.trim();
    if trimmed.chars().count() > MAX_LAST_LINE {
        let cut: String = trimmed.chars().take(MAX_LAST_LINE).collect();
        format!("{cut}…")
    } else {
        trimmed.to_string()
    }
}

/// Dernières lignes non vides du log (les 4 derniers Ko suffisent : un log de
/// scan pèse facilement plusieurs Mo et on ne veut le lire qu'en fin de flux).
fn tail_lines(path: &str, max_lines: usize) -> Vec<String> {
    let Ok(mut f) = File::open(path) else {
        return Vec::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(MAX_LOG_TAIL);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    // On peut démarrer au milieu d'une ligne : on saute ce fragment.
    let skip = usize::from(start > 0);
    let mut lines: Vec<String> = String::from_utf8_lossy(&buf)
        .lines()
        .skip(skip)
        .map(clean_line)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() > max_lines {
        let drop_n = lines.len() - max_lines;
        lines.drain(..drop_n);
    }
    lines
}

/// Dernière ligne non vide du log (« » si fichier absent/vide).
fn last_line_of(path: &str) -> String {
    tail_lines(path, 1).pop().unwrap_or_default()
}

/// Le log se termine-t-il par une fin propre du scanner ? Permet de distinguer
/// « done » (terminé normalement) de « stopped » (tué / crash).
fn log_looks_complete(path: &str) -> bool {
    let tail = tail_lines(path, 40);
    tail.iter()
        .rev()
        .any(|l| DONE_MOTIFS.iter().any(|m| l.contains(m)))
}

// ---------------------------------------------------------------------------
// Snapshot : registre JSON → Vec<LiveScan>
// ---------------------------------------------------------------------------

/// Calcule l'état frais de chaque job et renvoie aussi la version mise à jour
/// du registre (les états terminés sont persistés, sinon ils Notation
/// « running » au redémarrage suivant).
fn snapshot_jobs(
    raw: &Map<String, Value>,
    reaped: &HashSet<u32>,
) -> (Vec<LiveScan>, Map<String, Value>) {
    let mut updated = raw.clone();
    let mut live = Vec::with_capacity(raw.len());

    for (pid_key, job) in raw {
        let Ok(pid) = pid_key.parse::<u32>() else {
            continue; // clé illisible : on l'ignore, pas de panic
        };
        let target = jstr(job, "target");
        let profile = jstr(job, "profile");
        let log_path = jstr(job, "log_path");
        let epoch = ju64(job, "epoch").unwrap_or(0);
        let started_at = {
            let s = jstr(job, "started_at");
            if s.is_empty() {
                iso8601(epoch)
            } else {
                s
            }
        };
        let stored_state = jstr(job, "state");

        let alive = !reaped.contains(&pid) && pid_alive(pid);
        let state = if alive {
            "running".to_string()
        } else if stored_state == "stopped" || !log_looks_complete(&log_path) {
            // Fin de log sans motif de sortie = interruption.
            "stopped".to_string()
        } else {
            "done".to_string()
        };

        let elapsed_s = now_epoch().saturating_sub(epoch);
        let last_line = last_line_of(&log_path);

        if let Some(entry) = updated.get_mut(pid_key) {
            entry["state"] = Value::String(state.clone());
        }

        live.push(LiveScan {
            pid,
            target,
            profile,
            started_at,
            elapsed_s,
            state,
            last_line,
            log_path,
        });
    }

    // Du plus récent au plus ancien : ce qui intéresse le GUI est en haut.
    live.sort_by_key(|s| std::cmp::Reverse(s.pid));
    (live, updated)
}

/// Liste les scans connus, avec état / elapsed / dernière ligne recalculés à
/// l'instant. Met aussi les états à jour dans le registre persisté.
pub fn list() -> Vec<LiveScan> {
    let _guard = registry_lock();
    reap_children();
    let raw = read_jobs_raw();
    let reaped = reap_children();
    let (live, updated) = snapshot_jobs(&raw, &reaped);
    write_jobs_raw(&updated);
    live
}

// ---------------------------------------------------------------------------
// Démarrage
// ---------------------------------------------------------------------------

/// Lance un scan depuis le GUI. Le processus est détaché : il survit à la fin
/// de la requête HTTP, ses sorties partent dans un FICHIER (jamais un pipe) et
/// le `Child` est conservé pour être récolté sans zombie.
pub fn start(target: &str, profile: &str) -> Result<LiveScan, String> {
    let target = validate_target(target)?;
    let flags = profile_flags(profile).ok_or_else(|| {
        format!(
            "profil inconnu : '{profile}' (valides : {})",
            profiles()
                .iter()
                .map(|(k, _)| *k)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    let profile_name = profile.trim().to_ascii_lowercase();

    let _guard = registry_lock();
    let reaped = reap_children();

    // 1) Limite de scans simultanés — comptée sur l'état RÉEL, pas sur le
    //    contenu brut du fichier (sinon on refuse à tort après un reboot).
    let (live, _) = snapshot_jobs(&read_jobs_raw(), &reaped);
    let running = live.iter().filter(|s| s.state == "running").count();
    if running >= MAX_CONCURRENT {
        return Err(format!(
            "limite de scans simultanés atteinte (max {MAX_CONCURRENT})"
        ));
    }

    // 2) Log : créé avant le spawn pour passer le descripteur au child.
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_log = format!("{dir}/.mcp-intruder-dash-scan-{stamp}.tmp");
    let stdout_file =
        File::create(&tmp_log).map_err(|e| format!("création du log impossible : {e}"))?;
    // stderr en append sur le MÊME fichier : deux descripteurs indépendants
    // qui écrivent au même offset se marcheraient dessus.
    let stderr_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&tmp_log)
        .map_err(|e| format!("création du log impossible : {e}"))?;

    // 3) Lancement. AUCUN shell : la cible est un argument à part entière,
    //    `-t/--target` est la forme explicite documentée par --help et elle
    //    est prioritaire sur le positionnel.
    let bin = scan_bin();
    let mut cmd = Command::new(&bin);
    cmd.args(&flags)
        .arg("-t")
        .arg(&target)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    let child = cmd
        .spawn()
        .map_err(|e| format!("lancement de {bin} impossible : {e}"))?;
    let pid = child.id();

    // 4) Le nom du log est basé sur le pid : on renomme une fois connu. Le
    //    child tient déjà son descripteur, le rename ne le perturbe pas.
    let log_path = format!("{dir}/mcp-intruder-dash-scan-{pid}.log");
    let _ = std::fs::rename(&tmp_log, &log_path);

    // 5) Le Child reste stocké : try_wait() à chaque snapshot() le récoltera.
    children_lock().push(child);

    // 6) Persistance.
    let epoch = now_epoch();
    let started_at = iso8601(epoch);
    let mut raw = read_jobs_raw();
    let record = serde_json::json!({
        "target": target,
        "profile": profile_name,
        "started_at": started_at,
        "epoch": epoch,
        "log_path": log_path,
        "state": "running",
    });
    raw.insert(pid.to_string(), record);
    write_jobs_raw(&raw);

    Ok(LiveScan {
        pid,
        target,
        profile: profile_name,
        started_at,
        elapsed_s: 0,
        state: "running".to_string(),
        last_line: "scan démarré…".to_string(),
        log_path,
    })
}

// ---------------------------------------------------------------------------
// Arrêt
// ---------------------------------------------------------------------------

/// Arrête un scan. Refus categoriel si le pid n'est pas dans NOTRE registre
/// (anti-BPIDF : un dashboard ne doit jamais pouvoir tuer un processus arbitraire).
pub fn stop(pid: u32) -> Result<String, String> {
    let _guard = registry_lock();
    reap_children();

    let mut raw = read_jobs_raw();
    let key = pid.to_string();
    let Some(job) = raw.get(&key) else {
        return Err(format!(
            "pid {pid} absent du registre : arrêt refusé (le processus ne fait pas partie des scans du dashboard)"
        ));
    };
    let target = jstr(job, "target");

    if !pid_alive(pid) {
        set_state(&mut raw, &key, "stopped");
        write_jobs_raw(&raw);
        return Ok(format!("pid {pid} déjà arrêté"));
    }

    // SIGTERM d'abord : le scanner a un trap de nettoyage.
    let term_ok = kill_pid(pid, "TERM");
    let mut still_alive = pid_alive(pid);
    if still_alive {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !pid_alive(pid) {
                still_alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    if still_alive {
        let _ = kill_pid(pid, "KILL");
        std::thread::sleep(Duration::from_millis(200));
    }

    set_state(&mut raw, &key, "stopped");
    write_jobs_raw(&raw);
    reap_children();

    if term_ok {
        Ok(format!(
            "scan pid {pid} ({target}) arrêté (SIGTERM puis nettoyage)"
        ))
    } else {
        Ok(format!(
            "scan pid {pid} ({target}) arrêté (SIGKILL — SIGTERM sans effet)"
        ))
    }
}

/// Force un état dans le registre.
fn set_state(raw: &mut Map<String, Value>, key: &str, state: &str) {
    if let Some(entry) = raw.get_mut(key) {
        entry["state"] = Value::String(state.to_string());
    }
}

// ---------------------------------------------------------------------------
// Utilitaire partagé avec machine.rs
// ---------------------------------------------------------------------------

/// Lance une commande, capture sa sortie et l'abandonne après `secs` secondes.
/// Le stdout est lu par un thread dédié : sans ce drainage, un processus qui
/// écrit beaucoup bloquerait sur son pipe ET le wait() ne reviendrait jamais.
/// `None` = timeout ou erreur ; `Some(stdout)` = sortie complète.
pub fn run_with_timeout(cmd: &mut Command, secs: u64) -> Option<String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().ok()?;
    let pid = child.id();

    let pipe = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut h) = pipe {
            let _ = h.read_to_string(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut killed = false;
    let mut reaped = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                reaped = true;
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }
        let now = Instant::now();
        if !killed && now >= deadline {
            let _ = kill_pid(pid, "KILL");
            killed = true;
        } else if killed && now >= deadline + Duration::from_secs(5) {
            break; // processus introuvable : on ne bloque pas le HTTP
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    if reaped {
        // Déjà mort : `wait` rend le statut immédiatement et libère les ressources.
        let _ = child.wait();
    }
    if !reaped {
        // Le thread de lecture peut rester bloqué sur un pipe held open par un
        // petit-fils : on l'abandonne plutôt que de figer la requête.
        return None;
    }
    let out = reader.join().unwrap_or_default();
    if out.trim().is_empty() {
        None
    } else {
        Some(out)
    }
}
