// src/mcp/jobs.rs — Plan de contrôle universel : registre de jobs asynchrones.
//
// Les outils synchrones (tools_scan.rs, tools_audit.rs) bloquent le client
// le temps de l'exécution — acceptable pour un audit rapide, pas pour un
// `scan_target` profil `full` ou un `brand_sec`. Ce module ajoute la quatrième
// dimension du serveur : le PILOTAGE. Cinq outils MCP (`job_start`,
// `job_status`, `job_result`, `job_stop`, `job_list`) soumettent, observent,
// récupèrent et arrêtent des jobs asynchrones, quel que soit le kind :
// - `scan`   — le MÊME chemin que l'outil `scan_target` : Config de profil
//   (miroir de tools_scan::profile_config) -> résolution cible
//   (`resolve_first_ip`) -> `AuditOrchestrator::run` -> `save_scan` sauf
//   `no_db` (échec DB = avertissement stderr, jamais un échec de job) ;
// - `module` — UN module moteur exécuté seul, catalogue fermé [`CATALOG`]
//   mappé sur les auditeurs réels ; les modules d'orchestration (findings,
//   progress, db, impact, netdns, nethttp, ports, loot) sont REFUSÉS ;
// - `bin`    — UN binaire d'impact de la liste blanche (`BIN_WHITELIST`),
//   spawn en argv pur (jamais `sh -c`), `child_pid` enregistré pour un kill
//   réel via `job_stop`, timeout dur 900 s ;
// - `diag`   — le même diagnostic que l'outil `tools_diag` (helper partagé
//   `tools_catalog::diag_environment`), utile pour tester le registre sans
//   réseau.
//
// ARCHITECTURE
// - [`JobRegistry`] : `Mutex<HashMap<String, Job>>` + compteur atomique,
//   partagé via `Arc` et capturé par `move` dans les closures des outils
//   (litemcp exécute chaque handler dans un thread borné ; les jobs vivent
//   dans leurs propres threads `std` détachés — std only, aucun runtime).
// - Cycle de vie : `Queued` (créé) -> `Running` (thread démarré) -> `Done`
//   | `Error` ; `Cancelled` depuis Queued/Running via `job_stop`. Première
//   écriture finale GAGNANTE : un job `Cancelled` (job_stop) ou déjà
//   `Error` (timeout) n'est jamais écrasé par la fin du thread de travail —
//   le résultat produit malgré tout est JETÉ.
// - Garde-fous : 8 jobs actifs maximum (au-delà : `rate_limited`, le client
//   réessaie après job_stop/job_list) ; historique plafonné à 100 jobs
//   finis (évince les plus anciens) ; id `job-{seq}-{nanos}` (compteur
//   atomique + nanos d'horloge).
// - Timeouts globaux par kind : `module` = min(deadline outil x1.2, 1800 s)
//   via thread interne borné (détaché au dépassement, son résultat tardif
//   est ignoré) ; `bin` = 900 s (boucle `try_wait` + kill) ; `diag` = 360 s ;
//   `scan` = borné par les deadlines internes de l'orchestrateur.
//
// LIMITES CONTRACTUELLES
// - PAS de persistance : le registre vit dans le processus du serveur — le
//   processus EST la vie des jobs. Un redémarrage perd tous les jobs (le
//   client doit rejouer `job_start`) ; il n'y a aucun état sur disque.
// - Annulation COOPÉRATIVE : scan et module ne sont pas interrompus au vol
//   (l'orchestrateur et les modules sont monolithiques) — `job_stop` marque
//   `Cancelled` immédiatement et le résultat final est jeté quand le thread
//   finit ; seul `kind=bin` subit un kill réel (child_pid + `kill <pid>`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use litemcp::prelude::*;
use serde_json::{json, Value};

use super::tools_catalog::diag_environment;
use super::{guarded, resolve_first_ip, to_json_clipped, ToolResult, DEFAULT_DB_NAME};
use crate::config::{Config, ToolFlags};
use crate::modules::box_prober::BoxProber;
use crate::modules::brand_sec::BrandSecAuditor;
use crate::modules::crt_sh::CrtShAuditor;
use crate::modules::db::DatabaseManager;
use crate::modules::diag_exposure::DiagExposureAuditor;
use crate::modules::dns::DnsAuditor;
use crate::modules::dns_hardening::DnsHardeningAuditor;
use crate::modules::dnsrecon_audit::DnsreconAuditor;
use crate::modules::email_sec::EmailSecAuditor;
use crate::modules::ffuf_audit::FfufAuditor;
use crate::modules::findings::SecurityFinding;
use crate::modules::ftp_audit::FtpAuditor;
use crate::modules::full_portscan::FullPortScanner;
use crate::modules::geo::GeoAuditor;
use crate::modules::http::HttpAuditor;
use crate::modules::http_probe::HttpProbe;
use crate::modules::nikto_deep::NiktoAuditor;
use crate::modules::nmap_deep::NmapAuditor;
use crate::modules::nuclei_deep::NucleiAuditor;
use crate::modules::obscura_audit::ObscuraAuditor;
use crate::modules::portscan_rustscan::RustScanWrapper;
use crate::modules::scheme_detect::{detect_scheme, root_urls};
use crate::modules::smb_audit::SmbAuditor;
use crate::modules::sqli_audit::scan_urls_parallel;
use crate::modules::sslscan_audit::SslscanAuditor;
use crate::modules::subdomains::{ScanMode, SubdomainScanner};
use crate::modules::tech_stack::TechStackAuditor;
use crate::modules::theharvester_audit::TheHarvesterAuditor;
use crate::modules::tls::TlsAuditor;
use crate::modules::vuln_audit::VulnAuditor;
use crate::modules::waf::WafAuditor;
use crate::modules::web_endpoints::WebEndpointsAuditor;
use crate::modules::whois_audit::WhoisAuditor;
use crate::orchestrator::AuditOrchestrator;

// ==============================================================================
// CONSTANTES DU REGISTRE
// ==============================================================================

/// Jobs actifs (Queued | Running) maximum : au-delà, `job_start` répond
/// `rate_limited` — le client libère avec job_stop ou attend job_list.
const MAX_ACTIVE_JOBS: usize = 8;

/// Plafond de l'historique : les jobs finis au-delà sont évincés (plus
/// anciens d'abord) pour que la mémoire reste bornée sur un serveur longue
/// durée.
const FINISHED_HISTORY_MAX: usize = 100;

/// Pas de polling de `job_result` quand il attend (`wait_seconds`).
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Timeout dur d'un job `bin` : boucle `try_wait` + kill au dépassement.
const BIN_TIMEOUT: Duration = Duration::from_secs(900);

/// Timeout global d'un job `diag` (l'équivalent synchrone est borné par le
/// `tool_timeout` serveur ; en job on applique une borne dédiée).
const DIAG_TIMEOUT: Duration = Duration::from_secs(360);

/// Plafond du timeout global d'un job `module` (min(deadline x1.2, ceci)).
const MODULE_DEADLINE_CAP: u64 = 1800;

/// Troncature de la sortie d'un binaire d'impact (caractères, pas octets).
const BIN_STDOUT_MAX_CHARS: usize = 50_000;
const BIN_STDERR_MAX_CHARS: usize = 10_000;

/// Liste blanche STRICTE des bins d'impact pilotables en job. Jamais
/// `dashboard` (serveur web), jamais `mcp_server` / `mcp_intruder`
/// (récursion). Le nom vient d'une énumération fermée : aucune entrée
/// opérateur ne atteint `Command::new`.
const BIN_WHITELIST: &[&str] = &[
    "chainx",
    "surfx",
    "lootx",
    "envx",
    "gkeyx",
    "mongodx",
    "mysqlx",
    "redisx",
    "elasticx",
    "ftplx",
    "ftpx",
    "cnametake",
    "cnamewatch",
    "gitdump",
    "impacts",
    "keyprobe",
    "spoofcheck",
    "subalive",
];

// ==============================================================================
// CATALOGUE DES MODULES MOTEUR
// ==============================================================================

/// Genre d'entrée attendu par un module du catalogue (pilote la
/// normalisation de la cible dans [`run_module_job`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum InputKind {
    /// Nom de domaine pur (whois, theHarvester, brand_sec/dnstwist...).
    Domain,
    /// Domaine OU IP — la cible du CLI (audit HTTP, diag_exposure...).
    Target,
    /// URL ou host[:port] web (obscura, scheme_detect, http_probe...).
    Url,
    /// hôte:port (sslscan — port nu accepté, défaut 443).
    HostPort,
}

/// Une entrée du catalogue : module moteur -> conditions d'exécution en job.
struct ModuleSpec {
    /// Nom du module = nom de fichier (stem), clé de `job_start.module`.
    name: &'static str,
    input: InputKind,
    /// Ports par défaut fournis au module (None = le module décide seul).
    /// `nmap_deep` exige des ports ouverts : le job autonome fournit une
    /// liste dédiée faute de scan préalable.
    ports: Option<&'static [u16]>,
    /// Deadline OUTIL en secondes ; le job applique min(x1.2, 1800 s).
    deadline_secs: u64,
    /// true = réservé à l'orchestrateur : `job_start` refuse avec un
    /// message explicite (passe par kind=scan).
    orchestration_only: bool,
}

/// Ports ouverts par défaut fournis à `nmap_deep` en job autonome
/// (l'orchestrateur, lui, lui passe les ports ouverts du scan core).
const NMAP_DEEP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080, 8443,
];

/// Ports de service sondés par défaut par `box_prober` en job autonome.
const BOX_PROBE_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5800, 5900, 6379, 8080, 8443,
];

/// Catalogue FERMÉ des modules pilotables en job — 39 modules = tous les
/// fichiers de src/modules/. Tout module absent du schéma de job_start est
/// donc refusé, et les 8 modules d'orchestration sont listés explicitement
/// pour un message d'erreur pédagogique.
static CATALOG: &[ModuleSpec] = &[
    // --- Modules Core (déjà exposés en synchrone par tools_audit.rs) ---
    ModuleSpec {
        name: "dns",
        input: InputKind::Domain,
        ports: None,
        deadline_secs: 60,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "tls",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 60,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "http",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 120,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "whois_audit",
        input: InputKind::Domain,
        ports: None,
        deadline_secs: 60,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "geo",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 60,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "email_sec",
        input: InputKind::Domain,
        ports: None,
        deadline_secs: 90,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "subdomains",
        input: InputKind::Domain,
        ports: None,
        deadline_secs: 300,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "crt_sh",
        input: InputKind::Domain,
        ports: None,
        deadline_secs: 90,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "waf",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 120,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "tech_stack",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 120,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "dnsrecon_audit",
        input: InputKind::Domain,
        ports: None,
        deadline_secs: 120,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "dns_hardening",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 60,
        orchestration_only: false,
    },
    // --- Modules Kali lourds / nécessitant un contexte d'exécution ---
    ModuleSpec {
        name: "nmap_deep",
        input: InputKind::Target,
        ports: Some(NMAP_DEEP_PORTS),
        deadline_secs: 600,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "sslscan_audit",
        input: InputKind::HostPort,
        ports: None,
        deadline_secs: 120,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "sqli_audit",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 300,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "ftp_audit",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 180,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "smb_audit",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 180,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "box_prober",
        input: InputKind::Target,
        ports: Some(BOX_PROBE_PORTS),
        deadline_secs: 180,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "full_portscan",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 1200,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "portscan_rustscan",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 240,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "theharvester_audit",
        input: InputKind::Domain,
        ports: None,
        deadline_secs: 240,
        orchestration_only: false,
    },
    // LONG : dnstwist balaie des centaines de variantes de domaine.
    ModuleSpec {
        name: "brand_sec",
        input: InputKind::Domain,
        ports: None,
        deadline_secs: 240,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "obscura_audit",
        input: InputKind::Url,
        ports: None,
        deadline_secs: 90,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "diag_exposure",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 180,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "scheme_detect",
        input: InputKind::Url,
        ports: None,
        deadline_secs: 30,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "nikto_deep",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 600,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "nuclei_deep",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 600,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "web_endpoints",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 120,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "http_probe",
        input: InputKind::Url,
        ports: None,
        deadline_secs: 60,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "ffuf_audit",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 300,
        orchestration_only: false,
    },
    ModuleSpec {
        name: "vuln_audit",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 600,
        orchestration_only: false,
    },
    // --- Modules d'orchestration : job_start REFUSE, passe par kind=scan ---
    ModuleSpec {
        name: "findings",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 0,
        orchestration_only: true,
    },
    ModuleSpec {
        name: "progress",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 0,
        orchestration_only: true,
    },
    ModuleSpec {
        name: "db",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 0,
        orchestration_only: true,
    },
    ModuleSpec {
        name: "impact",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 0,
        orchestration_only: true,
    },
    ModuleSpec {
        name: "netdns",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 0,
        orchestration_only: true,
    },
    ModuleSpec {
        name: "nethttp",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 0,
        orchestration_only: true,
    },
    ModuleSpec {
        name: "ports",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 0,
        orchestration_only: true,
    },
    // loot ÉCRIT sur le disque (/var/lib/mcp-intruder/loot) : exclusivement dans
    // un scan complet (profils vuln/full).
    ModuleSpec {
        name: "loot",
        input: InputKind::Target,
        ports: None,
        deadline_secs: 0,
        orchestration_only: true,
    },
];

fn module_spec(name: &str) -> Option<&'static ModuleSpec> {
    CATALOG.iter().find(|m| m.name == name)
}

/// Timeout global du job pour un module : min(deadline outil x1.2 arrondi
/// au-dessus, 1800 s).
fn module_job_deadline(spec: &ModuleSpec) -> Duration {
    let secs = (spec.deadline_secs * 12)
        .div_ceil(10)
        .min(MODULE_DEADLINE_CAP);
    Duration::from_secs(secs)
}

// ==============================================================================
// REGISTRE DE JOBS
// ==============================================================================

/// Statut d'un job — sérialisé tel quel dans les réponses MCP.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JobStatus {
    Queued,
    Running,
    Done,
    Error,
    Cancelled,
}

impl JobStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Done => "done",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
        }
    }

    fn is_final(self) -> bool {
        matches!(self, Self::Done | Self::Error | Self::Cancelled)
    }
}

/// Un job du registre : identité, horodatages, état final et poignée
/// d'annulation. `child_pid` n'est posé que par `kind=bin` (kill réel).
struct Job {
    seq: u64,
    /// Identifiant public du job : "job-{seq}-{nanos}".
    id: String,
    /// Description lisible : "scan", "diag", "module:nmap_deep", "bin:chainx".
    kind: String,
    status: JobStatus,
    submitted_at: Instant,
    started_at: Option<Instant>,
    finished_at: Option<Instant>,
    result: Option<Value>,
    error: Option<String>,
    cancel: Arc<AtomicBool>,
    child_pid: Option<u32>,
}

/// Registre partagé (via `Arc`) entre les closures des 5 outils et les
/// threads des jobs. Un registre neuf par `build_server()` : tests isolés,
/// et un serveur redémarré repart à zéro (pas de persistance).
struct JobRegistry {
    jobs: Mutex<HashMap<String, Job>>,
    seq: AtomicU64,
}

struct StopOutcome {
    kind: String,
    child_pid: Option<u32>,
}

impl JobRegistry {
    fn new() -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(0),
        }
    }

    /// Verrou du registre, tolérant au poisoning (un panic dans un thread
    /// de job ne doit pas condamner le serveur) : on reprend la garde même
    /// empoisonnée, le drapeau « jamais de panic » est préservé.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Job>> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Crée le job en `Queued` après contrôle du plafond de jobs actifs.
    /// Retourne (id, poignée d'annulation).
    fn create(&self, kind: &str) -> Result<(String, Arc<AtomicBool>), ToolError> {
        let mut jobs = self.lock();
        let active = jobs
            .values()
            .filter(|j| matches!(j.status, JobStatus::Queued | JobStatus::Running))
            .count();
        if active >= MAX_ACTIVE_JOBS {
            return Err(ToolError::rate_limited(format!(
                "trop de jobs actifs ({active}/{MAX_ACTIVE_JOBS}) — réessaie après job_stop/job_list"
            )));
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let id = format!("job-{seq}-{nanos}");
        let job = Job {
            seq,
            id: id.clone(),
            kind: kind.to_string(),
            status: JobStatus::Queued,
            submitted_at: Instant::now(),
            started_at: None,
            finished_at: None,
            result: None,
            error: None,
            cancel: Arc::new(AtomicBool::new(false)),
            child_pid: None,
        };
        let cancel = Arc::clone(&job.cancel);
        jobs.insert(id.clone(), job);
        evict_finished(&mut jobs);
        Ok((id, cancel))
    }

    /// Poignée d'annulation d'un job (lue une fois par le thread du job).
    fn cancel_flag(&self, id: &str) -> Option<Arc<AtomicBool>> {
        self.lock().get(id).map(|j| Arc::clone(&j.cancel))
    }

    fn mark_running(&self, id: &str) {
        if let Some(job) = self.lock().get_mut(id) {
            if job.status == JobStatus::Queued {
                job.status = JobStatus::Running;
                job.started_at = Some(Instant::now());
            }
        }
    }

    fn set_child_pid(&self, id: &str, pid: u32) {
        if let Some(job) = self.lock().get_mut(id) {
            job.child_pid = Some(pid);
        }
    }

    /// Écrit l'état final du job. PREMIÈRE écriture finale gagnante : si le
    /// job est déjà `Cancelled` (job_stop) ou `Error` (timeout global), le
    /// résultat produit malgré tout par le thread est JETÉ.
    fn finish(&self, id: &str, outcome: Result<Value, String>) {
        let mut jobs = self.lock();
        let Some(job) = jobs.get_mut(id) else {
            return;
        };
        if job.status.is_final() {
            return;
        }
        job.finished_at = Some(Instant::now());
        match outcome {
            Ok(v) => {
                job.status = JobStatus::Done;
                job.result = Some(v);
            }
            Err(e) => {
                job.status = JobStatus::Error;
                job.error = Some(e);
            }
        }
        evict_finished(&mut jobs);
    }

    /// Annule un job : drapeau coopératif + `Cancelled` immédiat. Le pid
    /// éventuel (kind=bin) est retourné pour un kill HORS verrou. Un job
    /// déjà fini est refusé en `invalid_input` explicite.
    fn stop(&self, id: &str) -> Result<StopOutcome, ToolError> {
        let mut jobs = self.lock();
        let Some(job) = jobs.get_mut(id) else {
            return Err(unknown_job(id));
        };
        if job.status.is_final() {
            return Err(ToolError::invalid_input(format!(
                "job {id} déjà terminé (statut : {}) — rien à annuler",
                job.status.as_str()
            )));
        }
        job.cancel.store(true, Ordering::Relaxed);
        job.status = JobStatus::Cancelled;
        job.finished_at = Some(Instant::now());
        Ok(StopOutcome {
            kind: job.kind.clone(),
            child_pid: job.child_pid,
        })
    }

    /// Snapshot sérialisable d'un job ; `with_result` ajoute le champ
    /// `result` quand le job est `Done` (utilisé par job_result).
    fn snapshot(&self, id: &str, with_result: bool) -> Option<Value> {
        let jobs = self.lock();
        let job = jobs.get(id)?;
        let mut v = job_view(job);
        if let Some(e) = &job.error {
            v["error"] = json!(e);
        }
        if with_result {
            if let Some(r) = &job.result {
                v["result"] = r.clone();
            }
        }
        Some(v)
    }

    /// Liste des jobs, triés par soumission ; `active_only` filtre sur
    /// Queued | Running.
    fn list(&self, active_only: bool) -> Value {
        let jobs = self.lock();
        let mut selected: Vec<&Job> = jobs
            .values()
            .filter(|j| !active_only || matches!(j.status, JobStatus::Queued | JobStatus::Running))
            .collect();
        selected.sort_by_key(|j| j.seq);
        let entries: Vec<Value> = selected.iter().map(|j| job_view(j)).collect();
        let count = entries.len();
        json!({ "count": count, "jobs": entries })
    }
}

/// Évince les jobs finis les plus anciens au-delà du plafond d'historique.
fn evict_finished(jobs: &mut HashMap<String, Job>) {
    let mut finished: Vec<(u64, String)> = jobs
        .values()
        .filter(|j| j.status.is_final())
        .map(|j| (j.seq, j.id.clone()))
        .collect();
    if finished.len() <= FINISHED_HISTORY_MAX {
        return;
    }
    finished.sort_by_key(|(seq, _)| *seq);
    let surplus = finished.len() - FINISHED_HISTORY_MAX;
    for (_, ancien) in finished.into_iter().take(surplus) {
        jobs.remove(&ancien);
    }
}

/// Vue sérialisée commune à job_status / job_result / job_list.
fn job_view(job: &Job) -> Value {
    let elapsed = job
        .finished_at
        .unwrap_or_else(Instant::now)
        .duration_since(job.submitted_at)
        .as_secs();
    json!({
        "job_id": job.id,
        "kind": job.kind,
        "status": job.status.as_str(),
        "elapsed_seconds": elapsed,
    })
}

fn unknown_job(id: &str) -> ToolError {
    ToolError::invalid_input(format!("job inconnu : {id} — vois job_list"))
}

// ==============================================================================
// PAYLOADS ET EXÉCUTION
// ==============================================================================

/// Ce qu'un thread de job doit exécuter — construit et validé SYNCHRONEment
/// par `job_start`, exécuté en arrière-plan par [`run_job`].
enum JobPayload {
    Scan {
        target: String,
        profile: String,
        no_db: bool,
        db_name: String,
    },
    Module {
        spec: &'static ModuleSpec,
        target: String,
    },
    Bin {
        path: PathBuf,
        args: Vec<String>,
    },
    Diag,
}

/// Point d'entrée du thread d'un job : `Queued` -> `Running` -> travail ->
/// `finish` (première écriture finale gagnante).
fn run_job(registry: Arc<JobRegistry>, id: String, payload: JobPayload) {
    registry.mark_running(&id);
    let outcome = match payload {
        JobPayload::Diag => run_with_deadline(DIAG_TIMEOUT, || Ok(diag_environment())),
        JobPayload::Module { spec, target } => {
            run_with_deadline(module_job_deadline(spec), move || {
                run_module_job(spec, &target)
            })
        }
        JobPayload::Scan {
            target,
            profile,
            no_db,
            db_name,
        } => run_scan_job(&target, &profile, no_db, &db_name),
        JobPayload::Bin { path, args } => run_bin_job(&registry, &id, path, args),
    };
    registry.finish(&id, outcome);
}

/// Exécute un travail dans un thread interne borné par un deadline global
/// (les modules et le diag n'offrent pas de point d'annulation). Au
/// dépassement, le job passe `Error` et le thread interne est DÉTACHÉ : son
/// résultat tardif arrive sur un canal mort et sera ignoré.
fn run_with_deadline<F>(deadline: Duration, work: F) -> Result<Value, String>
where
    F: FnOnce() -> Result<Value, String> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("mcp-job-work".to_string())
        .spawn(move || {
            // Garde anti-panic locale : un module qui panique ne doit pas
            // laisser le job en `Running` éternellement.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                .unwrap_or_else(|_| {
                    Err("panic interne du module (cible injoignable ou outil absent)".to_string())
                });
            let _ = tx.send(outcome);
        })
        .map_err(|e| format!("thread de travail indisponible : {e}"))?;
    match rx.recv_timeout(deadline) {
        Ok(outcome) => outcome,
        Err(_) => Err(format!(
            "timeout global du job ({} s) dépassé — thread détaché, résultat jeté",
            deadline.as_secs()
        )),
    }
}

// ==============================================================================
// KIND = SCAN — miroir exact du chemin de tools_scan::scan_target
// ==============================================================================

fn run_scan_job(target: &str, profile: &str, no_db: bool, db_name: &str) -> Result<Value, String> {
    let config = profile_config(target, profile, no_db, db_name).map_err(|e| e.message)?;
    let first_ip = resolve_first_ip(target).map_err(|e| e.message)?;
    // L'orchestrateur protège déjà chaque module (run_guarded) ; la garde
    // ci-dessous couvre le reste — même contrat que tools_scan.
    let report = guarded("job_scan", || {
        Ok(AuditOrchestrator::run(&config, &first_ip))
    })
    .map_err(|e| e.message)?;

    // Persistance : même contrat que main.rs — un échec DB n'invalide PAS
    // le job (avertissement sur stderr).
    let mut scan_id = None;
    if !no_db {
        match DatabaseManager::save_scan(&report, &config.db_name) {
            Ok(id) => scan_id = Some(id),
            Err(e) => eprintln!("[MCP] job scan : échec du catalogage PostgreSQL : {e}"),
        }
    }

    // Sérialisation MIROIR de tools_scan::scan_target (même forme JSON).
    let findings: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            json!({
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
            })
        })
        .collect();
    let recommandations: Vec<&str> = report
        .findings
        .iter()
        .take(3)
        .map(|f| f.recommendation.as_str())
        .collect();

    Ok(json!({
        "target": report.target,
        "ip": first_ip,
        "profile": profile,
        "overall_score": report.overall_score,
        "counts": severity_counts(&report.findings),
        "findings": findings,
        "scan_id": scan_id,
        "duration_seconds": report.duration_seconds,
        "recommandations": recommandations,
    }))
}

/// Construit la `Config` moteur pour le profil demandé.
///
/// MIROIR de tools_scan::profile_config — les deux fonctions doivent rester
/// synchronisées (tools_scan.rs n'est pas modifiable depuis jobs.rs et la
/// fonction y est privée) : même mapping profil -> `ToolFlags` que
/// `Config::parse` dans src/config.rs. `json_mode = true` : stdout est
/// réservé au serveur MCP.
fn profile_config(
    target: &str,
    profile: &str,
    no_db: bool,
    db_name: &str,
) -> Result<Config, ToolError> {
    let mut tools = ToolFlags::default();
    match profile {
        // `-1/--fast` : modules Core uniquement, aucun outil Kali.
        "fast" => {}
        // `-2/--web` : WAF + WhatWeb + SSLScan + Dnstwist + Httpx.
        "web" => {
            tools.waf = true;
            tools.whatweb = true;
            tools.sslscan = true;
            tools.dnstwist = true;
            tools.httpx = true;
        }
        // `-d/--discovery` : Ffuf + Nikto + WAF.
        "discovery" => {
            tools.ffuf = true;
            tools.nikto = true;
            tools.waf = true;
        }
        // `-4/--infra` : Nmap + SSLScan + RustScan.
        "infra" => {
            tools.nmap = true;
            tools.sslscan = true;
            tools.rustscan = true;
        }
        // `-5/--vuln` : Nuclei + Nikto + Nmap + SQLMap + Loot.
        "vuln" => {
            tools.nuclei = true;
            tools.nikto = true;
            tools.nmap = true;
            tools.sqlmap = true;
            tools.loot = true;
        }
        // `-3/--full` : TOUS les outils Kali (SQLMap/Loot exclus par defaut,
        // fidele a enable_all()).
        "full" => tools.enable_all(),
        autre => {
            return Err(ToolError::invalid_input(format!(
                "profil inconnu : {autre} (attendus : fast, web, discovery, infra, vuln, full)"
            )));
        }
    }

    Ok(Config {
        target: target.to_string(),
        json_mode: true,
        timeout_ms: 800,
        custom_ports: None,
        db_name: db_name.to_string(),
        save_to_db: !no_db,
        show_history: false,
        history_limit: 5,
        tools,
    })
}

/// Comptage des constats par sévérité — MIROIR de tools_scan::severity_counts
/// (les cinq niveaux du moteur toujours présents, à zéro s'il n'y a rien).
fn severity_counts(findings: &[SecurityFinding]) -> Value {
    let mut counts = serde_json::Map::new();
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        let n = findings.iter().filter(|f| f.severity == severity).count();
        counts.insert(severity.to_string(), json!(n));
    }
    Value::Object(counts)
}

// ==============================================================================
// KIND = MODULE — un module moteur du catalogue, exécuté seul
// ==============================================================================

fn run_module_job(spec: &ModuleSpec, target_raw: &str) -> Result<Value, String> {
    let target = normalize_input(spec.input, target_raw);
    let ports: &[u16] = spec.ports.unwrap_or(&[]);
    match spec.name {
        // --- Core : mêmes appels que tools_audit.rs ----------------------
        "dns" => Ok(to_json_clipped(&DnsAuditor::audit(&target))),
        "tls" => {
            let ip = resolve_ip(&target)?;
            Ok(to_json_clipped(&TlsAuditor::audit(&target, &ip)))
        }
        "http" => Ok(to_json_clipped(&HttpAuditor::audit(&target, ports))),
        "whois_audit" => Ok(to_json_clipped(&WhoisAuditor::audit(&target))),
        "geo" => {
            let ip = resolve_ip(&target)?;
            Ok(to_json_clipped(&GeoAuditor::audit(&ip)))
        }
        "email_sec" => {
            // Même contrat que l'orchestrateur : les enregistrements SPF/
            // DMARC bruts proviennent du module DNS.
            let dns = DnsAuditor::audit(&target);
            Ok(to_json_clipped(&EmailSecAuditor::audit(
                &target,
                dns.spf_record.as_deref(),
                dns.dmarc_record.as_deref(),
            )))
        }
        "subdomains" => {
            let subs = SubdomainScanner::scan_with_mode(&target, ScanMode::Auto);
            Ok(json!({ "count": subs.len(), "subdomains": subs }))
        }
        "crt_sh" => Ok(to_json_clipped(&CrtShAuditor::audit(&target))),
        "waf" => Ok(to_json_clipped(&WafAuditor::audit(&target))),
        "tech_stack" => Ok(to_json_clipped(&TechStackAuditor::audit(&target, ports))),
        "dnsrecon_audit" => Ok(to_json_clipped(&DnsreconAuditor::audit(&target))),
        "dns_hardening" => {
            let ip = resolve_ip(&target)?;
            Ok(to_json_clipped(&DnsHardeningAuditor::audit(&ip, &target)))
        }
        // --- Kali lourds --------------------------------------------------
        "nmap_deep" => Ok(to_json_clipped(&NmapAuditor::audit(&target, ports))),
        "sslscan_audit" => Ok(to_json_clipped(&SslscanAuditor::audit(&target, ports))),
        "sqli_audit" => {
            // Même construction d'URLs que l'orchestrateur (https puis http).
            let urls = vec![format!("https://{target}"), format!("http://{target}")];
            let findings = scan_urls_parallel(urls.clone(), 60);
            Ok(json!({
                "target": target,
                "urls_probed": urls,
                "count": findings.len(),
                "findings": findings,
            }))
        }
        "ftp_audit" => Ok(to_json_clipped(&FtpAuditor::audit(&target))),
        "smb_audit" => Ok(to_json_clipped(&SmbAuditor::audit(&target))),
        "box_prober" => Ok(to_json_clipped(&BoxProber::audit(&target, ports))),
        "full_portscan" => {
            // Mêmes paramètres que l'orchestrateur : TCP connect natif,
            // 300 ms/port. Ports de catalogue = plages [p, p] unitaires.
            let mut results = Vec::new();
            if ports.is_empty() {
                results.extend(FullPortScanner::scan_all(
                    &target,
                    Duration::from_millis(300),
                    None::<fn(u16)>,
                ));
            } else {
                for &p in ports {
                    results.extend(FullPortScanner::scan_range(
                        &target,
                        p,
                        p,
                        Duration::from_millis(300),
                        None::<fn(u16)>,
                    ));
                }
            }
            let open_ports: Vec<u16> = results
                .iter()
                .filter(|r| r.is_open)
                .map(|r| r.port)
                .collect();
            Ok(json!({
                "target": target,
                "open_ports": open_ports,
                "results": results,
            }))
        }
        "portscan_rustscan" => {
            if !RustScanWrapper::is_available() {
                return Err("portscan_rustscan : binaire rustscan introuvable".to_string());
            }
            RustScanWrapper::scan_ports(&target, 3)
                .map(|r| to_json_clipped(&r))
                .map_err(|e| format!("portscan_rustscan : {e}"))
        }
        "theharvester_audit" => Ok(to_json_clipped(&TheHarvesterAuditor::audit(&target))),
        "brand_sec" => Ok(to_json_clipped(&BrandSecAuditor::audit(&target))),
        "obscura_audit" => Ok(to_json_clipped(&ObscuraAuditor::audit(&target, false))),
        "diag_exposure" => Ok(to_json_clipped(&DiagExposureAuditor::audit(&target, ports))),
        "scheme_detect" => {
            let plan = detect_scheme(&target);
            Ok(json!({
                "hostport": target,
                "order": plan.order,
                "reachable": plan.reachable,
                "root_urls": root_urls(&target),
            }))
        }
        "nikto_deep" => Ok(to_json_clipped(&NiktoAuditor::audit(&target, false))),
        "nuclei_deep" => Ok(to_json_clipped(&NucleiAuditor::audit(&target, false))),
        "web_endpoints" => {
            let ip = resolve_ip(&target)?;
            Ok(to_json_clipped(&WebEndpointsAuditor::audit(&target, &ip)))
        }
        "http_probe" => {
            let url = ensure_scheme(&target);
            let results = HttpProbe::probe(vec![url.clone()]);
            Ok(json!({
                "target": url,
                "count": results.len(),
                "results": results,
            }))
        }
        "ffuf_audit" => Ok(to_json_clipped(&FfufAuditor::audit(&target, ports, false))),
        "vuln_audit" => Ok(to_json_clipped(&VulnAuditor::audit(&target, ports, false))),
        // Toute entrée du catalogue non gérée ci-dessus = orchestration-only
        // (le refus est déjà fait à job_start ; ce bras est un filet).
        autre => Err(format!(
            "module {autre} : orchestration uniquement, passe par kind=scan"
        )),
    }
}

/// Résolution IP locale au job (mêmes erreurs lisibles que les outils
/// synchrones, mais en `Result<_, String>` : on est hors handler MCP).
fn resolve_ip(target: &str) -> Result<String, String> {
    resolve_first_ip(target).map_err(|e| e.message)
}

/// Normalise l'entrée selon le genre déclaré du module : les modules "url"
/// construisent eux-mêmes https://host (obscura, nuclei...) — on retire un
/// schéma/chemin éventuel. Les autres genres passent tels quels.
fn normalize_input(kind: InputKind, raw: &str) -> String {
    match kind {
        InputKind::Url => strip_scheme(raw).to_string(),
        _ => raw.to_string(),
    }
}

/// "https://host:8443/path?x" -> "host:8443" (en caractères, pas en octets).
fn strip_scheme(raw: &str) -> &str {
    let no_scheme = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .unwrap_or(raw);
    match no_scheme.find(['/', '?']) {
        Some(i) => &no_scheme[..i],
        None => no_scheme,
    }
}

/// "host:8443" -> "https://host:8443" (http_probe exige une URL complète).
fn ensure_scheme(url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{url}")
    }
}

// ==============================================================================
// KIND = BIN — binaire d'impact de la liste blanche, supervisé
// ==============================================================================

/// Résolution du binaire : /usr/local/bin/<bin> d'abord (installation
/// `cargo install`), puis target/release/<bin> du crate. `is_file()` sur
/// chaque candidat : aucune résolution par PATH (pas de détournement).
fn resolve_bin(bin: &str) -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("/usr/local/bin").join(bin),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("release")
            .join(bin),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

/// Exécute le binaire en argv pur (JAMAIS `sh -c`), stdin nul, supervise
/// par `try_wait` : kill au deadline de 900 s ET à l'annulation (le drapeau
/// `cancel` du job). `child_pid` est enregistré au registre dès le spawn
/// pour que `job_stop` puisse tuer hors bande.
fn run_bin_job(
    registry: &JobRegistry,
    id: &str,
    path: PathBuf,
    args: Vec<String>,
) -> Result<Value, String> {
    let cancel = registry
        .cancel_flag(id)
        .ok_or_else(|| format!("job {id} disparu du registre"))?;
    let mut child = Command::new(&path)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("binaire {} : échec du spawn : {e}", path.display()))?;
    registry.set_child_pid(id, child.id());

    let start = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            // `finish` verra déjà Cancelled (posé par job_stop) et jettera
            // ce résultat — on retourne une erreur générique sans importance.
            return Err("job annulé".to_string());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().map_err(|e| {
                    format!("binaire {} : lecture de la sortie : {e}", path.display())
                })?;
                let stdout = clip_chars(
                    &String::from_utf8_lossy(&output.stdout),
                    BIN_STDOUT_MAX_CHARS,
                );
                let stderr = clip_chars(
                    &String::from_utf8_lossy(&output.stderr),
                    BIN_STDERR_MAX_CHARS,
                );
                let bin = path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or_default()
                    .to_string();
                return Ok(json!({
                    "bin": bin,
                    "args": args,
                    "exit_code": status.code(),
                    "stdout": stdout,
                    "stderr": stderr,
                    "duration_seconds": start.elapsed().as_secs_f64(),
                }));
            }
            Ok(None) => {
                if start.elapsed() >= BIN_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "timeout du binaire ({} s) — processus tué",
                        BIN_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(format!(
                    "binaire {} : échec de supervision : {e}",
                    path.display()
                ))
            }
        }
    }
}

/// Tue le processus enfant d'un job `bin` : `kill <pid>` en argv direct
/// (jamais `sh -c`). Best effort — un échec de spawn (plateforme sans
/// `kill`) n'invalide pas l'annulation : le drapeau coopératif suffit.
fn kill_child(pid: u32) {
    let _ = Command::new("kill").arg(pid.to_string()).spawn();
}

/// Tronque en caractères (pas en octets, UTF-8 préservé).
fn clip_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!(
            "{}\n… (tronqué à {max} caractères)",
            s.chars().take(max).collect::<String>()
        )
    }
}

// ==============================================================================
// OUTILS MCP — job_start / job_status / job_result / job_stop / job_list
// ==============================================================================

/// Enregistre les 5 outils du plan de contrôle jobs sur le builder. Le
/// registre est créé ICI (un par serveur) et partagé par `Arc` entre les
/// cinq closures.
pub(super) fn register(builder: ServerBuilder) -> ServerBuilder {
    let registry = Arc::new(JobRegistry::new());

    let reg_start = Arc::clone(&registry);
    let reg_status = Arc::clone(&registry);
    let reg_result = Arc::clone(&registry);
    let reg_stop = Arc::clone(&registry);
    let reg_list = Arc::clone(&registry);

    builder
        .tool_parse(
            "job_start",
            "Démarre un job asynchrone en arrière-plan et rend immédiatement { job_id, kind, \
             status: \"queued\" }. Kinds : \"scan\" (scan_target complet — `target` requis, \
             `profile` fast/web/discovery/infra/vuln/full, no_db par défaut) ; \"module\" (UN \
             module moteur du catalogue — nmap_deep, sslscan_audit, sqli_audit, ftp_audit, \
             smb_audit, box_prober, full_portscan, portscan_rustscan, theharvester_audit, \
             brand_sec, obscura_audit, diag_exposure, scheme_detect, nikto_deep, nuclei_deep, \
             web_endpoints, http_probe, ffuf_audit, vuln_audit et les modules Core dns, tls, \
             http, whois_audit, geo, email_sec, subdomains, crt_sh, waf, tech_stack, \
             dnsrecon_audit, dns_hardening — les modules d'orchestration findings, progress, \
             db, impact, netdns, nethttp, ports, loot sont refusés) ; \"bin\" (un binaire \
             d'impact de la liste blanche : chainx, surfx, lootx, envx, gkeyx, mongodx, \
             mysqlx, redisx, elasticx, ftplx, ftpx, cnametake, cnamewatch, gitdump, impacts, \
             keyprobe, spoofcheck, subalive — `args` = argv) ; \"diag\" (diagnostic \
             environnement, aucun argument). Interroger ensuite avec job_status / job_result.",
            zod::object()
                .field("kind", zod::enumeration(&["scan", "module", "bin", "diag"]))
                .opt("target", zod::string().min(1).max(253))
                .opt(
                    "profile",
                    zod::enumeration(&["fast", "web", "discovery", "infra", "vuln", "full"])
                        .default("fast"),
                )
                .opt("module", zod::string().min(1).max(64))
                .opt("bin", zod::string().min(1).max(64))
                .opt("args", zod::array(zod::string()).max(32))
                .opt("no_db", zod::boolean().default(true))
                .strict(),
            move |args: JobStartArgs| -> ToolResult { job_start(Arc::clone(&reg_start), args) },
        )
        .annotate(
            "job_start",
            ToolAnnotations::new()
                .title("Démarrer un job asynchrone")
                .read_only(false)
                .open_world(true),
        )
        .tool_parse(
            "job_status",
            "Snapshot d'un job sans attendre : kind, statut (queued/running/done/error/\
             cancelled), durée écoulée et erreur éventuelle. Ne bloque jamais.",
            zod::object().field("job_id", zod::string().min(1)).strict(),
            move |args: JobIdArgs| -> ToolResult {
                reg_status
                    .snapshot(&args.job_id, false)
                    .ok_or_else(|| unknown_job(&args.job_id))
            },
        )
        .annotate(
            "job_status",
            ToolAnnotations::new()
                .title("Statut d'un job")
                .read_only(true)
                .idempotent(true),
        )
        .tool_parse(
            "job_result",
            "Résultat complet d'un job : attend en polling (250 ms) jusqu'à `wait_seconds` \
             (0..60, défaut 0) ; si le job est `done`, retourne le résultat JSON complet \
             (même forme que scan_target pour kind=scan), sinon le snapshot de statut.",
            zod::object()
                .field("job_id", zod::string().min(1))
                .opt("wait_seconds", zod::integer().min(0).max(60).default(0))
                .strict(),
            move |args: JobResultArgs| -> ToolResult { job_result(&reg_result, args) },
        )
        .annotate(
            "job_result",
            ToolAnnotations::new()
                .title("Résultat d'un job")
                .read_only(true)
                .idempotent(true),
        )
        .tool_parse(
            "job_stop",
            "Annule un job : drapeau d'annulation immédiat, kill réel du processus pour \
             kind=bin (child_pid), statut `cancelled`. Le résultat d'un scan annulé est \
             jeté (annulation coopérative). Un job déjà fini est refusé.",
            zod::object().field("job_id", zod::string().min(1)).strict(),
            move |args: JobIdArgs| -> ToolResult { job_stop(&reg_stop, args) },
        )
        .annotate(
            "job_stop",
            ToolAnnotations::new()
                .title("Arrêter un job")
                .read_only(false)
                .open_world(true),
        )
        .tool_parse(
            "job_list",
            "Liste les jobs du registre (triés par soumission) : job_id, kind, statut, durée. \
             `active_only` limite aux jobs non terminés (queued/running).",
            zod::object()
                .opt("active_only", zod::boolean().default(false))
                .strict(),
            move |args: JobListArgs| -> ToolResult { Ok(reg_list.list(args.active_only)) },
        )
        .annotate(
            "job_list",
            ToolAnnotations::new()
                .title("Lister les jobs")
                .read_only(true)
                .idempotent(true),
        )
}

// ==============================================================================
// HANDLERS
// ==============================================================================

#[derive(serde::Deserialize)]
struct JobStartArgs {
    kind: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    bin: Option<String>,
    #[serde(default)]
    args: Option<Vec<String>>,
    // Défaut zod = true ; ce défaut serde ne s'applique que si le schéma
    // n'a pas injecté la valeur (double ceinture).
    #[serde(default = "default_true")]
    no_db: bool,
}

fn default_true() -> bool {
    true
}

#[derive(serde::Deserialize)]
struct JobIdArgs {
    job_id: String,
}

#[derive(serde::Deserialize)]
struct JobResultArgs {
    job_id: String,
    #[serde(default)]
    wait_seconds: u64,
}

#[derive(serde::Deserialize)]
struct JobListArgs {
    #[serde(default)]
    active_only: bool,
}

/// Valide SYNCHRONEment les arguments (échec rapide, sans consommer le
/// quota de jobs), crée le job puis démarre son thread.
fn job_start(registry: Arc<JobRegistry>, args: JobStartArgs) -> ToolResult {
    let (kind, payload) = match args.kind.as_str() {
        "scan" => {
            let target = require_target(args.target.as_deref(), "scan")?;
            let profile = if args.profile.is_empty() {
                "fast".to_string()
            } else {
                args.profile
            };
            (
                "scan".to_string(),
                JobPayload::Scan {
                    target,
                    profile,
                    no_db: args.no_db,
                    db_name: DEFAULT_DB_NAME.to_string(),
                },
            )
        }
        "module" => {
            let target = require_target(args.target.as_deref(), "module")?;
            let module = args
                .module
                .as_deref()
                .filter(|m| !m.is_empty())
                .ok_or_else(|| {
                    ToolError::invalid_input(
                        "kind=module : champ `module` requis (nom du catalogue : nmap_deep, \
                     sslscan_audit, brand_sec, ... — vois la description de job_start)",
                    )
                })?;
            let Some(spec) = module_spec(module) else {
                let disponibles = CATALOG
                    .iter()
                    .map(|m| m.name)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(ToolError::invalid_input(format!(
                    "module inconnu : {module} — modules du catalogue : {disponibles}"
                )));
            };
            if spec.orchestration_only {
                // loot est le seul à écrire sur disque : renvoyer vers les
                // profils qui l'activent.
                let indice = if spec.name == "loot" {
                    " (profil vuln/full pour loot)"
                } else {
                    ""
                };
                return Err(ToolError::invalid_input(format!(
                    "module {} : orchestration uniquement, passe par kind=scan{indice}",
                    spec.name
                )));
            }
            (
                format!("module:{}", spec.name),
                JobPayload::Module { spec, target },
            )
        }
        "bin" => {
            let bin = args
                .bin
                .as_deref()
                .filter(|b| !b.is_empty())
                .ok_or_else(|| {
                    ToolError::invalid_input(
                        "kind=bin : champ `bin` requis (liste blanche : chainx, surfx, lootx, \
                         envx, gkeyx, mongodx, mysqlx, redisx, elasticx, ftplx, ftpx, \
                         cnametake, cnamewatch, gitdump, impacts, keyprobe, spoofcheck, \
                         subalive)",
                    )
                })?;
            if !BIN_WHITELIST.contains(&bin) {
                return Err(ToolError::invalid_input(format!(
                    "binaire {bin} : hors liste blanche (autorisés : {})",
                    BIN_WHITELIST.join(", ")
                )));
            }
            let Some(path) = resolve_bin(bin) else {
                return Err(ToolError::invalid_input(format!(
                    "binaire {bin} introuvable — installe avec cargo install --path . --bin {bin}"
                )));
            };
            (
                format!("bin:{bin}"),
                JobPayload::Bin {
                    path,
                    args: args.args.unwrap_or_default(),
                },
            )
        }
        "diag" => ("diag".to_string(), JobPayload::Diag),
        autre => {
            return Err(ToolError::invalid_input(format!(
                "kind inconnu : {autre} (attendus : scan, module, bin, diag)"
            )));
        }
    };

    // Quota de jobs actifs + insertion en `Queued` (sous un seul verrou).
    let (job_id, _cancel) = registry.create(&kind)?;

    // Thread dédié : le registre est cloné par Arc, le payload est possédé.
    let reg = Arc::clone(&registry);
    let id = job_id.clone();
    let spawned = std::thread::Builder::new()
        .name(format!("mcp-{job_id}"))
        .spawn(move || run_job(reg, id, payload));
    if spawned.is_err() {
        registry.finish(
            &job_id,
            Err("thread de job indisponible (serveur surchargé)".to_string()),
        );
        return Err(ToolError::internal(
            "impossible de démarrer le thread du job",
        ));
    }

    Ok(json!({ "job_id": job_id, "kind": kind, "status": "queued" }))
}

/// `job_result` : polling 250 ms jusqu'à `wait_seconds` (0 = snapshot
/// immédiat), puis résultat complet si `done`, sinon snapshot de statut.
fn job_result(registry: &JobRegistry, args: JobResultArgs) -> ToolResult {
    let deadline = Instant::now() + Duration::from_secs(args.wait_seconds);
    loop {
        match registry.snapshot(&args.job_id, true) {
            None => return Err(unknown_job(&args.job_id)),
            Some(v) => {
                let fini = v["status"]
                    .as_str()
                    .is_some_and(|s| matches!(s, "done" | "error" | "cancelled"));
                if fini || Instant::now() >= deadline {
                    return Ok(v);
                }
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// `job_stop` : drapeau + `Cancelled` sous verrou, kill du pid (kind=bin)
/// HORS verrou.
fn job_stop(registry: &JobRegistry, args: JobIdArgs) -> ToolResult {
    let outcome = registry.stop(&args.job_id)?;
    if let Some(pid) = outcome.child_pid {
        kill_child(pid);
    }
    Ok(json!({
        "job_id": args.job_id,
        "kind": outcome.kind,
        "status": "cancelled",
        "child_pid_killed": outcome.child_pid.is_some(),
    }))
}

/// `target` requis pour les kinds scan et module.
fn require_target(target: Option<&str>, kind: &str) -> Result<String, ToolError> {
    match target.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => Ok(t.to_string()),
        None => Err(ToolError::invalid_input(format!(
            "kind={kind} : champ `target` requis (domaine ou IP)"
        ))),
    }
}

// ==============================================================================
// TESTS — dispatch JSON-RPC en mémoire, sans réseau ni PostgreSQL
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::build_server;
    use litemcp::ServerCore;

    /// Requête JSON-RPC 2.0 minimaliste, même forme que les tests de
    /// mod.rs et de litemcp.
    fn rpc(id: u64, method: &str, params: &str) -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#)
            .into_bytes()
    }

    /// Appelle un outil via ServerCore::dispatch et parse la réponse.
    fn call(core: &ServerCore, id: u64, name: &str, arguments: &str) -> Value {
        let raw = core
            .dispatch(&rpc(
                id,
                "tools/call",
                &format!(r#"{{"name":"{name}","arguments":{arguments}}}"#),
            ))
            .expect("tools/call doit répondre");
        serde_json::from_slice(&raw).expect("réponse JSON-RPC valide")
    }

    #[test]
    fn job_lifecycle_diag_completes_with_result() {
        let core = build_server().core();

        // 1. job_start kind=diag -> { job_id, kind, status: "queued" }.
        let started = call(&core, 10, "job_start", r#"{"kind":"diag"}"#);
        assert!(
            started.get("error").is_none(),
            "job_start diag ne doit pas échouer : {started}"
        );
        let sc = &started["result"]["structuredContent"];
        assert_eq!(sc["status"], "queued", "job_start : {started}");
        let job_id = sc["job_id"].as_str().expect("job_id présent").to_string();
        assert!(job_id.starts_with("job-"), "id : {job_id}");

        // 2. job_status (ne bloque jamais, même si le job tourne encore).
        let status = call(
            &core,
            11,
            "job_status",
            &format!(r#"{{"job_id":"{job_id}"}}"#),
        );
        assert_eq!(
            status["result"]["structuredContent"]["job_id"],
            job_id.as_str(),
            "job_status : {status}"
        );

        // 3. job_result avec attente -> status "done" + résultat diagnostic
        //    (au moins un outil sondé, présent ou absent).
        let result = call(
            &core,
            12,
            "job_result",
            &format!(r#"{{"job_id":"{job_id}","wait_seconds":30}}"#),
        );
        let sc = &result["result"]["structuredContent"];
        assert_eq!(sc["status"], "done", "job_result : {result}");
        assert!(
            sc["result"].get("nmap").is_some(),
            "résultat diag sans outil nmap : {result}"
        );
    }

    #[test]
    fn job_start_module_inconnu_est_refuse() {
        let core = build_server().core();
        let v = call(
            &core,
            20,
            "job_start",
            r#"{"kind":"module","module":"module_fantome","target":"example.com"}"#,
        );
        assert_eq!(v["result"]["isError"], true, "réponse : {v}");
        let brut = v.to_string();
        assert!(
            brut.contains("module_fantome"),
            "le message doit nommer le module inconnu : {v}"
        );
    }

    #[test]
    fn job_start_module_orchestration_only_est_refuse() {
        let core = build_server().core();
        let v = call(
            &core,
            21,
            "job_start",
            r#"{"kind":"module","module":"loot","target":"example.com"}"#,
        );
        assert_eq!(v["result"]["isError"], true, "réponse : {v}");
        let brut = v.to_string();
        assert!(
            brut.contains("orchestration"),
            "le message doit expliquer l'orchestration-only : {v}"
        );
    }

    #[test]
    fn job_status_et_job_stop_sur_id_inconnu_echouent() {
        let core = build_server().core();
        let status = call(&core, 22, "job_status", r#"{"job_id":"job-inexistant"}"#);
        assert_eq!(status["result"]["isError"], true, "réponse : {status}");
        assert!(
            status.to_string().contains("job-inexistant"),
            "message sans l'id : {status}"
        );

        let stop = call(&core, 23, "job_stop", r#"{"job_id":"job-inexistant"}"#);
        assert_eq!(stop["result"]["isError"], true, "réponse : {stop}");
    }

    #[test]
    fn tools_list_contient_les_cinq_outils_jobs() {
        let core = build_server().core();
        let raw = core
            .dispatch(&rpc(24, "tools/list", "{}"))
            .expect("tools/list doit répondre");
        let v: Value = serde_json::from_slice(&raw).unwrap();
        let names: Vec<&str> = v["result"]["tools"]
            .as_array()
            .expect("result.tools tableau")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();

        for attendu in [
            "job_start",
            "job_status",
            "job_result",
            "job_stop",
            "job_list",
        ] {
            assert!(
                names.contains(&attendu),
                "outil manquant : {attendu} (présents : {names:?})"
            );
        }
        assert_eq!(
            names.len(),
            24,
            "24 outils attendus (21 historiques + 3 skills), trouvés : {names:?}"
        );
    }
}
