// src/dash/model.rs — Types partagés du tableau de bord.
// Contrat stable : les modules db/, charts/, machine/, scans/, api/ compilent
// tous contre ces structures. Ne pas changer un champ sans mettre à jour tous.

use serde::Serialize;

/// Un scan catalogué dans audit_scans.
#[derive(Debug, Clone, Serialize)]
pub struct ScanRow {
    pub id: i64,
    pub target: String,
    pub created_at: String,
    pub score: i32,
    pub ports: i32,
    pub findings: i32,
    pub duration: f64,
}

/// Statistiques d'un module Rust du scanner (registry ou DB).
#[derive(Debug, Clone, Serialize)]
pub struct ModuleStat {
    /// nom du fichier module, ex. "dns_hardening"
    pub key: String,
    /// libellé lisible FR
    pub label: String,
    /// groupe fonctionnel : réseau, web, détection, surface, preuve
    pub group: String,
    /// outil externe sous-jacent ou "interne"
    pub tool: String,
    /// description courte en français simple (mode noob)
    pub blurb: String,
    /// nombre d'éléments trouvés sur le scan affiché
    pub count: i64,
    /// sévérité maximale constatée dans ce module ce scan-ci
    pub severity_max: Option<String>,
    /// 0 = aucune donnée, 1 = partiel, 2 = complet
    pub coverage: u8,
    /// graphique miniature (points) propre au module, ex. [3,1,4,1,5]
    pub spark: Vec<f64>,
}

/// Un constat de sécurité (audit_findings).
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: String,
    pub category: String,
    pub title: String,
    pub recommendation: String,
}

/// Statistiques agrégées d'un outil externe (audit_tool_outputs).
#[derive(Debug, Clone, Serialize)]
pub struct ToolStat {
    pub name: String,
    pub status: String,
    pub runs: i64,
    pub items: i64,
    pub avg_secs: f64,
}

/// Un verdict de preuve d'impact (audit_impact).
#[derive(Debug, Clone, Serialize)]
pub struct ImpactVerdict {
    pub module: String,
    pub verdict: String,
    pub detail: String,
    pub evidence: String,
    pub created_at: String,
}

/// Élément de graphe : une barre horizontale, un point d'une donut, etc.
#[derive(Debug, Clone, Serialize)]
pub struct Bucket {
    pub label: String,
    pub value: f64,
    /// classe CSS de couleur : crit / high / med / low / info / ok / mute
    pub tone: String,
}

/// Série temporelle (scores dans le temps, scans par jour...).
#[derive(Debug, Clone, Serialize)]
pub struct Series {
    pub labels: Vec<String>,
    pub values: Vec<f64>,
}

/// Port ouvert du scan affiché.
#[derive(Debug, Clone, Serialize)]
pub struct PortRow {
    pub port: i32,
    pub service: String,
    pub state: String,
    pub banner: String,
}

/// Sous-domaine / point de surface.
#[derive(Debug, Clone, Serialize)]
pub struct HostRow {
    pub host: String,
    pub status: Option<i32>,
    pub ip: String,
    pub title: String,
    pub tech: String,
    pub server: String,
    pub alive: bool,
}

/// En-tête HTTP avec son évaluation.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderRow {
    pub name: String,
    pub value: String,
    pub evaluation: String,
}

/// Enregistrement DNS.
#[derive(Debug, Clone, Serialize)]
pub struct DnsRow {
    pub rtype: String,
    pub value: String,
    pub secure: bool,
}

/// Certificat TLS.
#[derive(Debug, Clone, Serialize)]
pub struct TlsRow {
    pub protocol: String,
    pub cipher: String,
    pub issuer: String,
    pub days_remaining: Option<i32>,
    pub valid: bool,
    pub tls10: bool,
    pub tls11: bool,
    pub tls12: bool,
    pub tls13: bool,
}

/// Piste de loot.
#[derive(Debug, Clone, Serialize)]
pub struct LootRow {
    pub url: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub content_type: String,
    pub status: i32,
    pub severity: String,
    pub local_path: String,
}

/// Métriques machine hôte (Kali).
#[derive(Debug, Clone, Serialize)]
pub struct Machine {
    pub host: String,
    pub os: String,
    pub cores: usize,
    pub cpu_pct: f64,
    pub load: Vec<f64>,
    pub ram_total_mb: u64,
    pub ram_used_mb: u64,
    pub swap_used_mb: u64,
    pub disk_used_pct: f64,
    pub disk_total_gb: f64,
    pub disk_free_gb: f64,
    pub uptime_s: u64,
    pub net_rx_mb: f64,
    pub net_tx_mb: f64,
    pub services: Vec<ServiceState>,
    pub scanner_running: bool,
    pub active_scans: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceState {
    pub name: String,
    pub state: String,
    pub since: String,
}

/// Un scan lancé depuis l'interface.
#[derive(Debug, Clone, Serialize)]
pub struct LiveScan {
    pub pid: u32,
    pub target: String,
    pub profile: String,
    pub started_at: String,
    pub elapsed_s: u64,
    pub state: String,
    pub last_line: String,
    pub log_path: String,
}

/// Top-level payload de /api/overview.
#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub generated_at: String,
    pub db_name: String,
    pub current_scan: i64,
    pub target: String,
    pub scan_date: String,
    pub score: i32,
    pub kpis: Kpis,
    pub modules: Vec<ModuleStat>,
    pub severity: Vec<Bucket>,
    pub categories: Vec<Bucket>,
    pub dns_types: Vec<Bucket>,
    pub header_eval: Vec<Bucket>,
    pub tools: Vec<ToolStat>,
    pub impacts: Vec<ImpactVerdict>,
    pub findings: Vec<Finding>,
    pub scans: Vec<ScanRow>,
    pub ports: Vec<PortRow>,
    pub hosts: Vec<HostRow>,
    pub headers: Vec<HeaderRow>,
    pub dns: Vec<DnsRow>,
    pub tls: Vec<TlsRow>,
    pub loot: Vec<LootRow>,
    pub score_series: Series,
    pub findings_series: Series,
    pub port_histogram: Vec<Bucket>,
    pub live: Vec<LiveScan>,
    pub machine: Machine,
}

#[derive(Debug, Clone, Serialize)]
pub struct Kpis {
    pub scans: i64,
    pub targets: i64,
    pub findings: i64,
    pub findings_purged: i64,
    pub modules_total: usize,
    pub modules_active: usize,
    pub crit: i64,
    pub high: i64,
    pub ports: i64,
    pub hosts: i64,
    pub loot: i64,
    pub db_size_mb: f64,
    /// Message d'erreur si le catalogue n'a pas pu être lu (bandeau rouge),
    /// chaîne vide quand tout s'est bien passé.
    pub error: String,
}
