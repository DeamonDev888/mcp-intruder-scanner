// src/mcp/tools_scan.rs — Outils MCP de scan orchestre et d'historique.
//
// `scan_target` reproduit exactement le chemin de main.rs : config de
// profil -> resolution de la cible -> AuditOrchestrator::run -> persistance
// PostgreSQL. `scan_history` lit le catalogue PostgreSQL.

use litemcp::prelude::*;
use serde_json::json;

use super::{guarded, resolve_first_ip, ToolResult};
use crate::config::{Config, ToolFlags};
use crate::modules::db::DatabaseManager;
use crate::modules::findings::SecurityFinding;
use crate::orchestrator::AuditOrchestrator;

/// Enregistre `scan_target` et `scan_history` sur le builder.
pub(super) fn register(builder: ServerBuilder, db: &str) -> ServerBuilder {
    let db_scan = db.to_string();
    let db_hist = db.to_string();

    let builder = builder
        .tool_parse(
            "scan_target",
            "Scan de surface complet orchestre sur une cible (domaine ou IP) : ports, DNS, TLS, \
             HTTP, sous-domaines, géoIP, messagerie + outils Kali selon le profil. Appel LONG \
             (de ~2 s en `fast` à plusieurs minutes en `full`) — le timeout serveur de 1800 s \
             couvre les profils lourds. Catégorisé en PostgreSQL sauf `no_db`.",
            zod::object()
                .field("target", zod::string().min(1).max(253))
                .opt(
                    "profile",
                    zod::enumeration(&["fast", "web", "discovery", "infra", "vuln", "full"])
                        .default("fast"),
                )
                .opt("no_db", zod::boolean().default(false))
                .strict(),
            move |args: ScanTargetArgs| -> ToolResult {
                let config = profile_config(&args.target, &args.profile, args.no_db, &db_scan)?;
                let first_ip = resolve_first_ip(&args.target)?;
                // Scan complet : l'orchestrateur protege deja chaque module
                // (run_guarded), la garde ci-dessus couvre le reste.
                let report = guarded("scan_target", || {
                    Ok(AuditOrchestrator::run(&config, &first_ip))
                })?;

                // Persistance : meme contrat que main.rs — un echec DB
                // n'invalide PAS le scan (avertissement sur stderr).
                let mut scan_id = None;
                if !args.no_db {
                    match DatabaseManager::save_scan(&report, &config.db_name) {
                        Ok(id) => scan_id = Some(id),
                        Err(e) => {
                            eprintln!("[MCP] scan_target : échec du catalogage PostgreSQL : {e}")
                        }
                    }
                }

                let findings: Vec<serde_json::Value> = report
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
                    "profile": args.profile,
                    "overall_score": report.overall_score,
                    "counts": severity_counts(&report.findings),
                    "findings": findings,
                    "scan_id": scan_id,
                    "duration_seconds": report.duration_seconds,
                    "recommandations": recommandations,
                }))
            },
        )
        .annotate(
            "scan_target",
            ToolAnnotations::new()
                .title("Scan de surface complet")
                .read_only(false)
                .destructive(false)
                .open_world(true),
        );

    builder
        .tool_parse(
            "scan_history",
            "Historique des scans catalogués en PostgreSQL : score, durée, ports ouverts et \
             nombre de constats par exécution. `target` vide = toutes cibles.",
            zod::object()
                .opt("target", zod::string().max(253).default(""))
                .opt("limit", zod::integer().min(1).max(500).default(25))
                .strict(),
            move |args: HistoryArgs| -> ToolResult {
                // Emprunt (pas de move) : la closure externe est `Fn` et
                // `db_hist` lui appartient — `guarded` exécute la closure
                // interne de façon synchrone, l'emprunt ne sort jamais.
                guarded("scan_history", || {
                    match DatabaseManager::get_history(&args.target, args.limit, &db_hist) {
                        Ok(entries) => Ok(json!({
                            "count": entries.len(),
                            "scans": entries
                                .iter()
                                .map(|e| {
                                    json!({
                                        "id": e.id,
                                        "target": e.target,
                                        "created_at": e.created_at,
                                        "overall_score": e.overall_score,
                                        "duration_seconds": e.duration_seconds,
                                        "open_ports_count": e.open_ports_count,
                                        "findings_count": e.findings_count,
                                    })
                                })
                                .collect::<Vec<_>>(),
                        })),
                        Err(e) => Err(format!(
                            "scan_history : PostgreSQL injoignable ou base absente ({e})"
                        )
                        .into()),
                    }
                })
            },
        )
        .annotate(
            "scan_history",
            ToolAnnotations::new()
                .title("Historique des scans")
                .read_only(true)
                .idempotent(true),
        )
}

// ==============================================================================
// ARGUMENTS ET CONSTRUCTION DE CONFIG
// ==============================================================================

#[derive(serde::Deserialize)]
struct ScanTargetArgs {
    target: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    no_db: bool,
}

#[derive(serde::Deserialize)]
struct HistoryArgs {
    #[serde(default)]
    target: String,
    #[serde(default)]
    limit: usize,
}

/// Construit la `Config` moteur pour le profil demande.
///
/// NOTE D'API : la correspondance profil -> `ToolFlags` est faite A LA MAIN
/// ici (meme mapping que `Config::parse` dans src/config.rs) parce que la
/// construction programmatique via `Config::try_parse_from` est impossible :
/// le type clap `Cli` est PRIVE dans config.rs et `Config` n'derive pas
/// `Parser`. Tous les champs de `Config`/`ToolFlags` sont `pub` : la
/// construction directe est stable au sein du meme crate.
///
/// `json_mode = true` : stdout est reserve au serveur, le moniteur
/// interactif de progression ne doit pas s'afficher.
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

/// Comptage des constats par sévérité — les cinq niveaux du moteur
/// (CRITICAL, HIGH, MEDIUM, LOW, INFO) sont toujours présents, à zéro
/// s'il n'y a rien à signaler.
fn severity_counts(findings: &[SecurityFinding]) -> serde_json::Value {
    let mut counts = serde_json::Map::new();
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        let n = findings.iter().filter(|f| f.severity == severity).count();
        counts.insert(severity.to_string(), json!(n));
    }
    serde_json::Value::Object(counts)
}
