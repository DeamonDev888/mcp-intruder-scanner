// src/mcp/mod.rs — Serveur Model Context Protocol de MCP Intruder.
//
// Expose le moteur de scan comme outils MCP (Streamable HTTP, crate
// `litemcp`). Point d'entree unique : `build_server()` retourne le
// ServerBuilder complet (tous les outils enregistres, annotees, observabilite)
// ; le binaire `src/bin/mcp_server.rs` se charge des arguments CLI, du bind
// et de `serve()`.
//
// Inventaire des outils exposes (21) :
// - `ping`               — sonde de vie (ici, dans mod.rs) ;
// - `scan_target`        — scan complet orchestre (tools_scan.rs) ;
// - `scan_history`       — historique PostgreSQL (tools_scan.rs) ;
// - `tools_diag`         — diagnostic environnement Kali (tools_catalog.rs) ;
// - 12 audits rapides lecture-seule, un par module moteur appelable
//   directement sur une cible (tools_audit.rs) : dns_audit, tls_audit,
//   http_audit, whois_audit, geo_locate, email_sec_audit, subdomains_audit,
//   crt_sh_lookup, waf_detect, tech_stack_audit, dnsrecon_audit,
//   dns_hardening_audit ;
// - 5 outils du plan de controle jobs (jobs.rs) : job_start, job_status,
//   job_result, job_stop, job_list — registre de jobs asynchrones (threads
//   `std`, max 8 actifs, historique 100 finis, PAS de persistance : le
//   processus est la vie des jobs) pour piloter TOUTES les capacites du
//   moteur, y compris les executions longues : kind=scan (meme chemin que
//   scan_target), kind=module (un module moteur du catalogue ferme),
//   kind=bin (binaire d'impact de la liste blanche), kind=diag
//   (diagnostic environnement).
//
// Contraintes de securite heritees du crate :
// - bind par defaut 127.0.0.1 (le client MCP est local ou via tunnel) ;
// - les outils sont lecture-seule sur la cible (HTTP GET / DNS) ;
// - les secrets du catalogue ne sortent jamais en clair (mask_secret) ;
// - JAMAIS de panic : chaque appel moteur passe par `guarded()`, chaque
//   cible injoignable devient un `Err(...)` lisible par le client ;
// - aucun chemin d'execution ne passe par `sh -c`.

mod jobs;
mod tools_audit;
mod tools_catalog;
mod tools_scan;

use std::time::Duration;

use litemcp::prelude::*;
use serde::Serialize;

use crate::target_parser::{TargetParser, TargetVerdict};

/// Nom de la base PostgreSQL par defaut (meme valeur que le flag `--db`
/// du CLI et du binaire `mcp_server`).
pub const DEFAULT_DB_NAME: &str = "mcp_intruder_audit";

/// Troncature des champs `raw_output` geants des modules (sortie brute
/// d'outils Kali) : au-dela, la reponse MCP sature le client sans valeur
/// ajoutee. Le texte est coupe en CARACTERES (pas en octets) pour ne pas
/// sectionner un UTF-8 multi-octets.
pub(crate) const RAW_OUTPUT_MAX_CHARS: usize = 2000;

/// Timeout d'execution d'un handler MCP. Un `scan_target` profil `full`
/// dure plusieurs minutes (tous les outils Kali) : 30 min couvrent le pire
/// cas observe et laissent au serveur une sortie propre si un handler se
/// pend (le thread continue en arriere-plan, son resultat est ignore).
const TOOL_TIMEOUT: Duration = Duration::from_secs(1800);

/// Construit le serveur MCP complet sur la base PostgreSQL par defaut
/// ([`DEFAULT_DB_NAME`]). Voir [`build_server_with_db`].
pub fn build_server() -> ServerBuilder {
    build_server_with_db(DEFAULT_DB_NAME)
}

/// Construit le serveur MCP complet : tous les outils du moteur de scan
/// enregistres avec leurs schemas zod et leurs annotations, le hook
/// d'observabilite et le timeout d'execution. Le binaire appelle ensuite
/// `.bind(addr)?.serve()`.
///
/// `db_name` nomme la base PostgreSQL utilisee par `scan_target`
/// (persistance) et `scan_history` (lecture).
///
/// Separee du bind pour rester testable : `ServerCore::dispatch()` permet de
/// valider initialize/tools/list/tools/call en memoire, sans socket.
pub fn build_server_with_db(db_name: &str) -> ServerBuilder {
    let db = db_name.to_string();

    let builder = ServerBuilder::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")).tool(
        "ping",
        "Sonde de disponibilité du serveur MCP Intruder (aucun scan)",
        |_args: &serde_json::Value| {
            Ok(serde_json::json!({
                "pong": true,
                "server": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION"),
            }))
        },
    );
    let builder = builder.annotate(
        "ping",
        ToolAnnotations::new()
            .title("Ping")
            .read_only(true)
            .idempotent(true),
    );

    // Assemblage : chaque sous-module enregistre ses outils + annotations.
    let builder = tools_scan::register(builder, &db);
    let builder = tools_audit::register(builder);
    let builder = tools_catalog::register(builder);
    // Plan de controle jobs : soumission/observation/arrêt d'exécutions
    // longues en arrière-plan (kind=scan, module, bin, diag) — porte le
    // total du serveur à 21 outils.
    let builder = jobs::register(builder);

    builder
        .on_call(|event| {
            eprintln!(
                "[MCP] {} {} -> {:?} ({:?})",
                event.method,
                event.name.unwrap_or("-"),
                event.status,
                event.duration
            );
        })
        .tool_timeout(TOOL_TIMEOUT)
}

// ==============================================================================
// HELPERS PARTAGES — resolution de cible, garde anti-panic, troncature
// ==============================================================================

/// Résout une cible (domaine ou IP) et retourne la PREMIERE adresse IP,
/// meme contrat que main.rs (`TargetParser` -> premiere IP -> orchestrateur).
/// Toute cible invalide ou injoignable devient une erreur lisible par le
/// client MCP — jamais de panic.
pub(crate) fn resolve_first_ip(target: &str) -> Result<String, ToolError> {
    match TargetParser::resolve(target) {
        TargetVerdict::Resolved(ips) => ips
            .first()
            .map(std::string::ToString::to_string)
            .ok_or_else(|| {
                ToolError::invalid_input(format!("cible {target} : aucune adresse IP resolue"))
            }),
        TargetVerdict::InvalidFormat(reason) => Err(ToolError::invalid_input(format!(
            "cible : format invalide ({reason})"
        ))),
        TargetVerdict::Unresolvable(reason) => {
            Err(format!("cible injoignable : résolution DNS impossible ({reason})").into())
        }
    }
}

/// Garde anti-panic transversale : execute un appel moteur en capturant
/// toute panic. Le contrat « JAMAIS de panic » tient meme si un module
/// moteur (code tiers de ce crate, subprocess) panique sur une entree
/// surprenante : le client MCP recoit une erreur classee, le serveur vit.
pub(crate) fn guarded<F, T>(module: &str, f: F) -> Result<T, ToolError>
where
    F: FnOnce() -> Result<T, ToolError>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => Err(format!(
            "module {module} : cible injoignable ou outil absent (erreur interne)"
        )
        .into()),
    }
}

/// Sérialise un resultat de module moteur en `Value` JSON en tronquant le
/// champ `raw_output` (sortie brute d'outil Kali) a
/// [`RAW_OUTPUT_MAX_CHARS`] caracteres. Les struct sans `raw_output`
/// passent tels quels.
pub(crate) fn to_json_clipped<T: Serialize>(result: &T) -> serde_json::Value {
    let mut value = match serde_json::to_value(result) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "error": format!("échec de sérialisation du résultat : {e}")
            });
        }
    };
    if let Some(obj) = value.as_object_mut() {
        if let Some(raw) = obj
            .get_mut("raw_output")
            .as_deref()
            .and_then(serde_json::Value::as_str)
        {
            if raw.chars().count() > RAW_OUTPUT_MAX_CHARS {
                let clipped: String = raw.chars().take(RAW_OUTPUT_MAX_CHARS).collect();
                obj.insert(
                    "raw_output".to_string(),
                    serde_json::Value::String(format!(
                        "{clipped}\n… (sortie brute tronquée à {} caractères)",
                        RAW_OUTPUT_MAX_CHARS
                    )),
                );
            }
        }
    }
    value
}

// ==============================================================================
// TESTS — dispatch JSON-RPC en memoire, sans reseau ni PostgreSQL
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Requete JSON-RPC 2.0 minimaliste, meme forme que les tests de
    /// litemcp (server.rs / tests/smoke.rs).
    fn rpc(id: u64, method: &str, params: &str) -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#)
            .into_bytes()
    }

    #[test]
    fn initialize_exposes_server_info() {
        let core = build_server().core();
        let raw = core
            .dispatch(&rpc(1, "initialize", "{}"))
            .expect("initialize doit répondre");
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["result"]["serverInfo"]["name"], "mcp_intruder");
        assert_eq!(
            v["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn tools_list_contains_all_registered_tools() {
        let core = build_server().core();
        let raw = core
            .dispatch(&rpc(2, "tools/list", "{}"))
            .expect("tools/list doit répondre");
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let names: Vec<&str> = v["result"]["tools"]
            .as_array()
            .expect("result.tools doit être un tableau")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();

        const ATTENDUS: &[&str] = &[
            "ping",
            "scan_target",
            "scan_history",
            "tools_diag",
            "dns_audit",
            "tls_audit",
            "http_audit",
            "whois_audit",
            "geo_locate",
            "email_sec_audit",
            "subdomains_audit",
            "crt_sh_lookup",
            "waf_detect",
            "tech_stack_audit",
            "dnsrecon_audit",
            "dns_hardening_audit",
        ];
        for attendu in ATTENDUS {
            assert!(
                names.contains(attendu),
                "outil manquant dans tools/list : {attendu} (présents : {names:?})"
            );
        }
    }

    #[test]
    fn ping_call_succeeds_without_error() {
        let core = build_server().core();
        let raw = core
            .dispatch(&rpc(3, "tools/call", r#"{"name":"ping","arguments":{}}"#))
            .expect("tools/call ping doit répondre");
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert!(
            v.get("error").is_none(),
            "ping ne doit pas renvoyer d'erreur JSON-RPC : {v}"
        );
        assert_ne!(v["result"]["isError"], true, "ping doit réussir : {v}");
        assert_eq!(v["result"]["structuredContent"]["pong"], true);
    }

    #[test]
    fn out_of_schema_call_is_invalid_params() {
        let core = build_server().core();

        // Champ requis `target` vide (min 1) : refuse AVANT le handler,
        // donc sans aucun acces reseau ni base.
        let raw = core
            .dispatch(&rpc(
                4,
                "tools/call",
                r#"{"name":"scan_target","arguments":{"target":""}}"#,
            ))
            .expect("tools/call doit répondre");
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["error"]["code"], -32602, "réponse : {v}");

        // Champ inconnu sur objet strict : meme refus -32602.
        let raw = core
            .dispatch(&rpc(
                5,
                "tools/call",
                r#"{"name":"scan_history","arguments":{"limit_inconnu":1}}"#,
            ))
            .expect("tools/call doit répondre");
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["error"]["code"], -32602, "réponse : {v}");

        // Hors bornes : limit = 0 (< min 1).
        let raw = core
            .dispatch(&rpc(
                6,
                "tools/call",
                r#"{"name":"scan_history","arguments":{"limit":0}}"#,
            ))
            .expect("tools/call doit répondre");
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["error"]["code"], -32602, "réponse : {v}");
    }
}
