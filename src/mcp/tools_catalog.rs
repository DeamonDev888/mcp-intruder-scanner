// src/mcp/tools_catalog.rs — Diagnostic d'environnement du serveur MCP.
//
// `tools_diag` reprend le contrat de la sous-commande `tools` du CLI
// (src/config.rs::print_tools_status) mais en version self-contained :
// presence de chaque binaire Kali via `which`, puis version courte via
// `--version`. Aucune sortie sur stdout, aucun `sh -c` : uniquement
// `Command::new(binaire).arg(...)` — le nom de l'outil est une constante
// compilee, jamais une entree operateur.

use litemcp::prelude::*;
use serde_json::{json, Map, Value};

/// Binaires diagnostiques : outils Kali utilises par les modules du moteur
/// + `pg_isready` (joignabilite PostgreSQL) + `sha256sum` (calcul d'empreintes).
const DIAG_TOOLS: &[&str] = &[
    "nmap",
    "rustscan",
    "ffuf",
    "nuclei",
    "nikto",
    "sqlmap",
    "sslscan",
    "dnsrecon",
    "theHarvester",
    "whatweb",
    "httpx",
    "dig",
    "curl",
    "sha256sum",
    "pg_isready",
];

/// Longueur max de la ligne de version remontee (evite les bannieres
/// multi-lignes de certains outils).
const VERSION_MAX_CHARS: usize = 80;

/// Enregistre `tools_diag` sur le builder.
pub(super) fn register(builder: ServerBuilder) -> ServerBuilder {
    builder
        .tool(
            "tools_diag",
            "Diagnostic de l'environnement du serveur : présence et version courte de chaque \
             binaire requis par les modules (nmap, rustscan, ffuf, nuclei, nikto, sqlmap, \
             sslscan, dnsrecon, theHarvester, whatweb, httpx, dig, curl, sha256sum) et \
             pg_isready pour PostgreSQL. Aucun scan, aucune requête réseau.",
            |_args: &Value| Ok(diag_environment()),
        )
        .annotate(
            "tools_diag",
            ToolAnnotations::new()
                .title("Diagnostic de l'environnement")
                .read_only(true)
                .idempotent(true),
        )
}

/// Exécute le diagnostic complet : présence + version courte de chaque
/// binaire du catalogue. `pub(super)` pour la réutilisation par le registre
/// de jobs (`jobs.rs`, job `kind=diag`) — même logique que l'outil
/// `tools_diag`, un seul point de vérité.
pub(super) fn diag_environment() -> Value {
    let mut outils = Map::new();
    for name in DIAG_TOOLS {
        outils.insert((*name).to_string(), probe_tool(name));
    }
    Value::Object(outils)
}

/// Sonde UN binaire : présent sur le PATH ? quelle version courte ?
/// Aucun panic possible : chaque `Command::output()` en échec (binaire
/// introuvable, OSError plateforme) devient un "absent".
fn probe_tool(name: &str) -> Value {
    let present = std::process::Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false);

    if !present {
        return json!({ "present": false, "version": Value::Null });
    }

    // Version : meilleur effort. Certains outils parlent sur stderr
    // (ffuf sans `--version` exact, nikto...), on prend la premiere ligne
    // non vide stdout OU stderr.
    let version = std::process::Command::new(name)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            stdout
                .lines()
                .chain(stderr.lines())
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(shorten)
        });

    json!({ "present": true, "version": version })
}

/// Tronque une ligne de version en caracteres (pas en octets).
fn shorten(line: &str) -> String {
    line.chars().take(VERSION_MAX_CHARS).collect()
}
