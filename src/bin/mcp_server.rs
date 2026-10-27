// src/bin/mcp_server.rs — Binaire serveur MCP de MCP Intruder.
//
// Construit le serveur MCP complet (`mcp_intruder::mcp::build_server_with_db`)
// et le sert en Streamable HTTP (crate litemcp) : POST /mcp pour chaque
// message JSON-RPC, GET /health comme sonde de vie. Bind par defaut en
// loopback : le client MCP est local ou passe par un tunnel.
//
// Les logs (demarrage + observabilite par message) sortent sur STDERR —
// stdout n'est jamais utilise par le serveur.

use clap::Parser;

/// Arguments du binaire serveur MCP.
#[derive(Parser, Debug)]
#[command(
    name = "mcp_server",
    version,
    about = "MCP Intruder — serveur Model Context Protocol (Streamable HTTP, litemcp) : \
             expose le moteur de scan de surface comme outils MCP"
)]
struct ServerArgs {
    /// Adresse TCP d'écoute (route MCP /mcp + sonde de vie /health)
    #[arg(long, default_value = "127.0.0.1:7808")]
    bind: String,

    /// Nom de la base PostgreSQL (scan_target / scan_history)
    #[arg(long, default_value = "mcp_intruder_audit")]
    db: String,
}

fn main() -> std::io::Result<()> {
    let args = ServerArgs::parse();

    eprintln!(
        "[MCP] {} v{} — serveur Model Context Protocol (Streamable HTTP)",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("[MCP] URL MCP      : http://{}/mcp", args.bind);
    eprintln!("[MCP] Sonde de vie : http://{}/health", args.bind);
    eprintln!("[MCP] PostgreSQL   : base '{}'", args.db);

    mcp_intruder::mcp::build_server_with_db(&args.db)
        .bind(&args.bind)?
        .serve()
}
