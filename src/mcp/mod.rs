// src/mcp/mod.rs — Serveur Model Context Protocol de MCP Intruder.
//
// Expose le moteur de scan comme outils MCP (Streamable HTTP, crate
// `litemcp`). Point d'entree unique : `build_server()` retourne le
// ServerBuilder complet (tous les outils enregistres, annotees, observabilite)
// ; le binaire `src/bin/mcp_server.rs` se charge des arguments CLI, du bind
// et de `serve()`.
//
// Contraintes de securite heritees du crate :
// - bind par defaut 127.0.0.1 (le client MCP est local ou via tunnel) ;
// - les outils sont lecture-seule sur la cible (HTTP GET / DNS) ;
// - les secrets du catalogue ne sortent jamais en clair (mask_secret).

use litemcp::prelude::*;

/// Construit le serveur MCP complet : tous les outils du moteur de scan
/// enregistres avec leurs schemas zod et leurs annotations. Le binaire
/// appelle ensuite `.bind(addr)?.serve()`.
///
/// Separee du bind pour rester testable : `ServerCore::dispatch()` permet de
/// valider initialize/tools/list/tools/call en memoire, sans socket.
pub fn build_server() -> ServerBuilder {
    ServerBuilder::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
        .tool(
            "ping",
            "Sonde de disponibilité du serveur MCP Intruder (aucun scan)",
            |_args: &serde_json::Value| {
                Ok(serde_json::json!({
                    "pong": true,
                    "server": env!("CARGO_PKG_NAME"),
                    "version": env!("CARGO_PKG_VERSION"),
                }))
            },
        )
        .annotate(
            "ping",
            ToolAnnotations::new()
                .title("Ping")
                .read_only(true)
                .idempotent(true),
        )
        .on_call(|event| {
            eprintln!(
                "[MCP] {} {} -> {:?} ({:?})",
                event.method,
                event.name.unwrap_or("-"),
                event.status,
                event.duration
            );
        })
}
