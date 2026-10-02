// src/bin/dashboard.rs — Point d'entrée du tableau de bord mcp_intruder.
//
// Sert une interface web locale sur 127.0.0.1 :0 (port libre) ou --port N.
// Lecture seule sur le catalogue PostgreSQL ; le seul effet de bord possible
// est le lancement d'un scan depuis l'interface (POST /api/scan/start).
//
// Usage : mcp-intruder-dashboard [--port 8099] [--db mcp_intruder_audit]

use mcp_intruder::dash::server::Server;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut port: u16 = 0;
    let mut db = "mcp_intruder_audit".to_string();

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--port" | "-p" => {
                port = argv.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(8099);
                i += 1;
            }
            "--db" => {
                if let Some(v) = argv.get(i + 1) {
                    db = v.clone();
                }
                i += 1;
            }
            "--help" | "-h" => {
                println!("mcp-intruder-dashboard [--port 8099] [--db mcp_intruder_audit]");
                println!("  l'interface s'ouvre sur http://127.0.0.1:<port>");
                println!("  Ctrl+K dans la page ouvre la palette de commandes");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    // Port 0 = le système choisit un port libre : plusieurs dashboards peuvent
    // coexister sans se marcher dessus (utile en labo avec d'autres services).
    if port == 0 {
        port = 8099;
    }

    let srv = Server {
        db_name: db,
        port,
    };

    // Le panic hook restaure le curseur et ne pollue pas stdout : ici le
    // serveur est silencieux, tout va dans le journal.
    if let Err(e) = srv.serve() {
        eprintln!("[dashboard] serveur arrêté : {e}");
        std::process::exit(1);
    }
}
