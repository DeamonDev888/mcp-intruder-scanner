// src/bin/wizard.rs — Point d'entree de l'assistant de configuration.
//
// Deux modes :
//   - GUI web (par defaut) : sert une page unique sur 127.0.0.1 et ouvre le
//     navigateur si possible. Utilisable sur macOS, Windows et Linux avec
//     bureau.
//   - headless (--headless) : tout se passe dans le terminal, sans navigateur.
//     C'est le mode prevu pour un serveur Linux sans interface.
//
// Usage :
//   mcp-intruder-wizard [--port 8098] [--headless] [--status] [--no-browser]

use mcp_intruder::wizard::{api, headless, server::Server, DEFAULT_PORT};

/// Ouvre l'URL dans le navigateur par defaut de l'OS.
///
/// Le binaire est lance sans shell et avec un argument : aucune chaine de
/// commande n'est interpretee. Si l'ouverture echoue (serveur headless), ce
/// n'est pas une erreur : l'URL est affichee au terminal.
fn open_browser(url: &str) {
    let candidates: &[(&str, &[&str])] =
        &[("xdg-open", &[url]), ("open", &[url]), ("wslview", &[url])];
    for (bin, args) in candidates {
        if mcp_intruder::platform::which(bin).is_some() {
            let _ = std::process::Command::new(bin).args(*args).spawn();
            return;
        }
    }
    // Windows : le binaire est dans PATH par defaut.
    if cfg!(windows) {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn();
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut port: u16 = DEFAULT_PORT;
    let mut headless_mode = false;
    let mut no_browser = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--port" | "-p" => {
                port = argv
                    .get(i + 1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(DEFAULT_PORT);
                i += 1;
            }
            "--headless" => {
                headless_mode = true;
            }
            "--no-browser" => {
                no_browser = true;
            }
            "--status" | "-s" => {
                // Mode sans serveur : diagnostic sur stdout, pour scripting.
                let d = api::diagnose();
                println!("{}", d.headline);
                println!("systeme    : {} {}", d.os_label, d.distro);
                println!(
                    "kali natif : {}",
                    if d.is_native_kali { "oui" } else { "non" }
                );
                println!(
                    "runtime    : {}",
                    if d.container_runtime.is_empty() {
                        "absent"
                    } else {
                        &d.container_runtime
                    }
                );
                println!(
                    "image      : {}",
                    if d.kali_image_present {
                        "presente"
                    } else {
                        "absente"
                    }
                );
                println!(
                    "outillage  : {}",
                    if d.tools_ready {
                        "operationnel"
                    } else {
                        "incomplet"
                    }
                );
                for s in &d.steps {
                    println!("  [{}] {} — {}", s.state, s.title, s.detail);
                }
                std::process::exit(if d.tools_ready { 0 } else { 1 });
            }
            "--help" | "-h" => {
                println!("MCP Intruder — assistant de configuration");
                println!();
                println!("usage: mcp-intruder-wizard [--port 8098] [--headless] [--status]");
                println!();
                println!("  --port, -p     port d'ecoute (defaut 8098, 0 = port libre)");
                println!("  --headless     mode terminal, sans navigateur (serveur Linux)");
                println!("  --status, -s   diagnostic sur stdout, sans serveur");
                println!("  --no-browser   n'ouvre pas le navigateur automatiquement");
                println!("  --help, -h     cette aide");
                println!();
                println!("Mode graphique : page unique sur http://127.0.0.1:<port>");
                println!("Mode headless  : diagnostic et installation dans le terminal.");
                println!();
                println!("L'assistant installe le runtime de conteneur (Docker/Podman)");
                println!("puis l'image Kali officielle kalilinux/kali-rolling:latest.");
                println!("Sur un Kali natif, aucune installation n'est proposee.");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    // Mode headless : tout se passe dans le terminal.
    if headless_mode {
        std::process::exit(headless::run());
    }

    // Mode graphique : diagnostic immediat puis serveur web.
    let d = api::diagnose();
    println!("[wizard] {}", d.headline);

    let server = Server { port };
    let url = format!("http://127.0.0.1:{port}");
    if !no_browser {
        open_browser(&url);
    }
    println!("[wizard] assistant disponible sur {url}");
    println!("[wizard] ouvrez cette URL dans votre navigateur pour configurer l'outillage Kali");

    if let Err(e) = server.serve() {
        eprintln!("[wizard] serveur impossible : {e}");
        std::process::exit(1);
    }
}
