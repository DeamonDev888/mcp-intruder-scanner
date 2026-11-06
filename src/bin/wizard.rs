// src/bin/wizard.rs — Assistant de configuration natif (terminal).
//
// Aucune interface web : le wizard est un programme de console, identique
// sous Windows, macOS et Linux, y compris sur un serveur sans affichage.
//
//   - sans option, dans un terminal : assistant interactif (menu) ;
//   - --headless, ou entree standard redirigee : rapport + commandes exactes,
//     sans interaction (CI, script, conteneur) ;
//   - --status : diagnostic compact sur stdout, code de sortie 0/1.
//
// Usage :
//   wizard [--headless] [--pause] [--status] [--help] [--version]

use mcp_intruder::wizard::{api, native};
use std::io::IsTerminal;

fn main() {
    let mut report_only = false;
    let mut interactive = false;
    let mut pause = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--headless" | "--report" => report_only = true,
            "--interactive" | "-i" => interactive = true,
            "--pause" => pause = true,
            "--status" | "-s" => std::process::exit(status()),
            "--help" | "-h" => {
                help();
                return;
            }
            "--version" | "-V" => {
                println!("wizard {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            other => {
                eprintln!("option inconnue : {other}");
                eprintln!("wizard --help");
                std::process::exit(2);
            }
        }
    }

    // Sans terminal (CI, entree redirigee), l'interaction est impossible :
    // on bascule sur le rapport au lieu d'attendre une saisie qui n'arrivera
    // jamais. --interactive force le menu malgre tout (tests, terminal exotique).
    let code = if report_only || (!interactive && !std::io::stdin().is_terminal()) {
        native::run_report()
    } else {
        native::run_interactive(pause)
    };
    std::process::exit(code);
}

/// Diagnostic compact, destine aux scripts.
fn status() -> i32 {
    let d = api::diagnose();
    println!("{}", d.headline);
    println!("systeme    : {} {}", d.os_label, d.distro);
    println!(
        "kali natif : {}",
        if d.is_native_kali { "oui" } else { "non" }
    );
    if d.container_runtime.is_empty() {
        println!("runtime    : absent");
    } else {
        println!(
            "runtime    : {} ({})",
            d.container_runtime, d.container_version
        );
        println!(
            "demon      : {}",
            if d.container_daemon_ready {
                "actif"
            } else {
                "arrete"
            }
        );
    }
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
        println!("  [{}] {} - {}", s.state, s.title, s.detail);
    }
    if d.tools_ready {
        0
    } else {
        1
    }
}

fn help() {
    println!("MCP Intruder - assistant de configuration (terminal)");
    println!();
    println!("usage: wizard [options]");
    println!();
    println!("  (aucune option)  assistant interactif dans le terminal");
    println!("  --headless       rapport et commandes, sans interaction (CI, serveur)");
    println!("  --interactive    force le menu interactif meme sans terminal");
    println!("  --pause          attend Entree avant de fermer (lancement par double-clic)");
    println!("  --status, -s     diagnostic sur stdout, code de sortie 0/1");
    println!("  --help, -h       cette aide");
    println!("  --version, -V    version");
    println!();
    println!("L'assistant installe le runtime de conteneur (Docker/Podman) puis");
    println!("l'image Kali officielle kalilinux/kali-rolling:latest. Sur un Kali");
    println!("natif, aucune installation n'est proposee. Aucune commande n'est");
    println!("lancee sans votre choix.");
}
