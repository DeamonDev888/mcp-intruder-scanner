// src/wizard/native.rs — Assistant natif, dans le terminal.
//
// Le wizard est un programme de console : aucun serveur HTTP, aucune page
// web, aucun navigateur. Il affiche le diagnostic, propose les actions
// disponibles et les execute apres un choix explicite.
//
// Deux modes :
//   - interactif (defaut quand l'entree standard est un terminal) : menu ;
//   - rapport (--headless, ou entree redirigee) : diagnostic et commandes
//     exactes a executer, sans interaction. C'est le mode utilise en CI et
//     sur un serveur sans terminal.

use crate::wizard::api::{self, Diagnostic};
use std::io::{BufRead, IsTerminal, Write};

/// Largeur du cadre (colonnes).
const WIDTH: usize = 74;

/// Nombre de lignes de sortie affichees apres une action (le reste est
/// resume : winget et apt-get peuvent produire des centaines de lignes).
const MAX_OUTPUT_LINES: usize = 30;

fn rule() -> String {
    "=".repeat(WIDTH)
}

fn banner() {
    println!("{}", rule());
    println!("  MCP Intruder - assistant de configuration");
    println!("  {}", rule());
    println!();
}

/// Marqueur court d'une etape, aligne sur les quatre colonnes.
fn state_tag(state: &str) -> &'static str {
    match state {
        "done" => "[OK]",
        "warn" => "[!!]",
        "ko" => "[KO]",
        _ => "[--]",
    }
}

/// Affiche le diagnostic complet de la plateforme et des etapes.
fn show_diagnostic(d: &Diagnostic) {
    println!("Plateforme : {}", d.os_label);
    if !d.distro.is_empty() {
        println!("Distribution : {}", d.distro);
    }
    println!(
        "Kali natif : {}",
        if d.is_native_kali { "oui" } else { "non" }
    );
    if d.container_runtime.is_empty() {
        println!("Runtime    : absent");
    } else {
        println!(
            "Runtime    : {} ({})",
            d.container_runtime, d.container_version
        );
        println!(
            "Demon      : {}",
            if d.container_daemon_ready {
                "actif"
            } else {
                "arrete"
            }
        );
    }
    println!(
        "Image Kali : {}",
        if d.kali_image_present {
            "presente"
        } else {
            "absente"
        }
    );
    println!(
        "Outillage  : {}",
        if d.tools_ready {
            "operationnel"
        } else {
            "incomplet"
        }
    );
    println!();
    println!("Etapes :");
    for s in &d.steps {
        println!("  {} {}", state_tag(s.state), s.title);
        println!("       {}", s.detail);
    }
    println!();
}

/// Une entree du menu, avec la commande exacte qui sera lancee.
struct Choice {
    key: &'static str,
    label: &'static str,
    hint: String,
}

/// Menu adapte a l'etat courant : on ne propose que ce qui est utile.
fn choices(d: &Diagnostic) -> Vec<Choice> {
    let mut out = Vec::new();
    if !d.is_native_kali {
        if d.container_runtime.is_empty() {
            out.push(Choice {
                key: "i",
                label: "Installer le runtime de conteneur",
                hint: d.runtime_install.command.clone(),
            });
        } else if !d.container_daemon_ready {
            out.push(Choice {
                key: "i",
                label: "Verifier le runtime (demon arrete)",
                hint: d.daemon_start_hint.clone(),
            });
        }
        if !d.kali_image_present && !d.container_runtime.is_empty() && d.container_daemon_ready {
            out.push(Choice {
                key: "p",
                label: "Telecharger l'image Kali",
                hint: d.image_pull.command.clone(),
            });
        }
    }
    out.push(Choice {
        key: "v",
        label: "Verifier l'outillage",
        hint: "nmap, nuclei, nikto, wafw00f, whatweb, sslscan, ffuf, dnsrecon...".to_string(),
    });
    out.push(Choice {
        key: "r",
        label: "Rafraichir le diagnostic",
        hint: String::new(),
    });
    out.push(Choice {
        key: "q",
        label: "Quitter",
        hint: String::new(),
    });
    out
}

/// Affiche la sortie d'une commande, bornee en lignes.
fn print_output(out: &str) {
    let lines: Vec<&str> = out.lines().collect();
    for line in lines.iter().take(MAX_OUTPUT_LINES) {
        println!("     {line}");
    }
    if lines.len() > MAX_OUTPUT_LINES {
        println!(
            "     ... ({} lignes omises)",
            lines.len() - MAX_OUTPUT_LINES
        );
    }
}

/// Rend compte du resultat d'une action.
fn report(r: api::ActionResult) {
    println!();
    println!("{} {}", if r.ok { "[OK]" } else { "[KO]" }, r.message);
    if !r.output.is_empty() {
        print_output(&r.output);
    }
}

/// Invite l'utilisateur ; `None` si l'entree est fermee (EOF).
fn ask(prompt: &str) -> Option<String> {
    print!("{prompt} > ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line.trim().to_lowercase()),
        Err(_) => None,
    }
}

/// Attend Entree (utile quand le binaire est lance par double-clic).
fn wait_enter() {
    print!("Appuyez sur Entree pour fermer...");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

/// Rappelle les commandes a lancer une fois l'outillage pret.
fn print_next_steps(d: &Diagnostic) {
    println!("Configuration terminee : l'outillage est operationnel.");
    println!();
    println!("  mcp_intruder <cible> --fast --json   # un scan");
    println!("  mcp_intruder tools                   # etat de l'outillage");
    if d.is_native_kali || d.container_runtime.is_empty() {
        println!("  mcp_intruder_server --bind 127.0.0.1:7808");
    } else {
        println!("  docker run -p 7808:7808 mcp-intruder/server");
    }
    println!();
    println!("Puis declarez http://127.0.0.1:7808/mcp dans votre client MCP.");
}

/// Assistant interactif : menu, actions, rafraichissement.
///
/// Retourne 0 si l'outillage est operationnel a la sortie, 1 sinon.
pub fn run_interactive(pause: bool) -> i32 {
    banner();
    let code = loop {
        let d = api::diagnose();
        show_diagnostic(&d);

        // Plus rien a faire : on termine sur les commandes utiles.
        if d.tools_ready {
            print_next_steps(&d);
            break 0;
        }

        let items = choices(&d);
        println!("Actions :");
        for item in &items {
            if item.hint.is_empty() {
                println!("  {}) {}", item.key, item.label);
            } else {
                println!("  {}) {}", item.key, item.label);
                println!("      {}", item.hint);
            }
        }
        println!();

        let Some(choice) = ask("Choix (lettre + Entree)") else {
            break 1;
        };
        match choice.as_str() {
            "q" | "quitter" => break 1,
            "r" | "" => {}
            "i" => report(api::install_runtime()),
            "p" => report(api::pull_image()),
            "v" => report(api::verify()),
            other => println!("Choix inconnu : {other}"),
        }
        println!();
    };

    if code == 1 {
        println!();
        println!(
            "Configuration incomplete : levez l'etape bloquante ci-dessus, puis relancez `wizard`."
        );
    }

    if pause && std::io::stdin().is_terminal() {
        wait_enter();
    }
    code
}

/// Mode rapport : diagnostic puis commandes exactes, sans interaction.
///
/// Retourne 0 si l'outillage est operationnel, 1 sinon.
pub fn run_report() -> i32 {
    banner();
    let d = api::diagnose();
    show_diagnostic(&d);

    if d.tools_ready {
        print_next_steps(&d);
        return 0;
    }

    println!("Etapes a executer :");
    if !d.is_native_kali {
        if d.container_runtime.is_empty() {
            println!("  - Installer le runtime de conteneur :");
            println!("      $ {}", d.runtime_install.command);
        } else if !d.container_daemon_ready {
            println!("  - Demarrer le runtime de conteneur :");
            println!("      $ {}", d.daemon_start_hint);
        }
        if !d.kali_image_present {
            println!("  - Telecharger l'image Kali :");
            println!("      $ {}", d.image_pull.command);
        }
    }
    println!();
    println!("Relancez `wizard` dans un terminal pour executer ces etapes.");
    1
}
