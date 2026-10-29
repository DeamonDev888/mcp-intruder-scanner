// src/wizard/headless.rs — Assistant en mode terminal (Linux sans navigateur).
//
// Sur un serveur Linux headless, une page web n'est pas exploitable : pas de
// navigateur, pas d'affichage. Ce mode fait la meme chose que l'assistant
// graphique, mais en ligne de commande :
//   - diagnostic detaille de la plateforme
//   - commande exacte a executer pour chaque etape bloquante
//   - execution possible des etapes non privilegiees (telechargement de
//     l'image), avec confirmation explicite de l'utilisateur
//
// L'etape d'installation du runtime resteure a l'utilisateur : elle exige
// des privileges administrateur et n'est jamais lancee en silence.

use crate::wizard::api;
use std::io::{BufRead, Write};

/// Caractere de fin de ligne adapte a la plateforme.
const NL: &str = if cfg!(windows) { "\r\n" } else { "\n" };

/// Bandeau d'en-tete.
fn banner() {
    println!("{}{}", "=".repeat(72), NL);
    println!("  MCP Intruder — assistant de configuration (mode headless)");
    println!("  {}{}", "=".repeat(72), NL);
}

/// Affiche le diagnostic complet.
fn show_diagnostic() {
    let d = api::diagnose();
    println!("{}Plateforme : {}", NL, d.os_label);
    if !d.distro.is_empty() {
        println!("Distribution : {}", d.distro);
    }
    println!(
        "Kali natif    : {}",
        if d.is_native_kali { "oui" } else { "non" }
    );
    println!(
        "Runtime       : {}",
        if d.container_runtime.is_empty() {
            "absent"
        } else {
            &d.container_runtime
        }
    );
    println!(
        "Image Kali    : {}",
        if d.kali_image_present {
            "presente"
        } else {
            "absente"
        }
    );
    println!(
        "Outillage     : {}",
        if d.tools_ready {
            "operationnel"
        } else {
            "incomplet"
        }
    );
    println!("{}Etapes :", NL);
    for s in &d.steps {
        println!("  [{}] {}", s.state.to_uppercase(), s.title);
        println!("         {}", s.detail);
    }
}

/// Invite l'utilisateur a confirmer (oui/non). Defaut : non.
fn confirm(prompt: &str) -> bool {
    print!("{}{} [oui/N] ", NL, prompt);
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) => false,
        Ok(_) => {
            let v = line.trim().to_lowercase();
            v == "o" || v == "oui" || v == "y" || v == "yes"
        }
        Err(_) => false,
    }
}

/// Execute l'assistant en mode terminal.
///
/// Retourne 0 si l'outillage est operationnel a la fin, 1 sinon.
pub fn run() -> i32 {
    banner();
    show_diagnostic();
    println!();

    let d = api::diagnose();

    // Sur un Kali natif, rien a installer : on verifie juste l'outillage.
    if d.is_native_kali {
        println!(
            "{}Kali Linux natif detecte : aucune installation requise.{}",
            NL, NL
        );
        let r = api::verify();
        println!("{}{}", NL, r.message);
        return if r.ok { 0 } else { 1 };
    }

    // Etape 1 : runtime de conteneur.
    if d.container_runtime.is_empty() {
        println!(
            "{}[1/2] Runtime de conteneur absent. Installez-le avec la commande suivante (privileges administrateur) :",
            NL
        );
        println!("{}  $ {}", NL, d.runtime_install.command);
        println!(
            "{}Une fois installe, relancez : mcp-intruder-wizard --headless{}",
            NL, NL
        );
        if confirm("Tenter l'installation maintenant ?") {
            let r = api::install_runtime();
            println!("{}{}", NL, r.message);
            if !r.output.is_empty() {
                println!("{}{}", NL, r.output);
            }
        }
    } else {
        println!(
            "{}[1/2] Runtime deja present : {}{}",
            NL, d.container_runtime, NL
        );
    }

    // Etape 2 : image Kali.
    let d2 = api::diagnose();
    if !d2.is_native_kali && !d2.kali_image_present {
        if d2.container_runtime.is_empty() {
            println!(
                "{}[2/2] Image Kali : impossible sans runtime de conteneur.{}",
                NL, NL
            );
            println!("{}  $ {}", NL, d2.image_pull.command);
            println!(
                "{}Commande a executer apres installation du runtime, puis relancez mcp-intruder-wizard --headless{}",
                NL, NL
            );
            return 1;
        }
        println!("{}[2/2] Telechargement de l'image Kali officielle...", NL);
        if confirm("Lancer le telechargement ?") {
            let r = api::pull_image();
            println!("{}{}", NL, r.message);
            if !r.output.is_empty() {
                println!("{}{}", NL, r.output);
            }
        } else {
            println!(
                "{}Telechargement ignore. Commande : {}{}",
                NL, d2.image_pull.command, NL
            );
        }
    }

    // Controle final.
    println!("{}Verification finale...", NL);
    let r = api::verify();
    println!("{}{}", NL, r.message);
    if !r.output.is_empty() {
        println!("{}Outils manquants :{}{}", NL, NL, r.output);
    }

    let final_d = api::diagnose();
    println!();
    if final_d.tools_ready {
        println!(
            "{}Configuration terminee. Vous pouvez lancer un scan :{}",
            NL, NL
        );
        println!("  $ mcp_intruder <cible> --fast --json");
        println!("  $ mcp_intruder tools          # etat de l'outillage");
        0
    } else {
        println!(
            "{}Configuration incomplete : consultez les etapes ci-dessus.{}",
            NL, NL
        );
        1
    }
}
