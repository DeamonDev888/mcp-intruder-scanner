// src/wizard/api.rs — Logique de l'assistant : diagnostic et actions.
//
// Chaque action est declenchee par un POST explicite de l'interface.
// L'installation d'un runtime et le telechargement de l'image sont des
// operations qui modifient le systeme : elles renvoient la commande exacte
// et son resultat, jamais une execution silencieuse.

use crate::platform::{self, HostOs, Platform, KALI_IMAGE};
use serde::Serialize;

/// Une etape de l'assistant et son etat.
#[derive(Debug, Clone, Serialize)]
pub struct Step {
    /// Identifiant technique de l'etape.
    pub id: &'static str,
    /// Titre affiche.
    pub title: &'static str,
    /// Detail de l'etape.
    pub detail: String,
    /// Etat : "done" | "todo" | "warn" | "busy" | "ko".
    pub state: &'static str,
}

/// Commande proposee a l'utilisateur, avec le mode d'execution.
#[derive(Debug, Clone, Serialize)]
pub struct CommandHint {
    /// Commande a executer telle quelle.
    pub command: String,
    /// Comment l'executer (sudo, privileged, etc.).
    pub elevated: bool,
}

/// Diagnostic complet de la plateforme, vu par l'assistant.
#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub os: &'static str,
    pub os_label: String,
    pub distro: String,
    pub is_native_kali: bool,
    pub container_runtime: String,
    pub container_version: String,
    pub kali_image_present: bool,
    pub native_tools_present: bool,
    pub tools_ready: bool,
    pub summary: String,
    pub steps: Vec<Step>,
    pub runtime_install: CommandHint,
    pub image_pull: CommandHint,
    /// Message court affichable en banniere.
    pub headline: String,
}

/// Etat de l'assistant, recalcule a chaque appel.
pub fn diagnose() -> Diagnostic {
    let p = Platform::detect();
    diagnose_platform(&p)
}

/// Variante testable : diagnostic a partir d'une plateforme connue.
pub fn diagnose_platform(p: &Platform) -> Diagnostic {
    let tools_ready = p.is_native_kali || (p.kali_image_present && !p.container_runtime.is_empty());

    let mut steps = Vec::new();

    // Etape 1 : plateforme.
    steps.push(Step {
        id: "platform",
        title: "Plateforme detectee",
        detail: p.summary(),
        state: "done",
    });

    // Etape 2 : runtime de conteneur.
    let runtime_state = if !p.container_runtime.is_empty() || p.is_native_kali {
        "done"
    } else {
        "todo"
    };
    let runtime_detail = if !p.container_runtime.is_empty() {
        format!("{} — {}", p.container_runtime, p.container_version)
    } else if p.is_native_kali {
        "Inutile : l'outillage Kali est present nativement.".to_string()
    } else {
        format!(
            "Runtime absent. Commande : {}",
            platform::install_runtime_hint(p.os)
        )
    };
    steps.push(Step {
        id: "runtime",
        title: "Runtime de conteneur",
        detail: runtime_detail,
        state: runtime_state,
    });

    // Etape 3 : image Kali.
    let image_state = if p.kali_image_present || p.is_native_kali {
        "done"
    } else {
        "todo"
    };
    let image_detail = if p.kali_image_present {
        format!("Image presente : {KALI_IMAGE}")
    } else if p.is_native_kali {
        "Inutile : Kali natif, pas de conteneur requis.".to_string()
    } else {
        format!("Image a telecharger : {KALI_IMAGE}")
    };
    steps.push(Step {
        id: "image",
        title: "Image Kali Linux",
        detail: image_detail,
        state: image_state,
    });

    // Etape 4 : controle final.
    steps.push(Step {
        id: "verify",
        title: "Outillage operationnel",
        detail: if tools_ready {
            "Les modules de scan peuvent s'executer.".to_string()
        } else {
            "En attente de la resolution des etapes precedentes.".to_string()
        },
        state: if tools_ready { "done" } else { "todo" },
    });

    let headline = if p.is_native_kali {
        "Kali Linux natif — aucune installation requise.".to_string()
    } else if tools_ready {
        format!("{} operationnel via {}.", p.os, p.container_runtime)
    } else if p.container_runtime.is_empty() {
        format!(
            "{} : le runtime de conteneur est requis pour l'outillage Kali.",
            p.os
        )
    } else {
        format!("{} : l'image Kali doit etre telechargee.", p.os)
    };

    Diagnostic {
        os: p.os.id(),
        os_label: p.os.label().to_string(),
        distro: p.distro.clone(),
        is_native_kali: p.is_native_kali,
        container_runtime: p.container_runtime.clone(),
        container_version: p.container_version.clone(),
        kali_image_present: p.kali_image_present,
        native_tools_present: p.native_tools_present,
        tools_ready,
        summary: p.summary(),
        steps,
        runtime_install: CommandHint {
            command: platform::install_runtime_hint(p.os).to_string(),
            elevated: p.os != HostOs::Windows,
        },
        image_pull: CommandHint {
            command: platform::pull_image_hint(),
            elevated: false,
        },
        headline,
    }
}

/// Resultat d'une action declenchee depuis l'assistant.
#[derive(Debug, Clone, Serialize)]
pub struct ActionResult {
    pub ok: bool,
    pub message: String,
    /// Sortie brute de la commande, si applicable.
    pub output: String,
    /// Etapes mises a jour apres l'action.
    pub diagnostic: Diagnostic,
}

/// Installe le runtime de conteneur.
///
/// Sur Linux et macOS la commande exige les privileges root : elle est
/// lancee via `sudo -n` si possible, sinon l'utilisateur doit executer la
/// commande affichee dans l'interface (le runtime etant deja absent, aucune
/// elevation automatique n'est tentee en mode non interactif).
pub fn install_runtime() -> ActionResult {
    let p = Platform::detect();
    if p.is_native_kali {
        return ActionResult {
            ok: true,
            message: "Kali natif : installation inutile.".to_string(),
            output: String::new(),
            diagnostic: diagnose_platform(&p),
        };
    }
    if !p.container_runtime.is_empty() {
        return ActionResult {
            ok: true,
            message: format!("Runtime deja present : {}.", p.container_runtime),
            output: String::new(),
            diagnostic: diagnose_platform(&p),
        };
    }

    let (cmd, args): (&str, Vec<&str>) = match p.os {
        HostOs::Linux => (
            "sudo",
            vec![
                "-n",
                "apt-get",
                "update",
                "-qq",
                "&&",
                "sudo",
                "-n",
                "apt-get",
                "install",
                "-y",
                "docker.io",
            ],
        ),
        HostOs::MacOs => ("brew", vec!["install", "--cask", "docker"]),
        HostOs::Windows => (
            "winget",
            vec!["install", "--id", "Docker.DockerDesktop", "-e"],
        ),
        HostOs::Other => {
            return ActionResult {
                ok: false,
                message: "Systeme non reconnu : installez Docker ou Podman manuellement."
                    .to_string(),
                output: platform::install_runtime_hint(p.os).to_string(),
                diagnostic: diagnose_platform(&p),
            }
        }
    };

    // Sur Linux, la commande combinee avec `&&` passe par un shell : on la
    // decompose pour rester dans la regle "args() seulement, jamais sh -c".
    let output = if p.os == HostOs::Linux {
        let mut out =
            platform::run_capture("sudo", &["-n", "apt-get", "update", "-qq"]).unwrap_or_default();
        out.push('\n');
        out.push_str(
            &platform::run_capture("sudo", &["-n", "apt-get", "install", "-y", "docker.io"])
                .unwrap_or_default(),
        );
        out
    } else {
        platform::run_capture(cmd, &args).unwrap_or_default()
    };

    let after = Platform::detect();
    let ok = !after.container_runtime.is_empty();
    ActionResult {
        ok,
        message: if ok {
            format!("Runtime installe : {}.", after.container_runtime)
        } else {
            format!(
                "Installation non aboutie. Executez manuellement : {}",
                platform::install_runtime_hint(p.os)
            )
        },
        output,
        diagnostic: diagnose_platform(&after),
    }
}

/// Telecharge l'image Kali officielle.
pub fn pull_image() -> ActionResult {
    let p = Platform::detect();
    if p.is_native_kali {
        return ActionResult {
            ok: true,
            message: "Kali natif : aucune image a telecharger.".to_string(),
            output: String::new(),
            diagnostic: diagnose_platform(&p),
        };
    }
    if p.container_runtime.is_empty() {
        return ActionResult {
            ok: false,
            message: "Aucun runtime de conteneur : installez-le d'abord.".to_string(),
            output: String::new(),
            diagnostic: diagnose_platform(&p),
        };
    }
    if p.kali_image_present {
        return ActionResult {
            ok: true,
            message: format!("Image deja presente : {KALI_IMAGE}."),
            output: String::new(),
            diagnostic: diagnose_platform(&p),
        };
    }

    let rt = p.container_runtime.clone();
    let output = platform::run_capture(&rt, &["pull", KALI_IMAGE]).unwrap_or_default();
    let after = Platform::detect();
    ActionResult {
        ok: after.kali_image_present,
        message: if after.kali_image_present {
            format!("Image telechargee : {KALI_IMAGE}.")
        } else {
            format!(
                "Telechargement echoue. Relancez : {}.",
                platform::pull_image_hint()
            )
        },
        output,
        diagnostic: diagnose_platform(&after),
    }
}

/// Verifie que les outils Kali sont accessibles et liste ceux qui manquent.
pub fn verify() -> ActionResult {
    let p = Platform::detect();
    let missing: Vec<&str> = platform::TOOLS
        .iter()
        .copied()
        .filter(|t| platform::which(t).is_none())
        .collect();

    let ok = p.is_native_kali || (p.kali_image_present && !p.container_runtime.is_empty());
    let message = if ok {
        format!(
            "Outillage operationnel. {} outil(s) natif(s) present(s).",
            platform::TOOLS.len() - missing.len()
        )
    } else {
        format!(
            "Outillage incomplet : {} outil(s) manquant(s) ({})",
            missing.len(),
            missing.join(", ")
        )
    };

    ActionResult {
        ok,
        message,
        output: missing.join("\n"),
        diagnostic: diagnose_platform(&p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_expose_toutes_les_etapes() {
        let d = diagnose();
        assert_eq!(d.steps.len(), 4);
        assert_eq!(d.steps[0].id, "platform");
        assert_eq!(d.steps[3].id, "verify");
        assert!(!d.headline.is_empty());
        assert!(!d.runtime_install.command.is_empty());
        assert!(!d.image_pull.command.is_empty());
    }

    #[test]
    fn etape_runtime_reflete_la_presence_du_runtime() {
        let d = diagnose();
        let p = Platform::detect();
        if p.container_runtime.is_empty() && !p.is_native_kali {
            assert_eq!(d.steps[1].state, "todo");
        } else {
            assert_eq!(d.steps[1].state, "done");
        }
    }

    #[test]
    fn etape_image_reflete_la_presence_de_l_image() {
        let d = diagnose();
        let p = Platform::detect();
        if p.kali_image_present || p.is_native_kali {
            assert_eq!(d.steps[2].state, "done");
        } else {
            assert_eq!(d.steps[2].state, "todo");
        }
    }

    #[test]
    fn hint_pull_utilise_l_image_officielle() {
        let d = diagnose();
        assert!(d.image_pull.command.contains(KALI_IMAGE));
        assert!(!d.image_pull.elevated);
    }

    #[test]
    fn verify_liste_les_outils_manquants_sans_paniquer() {
        let r = verify();
        assert!(!r.message.is_empty());
        assert_eq!(r.diagnostic.steps.len(), 4);
    }

    #[test]
    fn install_runtime_sur_kali_natif_est_un_no_op_sure() {
        let p = Platform::detect();
        if p.is_native_kali {
            let r = install_runtime();
            assert!(r.ok);
            assert!(r.message.contains("natif"));
        }
    }

    #[test]
    fn pull_image_sans_runtime_echoue_proprement() {
        let p = Platform::detect();
        if p.container_runtime.is_empty() && !p.is_native_kali {
            let r = pull_image();
            assert!(!r.ok);
            assert!(r.message.contains("runtime"));
        }
    }
}
