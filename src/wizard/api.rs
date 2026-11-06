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
    /// Le demon du runtime repond (sinon l'installation est inutile : il faut
    /// le demarrer).
    pub container_daemon_ready: bool,
    /// Consigne de demarrage du demon, adaptee a l'OS (vide si aucun runtime).
    pub daemon_start_hint: String,
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
    // L'outillage n'est pret que si l'image DERIVEE existe (base + paquets),
    // pas seulement l'image de base Kali.
    let tools_ready = p.is_native_kali
        || (!p.container_runtime.is_empty() && p.container_daemon_ready && p.derived_image_present);

    let mut steps = Vec::new();

    // Etape 1 : plateforme.
    steps.push(Step {
        id: "platform",
        title: "Plateforme detectee",
        detail: p.summary(),
        state: "done",
    });

    // Etape 2 : runtime de conteneur. Un binaire present ne suffit pas : le
    // demon doit repondre, sinon l'image ne peut ni etre tiree ni executee.
    let runtime_ready = !p.container_runtime.is_empty() && p.container_daemon_ready;
    let runtime_state = if runtime_ready || p.is_native_kali {
        "done"
    } else if !p.container_runtime.is_empty() {
        "warn"
    } else {
        "todo"
    };
    let runtime_detail = if runtime_ready {
        format!("{} — {}", p.container_runtime, p.container_version)
    } else if !p.container_runtime.is_empty() {
        format!(
            "{} installe ({}) mais le demon ne repond pas : {}",
            p.container_runtime,
            p.container_version,
            platform::daemon_start_hint(p.os, &p.container_runtime)
        )
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
    let image_state = if p.derived_image_present || p.is_native_kali {
        "done"
    } else {
        "todo"
    };
    let image_detail = if p.derived_image_present {
        format!(
            "Image d'outillage presente : {}",
            crate::docker_tools::DERIVED_IMAGE
        )
    } else if p.kali_image_present {
        format!("Base presente ({KALI_IMAGE}) ; outillage construit au premier scan.")
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

    // Etape 4 : controle final. Le geste de lancement differe selon le mode :
    // en natif c'est le binaire, en conteneur c'est l'image qui le demarre.
    let launch_hint = if p.is_native_kali || p.container_runtime.is_empty() {
        "Demarrer le serveur : mcp_intruder_server"
    } else {
        "Le serveur demarre avec le conteneur : docker run -p 7808:7808 mcp-intruder/server"
    };
    steps.push(Step {
        id: "verify",
        title: "Outillage operationnel",
        detail: if tools_ready {
            format!("Les modules de scan peuvent s'executer. {launch_hint}")
        } else if !p.container_runtime.is_empty() && !p.container_daemon_ready {
            format!(
                "Le runtime est installe mais son demon est arrete : {}",
                platform::daemon_start_hint(p.os, &p.container_runtime)
            )
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
    } else if !p.container_daemon_ready {
        format!(
            "{} : {} est installe mais son demon est arrete — {}",
            p.os,
            p.container_runtime,
            platform::daemon_start_hint(p.os, &p.container_runtime)
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
        container_daemon_ready: p.container_daemon_ready,
        daemon_start_hint: if p.container_runtime.is_empty() {
            String::new()
        } else {
            platform::daemon_start_hint(p.os, &p.container_runtime)
        },
        kali_image_present: p.kali_image_present,
        native_tools_present: p.native_tools_present,
        tools_ready,
        summary: p.summary(),
        steps,
        runtime_install: CommandHint {
            command: platform::install_runtime_hint(p.os),
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
        let started = p.container_daemon_ready;
        return ActionResult {
            ok: started,
            message: if started {
                format!("Runtime deja present : {}.", p.container_runtime)
            } else {
                format!(
                    "{} est installe mais son demon ne repond pas : {}.",
                    p.container_runtime,
                    platform::daemon_start_hint(p.os, &p.container_runtime)
                )
            },
            output: String::new(),
            diagnostic: diagnose_platform(&p),
        };
    }

    let (cmd, args): (&str, Vec<&str>) = match p.os {
        HostOs::Linux => ("sudo", Vec::new()),
        HostOs::MacOs => ("brew", vec!["install", "--cask", "docker"]),
        HostOs::Windows => (
            "winget",
            vec![
                "install",
                "--id",
                "Docker.DockerDesktop",
                "-e",
                "--accept-source-agreements",
                "--accept-package-agreements",
            ],
        ),
        HostOs::Other => {
            return ActionResult {
                ok: false,
                message: "Systeme non reconnu : installez Docker ou Podman manuellement."
                    .to_string(),
                output: platform::install_runtime_hint(p.os),
                diagnostic: diagnose_platform(&p),
            }
        }
    };

    // Sur Linux, la commande depend du gestionnaire de paquets detecte :
    // chaque etape est lancee separement (args only, jamais de shell).
    let output = match p.os {
        HostOs::Linux => {
            let mut out = String::new();
            for step in platform::linux_install_commands() {
                let mut step_args: Vec<&str> = Vec::with_capacity(step.len() + 1);
                step_args.push("-n");
                step_args.extend(step.iter().copied());
                out.push_str(&format!("$ sudo {}\n", step.join(" ")));
                out.push_str(&platform::run_capture("sudo", &step_args).unwrap_or_default());
                out.push('\n');
            }
            out
        }
        HostOs::MacOs => {
            let out = platform::run_capture(cmd, &args).unwrap_or_default();
            // Le cask installe Docker.app : on tente de le demarrer sans bloquer.
            let _ = std::process::Command::new("open")
                .args(["-a", "Docker"])
                .spawn();
            out
        }
        _ => platform::run_capture(cmd, &args).unwrap_or_default(),
    };

    let after = Platform::detect();
    let ok = !after.container_runtime.is_empty() && after.container_daemon_ready;
    ActionResult {
        ok,
        message: if ok {
            format!("Runtime installe : {}.", after.container_runtime)
        } else if !after.container_runtime.is_empty() {
            format!(
                "{} installe mais le demon ne repond pas encore : {}.",
                after.container_runtime,
                platform::daemon_start_hint(after.os, &after.container_runtime)
            )
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
    if !p.container_daemon_ready {
        return ActionResult {
            ok: false,
            message: format!(
                "{} est installe mais son demon ne repond pas : {}.",
                p.container_runtime,
                platform::daemon_start_hint(p.os, &p.container_runtime)
            ),
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

    let ok = p.is_native_kali
        || (p.kali_image_present && !p.container_runtime.is_empty() && p.container_daemon_ready);
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
    fn diagnostic_d_un_runtime_arrete_invite_a_demarrer_le_demon() {
        let p = Platform {
            os: HostOs::Windows,
            is_native_kali: false,
            distro: String::new(),
            container_runtime: "docker".to_string(),
            container_version: "Docker version test".to_string(),
            container_daemon_ready: false,
            kali_image_present: true,
            derived_image_present: true,
            native_tools_present: false,
        };
        let d = diagnose_platform(&p);
        assert_eq!(d.steps[1].state, "warn");
        assert!(d.steps[1].detail.contains("demon"));
        assert!(d.headline.contains("demon"));
        assert!(!d.tools_ready);
        assert!(d.daemon_start_hint.contains("Docker Desktop"));
    }

    #[test]
    fn diagnostic_d_un_runtime_actif_est_operationnel() {
        let p = Platform {
            os: HostOs::Linux,
            is_native_kali: false,
            distro: "Debian".to_string(),
            container_runtime: "docker".to_string(),
            container_version: "Docker version test".to_string(),
            container_daemon_ready: true,
            kali_image_present: true,
            derived_image_present: true,
            native_tools_present: false,
        };
        let d = diagnose_platform(&p);
        assert_eq!(d.steps[1].state, "done");
        assert!(d.tools_ready);
        assert!(d.headline.contains("operationnel"));
        assert!(d.steps[3].detail.contains("docker run"));
    }

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
        if p.is_native_kali || (!p.container_runtime.is_empty() && p.container_daemon_ready) {
            assert_eq!(d.steps[1].state, "done");
        } else if !p.container_runtime.is_empty() {
            assert_eq!(d.steps[1].state, "warn");
        } else {
            assert_eq!(d.steps[1].state, "todo");
        }
    }

    #[test]
    fn etape_image_reflete_la_presence_de_l_image() {
        let d = diagnose();
        let p = Platform::detect();
        // L'etape image est "done" quand l'image DERIVEE existe (base + outils),
        // pas seulement l'image de base Kali.
        if p.derived_image_present || p.is_native_kali {
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
