// src/wizard/mod.rs — Assistant de demarrage graphique (hors Kali natif).
//
// Le moteur de scan s'appuie sur l'outillage Kali. Sur un hote qui n'est pas
// un Kali natif, l'assistant guide l'utilisateur :
//   etape 1 — diagnostic de la plateforme (OS, runtime de conteneur, image)
//   etape 2 — installation du runtime (Docker/Podman) si absent, avec la
//              commande exacte affichee et une confirmation explicite
//   etape 3 — telechargement de l'image officielle kalilinux/kali-rolling
//   etape 4 — controle final : les outils Kali sont accessibles
//
// L'assistant est servi par un serveur HTTP local (127.0.0.1) sur un port
// libre, comme le tableau de bord. Il n'execute AUCUNE installation sans
// un POST explicite de l'utilisateur.

pub mod api;
pub mod headless;
pub mod server;
pub mod ui;

/// Port par defaut du serveur de l'assistant (0 = port libre).
pub const DEFAULT_PORT: u16 = 8098;

/// Image Docker officielle Kali Linux (voir `crate::platform::KALI_IMAGE`).
pub use crate::platform::KALI_IMAGE;
