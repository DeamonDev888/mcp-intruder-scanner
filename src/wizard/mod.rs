// src/wizard/mod.rs — Assistant de configuration natif (terminal).
//
// Le moteur de scan s'appuie sur l'outillage Kali. Sur un hote qui n'est pas
// un Kali natif, l'assistant guide l'utilisateur :
//   etape 1 — diagnostic de la plateforme (OS, runtime de conteneur, image)
//   etape 2 — installation du runtime (Docker/Podman) si absent, avec la
//              commande exacte affichee et un choix explicite
//   etape 3 — telechargement de l'image officielle kalilinux/kali-rolling
//   etape 4 — controle final : les outils Kali sont accessibles
//
// Tout se passe dans le terminal : pas de serveur HTTP, pas de navigateur,
// meme comportement sous Windows, macOS et Linux (y compris sans affichage).
// Aucune installation n'est lancee sans un choix explicite de l'utilisateur.

pub mod api;
pub mod native;

/// Image Docker officielle Kali Linux (voir `crate::platform::KALI_IMAGE`).
pub use crate::platform::KALI_IMAGE;
