// src/dash/mod.rs — Tableau de bord mcp_intruder.
//
// Serveur HTTP local (127.0.0.1 uniquement) qui lit le catalogue PostgreSQL
// et rend une interface web unique. Zéro dépendance HTTP externe : le serveur
// est un TcpListener std, un thread par requête.
//
// Architecture (fichiers écrits en parallèle, un seul propriétaire chacun) :
//   model.rs   — contrat de types partagé (serde::Serialize)
//   db.rs      — lecture PostgreSQL → model::Overview
//   charts.rs  — générateurs SVG (aucune dépendance, aucun JS externe)
//   ui.rs      — design system : squelette HTML + CSS + JS d'animations
//   machine.rs — métriques hôte (/proc, systemctl)
//   scans.rs   — lancement / suivi / arrêt des scans depuis l'interface
//   server.rs  — routage HTTP + assemblage de la vue (ce fichier + mod.rs)

pub mod charts;
pub mod db;
pub mod machine;
pub mod model;
pub mod scans;
pub mod server;
pub mod ui;

/// Profil de scan proposé dans le sélecteur GUI.
/// Les flags correspondent à la vraie CLI de mcp_intruder (`--help`) :
/// -1 fast, -2 web, -3 full, -4 infra, -5 vuln, -d discovery.
pub const PROFILES: &[(&str, &str, &str)] = &[
    (
        "fast",
        "-1",
        "Modules Rust noyau uniquement — le plus rapide",
    ),
    ("web", "-2", "WAF, WhatWeb, SSLscan, Dnstwist, Httpx"),
    (
        "discovery",
        "-d",
        "Ffuf, Nikto, détection WAF — recherche de surface",
    ),
    (
        "infra",
        "-4",
        "Nmap, SSLscan, RustScan — cartographie de ports",
    ),
    (
        "vuln",
        "-5",
        "Nuclei, Nikto, Nmap, Sqlmap — hunt de vulnérabilités",
    ),
    (
        "full",
        "-3",
        "Tous les outils Kali — le plus complet, le plus lent",
    ),
];
