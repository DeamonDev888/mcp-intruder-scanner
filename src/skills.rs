// src/skills.rs — Catalogue de skills MCP-Intruder (340 skills du bundle).
//
// Le bundle mcp-intruder-skills (repo public DeamonDev888/mcp-intruder-skills)
// livre 340 skills de cyberguerre offensive au format SKILL.md :
//   bughunter/  45 skills Tier 1 (hunt-xss, triage-validation, web2-recon...)
//   acs/        94 skills Tier 1 (Web AppSec, API, AI Security...) + mappings
//   optional/   201 skills opt-in en 5 packs (bughunter 38, acs-ot-ics 29,
//               acs-red-team 35, acs-cloud 66, acs-container 33)
//
// Ce module lit le manifest machine (skills-manifest.json) livre a la racine
// du bundle, l'indexe en memoire, et l'expose au serveur MCP pour qu'un agent
// puisse chercher un skill par mot-cle, lister le catalogue, et lire le
// SKILL.md complet d'une entree — sans quitter le protocole MCP.
//
// Localisations cherchees, dans l'ordre :
//   1. $MCP_INTRUDER_SKILLS_DIR (surcharge explicite)
//   2. ./mcp-intruder-skills (working directory)
//   3. ~/mcp-intruder-skills (home)
//   4. ../mcp-intruder-skills (voisin du binaire)

use serde::Serialize;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Chemins de recherche du bundle, dans l'ordre.
fn candidate_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(dir) = std::env::var_os("MCP_INTRUDER_SKILLS_DIR") {
        v.push(PathBuf::from(dir));
    }
    if let Ok(cwd) = std::env::current_dir() {
        v.push(cwd.join("mcp-intruder-skills"));
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let home = PathBuf::from(home);
        v.push(home.join("mcp-intruder-skills"));
        v.push(home.join(".claude").join("skills"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            v.push(parent.join("mcp-intruder-skills"));
            v.push(
                parent
                    .parent()
                    .map(|p| p.join("mcp-intruder-skills"))
                    .unwrap_or_default(),
            );
        }
    }
    v
}

/// Localisation du bundle (premier dossier contenant skills-manifest.json).
pub fn bundle_dir() -> Option<PathBuf> {
    static CELL: OnceLock<Option<PathBuf>> = OnceLock::new();
    CELL.get_or_init(|| {
        candidate_dirs()
            .into_iter()
            .find(|dir| dir.join("skills-manifest.json").is_file())
    })
    .clone()
}

/// Une entree du catalogue (une ligne du manifest).
#[derive(Debug, Clone, Serialize)]
pub struct SkillEntry {
    pub id: String,
    pub category: String,
    pub tier: String,
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// Etat du catalogue charge.
#[derive(Debug, Clone, Serialize)]
pub struct SkillsCatalog {
    /// Nombre total de skills indexes.
    pub total: usize,
    /// Le bundle est-il trouve sur cette machine ?
    pub bundle_found: bool,
    /// Dossier du bundle (vide si absent).
    pub bundle_dir: String,
    /// Repartition par source (bughunter / acs / optional-pack).
    pub by_source: Vec<(String, usize)>,
    /// Repartition par tier.
    pub by_tier: Vec<(String, usize)>,
}

/// Cache du catalogue parse (chargement unique par process).
fn catalog_cache() -> &'static OnceLock<CatalogLoad> {
    static CELL: OnceLock<CatalogLoad> = OnceLock::new();
    &CELL
}

#[derive(Debug, Clone)]
struct CatalogLoad {
    entries: Vec<SkillEntry>,
    catalog: SkillsCatalog,
}

/// Charge et parse le manifest (memoire cachee).
fn load() -> CatalogLoad {
    catalog_cache()
        .get_or_init(|| {
            let mut entries: Vec<SkillEntry> = Vec::new();
            let mut by_source: std::collections::BTreeMap<String, usize> = Default::default();
            let mut by_tier: std::collections::BTreeMap<String, usize> = Default::default();
            let dir = bundle_dir();

            let Some(dir) = dir else {
                return CatalogLoad {
                    entries,
                    catalog: SkillsCatalog {
                        total: 0,
                        bundle_found: false,
                        bundle_dir: String::new(),
                        by_source: vec![],
                        by_tier: vec![],
                    },
                };
            };

            let manifest_path = dir.join("skills-manifest.json");
            let raw = match std::fs::read_to_string(&manifest_path) {
                Ok(r) => r,
                Err(_) => {
                    return CatalogLoad {
                        entries,
                        catalog: SkillsCatalog {
                            total: 0,
                            bundle_found: false,
                            bundle_dir: dir.to_string_lossy().to_string(),
                            by_source: vec![],
                            by_tier: vec![],
                        },
                    }
                }
            };

            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(list) = v.get("skills").and_then(|s| s.as_array()) {
                    for it in list {
                        let get =
                            |k: &str| it.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                        let e = SkillEntry {
                            id: get("id"),
                            category: get("category"),
                            tier: get("tier"),
                            source: get("source"),
                            path: get("path"),
                            description: get("description"),
                        };
                        *by_source.entry(e.source.clone()).or_insert(0) += 1;
                        *by_tier.entry(e.tier.clone()).or_insert(0) += 1;
                        entries.push(e);
                    }
                }
            }
            entries.sort_by(|a, b| a.id.cmp(&b.id));

            let catalog = SkillsCatalog {
                total: entries.len(),
                bundle_found: true,
                bundle_dir: dir.to_string_lossy().to_string(),
                by_source: by_source.into_iter().collect(),
                by_tier: by_tier.into_iter().collect(),
            };
            CatalogLoad { entries, catalog }
        })
        .clone()
}

/// Etat du catalogue (total, repartitions, dossier).
pub fn catalog() -> SkillsCatalog {
    load().catalog
}

/// Toutes les entrees.
pub fn all() -> Vec<SkillEntry> {
    load().entries
}

/// Recherche plein-texte insensible a la casse sur id + description + categorie.
///
/// Tous les termes doivent matcher (ET logique). Retourne au plus `limit`
/// resultats, tries par pertinence grossiere (les matches sur l'id d'abord).
pub fn search(terms: &[&str], limit: usize) -> Vec<SkillEntry> {
    if terms.is_empty() {
        return all().into_iter().take(limit).collect();
    }
    let mut scored: Vec<(usize, SkillEntry)> = Vec::new();
    for e in all() {
        let id = e.id.to_lowercase();
        let desc = e.description.to_lowercase();
        let cat = e.category.to_lowercase();
        let mut score = 0;
        let mut all_match = true;
        for t in terms {
            let t = t.to_lowercase();
            if id.contains(&t) {
                score += 3;
            } else if cat.contains(&t) {
                score += 2;
            } else if desc.contains(&t) {
                score += 1;
            } else {
                all_match = false;
                break;
            }
        }
        if all_match {
            scored.push((score, e));
        }
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.id.cmp(&b.1.id)));
    scored.into_iter().map(|(_, e)| e).take(limit).collect()
}

/// Lit le SKILL.md complet d'un skill par son id.
pub fn read_skill(id: &str) -> Option<(SkillEntry, String)> {
    let entries = load().entries;
    let entry = entries
        .into_iter()
        .find(|e| e.id.eq_ignore_ascii_case(id))?;
    let dir = bundle_dir()?;
    // le chemin du manifest est relatif a la racine du bundle
    let skill_path = if entry.path.is_empty() {
        // secours : recherche par nom de dossier
        let mut found: Option<PathBuf> = None;
        for base in ["bughunter", "acs", "optional"] {
            let p = dir.join(base).join(&entry.id).join("SKILL.md");
            if p.is_file() {
                found = Some(p);
                break;
            }
        }
        found?
    } else {
        let p = dir.join(&entry.path);
        // le manifest pointe vers le dossier du skill ; SKILL.md si absent
        if p.is_file() {
            p
        } else {
            p.join("SKILL.md")
        }
    };
    let body = std::fs::read_to_string(&skill_path).ok()?;
    Some((entry, body))
}

/// Liste des packs optionnels disponibles avec leur decompte.
pub fn optional_packs() -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = Vec::new();
    for e in all() {
        if let Some(pack) = e.source.strip_prefix("optional/") {
            match out.iter_mut().find(|(p, _)| p == pack) {
                Some((_, n)) => *n += 1,
                None => out.push((pack.to_string(), 1)),
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recherche_vide_retourne_les_premiers() {
        let r = search(&[], 5);
        assert!(r.len() <= 5);
    }

    #[test]
    fn recherche_et_logique() {
        // un terme qui ne matche rien -> 0 resultat
        let r = search(&["zzzz-terme-inexistant-xyz"], 10);
        assert!(r.is_empty());
    }

    #[test]
    fn read_skill_inconnu_est_none_sans_panic() {
        let r = read_skill("zzz-skill-inexistant-xyz");
        assert!(r.is_none());
    }

    #[test]
    fn optional_packs_sont_tries_si_present() {
        let packs = optional_packs();
        for w in packs.windows(2) {
            assert!(w[0].0 <= w[1].0, "packs non tries : {packs:?}");
        }
        // les packs optionnels proviennent du champ source "optional/<pack>" ;
        // si le manifest n'utilise pas ce format, la liste est simplement vide.
    }
}
