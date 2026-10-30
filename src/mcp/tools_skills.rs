// src/mcp/tools_skills.rs — Outils MCP du catalogue de skills (340 skills).
//
// Trois outils en lecture seule :
//   skills_catalog : etat du bundle + repartitions (source, tier, packs)
//   skills_search  : recherche plein-texte (id, description, categorie)
//   skills_show    : lecture du SKILL.md complet d'un skill par son id
//
// Le bundle est localise automatiquement (MCP_INTRUDER_SKILLS_DIR, cwd,
// home) ; tous les outils repondent proprement meme si le bundle est absent.

use super::ServerBuilder;
use crate::skills;
use litemcp::prelude::*;
use serde_json::{json, Value};

pub(super) fn register(builder: ServerBuilder) -> ServerBuilder {
    builder
        .tool(
            "skills_catalog",
            "Catalogue des skills MCP-Intruder : 340 skills de cyberguerre offensive du bundle \
             mcp-intruder-skills (bughunter 45 Tier 1, acs 94 Tier 1, 201 optionnels en 5 packs). \
             Renvoie le total, les repartitions par source et par tier, la liste des packs \
             optionnels avec leur decompte, et le dossier local du bundle. Lecture seule.",
            |_args: &Value| Ok(skills_catalog()),
        )
        .annotate(
            "skills_catalog",
            ToolAnnotations::new()
                .title("Catalogue des skills")
                .read_only(true)
                .idempotent(true),
        )
        .tool(
            "skills_search",
            "Recherche plein-texte dans les 340 skills (id, description, categorie). Tous les \
             termes fournis doivent matcher (ET logique, insensible a la casse). Exemples : \
             'xss', 'container escape', 'kubernetes rbac', 'prompt injection'. Renvoie les \
             fiche de chaque resultat (id, categorie, tier, description tronquee). Lecture seule.",
            |args: &Value| {
                let query = args
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20)
                    .clamp(1, 100) as usize;
                Ok(skills_search(&query, limit))
            },
        )
        .annotate(
            "skills_search",
            ToolAnnotations::new()
                .title("Recherche dans les skills")
                .read_only(true)
                .idempotent(true),
        )
        .tool(
            "skills_show",
            "Lit le SKILL.md complet d'un skill par son id exact (ex: hunt-reflected-xss, \
             testing-rag-pipeline-data-poisoning). Renvoie l'id, la categorie, le tier et le \
             corps markdown integral du skill. Lecture seule.",
            |args: &Value| {
                let id = args
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(skills_show(&id))
            },
        )
        .annotate(
            "skills_show",
            ToolAnnotations::new()
                .title("Contenu d'un skill")
                .read_only(true)
                .idempotent(true),
        )
}

/// Etat du catalogue + repartitions.
fn skills_catalog() -> Value {
    let c = skills::catalog();
    let packs = skills::optional_packs();
    json!({
        "bundle_found": c.bundle_found,
        "bundle_dir": c.bundle_dir,
        "total": c.total,
        "by_source": c.by_source.into_iter().map(|(k, n)| json!({"source": k, "count": n})).collect::<Vec<_>>(),
        "by_tier": c.by_tier.into_iter().map(|(k, n)| json!({"tier": k, "count": n})).collect::<Vec<_>>(),
        "optional_packs": packs.into_iter().map(|(k, n)| json!({"pack": k, "count": n})).collect::<Vec<_>>(),
        "hint": if c.bundle_found { String::new() } else {
            "Bundle absent : clonez https://github.com/DeamonDev888/mcp-intruder-skills ou \
             definissez MCP_INTRUDER_SKILLS_DIR."
                .to_string()
        },
    })
}

/// Recherche plein-texte.
fn skills_search(query: &str, limit: usize) -> Value {
    let terms: Vec<&str> = query.split_whitespace().collect();
    if terms.is_empty() {
        return json!({
            "error": "query vide : fournissez un ou plusieurs mots-cles",
            "total_catalog": skills::catalog().total,
        });
    }
    let results = skills::search(&terms, limit);
    let items: Vec<Value> = results
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id,
                "category": e.category,
                "tier": e.tier,
                "source": e.source,
                "description": truncate(&e.description, 220),
            })
        })
        .collect();
    json!({
        "query": query,
        "matches": items.len(),
        "results": items,
    })
}

/// Lecture du SKILL.md complet.
fn skills_show(id: &str) -> Value {
    match skills::read_skill(id) {
        Some((e, body)) => json!({
            "found": true,
            "id": e.id,
            "category": e.category,
            "tier": e.tier,
            "source": e.source,
            "bytes": body.len(),
            "content": body,
        }),
        None => {
            let c = skills::catalog();
            json!({
                "found": false,
                "id": id,
                "hint": if c.bundle_found {
                    "id inconnu : utilisez skills_search pour trouver les ids valides".to_string()
                } else {
                    "bundle absent de cette machine : MCP_INTRUDER_SKILLS_DIR ou clone du repo".to_string()
                },
            })
        }
    }
}

/// Troncature avec suffixe.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_repond_meme_sans_bundle() {
        let v = skills_catalog();
        assert!(v.get("total").is_some());
        assert!(v.get("bundle_found").is_some());
    }

    #[test]
    fn search_sans_query_renvoie_erreur_structuree() {
        let v = skills_search("", 10);
        assert_eq!(
            v.get("error").and_then(|e| e.as_str()),
            Some("query vide : fournissez un ou plusieurs mots-cles")
        );
    }

    #[test]
    fn search_terme_inexistant_zero_match() {
        let v = skills_search("zzz-inexistant-xyz", 10);
        assert_eq!(v.get("matches").and_then(|m| m.as_u64()), Some(0));
    }

    #[test]
    fn show_inconnu_renvoie_found_false() {
        let v = skills_show("zzz-inexistant-xyz");
        assert_eq!(v.get("found").and_then(|f| f.as_bool()), Some(false));
    }

    #[test]
    fn truncate_court_avec_suffixe() {
        assert_eq!(truncate("abcdefghij", 4), "abcd...");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
