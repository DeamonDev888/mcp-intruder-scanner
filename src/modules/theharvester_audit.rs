use std::fs;
use std::time::Instant;

/// Forme du JSON écrit par theHarvester (-f). Champs optionnels : certaines
/// versions n'écrivent que hosts + emails.
#[derive(Debug, Default, serde::Deserialize)]
struct HarvesterJson {
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TheHarvesterResult {
    pub hosts: Vec<String>,
    pub emails: Vec<String>,
    pub ips: Vec<String>,
    /// P1-2 : code de sortie REEL de theHarvester.
    pub success: bool,
    pub execution_time_seconds: f32,
    pub raw_output: String,
}

pub struct TheHarvesterAuditor;

impl TheHarvesterAuditor {
    pub fn audit(domain: &str) -> TheHarvesterResult {
        let start = Instant::now();
        let mut result = TheHarvesterResult::default();

        let base_path = format!(
            "/tmp/harvester_{}_{}",
            crate::utils::sanitize_target(domain),
            std::process::id()
        );

        let cmd_res = crate::utils::run_tool(
            "theHarvester",
            &["-d", domain, "-b", "duckduckgo,crtsh", "-f", &base_path],
            150,
        );

        result.execution_time_seconds = start.elapsed().as_secs_f32();

        match cmd_res {
            Some(out) => {
                result.success = out.status.success();
                result.raw_output = String::from_utf8_lossy(&out.stdout).to_string();
            }
            None => result.success = false,
        }

        let json_path = format!("{base_path}.json");
        let xml_path = format!("{base_path}.xml");

        // Nettoyage inconditionnel des DEUX fichiers (le xml fuitait si le json
        // était absent — cas fréquent de crash partiel de theHarvester)
        let content = fs::read_to_string(&json_path);
        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&xml_path);
        if let Ok(content) = content {
            // theHarvester -f <fichier>.json : objet {"hosts":[], "emails":[],
            // "ips":[]}. serde_json remplace l'extraction manuelle par
            // find/accolades (source historique de findings fantômes).
            let parsed: HarvesterJson = serde_json::from_str(&content).unwrap_or_default();

            for host in parsed.hosts {
                let clean = host.trim().to_lowercase();
                if !clean.is_empty() && !result.hosts.contains(&clean) {
                    result.hosts.push(clean);
                }
            }
            for email in parsed.emails {
                let clean = email.trim().to_lowercase();
                if !clean.is_empty() && !result.emails.contains(&clean) {
                    result.emails.push(clean);
                }
            }
            for ip in parsed.ips {
                let clean = ip.trim().to_string();
                if !clean.is_empty() && !result.ips.contains(&clean) {
                    result.ips.push(clean);
                }
            }
        }

        result
    }

    pub fn to_findings(
        &self,
        res: &TheHarvesterResult,
    ) -> Vec<crate::modules::findings::SecurityFinding> {
        use crate::modules::findings::SecurityFinding;
        let mut findings = Vec::new();

        if !res.emails.is_empty() {
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "OSINT",
                title: format!(
                    "theHarvester - {} adresse(s) email repérée(s) dans les moteurs OSINT ({})",
                    res.emails.len(),
                    res.emails.join(", ")
                ),
                recommendation: "Sensibiliser les collaborateurs associés à ces courriels contre le phishing ciblé et le spear-phishing.".into(),
            });
        }

        if !res.hosts.is_empty() {
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "OSINT",
                title: format!(
                    "theHarvester - {} hôte(s) et sous-domaine(s) identifié(s) dans les certificats/moteurs OSINT",
                    res.hosts.len()
                ),
                recommendation: "Vérifier que tous les sous-domaines indexés publiquement sont sécurisés et à jour.".into(),
            });
        }

        findings
    }
}
