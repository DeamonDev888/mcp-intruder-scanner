use std::fs;
use std::time::Instant;

use serde_json::Value;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DnsreconSrv {
    pub name: String,
    pub target: String,
    pub port: u16,
    pub address: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DnsreconResult {
    /// A-records des sous-domaines du domaine audite (lecons bank8.example.com :
    /// ftp./whm./autoconfig. visibles par dnsrecon std mais jamais fusionnes).
    pub host_records: Vec<(String, String)>,
    pub srv_records: Vec<DnsreconSrv>,
    pub bind_versions: Vec<(String, String)>,
    pub nameservers: Vec<String>,
    pub soa_mname: Option<String>,
    /// P1-2 : code de sortie REEL de dnsrecon.
    pub success: bool,
    pub execution_time_seconds: f32,
    pub raw_output: String,
}

pub struct DnsreconAuditor;

impl DnsreconAuditor {
    pub fn audit(domain: &str) -> DnsreconResult {
        let start = Instant::now();
        let mut result = DnsreconResult::default();

        let json_path = format!(
            "/tmp/dnsrecon_{}_{}.json",
            crate::utils::sanitize_target(domain),
            std::process::id()
        );

        let cmd_res = crate::utils::run_tool(
            "dnsrecon",
            &["-d", domain, "-t", "std", "-j", &json_path],
            120,
        );

        result.execution_time_seconds = start.elapsed().as_secs_f32();

        match cmd_res {
            Some(out) => {
                result.success = out.status.success();
                result.raw_output = String::from_utf8_lossy(&out.stdout).to_string();
            }
            None => result.success = false,
        }

        // Nettoyage inconditionnel : même si la lecture échoue (fichier partiel, crash)
        let content = fs::read_to_string(&json_path);
        let _ = fs::remove_file(&json_path);
        if let Ok(content) = content {
            // dnsrecon -j écrit un tableau d'objets hétérogènes. serde_json
            // remplace le découpage manuel par accolades (source historique
            // de findings fantômes sur les valeurs échappées).
            let records: Vec<Value> = serde_json::from_str(&content).unwrap_or_default();
            for rec in records {
                let r_type = rec.get("type").and_then(Value::as_str).unwrap_or_default();

                match r_type {
                    "A" => {
                        let domain_str = rec
                            .get("domain")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        let address = rec
                            .get("address")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        if !domain_str.is_empty()
                            && !address.is_empty()
                            // Frontiere de point obligatoire : "evil.example.com"
                            // ne doit PAS matcher "example.com" (regle 13).
                            && (domain_str == domain
                                || domain_str.ends_with(&format!(".{domain}")))
                            && !result
                                .host_records
                                .contains(&(domain_str.clone(), address.clone()))
                        {
                            result.host_records.push((domain_str, address));
                        }
                    }
                    "SRV" => {
                        let target = rec
                            .get("target")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        let address = rec
                            .get("address")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        let domain_str = rec
                            .get("domain")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        // dnsrecon écrit le port en nombre ; une version
                        // ancienne peut l'écrire en chaîne.
                        let port = rec
                            .get("port")
                            .and_then(|v| {
                                v.as_u64()
                                    .map(|n| n as u16)
                                    .or_else(|| v.as_str().and_then(|s| s.parse::<u16>().ok()))
                            })
                            .unwrap_or(0);

                        result.srv_records.push(DnsreconSrv {
                            name: domain_str,
                            target,
                            port,
                            address,
                        });
                    }
                    "NS" => {
                        let target = rec
                            .get("target")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        if !target.is_empty() && !result.nameservers.contains(&target) {
                            result.nameservers.push(target.clone());
                        }

                        if let Some(version) = rec.get("Version").and_then(Value::as_str) {
                            let clean_v = version.trim().to_string();
                            if !clean_v.is_empty()
                                && !result
                                    .bind_versions
                                    .contains(&(target.clone(), clean_v.clone()))
                            {
                                result.bind_versions.push((target, clean_v));
                            }
                        }
                    }
                    "SOA" if result.soa_mname.is_none() => {
                        result.soa_mname =
                            rec.get("mname").and_then(Value::as_str).map(String::from);
                    }
                    _ => {}
                }
            }
        }

        result
    }

    pub fn to_findings(
        &self,
        res: &DnsreconResult,
    ) -> Vec<crate::modules::findings::SecurityFinding> {
        use crate::modules::findings::SecurityFinding;
        let mut findings = Vec::new();

        let mut emitted: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for (target, version) in &res.bind_versions {
            if !emitted.insert((target.clone(), version.clone())) {
                continue;
            }
            findings.push(SecurityFinding {
                severity: "LOW",
                category: "DNS",
                title: format!("Dnsrecon - Divulgation de version DNS sur {target} : {version}"),
                recommendation: "Masquer la version du serveur de noms (Knot/BIND) dans le fichier de configuration pour limiter l'empreinte d'attaque.".into(),
            });
        }

        if !res.srv_records.is_empty() {
            let srv_list: Vec<String> = res
                .srv_records
                .iter()
                .map(|s| format!("{}:{}", s.target, s.port))
                .collect();
            findings.push(SecurityFinding {
                severity: "INFO",
                category: "DNS",
                title: format!(
                    "Dnsrecon - {} service(s) SRV cartographié(s) ({})",
                    res.srv_records.len(),
                    srv_list.join(", ")
                ),
                recommendation: "S'assurer que les flux vers ces services internes ou de messagerie sont chiffrés en TLS.".into(),
            });
        }

        findings
    }
}
