use std::net::{IpAddr, ToSocketAddrs};

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsRecordEntry {
    pub record_type: String,
    pub value: String,
    pub is_secure: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DnsAuditResult {
    pub domain: String,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub soa_record: Option<String>,
    pub caa_records: Vec<String>,
    pub dnssec_active: bool,
    pub spf_found: bool,
    pub spf_strict: bool,
    pub spf_record: Option<String>,
    pub dmarc_found: bool,
    pub dmarc_policy: Option<String>,
    pub dmarc_record: Option<String>,
    pub reverse_ptr: Option<String>,
    pub all_records: Vec<DnsRecordEntry>,
    pub issues: Vec<String>,
}

impl DnsAuditResult {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            a_records: Vec::new(),
            aaaa_records: Vec::new(),
            mx_records: Vec::new(),
            txt_records: Vec::new(),
            ns_records: Vec::new(),
            soa_record: None,
            caa_records: Vec::new(),
            dnssec_active: false,
            spf_found: false,
            spf_strict: false,
            spf_record: None,
            dmarc_found: false,
            dmarc_policy: None,
            dmarc_record: None,
            reverse_ptr: None,
            all_records: Vec::new(),
            issues: Vec::new(),
        }
    }
}

pub struct DnsAuditor;

impl DnsAuditor {
    pub fn audit(domain: &str) -> DnsAuditResult {
        let mut result = DnsAuditResult::new(domain);

        // 1. Résolution standard A / AAAA
        let host_port = format!("{}:80", domain);
        if let Ok(addrs) = host_port.to_socket_addrs() {
            for addr in addrs {
                match addr.ip() {
                    IpAddr::V4(v4) => {
                        let s = v4.to_string();
                        if !result.a_records.contains(&s) {
                            result.a_records.push(s.clone());
                            result.all_records.push(DnsRecordEntry {
                                record_type: "A".to_string(),
                                value: s,
                                is_secure: false,
                            });
                        }
                    }
                    IpAddr::V6(v6) => {
                        let s = v6.to_string();
                        if !result.aaaa_records.contains(&s) {
                            result.aaaa_records.push(s.clone());
                            result.all_records.push(DnsRecordEntry {
                                record_type: "AAAA".to_string(),
                                value: s,
                                is_secure: false,
                            });
                        }
                    }
                }
            }
        }

        // 2. Résolution approfondie via dig
        Self::enrich_via_dig(domain, &mut result);

        // 3. Reverse PTR sur la première IP — natif UDP (zéro spawn dig)
        if let Some(first_ip) = result.a_records.first() {
            let mut s = String::new();
            if let Some(ans) =
                crate::modules::netdns::query(first_ip, "PTR", std::time::Duration::from_secs(2))
            {
                for (v, _) in &ans.answers {
                    if !v.is_empty() && !s.is_empty() {
                        s.push(' ');
                    }
                    if !v.is_empty() {
                        s.push_str(v);
                    }
                }
            }
            if s.is_empty() {
                // fallback dig (réseaux où UDP 53 sortant est bloqué)
                if let Some(out) = crate::utils::run_tool(
                    "dig",
                    &["+short", "-x", first_ip, "+time=2", "+tries=1"],
                    8,
                ) {
                    s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                }
            }
            if !s.is_empty() {
                result.reverse_ptr = Some(s.clone());
                result.all_records.push(DnsRecordEntry {
                    record_type: "PTR".to_string(),
                    value: s,
                    is_secure: false,
                });
            }
        }

        // Fallback apex — DOIT preceder les analyses SPF et DMARC (sinon le
        // finding « absent » est emis avant que l apex soit consulte).
        // Un sous-domaine (www.) n'heberge presque jamais la politique :
        // celle-ci vit sur le domaine registrable. Verifie live :
        // www.example.org muet, apex = v=spf1 ... ~all ;
        // www.pharma.example.com muet, apex = v=spf1 + DMARC p=reject.
        // L'hote doit avoir au moins 3 labels pour que l'apex differe.
        if result.txt_records.is_empty() {
            let apex = Self::registrable_domain(domain);
            if apex != domain {
                let mut apex_txt: Vec<String> = Vec::new();
                if let Some(ans) =
                    crate::modules::netdns::query(&apex, "TXT", std::time::Duration::from_secs(2))
                {
                    for (v, _) in &ans.answers {
                        let t = v.trim().trim_matches('"').to_string();
                        if !t.is_empty() {
                            apex_txt.push(t);
                        }
                    }
                }
                if apex_txt.is_empty() {
                    if let Some(output) = crate::utils::run_tool(
                        "dig",
                        &["+noall", "+answer", "+time=2", "+tries=1", "TXT", &apex],
                        8,
                    ) {
                        apex_txt = Self::dig_records_of_type(&output.stdout, "TXT");
                    }
                }
                for t in apex_txt {
                    result.txt_records.push(t.clone());
                    result.all_records.push(DnsRecordEntry {
                        record_type: "TXT".to_string(),
                        value: format!("[apex {apex}] {t}"),
                        is_secure: false,
                    });
                }
            }
        }

        // 4. Analyse SPF
        for txt in &result.txt_records {
            if txt.starts_with("v=spf1") {
                result.spf_found = true;
                result.spf_record = Some(txt.clone());
                result.spf_strict = txt.contains("-all");
                break;
            }
        }

        if !result.spf_found {
            result
                .issues
                .push("Absence d'enregistrement SPF (Sender Policy Framework).".into());
        } else if !result.spf_strict {
            result.issues.push(
                "Politique SPF laxiste (utilise ~all ou ?all au lieu de -all strict).".into(),
            );
        }

        // 5. Analyse DMARC
        if !result.dmarc_found {
            result
                .issues
                .push("Absence d'enregistrement DMARC sur _dmarc.".into());
        } else if let Some(ref pol) = result.dmarc_policy {
            if pol == "none" {
                result
                    .issues
                    .push("Politique DMARC en mode surveillance uniquement (p=none).".into());
            }
        }

        // 6. Contrôle CAA & DNSSEC
        if result.caa_records.is_empty() {
            result.issues.push(
                "Absence d'enregistrements CAA (autorisations de CA non restreintes).".into(),
            );
        }

        if !result.dnssec_active {
            result
                .issues
                .push("DNSSEC non activé pour ce domaine.".into());
        }

        // Cohérence : is_secure reflète le flag AD réellement observé (jamais hardcodé)
        for r in &mut result.all_records {
            r.is_secure = result.dnssec_active;
        }

        result
    }

    /// Domaine registrable approx : retire le premier label d'un sous-domaine
    /// (www.pharma.example.com -> pharma.example.com). 2 labels ou moins = inchangé.
    /// Approximation conservatrice (pas de PSL embarquée) : le fallback apex
    /// ne s'active que si TXT/DMARC manquent sur le hostname ET existent sur
    /// le parent direct.
    fn registrable_domain(domain: &str) -> String {
        let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).collect();
        if labels.len() >= 3 {
            labels[1..].join(".")
        } else {
            domain.to_string()
        }
    }

    /// Lignes `dig +noall +answer` du seul type demande.
    ///
    /// `dig +short` ne filtre rien : sur un nom qui porte une chaine CNAME, il
    /// renvoie les CNAME de la chaine pour TOUT type demande. C'est ainsi qu'une
    /// liste de CNAME atterrissait dans mx_records, txt_records, ns_records ET
    /// caa_records (verifie en base sur www.example.org). On exige
    /// donc explicitement le champ TYPE, et la chaine CNAME de resolution est
    /// ecartee : les IP finales sont de toute facon reprises via A/AAAA.
    fn dig_records_of_type(output: &[u8], rtype: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in String::from_utf8_lossy(output).lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // format +noall +answer : <nom> <ttl> IN <TYPE> <rdata...>
            if cols.len() < 5 || !cols[2].eq_ignore_ascii_case("IN") {
                continue;
            }
            if !cols[3].eq_ignore_ascii_case(rtype) {
                continue;
            }
            let trimmed = cols[4..].join(" ").trim_matches('"').trim().to_string();
            if !trimmed.is_empty() {
                out.push(trimmed);
            }
        }
        out
    }

    fn enrich_via_dig(domain: &str, result: &mut DnsAuditResult) {
        // MX natif UDP
        let mut got_mx_records: Vec<String> = Vec::new();
        if let Some(ans) =
            crate::modules::netdns::query(domain, "MX", std::time::Duration::from_secs(2))
        {
            for (v, _) in &ans.answers {
                let t = v.trim().trim_matches('"').to_string();
                if !t.is_empty() {
                    got_mx_records.push(t);
                }
            }
        }
        if got_mx_records.is_empty() {
            if let Some(output) = crate::utils::run_tool(
                "dig",
                &["+noall", "+answer", "+time=2", "+tries=1", "MX", domain],
                8,
            ) {
                got_mx_records = Self::dig_records_of_type(&output.stdout, "MX");
            }
        }
        for t in got_mx_records {
            result.mx_records.push(t.clone());
            result.all_records.push(DnsRecordEntry {
                record_type: "MX".to_string(),
                value: t,
                is_secure: false,
            });
        }
        // NS natif UDP
        let mut got_ns_records: Vec<String> = Vec::new();
        if let Some(ans) =
            crate::modules::netdns::query(domain, "NS", std::time::Duration::from_secs(2))
        {
            for (v, _) in &ans.answers {
                let t = v.trim().trim_matches('"').to_string();
                if !t.is_empty() {
                    got_ns_records.push(t);
                }
            }
        }
        if got_ns_records.is_empty() {
            if let Some(output) = crate::utils::run_tool(
                "dig",
                &["+noall", "+answer", "+time=2", "+tries=1", "NS", domain],
                8,
            ) {
                got_ns_records = Self::dig_records_of_type(&output.stdout, "NS");
            }
        }
        for t in got_ns_records {
            result.ns_records.push(t.clone());
            result.all_records.push(DnsRecordEntry {
                record_type: "NS".to_string(),
                value: t,
                is_secure: false,
            });
        }
        // TXT natif UDP
        let mut got_txt_records: Vec<String> = Vec::new();
        if let Some(ans) =
            crate::modules::netdns::query(domain, "TXT", std::time::Duration::from_secs(2))
        {
            for (v, _) in &ans.answers {
                let t = v.trim().trim_matches('"').to_string();
                if !t.is_empty() {
                    got_txt_records.push(t);
                }
            }
        }
        if got_txt_records.is_empty() {
            if let Some(output) = crate::utils::run_tool(
                "dig",
                &["+noall", "+answer", "+time=2", "+tries=1", "TXT", domain],
                8,
            ) {
                got_txt_records = Self::dig_records_of_type(&output.stdout, "TXT");
            }
        }
        for t in got_txt_records {
            result.txt_records.push(t.clone());
            result.all_records.push(DnsRecordEntry {
                record_type: "TXT".to_string(),
                value: t,
                is_secure: false,
            });
        }
        // SOA
        if let Some(output) =
            crate::utils::run_tool("dig", &["+short", "+time=2", "+tries=1", "SOA", domain], 8)
        {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                result.soa_record = Some(s.clone());
                result.all_records.push(DnsRecordEntry {
                    record_type: "SOA".to_string(),
                    value: s,
                    is_secure: false,
                });
            }
        }

        // CAA natif UDP
        let mut got_caa_records: Vec<String> = Vec::new();
        if let Some(ans) =
            crate::modules::netdns::query(domain, "CAA", std::time::Duration::from_secs(2))
        {
            for (v, _) in &ans.answers {
                let t = v.trim().trim_matches('"').to_string();
                if !t.is_empty() {
                    got_caa_records.push(t);
                }
            }
        }
        if got_caa_records.is_empty() {
            if let Some(output) = crate::utils::run_tool(
                "dig",
                &["+noall", "+answer", "+time=2", "+tries=1", "CAA", domain],
                8,
            ) {
                got_caa_records = Self::dig_records_of_type(&output.stdout, "CAA");
            }
        }
        for t in got_caa_records {
            result.caa_records.push(t.clone());
            result.all_records.push(DnsRecordEntry {
                record_type: "CAA".to_string(),
                value: t,
                is_secure: false,
            });
        }
        // DNSSEC : détection via le flag AD (Authentic Data) de la réponse DS.
        // Plus fiable que DNSKEY : certains résolveurs ne relaient pas les DNSKEY,
        // ce qui produisait des faux négatifs sur des zones pourtant signées.
        if let Some(out) = crate::utils::run_tool(
            "dig",
            &["+dnssec", "+comments", "+time=2", "+tries=1", "DS", domain],
            8,
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            let ad_flag = s.lines().any(|l| {
                l.trim_start().starts_with(";; flags:") && l.split_whitespace().any(|t| t == "ad")
            });
            if ad_flag {
                result.dnssec_active = true;
                result.all_records.push(DnsRecordEntry {
                    record_type: "DS".to_string(),
                    value: "DNSSEC actif (flag AD validé par le résolveur)".to_string(),
                    is_secure: false,
                });
            }
        }

        // DMARC (_dmarc.domain) — hostname PUIS apex en fallback : la politique
        // DMARC vit au niveau organizational (presque jamais sur www.).
        // Vérifié live : www.pharma.example.com muet, apex = p=reject.
        let dmarc_candidates = {
            let apex = Self::registrable_domain(domain);
            if apex != domain {
                vec![domain.to_string(), apex]
            } else {
                vec![domain.to_string()]
            }
        };
        'outer: for cand in &dmarc_candidates {
            let dmarc_target = format!("_dmarc.{}", cand);
            if let Some(output) = crate::utils::run_tool(
                "dig",
                &["+short", "+time=2", "+tries=1", "TXT", &dmarc_target],
                8,
            ) {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    let clean = line.trim().trim_matches('"');
                    if clean.starts_with("v=DMARC1") {
                        result.dmarc_found = true;
                        result.dmarc_record = Some(clean.to_string());

                        // Détection politique p=
                        for part in clean.split(';') {
                            let p = part.trim();
                            if p.starts_with("p=") {
                                result.dmarc_policy = Some(p.trim_start_matches("p=").to_string());
                            }
                        }

                        let tagged = if cand != domain {
                            format!("[apex {cand}] {clean}")
                        } else {
                            clean.to_string()
                        };
                        result.all_records.push(DnsRecordEntry {
                            record_type: "DMARC".to_string(),
                            value: tagged,
                            is_secure: false,
                        });
                        break 'outer;
                    }
                }
            }
        }
    }
}
