use std::net::{IpAddr, ToSocketAddrs};

/// Validation et résolution de la cible. Aucune restriction normative :
/// l'opérateur est maître de ce qu'il scanne. On valide uniquement :
///   - Format du host (regex stricte : lettres, chiffres, . - _, longueur 1..=253)
///   - Résolution DNS effective
///   - Déduplication des IPs
pub struct TargetParser;

#[derive(Debug, PartialEq, Eq)]
pub enum TargetVerdict {
    Resolved(Vec<IpAddr>),
    InvalidFormat(String),
    Unresolvable(String),
}

impl TargetParser {
    /// Valide UNIQUEMENT le format d'une cible (aucun réseau) et renvoie la
    /// cible normalisée (trim + minuscules). Accepte :
    ///   - un hostname (labels alphanum + `-` + `_`, 1..=63 par label,
    ///     total 1..=253 caractères) ;
    ///   - une IP v4/v6 brute ;
    ///   - le suffixe optionnel `:port` (0..=65535) derrière un hostname
    ///     ou une IP v4 (audits HTTP).
    pub fn validate_format(target: &str) -> Result<String, String> {
        let trimmed = target.trim().to_lowercase();
        if trimmed.is_empty() {
            return Err("Cible vide".into());
        }
        if trimmed.len() > 253 {
            return Err(format!(
                "Cible trop longue : {} caractères (max 253)",
                trimmed.len()
            ));
        }

        // IP brute (v4/v6) : acceptée telle quelle.
        if trimmed.parse::<IpAddr>().is_ok() {
            return Ok(trimmed);
        }

        // Suffixe ":port" optionnel — jamais une IPv6 nue (traitée plus haut)
        // ni un host contenant déjà deux-points (IPv6 sans crochet : refusée).
        let host = match trimmed.rsplit_once(':') {
            Some((host, port))
                if !host.is_empty() && !host.contains(':') && port.parse::<u16>().is_ok() =>
            {
                host
            }
            _ => trimmed.as_str(),
        };

        // Hostname : alphanum + . - _, chaque label 1..=63, séparés par .
        let host_ok = host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
        if !host_ok {
            return Err(format!(
                "Format de cible invalide : '{trimmed}' (attendu : hostname lettres/chiffres/./-/_, IP, ou hote:port)"
            ));
        }
        Ok(trimmed)
    }

    /// Valide le format et résout la cible en adresses IP.
    pub fn resolve(target: &str) -> TargetVerdict {
        let trimmed = match Self::validate_format(target) {
            Ok(t) => t,
            Err(reason) => return TargetVerdict::InvalidFormat(reason),
        };

        // IP directe → pas de résolution DNS
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return TargetVerdict::Resolved(vec![ip]);
        }

        // Retirer un éventuel suffixe :port (la résolution se fait sur le host)
        let host = trimmed
            .rsplit_once(':')
            .filter(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok())
            .map_or(trimmed.as_str(), |(h, _)| h);

        // Hostname → résolution DNS
        let host_port = format!("{host}:80");
        match host_port.to_socket_addrs() {
            Ok(addrs) => {
                let mut ips: Vec<IpAddr> = Vec::new();
                for sock_addr in addrs {
                    let ip = sock_addr.ip();
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                if ips.is_empty() {
                    TargetVerdict::Unresolvable(format!(
                        "Aucune adresse IP résolue pour '{host}'"
                    ))
                } else {
                    TargetVerdict::Resolved(ips)
                }
            }
            Err(e) => TargetVerdict::Unresolvable(format!(
                "Échec de résolution DNS pour '{host}': {e}"
            )),
        }
    }
}
