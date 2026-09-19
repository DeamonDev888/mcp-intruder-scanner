# MCP-Intruder Scanner — Offensive Surface Scanner

Scan de surface offensif modulaire en Rust : recon DNS, ports, TLS, en-têtes HTTP,
vulnérabilités web, sous-domaines, OSINT — avec orchestration des outils Kali
(nmap, nuclei, nikto, wafw00f, whatweb, sslscan, dnstwist, ffuf, whois, dnsrecon,
theHarvester, subfinder, httpx) et catalogage PostgreSQL optionnel.

## Démarrage rapide

```bash
# Prérequis : Rust (cargo), les outils Kali optionnels sur le PATH
cargo build --release

# Scan core (DNS, ports, TLS, HTTP, sous-domaines — 100% Rust + curl/dig/openssl)
./target/release/mcp_intruder example.com

# Sortie JSON (intégration pipeline)
./target/release/mcp_intruder example.com --no-db --json

# Profils
mcp_intruder example.com -2        # web : WAF + WhatWeb + SSLScan + Dnstwist
mcp_intruder example.com -4        # infra : Nmap + SSLScan
mcp_intruder example.com -5        # vuln : Nuclei + Nikto + Nmap
mcp_intruder example.com -3        # 360° : tous les outils
mcp_intruder example.com -d        # découverte : Ffuf + Nikto + WAF

# Historique PostgreSQL
mcp_intruder history 10
mcp_intruder tools                 # diagnostic environnement
```

## Console interactive (TUI)

```bash
./launch.sh                          # menu interactif
./launch.sh --check-tools            # diagnostic outils Kali
./launch.sh --stats                  # dashboard PostgreSQL
./launch.sh --findings HIGH          # constats par sévérité
./launch.sh --scan 14                # inspection d'un scan
./launch.sh -b "cible1,cible2"       # batch
```

## Modules

| Module | Ce qu'il fait |
|---|---|
| `ports` | Scan TCP connect (pool borné 24 workers) + bannières de services |
| `dns` | A/AAAA/MX/NS/TXT/SOA/CAA/DMARC + DNSSEC (flag AD) |
| `email_sec` | SPF lookups (RFC 7208), DKIM, DMARC, MTA-STS, TLS-RPT, BIMI |
| `tls` | Chaîne X.509, expiration, SANs, TLS 1.0/1.1 obsolètes, auto-signé |
| `http` | En-têtes de sécurité (HSTS/CSP/XFO/...), cookies, redirection HTTPS |
| `web_endpoints` | security.txt, robots.txt, méthodes HTTP, ALPN/h2 |
| `subdomains` | Énumération (subfinder + liste statique), vivant/muet, takeover |
| `vuln_audit` | jQuery/Bootstrap obsolètes, SRI, mixed content, CORS, secrets exposés |
| `geo` | Whois IP : ASN, org, pays, région |
| `nmap/nuclei/nikto/ffuf/...` | Wrappers outils Kali avec timeout et parse structuré |

## Sécurité de l'implémentation

- Aucun `sh -c` : tous les sous-processus passent par `Command::new(tool).args([...])`
- Timeout sur **tous** les sous-processus (helper `run_tool` : spawn/poll/kill)
- Panics de modules capturées (`catch_unwind`) — jamais de re-exécution d'outil
- Échappement SQL systématique, fichiers temporaires sanitarisés
- Sortie JSON conforme RFC 8259 (caractères de contrôle échappés)

## Base PostgreSQL (optionnelle)

```bash
createdb mcp_intruder_audit
psql -d mcp_intruder_audit -f init_schema.sql
psql -d mcp_intruder_audit -f schema_full.sql
psql -d mcp_intruder_audit -f schema_deep.sql
```

12 tables relationnelles : scans, findings, ports, headers, certificats TLS,
sous-domaines, géo, email, endpoints, durcissement DNS, sorties d'outils.

## Avertissement

Outil d'audit offensif destiné aux professionnels : **à n'utiliser que sur des
cibles que vous êtes autorisé à tester**. L'opérateur est responsable de la
conformité de ses scans à la loi applicable.

## Licence

Apache License 2.0 — voir [LICENSE](LICENSE).
