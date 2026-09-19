# MCP-Intruder Scanner — Offensive Surface Scanner

Scan de surface offensif modulaire en Rust : recon DNS, ports, TLS, en-têtes HTTP,
vulnérabilités web, sous-domaines, OSINT — avec orchestration des outils Kali
(nmap, nuclei, nikto, wafw00f, whatweb, sslscan, dnstwist, ffuf, whois, dnsrecon,
theHarvester, subfinder, httpx) et catalogage PostgreSQL optionnel.

## Installation

Trois méthodes, du plus simple au plus contrôlable.

### Méthode 1 — Cargo (depuis crates.io, une fois publié)

```bash
cargo install mcp_intruder
mcp_intruder --version
mcp_intruder example.com --no-db
```

> Le binaire s'installe dans `~/.cargo/bin/mcp_intruder`. Assure-toi que
> `~/.cargo/bin` est dans ton `PATH` (Rustup le fait automatiquement).

### Méthode 2 — Script d'installation (recommandé sur Kali/Debian)

Télécharge et lance en root — il gère Rust, PostgreSQL, les outils Kali et la DB :

```bash
curl -fsSL https://raw.githubusercontent.com/DeamonDev888/mcp-intruder-scanner/main/install.sh -o /tmp/install.sh
sudo bash /tmp/install.sh
```

Ce que fait le script :

| Étape | Action |
|---|---|
| 1 | Détection distro (apt/dnf/pacman) + installation des dépendances système (build-essential, libssl-dev, postgresql, dnsutils, whois, curl, ca-certificates) |
| 2 | Vérification des outils Kali (nmap, nuclei, nikto, wafw00f, whatweb, sslscan, dnstwist, ffuf, dnsrecon, theHarvester) — non bloquant, avertit si absents |
| 3 | Installation de Rust via rustup si absent |
| 4 | Clone du repo dans `/opt/mcp-intruder-scanner` (ou `MCP-INTRUDER_INSTALL_DIR`) |
| 5 | `cargo build --release` |
| 6 | `install` du binaire dans `/usr/local/bin/mcp_intruder` + `launch.sh` → `mcp-intruder` |
| 7 | Création et chargement du schéma PostgreSQL (12 tables) si Postgres joignable |
| 8 | Diagnostic final via `mcp_intruder tools` |

Variables d'environnement surchargeables :

```bash
MCP-INTRUDER_INSTALL_DIR=/opt/custom MCP-INTRUDER_BRANCH=main MCP-INTRUDER_DB=ma_db \
  sudo bash /tmp/install.sh
```

### Méthode 3 — Build depuis les sources (contrôle total)

```bash
git clone https://github.com/DeamonDev888/mcp-intruder-scanner.git
cd mcp-intruder-scanner
cargo build --release

# Binaire : ./target/release/mcp_intruder
# TUI     : ./launch.sh
```

Prérequis manuels : Rust ≥ 1.75, libssl-dev, OpenSSL ≥ 1.1, `psql` (PostgreSQL 12+
si tu veux l'historique), et les outils Kali sur le PATH pour les profils -2 à -5.

## Prérequis

| Outil | Rôle | Optionnel ? |
|---|---|---|
| **Rust ≥ 1.75** (rustup) | compilation du scanner | non |
| `libssl-dev` / `openssl-devel` | wrappers TLS (`openssl s_client`) | non |
| `curl`, `dig` (dnsutils), `whois` | modules HTTP/DNS/geo | non |
| `psql` + PostgreSQL 12+ | catalogage des scans (12 tables) | oui |
| `nmap` | profil `-4` et `-5` (NSE scripts) | oui |
| `nuclei`, `nikto`, `ffuf` | profil `-3`, `-5`, `-d` | oui |
| `wafw00f`, `whatweb`, `sslscan`, `dnstwist` | profil `-2` | oui |
| `dnsrecon`, `theHarvester` | OSINT | oui |
| `subfinder`, `httpx` | sous-domaines avancés | oui |

Diagnostic en local : `mcp_intruder tools` (mode CLI) ou `./launch.sh --check-tools` (TUI).

## Démarrage rapide

```bash
# Scan core (DNS, ports, TLS, HTTP, sous-domaines — 100% Rust + curl/dig/openssl)
mcp_intruder example.com

# Sortie JSON (intégration pipeline)
mcp_intruder example.com --no-db --json

# Profils
mcp_intruder example.com -2        # web : WAF + WhatWeb + SSLScan + Dnstwist
mcp_intruder example.com -4        # infra : Nmap + SSLScan
mcp_intruder example.com -5        # vuln : Nuclei + Nikto + Nmap
mcp_intruder example.com -3        # 360° : tous les outils
mcp_intruder example.com -d        # discovery : Ffuf + Nikto + WAF

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