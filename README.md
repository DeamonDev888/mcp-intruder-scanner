<p align="center">
  <img src="assets/mcp_intruder_banner.png" alt="MCP INTRUDER OFFENSIVE SURFACE SCANNER" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust%202021-orange?style=for-the-badge&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux%20Rolling-blue?style=for-the-badge&logo=kali-linux" alt="Kali Linux">
  <img src="https://img.shields.io/badge/Database-PostgreSQL%2018--Tables-336791?style=for-the-badge&logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Modules-24--Offensive-red?style=for-the-badge" alt="24 modules offensifs">
  <img src="https://img.shields.io/badge/Output-JSON%20Ready%20%7C%20TUI-cyan?style=for-the-badge" alt="CLI & JSON">
</p>

---

# 🛡️ MCP INTRUDER — Cyber Intelligence & Offensive Surface Engine 360°

> **Moteur modulaire d'audit de sécurité offensif et de cartographie de surface d'attaque.**
> Conçu pour être exécuté aussi bien par un **opérateur humain** (TUI interactif) que par un **agent IA autonome** en ligne de commande (CLI / JSON natif).

---

## 🤖 Guide Spécifique pour Agents IA & Automatisation CLI

> [!IMPORTANT]
> **Règle d'or pour les agents autonomes** :
> - Ne lancez **JAMAIS** `mcp-intruder` sans argument en script automatisé : cela déclenche la console TUI interactive qui attend des pressions de touches (`stdin`).
> - Pour une utilisation automatisée, utilisez directement `mcp_intruder` ou le wrapper `mcp-intruder` avec une **cible explicite** et des options CLI.
> - Utilisez le flag `--json` (ou `-j`) pour obtenir une sortie structurée directement exploitable par vos fonctions ou via `jq`.
> - **Par défaut, chaque scan est persisté en PostgreSQL** (12 tables relationnelles + payload JSONB). Utilisez `--no-db` pour le mode éphémère.

### 1. Commandes Recommandées pour Agents (Mode Non-Interactif)

```bash
# ⚡ 1. Audit rapide Core Rust (~1.5s) avec sortie JSON pure :
mcp_intruder example.com --fast --json

# 🌐 2. Audit de surface web standard (WAF + Tech + TLS + Typo + Httpx) :
mcp_intruder example.com --web --json

# 👑 3. Audit exhaustif 360° (15 modules Kali : SQLMap EXCLU, opt-in via --sqlmap) :
mcp_intruder example.com --full --json
mcp_intruder example.com --full --sqlmap --json   # avec SQLMap (16 modules actifs)

# 🔬 4. Lancement ciblé de modules précis :
mcp_intruder example.com --nmap --nuclei --json
mcp_intruder example.com -m rustscan,httpx,waf --json
mcp_intruder example.com --httpx --rustscan --sqlmap  # ProjectDiscovery + SQLMap

# 🗄️ 5. Consultation de l'historique PostgreSQL (10 derniers audits) :
mcp_intruder history 10
mcp_intruder history --target example.com  # filtré par cible

# 🛠️ 6. Vérification de l'environnement et disponibilité des outils :
mcp_intruder tools
```

### 2. Extraction & Parsing JSON pour Agents (`jq`)

Lorsque le flag `--json` est actif, le TUI est désactivé et `mcp_intruder` émet un objet JSON strict sur `stdout` :

```bash
# Récupérer uniquement le score global (0 à 100) :
mcp_intruder example.com -1 -j | jq '.overall_score'

# Extraire les vulnérabilités de sévérité CRITICAL ou HIGH :
mcp_intruder example.com -3 -j | jq '.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")'

# Lister tous les ports ouverts découverts :
mcp_intruder example.com -1 -j | jq '[.ports[] | select(.is_open) | .port]'

# Vérifier la présence d'une politique SPF / DMARC valide :
mcp_intruder example.com -1 -j | jq '{spf: .dns.spf_found, dmarc: .dns.dmarc_found}'

# Lister les technologies détectées par HTTPx (ProjectDiscovery) :
mcp_intruder example.com --httpx -j | jq '.http_probe[].technologies'

# Lister les ports vus par RustScan mais absents du scan Core :
mcp_intruder example.com --rustscan -j | jq '.rustscan.open_ports'

# Lister les injections SQL confirmées par SQLMap :
mcp_intruder example.com --sqlmap -j | jq '.sqli[] | {url, parameter, dbms}'
```

### 3. Matrice des Arguments & Codes de Retour (CLI Matrix)

| Argument / Flag | Description pour l'Agent | Temps Moyen | Dépendances |
|---|---|:---:|:---:|
| `-1`, `--fast` | Scan natif pur Rust (Ports, TLS, DNS, GéoIP) | ~1.5s | Zéro (Rust pur) |
| `-2`, `--web` | WAFW00F + WhatWeb + SSLScan + Dnstwist + **HTTPx** | ~7-12s | Python / Ruby / C / pdhttpx |
| `-3`, `--full` | **Audit complet 360°** (15 modules : SQLMap EXCLU, opt-in) | ~60-90s | Suite Kali |
| `-4`, `--infra` | Nmap (-sV -sC) + SSLScan + **RustScan** | ~25-35s | nmap, sslscan, rustscan |
| `-5`, `--vuln` | Nuclei (templates CVEs) + Nikto + Nmap + **SQLMap** | ~45-60s | nuclei, nikto, nmap, sqlmap |
| `-d`, `--discovery`| Ffuf (SecLists) + Nikto + Wafw00f | ~40s | ffuf, nikto |
| `--httpx` | Probe HTTP massif + tech detect (sous-domaines inclus) | ~5-15s | pdhttpx (ProjectDiscovery) |
| `--rustscan` | Balayage SYN ultra-rapide des 65535 ports | ~7s | rustscan |
| `--sqlmap` | Détection SQL injection (opt-in, EXCLU de --full) | ~5-60s | sqlmap |
| `--subfinder` | Énumération passive sous-domaines (auto si subfinder installé) | ~3s | subfinder |
| `-j`, `--json` | **Désactive le TUI** et émet du JSON machine | - | - |
| `--no-db` | Désactive la persistance PostgreSQL (mode éphémère) | - | - |
| `--timeout <MS>` | Ajuste le timeout TCP (défaut : 800 ms) | - | - |

**Codes de sortie (`Exit Codes`) :**
- `0` : Audit exécuté avec succès, rapport généré et persisté en DB (sauf `--no-db`).
- `1` : Erreur d'arguments CLI, cible invalide/non résoluble, ou échec de connexion critique.

### 4. Persistance PostgreSQL (par défaut)

Chaque scan est **automatiquement persisté** dans une base PostgreSQL locale (`mcp_intruder_audit` par défaut, modifiable via `--db <NAME>`).

**Schéma : 13 tables relationnelles** (écrites par chaque scan, en une transaction atomique) :
- `audit_scans` (header + payload JSONB exhaustif)
- `audit_dns_records`, `audit_ports`, `audit_http_headers`
- `audit_tls_certs` (incluant `valid_from`, `is_self_signed`, `supports_tls10..13`)
- `audit_subdomains`, `audit_findings`
- `audit_geo`, `audit_email_sec`, `audit_web_endpoints`
- `audit_dns_hardening`, `audit_tool_outputs`, `audit_tech` (composants versionnés + verdict EOL), `audit_loot` (fichiers exfiltrés, opt-in `--loot`)
- En complément : `audit_impact` (verdicts des modules de preuve d'impact) et `audit_surface` (cartographie surfx) sont alimentées par les bins dédiés, hors `save_scan`

```bash
# Lister les 10 derniers scans de example.com
sudo -u postgres psql mcp_intruder_audit -c \
  "SELECT id, target, overall_score, open_ports_count, findings_count, created_at
   FROM audit_scans WHERE target='example.com' ORDER BY id DESC LIMIT 10;"

# Lister les raw_output de tous les outils Kali utilisés dans le scan #42
sudo -u postgres psql mcp_intruder_audit -c \
  "SELECT tool_name, status, items_count, LEFT(summary, 80) FROM audit_tool_outputs WHERE scan_id=42;"

# Historique intégré via le binaire :
mcp_intruder history 5 --target example.com
```

---

## ⚡ Aperçu du Terminal TUI (Mode Interactif pour Humains)

Pour un utilisateur en direct sur le serveur Kali, `mcp-intruder` propose une console cyberpunk riche avec monitoring des threads en direct, sparkline des durées, ETA dynamique, et banner final adaptatif (💎 EXCELLENT → ☠️ CRITIQUE) :

<p align="center">
  <img src="assets/mcp-intruder_tui_logo.svg" alt="MCP Intruder TUI Interface" width="920">
</p>

---

## 🔬 Les 24 Modules Spécialisés Embarqués (v0.5)

### Modules Core Rust (toujours actifs)
1. **Ports Scanner** : Balayage TCP Connect des 64 ports critiques (résolution DNS, bannières, services, détection d'edge fantôme).
2. **Géolocalisation & ASN** : Whois + IP-API, ASN, organisation, pays, région.
3. **TLS Auditor** : Chaîne de certification complète, ciphers, validité, support TLS 1.0-1.3.
4. **DNS & Messagerie** : A/AAAA/MX/NS/TXT/CAA/SPF/DMARC/DKIM + DNSSEC.
5. **HTTP Headers** : HSTS, CSP, X-Frame-Options, X-Content-Type-Options, cookies, referrer-policy.
6. **Sous-domaines (Subfinder)** : Énumération passive via ProjectDiscovery subfinder (+ fallback statique 35 préfixes).
7. **Web Endpoints** : security.txt, robots.txt, ALPN, méthodes HTTP autorisées.
8. **Vulnérabilités applicatives** : Regex strictes jQuery, SRI, mixed content, CORS, secrets exposés.
9. **DNS Hardening** : Open resolver, récursion, zone transfer.

### Modules Kali (optionnels via flags ou profils)
10. **Nmap** : Reconnaissance fine des bannières et scripts NSE de vulnérabilités.
11. **Nuclei** : Détection active de CVEs via templates YAML ProjectDiscovery.
12. **Nikto** : Audit des configurations HTTP et fichiers sensibles.
13. **Wafw00f** : Empreinte de pare-feux applicatifs (Cloudflare, AWS WAF, Imperva).
14. **WhatWeb** : Analyse des stacks web (CMS, frameworks JS, serveurs).
15. **SSLScan** : Solidité des suites de chiffrement TLS 1.0-1.3 et failles.
16. **Dnstwist** : Détection d'usurpation, phishing et typosquatting.
17. **Ffuf** : Fuzzing haute vitesse des routes via dictionnaires SecLists.
18. **Whois** : Analyse des registres (CIRA/ICANN), contacts et expiration.
19. **Dnsrecon** : Cartographie SRV, NS et transferts de zone.
20. **theHarvester** : OSINT emails publics et sous-domaines.
21. **Obscura** : Moteur Headless V8, analyse dynamique DOM et screenshot PNG.

### Nouveaux Modules Offensifs v0.2 (ProjectDiscovery + Kali)
22. **HTTPx** (*ProjectDiscovery pdhttpx*) : Probe HTTP/HTTPS massif sur sous-domaines, détection de technologies (Cloudflare, Apache, nginx, etc.), titres, codes de statut.
23. **RustScan** : Balayage SYN ultra-rapide des 65535 ports en ~7 secondes (chose impossible avec notre scanner Core).
24. **SQLMap** (*opt-in explicite*) : Détection automatisée d'injections SQL sur les routes paramétrées. **EXCLU de `--full`** par défaut pour éviter le bruit réseau (charge active). À activer explicitement : `--sqlmap` ou `-5 --vuln`.

> [!NOTE]
> **Subfinder** (ProjectDiscovery) est utilisé **automatiquement** par le module Sous-domaines dès qu'il est installé. Pas besoin de flag.

---

## 🛠️ Déploiement & Installation

```bash
# 1. Compilation depuis le repo :
git clone https://github.com/DeamonDev888/mcp-intruder-scanner.git
cd mcp-intruder-scanner
cargo build --release

# 2. Déploiement global (bin principal + modules d'impact + TUI) :
sudo cp target/release/mcp_intruder /usr/local/bin/mcp_intruder
for b in chainx envx gitdump keyprobe gkeyx spoofcheck subalive surfx cnametake cnamewatch ftpx ftplx lootx impacts mysqlx redisx mongodx elasticx; do
  sudo cp target/release/$b /usr/local/bin/$b
done
sudo cp launch.sh /usr/local/bin/mcp-intruder
sudo chmod +x /usr/local/bin/mcp-intruder

# 3. Schéma PostgreSQL (13 tables de scan + audit_impact/audit_surface) :
sudo -u postgres psql -f init_schema.sql
sudo -u postgres psql -f schema_full.sql   # tables détaillées
sudo -u postgres psql -f init_role.sql     # rôle propriétaire

# 4. Vérification de l'installation :
mcp_intruder tools   # diagnostique les binaires + SecLists + PostgreSQL
```

### Dépendances Optionnelles (modules avancés)

| Outil | Module qui l'utilise | Installation manuelle si absente |
|---|---|---|
| `pdhttpx` | HTTPx (probe HTTP massif) | Téléchargé par `mcp-intruder-install.sh` ou `curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip \| sudo install -m 0755 /dev/stdin /usr/local/bin/pdhttpx` |
| `subfinder` | Sous-domaines (auto) | Téléchargé par `mcp-intruder-install.sh` ou binaire pré-compilé depuis GitHub releases |
| `rustscan` | Scan 65535 ports | `sudo apt install rustscan` |
| `sqlmap` | Injection SQL | `sudo apt install sqlmap` |

> [!WARNING]
> **httpx** (le nom seul) sur Kali est le script Python `encode/httpx`, **PAS** ProjectDiscovery. Le scanner détecte cela et télécharge `pdhttpx` automatiquement. Ne cherchez pas à installer `httpx` via apt.

---

## 🧪 Tests & Qualité

- **152 tests unitaires** : `cargo test` (0 failed) — dont une vingtaine d'anti-régression qui verrouillent les invariants critiques (score clamp, bind params, pas de sh -c, exclusions lab chainx, etc.)
- **Clippy strict** : `cargo clippy --all-targets -- -D warnings` (0 warning)
- **Lint format** : `cargo fmt --check`
- **Build release** : 4.7 MB, optimisé LTO

```bash
cargo test                  # 152/152 OK
cargo clippy --all-targets -- -D warnings  # strict : 0 warning obligatoire
```

---

## 🧩 18 modules d'impact intégrés (même crate depuis v0.5.0)

> Depuis la v0.5.0, les modules d'impact font **partie de `mcp_intruder`** (la crate `crate-impact` a été yankée sur crates.io — un seul crate, un seul `cargo install`).

Tous lecture-seule stricte (GET/DNS uniquement). Verdicts persistés dans `audit_impact`.

| Module | Rôle |
|---|---|
| `mcp_intruder chainx` | Dispatcher automatique — lit le catalogue DB, route chaque finding vers son bin (depuis v0.5.6 : finding DB exposée → `mysqlx`/`redisx`/`mongodx`) |
| `mcp_intruder envx <url>` | Preuve de contenu d'un `.env` exposé (gates anti-faux-positif WAF) |
| `mcp_intruder gitdump <base>` | Preuve d'un dépôt `.git/` exposé (remotes + identités, pas de dump complet) |
| `mcp_intruder keyprobe` (stdin) | Classification + vérif Google Maps des clés API |
| `mcp_intruder gkeyx` (stdin) | 9 sondes + fuite n° projet Google + phase EXPLOIT |
| `mcp_intruder spoofcheck <dom>` | Usurpabilité email (USURPABLE/PARTIEL/PROTEGE) |
| `mcp_intruder subalive <cible> [--fix]` | Re-sonde les sous-domaines « morts » du catalogue |
| `mcp_intruder surfx <cible>` | Cartographie offensive + flags de priorisation (login/admin/dev/vpn) |
| `mcp_intruder cnametake <dom>\|--db <cible>` | Takeover CNAME cloud (15 fingerprints) |
| `mcp_intruder cnamewatch <cible>` | Chien de garde takeover (cron-able, exit 3 = fenêtre ouverte) |
| `mcp_intruder ftpx <hôte>` | Preuve FTP anonyme (230 vs 530) |
| `mcp_intruder ftplx <hôte> [--dl]` | Loot FTP borné + SHA-256 (jamais d'upload) |
| `mcp_intruder lootx [scan_id]` | Qualification des fichiers lootés (SENSIBLE/NEUTRE/SANS_VALEUR) |
| `mcp_intruder mysqlx <hôte>` | Preuve d'exposition MySQL (greeting :3306, zéro credential) |
| `mcp_intruder redisx <hôte>` | Preuve d'exposition Redis (PING :6379, lecture seule) |
| `mcp_intruder mongodx <hôte>` | Preuve d'exposition MongoDB (hello OP_MSG :27017) |
| `mcp_intruder elasticx <hôte> [port]` | Preuve d'exposition Elasticsearch (GET / :9200, lecture seule) |
| `mcp_intruder impacts [--live]` | Dashboard DB + re-vérification live des clés |

```bash
cargo install --path .
mcp_intruder chainx                              # campagne auto sur 30j
mcp_intruder chainx grocer.example.com --force             # une cible
mcp_intruder impacts                            # dashboard
```

## 📚 Voir aussi


- **`CHANGELOG.md`** : historique des versions (v0.1 → v0.5.7)
- **`AUDIT-RUST-2026-09-19.md`** : audit statique complet (81 findings corrigés)
- **`MEMO-SERVEUR-KALI.md`** : notes d'environnement Kali et pièges connus

---

## 🖥️ Serveur MCP

Le binaire `mcp_server` expose le scanner aux agents IA via le protocole **MCP** (Model Context Protocol) :

- **Transport** : Streamable HTTP — `POST /mcp`, bind par défaut `127.0.0.1:7808`
- **Santé** : endpoint `GET /health`
- **16 outils** : `ping`, `scan_target`, `scan_history`, `tools_diag`, `dns_audit`, `tls_audit`, `http_audit`, `whois_audit`, `geo_locate`, `email_sec_audit`, `subdomains_audit`, `crt_sh_lookup`, `waf_detect`, `tech_stack_audit`, `dnsrecon_audit`, `dns_hardening_audit`

---

<p align="center">
  <img src="assets/mcp-intruder_logo.svg" alt="MCP Intruder Logo" width="380">
  <br>
  <sub>Moteur d'audit offensif · 24 modules · 17 modules d'impact · Persistance PostgreSQL · CLI/TUI/JSON</sub>
</p>
