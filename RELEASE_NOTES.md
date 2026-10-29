## MCP Intruder v0.6.3 — binaires multi-OS

Serveur Model Context Protocol offensif : expose le moteur de scan de surface
(DNS, ports, TLS, HTTP, 39 modules lecture-seule) comme outils MCP
(Streamable HTTP, LiteMCP) + catalogue PostgreSQL.

### Binaires

| Plateforme | Fichier |
|---|---|
| Linux x86_64 | `mcp-intruder-linux-x86_64.tar.gz` |
| macOS arm64 (Apple Silicon) | `mcp-intruder-macos-arm64.tar.gz` |
| macOS x86_64 (Intel) | `mcp-intruder-macos-x86_64.tar.gz` |
| Windows x86_64 | `mcp-intruder-windows-x86_64.zip` |

Chaque archive contient `mcp_intruder` (CLI + TUI), `mcp_server` (serveur MCP
Streamable HTTP), `LICENSE` et `README.md`.

### Corrigé

- **Portabilité Windows/macOS** — `envx` et `gitdump` utilisaient
  `std::os::unix::fs::PermissionsExt` hors bloc `#[cfg(unix)]` et écrivaient en
  `/tmp/...` : le crate ne compilait pas sous Windows. Nouveau helper portable
  `utils::write_private_file()` (mode 0600 sous Unix, ACL héritée sous Windows)
  et chemin via `std::env::temp_dir()`.
- **Schéma canonique** — `schema_full.sql` plaçait la virgule de séparation de
  colonne après le commentaire inline, donc commentée par SQL : le
  `CREATE TABLE audit_scans` échouait en erreur de syntaxe et le schéma ne
  s'appliquait jamais sur une base vierge. Virgule repositionnée avant le
  commentaire.
- **Fixture de test** — la purge des données avait substitué `evil-veridy.ca`
  par `evil.example.com`, qui est un sous-domaine valide de `example.com` (le
  point est la frontière) : le test échouait à tort. Fixture restaurée en
  `evil-example.com`.

### Ajouté

- CI multi-OS (clippy `-D warnings`, `cargo fmt --check`, tests, build release)
  sur Linux, macOS et Windows.
- Pipeline de release : publication automatique des 4 archives sur tag `v*`.

### Installation rapide

```bash
tar -xzf mcp-intruder-linux-x86_64.tar.gz
sudo cp mcp-intruder-linux-x86_64/mcp_intruder /usr/local/bin/
sudo cp mcp-intruder-linux-x86_64/mcp_server  /usr/local/bin/
```

Serveur MCP :

```bash
mcp_server --bind 127.0.0.1:7808 --db mcp_intruder_audit
# route MCP : http://127.0.0.1:7808/mcp
# sonde de vie : http://127.0.0.1:7808/health
```

### Prérequis

- PostgreSQL (socat/Unix socket) pour la persistance du catalogue — optionnel
  via `--no-db`.
- Outils Kali optionnels pour les modules enrichis : `nmap`, `nuclei`, `nikto`,
  `wafw00f`, `whatweb`, `sslscan`, `ffuf`, `dnsrecon`, `theHarvester`,
  `obscura`, `dig`, `curl`, `openssl`, `psql` + wordlists SecLists.
