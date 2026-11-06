## MCP Intruder v0.6.10 — binaires multi-OS

Serveur Model Context Protocol offensif : expose le moteur de scan de surface
(DNS, ports, TLS, HTTP, 39 modules lecture seule) comme outils MCP
(Streamable HTTP, LiteMCP) + catalogue PostgreSQL.

### Binaires

| Plateforme | Fichier |
|---|---|
| Linux x86_64 | `mcp-intruder-linux-x86_64.tar.gz` |
| macOS arm64 (Apple Silicon) | `mcp-intruder-macos-arm64.tar.gz` |
| macOS x86_64 (Intel) | `mcp-intruder-macos-x86_64.tar.gz` |
| Windows x86_64 | `mcp-intruder-windows-x86_64.zip` |

Chaque archive contient `mcp_intruder` (CLI + TUI), `mcp_intruder_server`
(serveur MCP Streamable HTTP), `wizard` (assistant de configuration),
`dashboard`, `LICENSE` et `README.md`.

### Changement de nom

- **`mcp_server` devient `mcp_intruder_server`** : `mcp_server` est un nom
  générique qui entrait en collision avec d'autres serveurs MCP de la machine.
  Les archives, le `Dockerfile`, le wizard et le README suivent. Si un
  déploiement existant appelle `mcp_server`, renommez le lien ou mettez à jour
  la ligne de commande.

### Ajouté

- **Image serveur conteneurisée** : build multi-stage (Rust → image Kali avec
  les 20 paquets), `ENTRYPOINT ["mcp_intruder_server"]` + `CMD ["--bind",
  "0.0.0.0:7808"]`. Le serveur démarre avec le conteneur, sans commande.
- **Assistant `wizard` natif** : programme de console, identique sous Windows,
  macOS et Linux (y compris un serveur sans affichage). Diagnostic des quatre
  étapes, menu d'actions limité à ce qui est utile, exécution après un choix
  explicite, puis rappel des commandes de lancement. Aucun serveur HTTP, aucune
  page web, aucun navigateur. `--headless` produit le rapport et les commandes
  exactes sans interaction ; `--pause` attend Entrée avant de fermer (lancement
  par double-clic).

### Corrigé

- **Windows — détection de l'outillage** : le PATH ne contient pas
  d'extension. La recherche d'un binaire résout désormais `PATHEXT`
  (`docker.exe`, `nmap.exe`…) au lieu de ne voir que les shims sans extension
  livrés par Docker Desktop. Un Docker installé par winget/Chocolatey est
  maintenant reconnu.
- **Runtime installé mais démon arrêté** : le wizard distinguait mal les deux
  cas. `docker info` est sondé ; si le démon ne répond pas (Docker Desktop
  fermé sous Windows/macOS, service arrêté sous Linux), l'étape passe en
  avertissement, l'outillage n'est pas déclaré opérationnel et la consigne de
  démarrage est affichée (`Docker Desktop`, `open -a Docker`,
  `sudo systemctl start docker`). L'installation du runtime n'est plus
  relancée inutilement.
- **Linux — gestionnaire de paquets** : l'assistant proposait `apt-get` sur
  toutes les distributions. Il détecte maintenant `apt`, `dnf`, `pacman`,
  `zypper` ou `apk` et propose la commande correspondante.
- **macOS** : la commande d'installation du cask est suivie d'une tentative de
  démarrage de Docker.app ; `colima` est proposé en alternative.
- **Windows — winget** : ajout de `--accept-source-agreements` et
  `--accept-package-agreements`, sans quoi l'installation non interactive
  échoue.
- **Nom affiché de l'assistant** : l'aide et les messages parlaient de
  `mcp-intruder-wizard` alors que le binaire installé est `wizard`.

### Retiré

- **Mode web du wizard** (page servie sur `127.0.0.1:8098`, modules `server` et
  `ui`) : supprimé. L'assistant est un programme de console natif, identique
  sur les trois systèmes. `--port` et `--no-browser` n'existent plus.
