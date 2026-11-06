# Image complète : serveur MCP + outillage Kali (20 paquets).
# Le serveur démarre AVEC le conteneur : l'ENTRYPOINT s'en charge, aucun
# argument à passer sur la ligne `docker run`.

FROM rust:1.90-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin mcp_intruder_server

FROM kalilinux/kali-rolling:latest
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nmap nikto sslscan wafw00f whatweb ffuf dnsrecon dnsutils whois theharvester \
        rustscan sqlmap subfinder httpx-toolkit nuclei curl git openssl python3 netcat-openbsd \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/mcp_intruder_server /usr/local/bin/mcp_intruder_server

EXPOSE 7808
ENTRYPOINT ["mcp_intruder_server"]
CMD ["--bind", "0.0.0.0:7808"]
