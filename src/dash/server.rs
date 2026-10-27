// src/dash/server.rs — routage HTTP et assemblage de la vue.
//
// TcpListener std sur 127.0.0.1, un thread par requête. Aucune dépendance
// HTTP externe. Les requêtes API renvoient du JSON ; la racine renvoie
// l'interface (ui::page_shell). Le client polling appelle /api/stream.

use crate::dash::{
    charts, db, machine,
    model::{Kpis, Overview, Series},
    scans, ui,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

pub struct Server {
    pub db_name: String,
    pub port: u16,
}

type Resp = (u16, &'static str, String);

fn ok_json(body: String) -> Resp {
    (200, "application/json; charset=utf-8", body)
}

fn err_json(code: u16, msg: &str) -> Resp {
    let body = serde_json::json!({ "error": msg }).to_string();
    (code, "application/json; charset=utf-8", body)
}

fn html(body: String) -> Resp {
    (200, "text/html; charset=utf-8", body)
}

/// Construit l'Overview complet. Ne panique jamais : une section en échec
/// renvoie des vecteurs vides, l'interface reste utilisable.
/// Vue vide mais valide : la page s'affiche avec un bandeau d'erreur au lieu
/// d'une page blanche quand le catalogue est momentanément injoignable.
fn empty_overview(db_name: &str, scan: Option<i64>, err: &str) -> Overview {
    Overview {
        generated_at: String::new(),
        db_name: db_name.to_string(),
        current_scan: scan.unwrap_or(0),
        target: String::new(),
        scan_date: String::new(),
        score: 0,
        kpis: Kpis {
            scans: 0,
            targets: 0,
            findings: 0,
            findings_purged: 0,
            modules_total: 0,
            modules_active: 0,
            crit: 0,
            high: 0,
            ports: 0,
            hosts: 0,
            loot: 0,
            db_size_mb: 0.0,
            error: err.to_string(),
        },
        modules: Vec::new(),
        severity: Vec::new(),
        categories: Vec::new(),
        dns_types: Vec::new(),
        header_eval: Vec::new(),
        tools: Vec::new(),
        impacts: Vec::new(),
        findings: Vec::new(),
        scans: Vec::new(),
        ports: Vec::new(),
        hosts: Vec::new(),
        headers: Vec::new(),
        dns: Vec::new(),
        tls: Vec::new(),
        loot: Vec::new(),
        score_series: Series {
            labels: Vec::new(),
            values: Vec::new(),
        },
        findings_series: Series {
            labels: Vec::new(),
            values: Vec::new(),
        },
        port_histogram: Vec::new(),
        live: Vec::new(),
        machine: machine::snapshot(db_name),
    }
}

/// Score global d'un scan (0 si absent). Kpis ne porte pas le score, on lit
/// donc la ligne du scan dans la liste récente.
fn score_of(c: &mut postgres::Client, scan: i64) -> i32 {
    db::fetch_scans(c, 200)
        .iter()
        .find(|s| s.id == scan)
        .map(|s| s.score)
        .unwrap_or(0)
}

pub fn build_overview(db_name: &str, scan: Option<i64>) -> Overview {
    let mut o = match db::connect(db_name) {
        Ok(mut c) => db::fetch_overview(&mut c, db_name, scan)
            .unwrap_or_else(|e| empty_overview(db_name, scan, &e)),
        Err(e) => empty_overview(db_name, scan, &e),
    };
    // Machine et scans live ne dépendent pas de PostgreSQL : on les lit
    // toujours, pour que l'interface reste vivante face à une base
    // momentanément injoignable (bandeau d'erreur plutôt qu'une page blanche).
    o.live = scans::list();
    o.machine = machine::snapshot(db_name);
    o
}

fn route(server: &Server, method: &str, path: &str, query: &str, body: &str) -> Resp {
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            html(ui::page_shell("MCP Intruder · tableau de bord", "scanner offensif · lecture seule", ""))
        }

        ("GET", "/api/overview") => {
            let scan = param_i64(query, "scan");
            let o = build_overview(&server.db_name, scan);
            ok_json(serde_json::to_string(&o).unwrap_or_else(|e| {
                format!("{{\"error\":\"sérialisation: {e}\"}}")
            }))
        }

        // Flux léger pour le polling : KPI + machine + live seulement.
        ("GET", "/api/stream") => {
            let scan = param_i64(query, "scan");
            let mut o = build_overview(&server.db_name, scan);
            o.findings.clear();
            o.hosts.clear();
            o.dns.clear();
            o.headers.clear();
            o.ports.clear();
            ok_json(serde_json::to_string(&o).unwrap_or_else(|e| {
                format!("{{\"error\":\"sérialisation: {e}\"}}")
            }))
        }

        ("GET", "/api/scans") => {
            match db::connect(&server.db_name) {
                Ok(mut c) => ok_json(serde_json::to_string(&db::fetch_scans(&mut c, 50))
                    .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))),
                Err(e) => err_json(503, &e),
            }
        }

        ("GET", "/api/targets") => {
            match db::connect(&server.db_name) {
                Ok(mut c) => ok_json(
                    serde_json::to_string(&db::list_targets(&mut c))
                        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
                ),
                Err(e) => err_json(503, &e),
            }
        }

        // Un graphe isolé : sert le SVG sans repasser par le JS
        // (utile pour le partage d'un graphique ou le débogage).
        ("GET", "/api/chart") => {
            let kind = param_str(query, "kind").unwrap_or_else(|| "score".to_string());
            let tone = param_str(query, "tone").unwrap_or_else(|| "amber".to_string());
            let scan = param_i64(query, "scan").unwrap_or(0);
            let mut c = match db::connect(&server.db_name) {
                Ok(c) => c,
                Err(_) => return html(charts::sparkline(&[], 240, 48, &tone)),
            };
            let svg = match kind.as_str() {
                "donut" => {
                    let b = db::fetch_buckets(&mut c, scan).0;
                    charts::donut(&b, 180)
                }
                "gauge" => {
                    let score = score_of(&mut c, scan);
                    charts::gauge(f64::from(score), 100.0, 180, "score")
                }
                "hbars" => {
                    let b = db::fetch_buckets(&mut c, scan).1;
                    charts::hbars(&b, 640, 22, 10)
                }
                "radar" => {
                    let m = db::fetch_modules(&mut c, scan);
                    let axes: Vec<(String, f64)> = m.iter().map(|x| (x.label.clone(), x.count as f64)).collect();
                    charts::radial_radar(&axes, 20.0, 220)
                }
                "histogram" => {
                    let b = db::fetch_port_histogram(&mut c, scan);
                    charts::histogram(&b, 640, 180)
                }
                "series" => {
                    let s = db::fetch_series(&mut c, None).0;
                    charts::stacked_line(&s, 640, 180, &tone)
                }
                "ring" => {
                    let k = db::fetch_kpis(&mut c, scan);
                    let pct = if k.scans > 0 {
                        (k.modules_active as f64 / k.modules_total.max(1) as f64) * 100.0
                    } else {
                        0.0
                    };
                    charts::ring_progress(pct, 180, &tone, "couverture")
                }
                "heatmap" => {
                    let s = db::fetch_series(&mut c, None).1;
                    charts::heatmap(&s.values, 20)
                }
                // "spark" par défaut : série des scores des derniers scans.
                _ => {
                    let s = db::fetch_series(&mut c, None).0;
                    charts::area_sparkline(&s.values, 640, 180, &tone)
                }
            };
            html(svg)
        }

        // Preview d'une cible sans lancer de scan : c'est ce qui rend
        // l'assistant noob sûr (on montre avant de tirer).
        ("GET", "/api/preview") => match param_str(query, "target") {
            None => err_json(400, "paramètre target manquant"),
            Some(t) => match scans::validate_target(&t) {
                Err(e) => err_json(400, &e),
                Ok(clean) => {
                    let known = match db::connect(&server.db_name) {
                        Ok(mut c) => db::fetch_scans(&mut c, 200)
                            .iter()
                            .any(|s| s.target.eq_ignore_ascii_case(&clean)),
                        Err(_) => false,
                    };
                    ok_json(
                        serde_json::json!({
                            "target": clean,
                            "known": known,
                            "profiles": crate::dash::PROFILES.iter()
                                .map(|(k, f, d)| serde_json::json!({"key":k,"flag":f,"desc":d}))
                                .collect::<Vec<_>>(),
                        })
                        .to_string(),
                    )
                }
            },
        },

        ("POST", "/api/scan/start") => {
            let form = parse_form(body);
            let target = form
                .iter()
                .find(|(k, _)| k == "target")
                .map(|(_, v)| v.clone())
                .or_else(|| param_str(query, "target"))
                .unwrap_or_default();
            let profile = form
                .iter()
                .find(|(k, _)| k == "profile")
                .map(|(_, v)| v.clone())
                .or_else(|| param_str(query, "profile"))
                .unwrap_or_else(|| "full".into());
            match scans::start(&target, &profile) {
                Ok(l) => ok_json(serde_json::to_string(&l).unwrap_or_default()),
                Err(e) => err_json(400, &e),
            }
        }

        ("POST", "/api/scan/stop") => {
            let form = parse_form(body);
            let pid = form
                .iter()
                .find(|(k, _)| k == "pid")
                .map(|(_, v)| v.clone())
                .or_else(|| param_str(query, "pid"))
                .and_then(|v| v.parse::<u32>().ok());
            match pid {
                None => err_json(400, "pid manquant"),
                Some(p) => match scans::stop(p) {
                    Ok(m) => ok_json(serde_json::json!({ "ok": true, "message": m }).to_string()),
                    Err(e) => err_json(400, &e),
                },
            }
        }

        ("GET", "/api/live") => ok_json(serde_json::to_string(&scans::list()).unwrap_or_default()),

        ("GET", "/api/health") => ok_json(
            serde_json::json!({
                "ok": true,
                "db": server.db_name,
                "postgres": db::connect(&server.db_name).is_ok(),
                "scans": scans::list().len(),
            })
            .to_string(),
        ),

        ("GET", "/api/export") => {
            let scan = param_i64(query, "scan");
            let o = build_overview(&server.db_name, scan);
            let body = serde_json::to_string_pretty(&o).unwrap_or_default();
            (
                200,
                "application/json; charset=utf-8",
                body,
            )
        }

        // Favicon inline : évite un 404 dans la console du navigateur.
        ("GET", "/favicon.ico") => (
            200,
            "image/svg+xml",
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' fill='#0d0a07'/><circle cx='16' cy='16' r='7' fill='none' stroke='#d9a24e' stroke-width='2'/><circle cx='16' cy='16' r='2' fill='#d9a24e'/></svg>"
                .to_string(),
        ),

        ("GET", "/api/assets/app.js") => (
            200,
            "application/javascript; charset=utf-8",
            ui::JS.to_string(),
        ),
        ("GET", "/api/assets/app.css") => (
            200,
            "text/css; charset=utf-8",
            ui::CSS.to_string(),
        ),

        _ => err_json(404, "route inconnue"),
    }
}

fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            match (it.next(), it.next()) {
                (Some(k), Some(v)) => Some((url_decode(k), url_decode(v))),
                _ => None,
            }
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn param_str(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let mut it = kv.splitn(2, '=');
        match (it.next(), it.next()) {
            (Some(k), Some(v)) if k == key => Some(url_decode(v)),
            _ => None,
        }
    })
}

fn param_i64(query: &str, key: &str) -> Option<i64> {
    param_str(query, key).and_then(|v| v.parse().ok())
}

impl Server {
    pub fn serve(self) -> std::io::Result<()> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr)?;
        println!("[dashboard] écoute sur http://{addr}");

        // Contrôle de disponibilité du catalogue au démarrage : si la base est
        // muette on le dit tout de suite plutôt que de laisser croire que
        // l'interface est vide parce qu'il n'y a rien à afficher.
        match db::connect(&self.db_name) {
            Ok(mut c) => {
                // fetch_scans renvoie un Vec (vide si la lecture échoue) :
                // une base muette ne doit pas empêcher le démarrage.
                let s = db::fetch_scans(&mut c, 1);
                println!(
                    "[dashboard] catalogue={} scans={} cible={}",
                    self.db_name,
                    s.len(),
                    s.first().map(|x| x.target.clone()).unwrap_or_default()
                );
            }
            Err(e) => eprintln!("[dashboard] ATTENTION PostgreSQL injoignable : {e}"),
        }

        // Thread d'acceptation : chaque connexion part dans son propre thread
        // pour qu'une requête lente (scan complet) ne bloque pas le reste.
        let srv = Arc::new(self);

        // Amorce du compteur CPU : cpu_pct() compare deux lectures de /proc/stat,
        // donc sans reference anterieure le PREMIER appel renvoie 0.0 et
        // l'interface affiche « CPU 0 % » alors que la machine travaille. Deux
        // lectures espacees de 200 ms etablissent la reference : la premiere
        // page servie affiche donc une valeur reelle, pas zero.
        {
            let _ = machine::snapshot(&srv.db_name);
            std::thread::sleep(Duration::from_millis(200));
            let _ = machine::snapshot(&srv.db_name);
        }

        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let srv = Arc::clone(&srv);
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut buf = [0u8; 8192];
                let Ok(n) = stream.read(&mut buf) else { return };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let mut parts = req.split_whitespace();
                let method = parts.next().unwrap_or("GET").to_string();
                let target = parts.next().unwrap_or("/").to_string();
                let (path, query) = match target.split_once('?') {
                    Some((p, q)) => (p.to_string(), q.to_string()),
                    None => (target.clone(), String::new()),
                };

                // Corps HTTP séparé après le double CRLF : POST /api/scan/*
                // envoie un corps application/x-www-form-urlencoded.
                let body = req
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b.to_string())
                    .unwrap_or_default();

                let (code, ctype, body_out) = route(&srv, &method, &path, &query, &body);
                let head = format!(
                    "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\r\n",
                    reason(code),
                    body_out.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body_out.as_bytes());
                let _ = stream.flush();
            });
        }
        Ok(())
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}
