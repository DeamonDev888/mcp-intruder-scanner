// src/wizard/server.rs — Serveur HTTP local de l'assistant (127.0.0.1).
//
// Meme architecture que le tableau de bord : un TcpListener std, un thread
// par requete, aucune dependance HTTP externe. L'assistant sert :
//   GET  /                 page unique de l'assistant
//   GET  /api/diagnostic   etat courant de la plateforme
//   POST /api/install      installe le runtime de conteneur
//   POST /api/pull         telecharge l'image Kali officielle
//   POST /api/verify       controle final de l'outillage
//   GET  /api/assets/*     CSS et JS inline

use crate::wizard::{api, ui};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

pub struct Server {
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

/// Lit le corps d'une requete POST (limite a 64 Ko : l'assistant n'envoie
/// que des actions, jamais de donnees volumineuses).
fn read_body(stream: &mut std::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 65_536 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn route(method: &str, path: &str) -> Resp {
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => html(ui::page()),

        ("GET", "/api/health") => ok_json(
            serde_json::json!({
                "ok": true,
                "version": env!("CARGO_PKG_VERSION"),
                "image": crate::platform::KALI_IMAGE,
            })
            .to_string(),
        ),

        ("GET", "/api/diagnostic") => ok_json(
            serde_json::to_string(&api::diagnose()).unwrap_or_else(|e| {
                format!("{{\"error\":\"serialisation: {e}\"}}")
            }),
        ),

        ("POST", "/api/install") => {
            let r = api::install_runtime();
            ok_json(serde_json::to_string(&r).unwrap_or_default())
        }

        ("POST", "/api/pull") => {
            let r = api::pull_image();
            ok_json(serde_json::to_string(&r).unwrap_or_default())
        }

        ("POST", "/api/verify") => {
            let r = api::verify();
            ok_json(serde_json::to_string(&r).unwrap_or_default())
        }

        ("GET", "/api/assets/app.css") => (
            200,
            "text/css; charset=utf-8",
            ui::CSS.to_string(),
        ),
        ("GET", "/api/assets/app.js") => (
            200,
            "application/javascript; charset=utf-8",
            ui::JS.to_string(),
        ),

        ("GET", "/favicon.ico") => (
            200,
            "image/svg+xml",
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' fill='#0d0a07'/><circle cx='16' cy='16' r='7' fill='none' stroke='#d9a24e' stroke-width='2'/><circle cx='16' cy='16' r='2' fill='#d9a24e'/></svg>"
                .to_string(),
        ),

        _ => err_json(404, "route inconnue"),
    }
}

impl Server {
    /// Demarre le serveur de l'assistant et renvoie l'adresse effective.
    pub fn serve(self) -> std::io::Result<()> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr)?;
        let local = listener.local_addr()?;
        println!("[wizard] assistant disponible sur http://{local}");
        println!(
            "[wizard] ouvrez cette URL dans votre navigateur pour configurer l'outillage Kali"
        );

        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

            let mut buf = [0u8; 8192];
            let n = match stream.read(&mut buf) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let mut parts = req.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_string();
            let target = parts.next().unwrap_or("/").to_string();
            let path = target.split('?').next().unwrap_or("/").to_string();

            if method == "POST" {
                let _ = read_body(&mut stream);
            }

            let (code, ctype, body) = route(&method, &path);
            let head = format!(
                "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reason(code),
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
        Ok(())
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}
