// findings/tests.rs — suite de tests du moteur de findings (ex-monolithe).
    use super::*;

    // --- Tests unitaires des sous-évaluateurs isolés (refactor evaluate) ---

    // --- Fix nuit 2026-09-30 : edge uniforme (phantom ports) ---
    // Fixture reelle capturee sur store.example.com (edge Imperva/Incapsula) : la
    // sonde RDP binaire sur :3389 renvoie « HTTP/1.1 400 Bad Request ...
    // X-Iinfo: ... _Incapsula_Resource » — l edge parle HTTP sur un port RDP.
    const IMPERVA_400: &str = "HTTP/1.1 400 Bad Request";
    const MYSQL_ACL_ERR: &str = "Host x is not allowed to connect to this MySQL server";

    #[test]
    fn test_http4xx_status_line_signature() {
        use crate::modules::ports::{http4xx_status_line, PortScanner};
        // Litmus : seule une reponse HTTP 4xx est une signature d edge
        assert_eq!(
            http4xx_status_line(Some(IMPERVA_400)).as_deref(),
            Some("HTTP/1.1 400")
        );
        assert_eq!(
            http4xx_status_line(Some("HTTP/1.0 403 Forbidden")).as_deref(),
            Some("HTTP/1.0 403")
        );
        // Bannieres de VRAIS services : jamais une signature
        assert_eq!(http4xx_status_line(Some(MYSQL_ACL_ERR)), None);
        assert_eq!(http4xx_status_line(Some("220- Pure-FTPd [TLS]")), None);
        assert_eq!(http4xx_status_line(Some("SSH-2.0-OpenSSH_9.2")), None);
        // 2xx/3xx sur port exotique = service HTTP reel, pas un artefact
        assert_eq!(http4xx_status_line(Some("HTTP/1.1 200 OK")), None);
        assert_eq!(http4xx_status_line(None), None);
        let _ = PortScanner::EDGE_UNIFORM_MIN; // rend le seuil visible
    }

    #[test]
    fn test_uniform_edge_downgrades_and_aggregates() {
        use crate::modules::ports::{PortScanResult, PortScanner};
        // Reproduit store.example.com : 3+ ports non-web 400 identiques + ports
        // muets (21/3306 silencieux) + 2 ports web legitimes (80/443).
        let mut ports = vec![
            PortScanResult {
                port: 80,
                is_open: true,
                service_hint: "HTTP",
                banner: Some("HTTP/1.1 301".into()),
                is_phantom_edge: false,
            },
            PortScanResult {
                port: 443,
                is_open: true,
                service_hint: "HTTPS",
                banner: None,
                is_phantom_edge: false,
            },
            PortScanResult {
                port: 3306,
                is_open: true,
                service_hint: "MySQL",
                banner: Some(IMPERVA_400.into()),
                is_phantom_edge: false,
            },
            PortScanResult {
                port: 6379,
                is_open: true,
                service_hint: "Redis",
                banner: Some(IMPERVA_400.into()),
                is_phantom_edge: false,
            },
            PortScanResult {
                port: 3389,
                is_open: true,
                service_hint: "RDP",
                banner: Some(IMPERVA_400.into()),
                is_phantom_edge: false,
            },
            PortScanResult {
                port: 21,
                is_open: true,
                service_hint: "FTP",
                banner: None,
                is_phantom_edge: false,
            },
        ];
        PortScanner::detect_uniform_edge(&mut ports);
        // Edge confirme : ports non-web 400 + muets marques fantomes
        assert!(
            ports
                .iter()
                .find(|p| p.port == 3306)
                .unwrap()
                .is_phantom_edge
        );
        assert!(
            ports
                .iter()
                .find(|p| p.port == 6379)
                .unwrap()
                .is_phantom_edge
        );
        assert!(
            ports
                .iter()
                .find(|p| p.port == 3389)
                .unwrap()
                .is_phantom_edge
        );
        assert!(ports.iter().find(|p| p.port == 21).unwrap().is_phantom_edge);
        // Ports web legitimes jamais touches
        assert!(!ports.iter().find(|p| p.port == 80).unwrap().is_phantom_edge);
        assert!(
            !ports
                .iter()
                .find(|p| p.port == 443)
                .unwrap()
                .is_phantom_edge
        );
        // Findings : PLUS AUCUN HIGH fantome, un seul INFO agrege
        let f = FindingsEngine::eval_ports(&ports, "store.example.com");
        assert!(
            f.iter()
                .all(|x| x.severity == "INFO" || x.severity == "LOW"),
            "findings: {f:?}"
        );
        let agg = f
            .iter()
            .find(|x| x.title.contains("edge répond uniformément"));
        assert!(agg.is_some(), "finding INFO agrege absent: {f:?}");
        assert_eq!(agg.unwrap().severity, "INFO");
    }

    #[test]
    fn test_uniform_edge_not_triggered_below_threshold() {
        use crate::modules::ports::PortScanResult;
        let mut ports = vec![PortScanResult {
            port: 2375,
            is_open: true,
            service_hint: "Docker",
            banner: Some("HTTP/1.1 400 Bad Request".into()),
            is_phantom_edge: false,
        }];
        crate::modules::ports::PortScanner::detect_uniform_edge(&mut ports);
        // 1 seul port 400 : sous le seuil (EDGE_UNIFORM_MIN=3), pas de marquage
        assert!(!ports[0].is_phantom_edge);
        let f = FindingsEngine::eval_ports(&ports, "example.com");
        assert!(!f
            .iter()
            .any(|x| x.title.contains("edge répond uniformément")));
    }

    #[test]
    fn test_real_mysql_not_flagged_phantom() {
        use crate::modules::ports::{PortScanResult, PortScanner};
        // Vrai mysqld (demo-target/cegep-example capture) : la banniere ACL MySQL
        // n est PAS une signature HTTP -> jamais fantome, finding HIGH conserve.
        let mut ports = vec![PortScanResult {
            port: 3306,
            is_open: true,
            service_hint: "MySQL",
            banner: Some(MYSQL_ACL_ERR.into()),
            is_phantom_edge: false,
        }];
        PortScanner::detect_uniform_edge(&mut ports);
        assert!(!ports[0].is_phantom_edge);
        let f = FindingsEngine::eval_ports(&ports, "example.org");
        assert!(f
            .iter()
            .any(|x| x.severity == "HIGH" && x.title.contains("3306")));
    }

    #[test]
    fn test_eval_tls_incomplete_chain_downgrades_medium() {
        // Fix faux positif archambault.ca : « unable to verify the first
        // certificate » = chaine INCOMPLETE (intermediaire GoDaddy non servi),
        // openssl verify -untrusted gdig2.crt leaf -> OK. Pas un CRITICAL.
        let tls = TlsAuditResult {
            subject: Some("CN=www.archambault.ca".into()),
            issues: vec![
                "Erreur de chaîne de confiance : Verification error: unable to verify the first certificate".into(),
            ],
            is_valid: false,
            ..Default::default()
        };
        let f = FindingsEngine::eval_tls(&tls);
        assert!(
            !f.iter().any(|x| x.severity == "CRITICAL"),
            "findings: {f:?}"
        );
        let m = f.iter().find(|x| x.title.contains("incomplète"));
        assert!(
            m.is_some(),
            "finding MEDIUM chaine incomplete absent: {f:?}"
        );
        assert_eq!(m.unwrap().severity, "MEDIUM");
    }

    #[test]
    fn test_eval_tls_truly_invalid_chain_stays_critical() {
        // Vraie chaine invalide (cert compromis/expired CA) : reste CRITICAL
        let tls = TlsAuditResult {
            subject: Some("CN=evil.example".into()),
            issues: vec![
                "Erreur de chaîne de confiance : Verification error: certificate signature failure"
                    .into(),
            ],
            is_valid: false,
            ..Default::default()
        };
        let f = FindingsEngine::eval_tls(&tls);
        assert!(f
            .iter()
            .any(|x| x.severity == "CRITICAL" && x.title.contains("invalide ou compromise")));
    }

    #[test]
    fn test_eval_tls_expiry_ladder() {
        // Présent + valide : ni CRITICAL chaîne, ni expiration
        let tls = TlsAuditResult {
            subject: Some("CN=example.com".into()),
            issuer: Some("Let's Encrypt".into()),
            is_valid: true,
            days_remaining: Some(90),
            ..Default::default()
        };
        let f = FindingsEngine::eval_tls(&tls);
        assert!(
            f.is_empty(),
            "certificat sain = aucun finding TLS, got {:?}",
            f
        );

        // Expiré depuis 3 jours : CRITICAL avec le titre exact du monolithe
        let tls = TlsAuditResult {
            subject: Some("CN=example.com".into()),
            is_valid: true,
            days_remaining: Some(-3),
            ..Default::default()
        };
        let f = FindingsEngine::eval_tls(&tls);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "CRITICAL");
        assert_eq!(f[0].title, "Certificat TLS EXPIRÉ depuis 3 jour(s)");

        // 20 jours : MEDIUM (palier < 30)
        let tls = TlsAuditResult {
            subject: Some("CN=example.com".into()),
            is_valid: true,
            days_remaining: Some(20),
            ..Default::default()
        };
        let f = FindingsEngine::eval_tls(&tls);
        assert_eq!((f.len(), f[0].severity), (1, "MEDIUM"));

        // Aucun certificat récupéré : unfinding INFO, pas un CRITICAL
        let f = FindingsEngine::eval_tls(&TlsAuditResult::default());
        assert_eq!((f.len(), f[0].severity, f[0].category), (1, "INFO", "TLS"));
    }

    #[test]
    fn test_eval_ports_loopback_db_not_flagged() {
        // 5432 sur une cible loopback = INFO (service local), pas HIGH
        let ports = vec![PortScanResult {
            port: 5432,
            is_open: true,
            service_hint: "postgresql",
            banner: None,

            is_phantom_edge: false,
        }];
        let f = FindingsEngine::eval_ports(&ports, "127.0.0.1");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "INFO");
        assert!(f[0].title.contains("non exposé publiquement"));

        // Même port sur un domaine public = HIGH
        let f = FindingsEngine::eval_ports(&ports, "example.com");
        assert_eq!((f.len(), f[0].severity), (1, "HIGH"));

        // Bannière courte (<= 8 chars) ignorée ; Telnet = CRITICAL
        let ports = vec![
            PortScanResult {
                port: 80,
                is_open: true,
                service_hint: "http",
                banner: Some("ssh".into()),

                is_phantom_edge: false,
            },
            PortScanResult {
                port: 23,
                is_open: true,
                service_hint: "telnet",
                banner: None,

                is_phantom_edge: false,
            },
        ];
        let f = FindingsEngine::eval_ports(&ports, "example.com");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, "CRITICAL");
        assert!(f[0].title.contains("Telnet"));
    }

    #[test]
    fn test_eval_dns_bare_ip_skips_all() {
        // Cible IP nue : tout le bloc DNS/email est sauté, quel que soit l'état
        // (réaliste : aucun audit DNS n'a lieu, dmarc_policy reste None)
        let dns = DnsAuditResult {
            domain: "192.0.2.10".into(),
            spf_found: false,
            mx_records: vec!["mail.example.com".into()],
            ..Default::default()
        };
        let f = FindingsEngine::eval_dns(&dns, true);
        assert!(f.is_empty(), "IP nue = zéro finding DNS, got {:?}", f);

        // Même état sur un domaine : findings dans l'ordre exact du monolithe
        let dns = DnsAuditResult {
            domain: "example.com".into(),
            dmarc_found: true,
            dmarc_policy: Some("none".into()),
            ..dns
        };
        let f = FindingsEngine::eval_dns(&dns, false);
        let got: Vec<_> = f.iter().map(|x| (x.severity, x.category)).collect();
        assert_eq!(
            got,
            vec![
                ("HIGH", "DNS"),   // SPF absent
                ("LOW", "DNS"),    // DMARC p=none
                ("LOW", "DNS"),    // DNSSEC absent
                ("INFO", "EMAIL"), // MX présents
                ("LOW", "DNS"),    // CAA absents
            ]
        );
    }

    #[test]
    fn test_eval_http_cookies_and_hsts_max_age() {
        // Pas de service HTTP : un seul unfinding INFO, cookies ignorés
        let http = HttpAuditResult {
            http_status: 0,
            cookies: vec![crate::modules::http::CookieAuditEntry {
                name: "sid".into(),
                secure: false,
                http_only: false,
                same_site: None,
            }],
            ..Default::default()
        };
        let f = FindingsEngine::eval_http(&http);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].title,
            "Aucun serveur HTTP/HTTPS accessible en tête de cible"
        );

        // Service présent : cookie non durci signalé + HSTS max-age trop court
        let http = HttpAuditResult {
            http_status: 200,
            hsts_present: Some(true),
            response_was_tls: true,
            hsts_value: Some("max-age=86400".into()),
            csp_present: true,
            csp_value: Some("script-src 'unsafe-inline'".into()),
            cookies: vec![crate::modules::http::CookieAuditEntry {
                name: "sid".into(),
                secure: true,
                http_only: false,
                same_site: None,
            }],
            ..Default::default()
        };
        let f = FindingsEngine::eval_http(&http);
        let titles: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert_eq!(
            titles,
            vec![
                "Pas de redirection forcée vers HTTPS",
                "CSP présente mais contournable : directive 'unsafe-inline' active",
                "En-tête X-Frame-Options manquant",
                "HSTS max-age trop court (86400 s < 6 mois recommandés)",
                "Cookie 'sid' émis sans attribut(s) de sécurité : HttpOnly, SameSite",
            ],
            "ordre d'émission identique au monolithe"
        );
    }
