//! The development IdP, driven by the production OIDC adapter and by plain HTTP requests.

use std::collections::BTreeMap;

use fieldseal_adapters_oidc::{OidcConfig, OidcIdentityProvider, percent_encode};
use fieldseal_dev_idp::{Config, DevIdp};
use fieldseal_registration::ports::{IdentityError, IdentityProvider};

const FACTORY_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
const FACTORY_CALLBACK: &str = "http://localhost:8080/sign-in/callback";
const CLI_REDIRECT: &str = "http://127.0.0.1:41234/callback";

fn config() -> Config {
    let file = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../examples/deployments/dev-idp.yaml")).unwrap();
    Config::parse(&file, |name| match name {
        "FIELDSEAL_SECRET_FACTORY_OIDC_CLIENT_SECRET" => Some(FACTORY_SECRET.to_owned()),
        "FIELDSEAL_SECRET_INTAKE_OIDC_CLIENT_SECRET" => Some("intake-secret".to_owned()),
        _ => None,
    })
    .unwrap()
}

fn start(bind: &str) -> DevIdp {
    DevIdp::start(config(), bind).unwrap()
}

/// What a request returned: the status, the `Location` header and the body.
struct Seen {
    status: u16,
    location: Option<String>,
    body: String,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().max_redirects(0).http_status_as_error(false).build().into()
}

fn get(url: &str) -> Seen {
    seen(agent().get(url).call().unwrap())
}

fn seen(mut r: ureq::http::Response<ureq::Body>) -> Seen {
    Seen {
        status: r.status().as_u16(),
        location: r.headers().get("location").map(|v| v.to_str().unwrap().to_owned()),
        body: r.body_mut().read_to_string().unwrap(),
    }
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The query of a redirect, as the callback map the adapter takes.
fn callback(location: &str) -> BTreeMap<String, String> {
    let (_, query) = location.split_once('?').expect("a query");
    query.split('&').map(|p| p.split_once('=').unwrap()).map(|(k, v)| (decode(k), decode(v))).collect()
}

fn factory_client(idp: &DevIdp) -> OidcIdentityProvider {
    let mut c = OidcConfig::new(idp.issuer(), "fieldseal-factory");
    c.client_secret = Some(FACTORY_SECRET.into());
    c.acr_values = Some("phr".into());
    OidcIdentityProvider::new(c).unwrap()
}

fn cli_client(idp: &DevIdp) -> OidcIdentityProvider {
    OidcIdentityProvider::new(OidcConfig::new(idp.issuer(), "fieldseal-cli")).unwrap()
}

/// What the factory's API uses to check a Bearer token.
fn api_verifier(idp: &DevIdp) -> OidcIdentityProvider {
    let mut c = OidcConfig::new(idp.issuer(), "fieldseal-factory");
    c.api_audience = Some("fieldseal-factory-api".into());
    c.cli_client_id = Some("fieldseal-cli".into());
    OidcIdentityProvider::new(c).unwrap()
}

#[test]
fn reg_002_the_factory_adapter_signs_in_against_the_dev_idp() {
    let idp = start("127.0.0.1:0");
    let oidc = factory_client(&idp);
    let sign_in = oidc.start_sign_in(FACTORY_CALLBACK).unwrap();
    let r = get(&format!("{}&login_hint=presenter", sign_in.redirect_to));
    assert_eq!(r.status, 302);
    let location = r.location.unwrap();
    assert!(location.starts_with(FACTORY_CALLBACK), "{location}");
    let person = oidc.finish_sign_in(&sign_in.pending, &callback(&location)).unwrap();
    assert_eq!(person.account.0, format!("{}|00000000-0000-4000-8000-000000000001", idp.issuer()));
    assert_eq!(person.role_names, ["collector", "operator", "results-reader"]);
    assert!(person.authentication.phishing_resistant);

    // The other login is the collector only.
    let sign_in = oidc.start_sign_in(FACTORY_CALLBACK).unwrap();
    let r = get(&format!("{}&login_hint=collector1", sign_in.redirect_to));
    let person = oidc.finish_sign_in(&sign_in.pending, &callback(&r.location.unwrap())).unwrap();
    assert_eq!(person.account.0, format!("{}|00000000-0000-4000-8000-000000000002", idp.issuer()));
    assert_eq!(person.role_names, ["collector"]);
}

#[test]
fn reg_002_a_confidential_client_with_the_wrong_secret_or_a_used_code_is_refused() {
    let idp = start("127.0.0.1:0");
    let good = factory_client(&idp);
    let mut c = OidcConfig::new(idp.issuer(), "fieldseal-factory");
    c.client_secret = Some("not-the-secret".into());
    let wrong = OidcIdentityProvider::new(c).unwrap();
    let sign_in = good.start_sign_in(FACTORY_CALLBACK).unwrap();
    let r = get(&format!("{}&login_hint=presenter", sign_in.redirect_to));
    let cb = callback(&r.location.unwrap());
    assert!(matches!(wrong.finish_sign_in(&sign_in.pending, &cb), Err(IdentityError::NotAuthenticated(_))));
    // A client that fails to authenticate does not get to use the code up for the real one.
    good.finish_sign_in(&sign_in.pending, &cb).unwrap();
    // A code is exchanged once.
    let sign_in = good.start_sign_in(FACTORY_CALLBACK).unwrap();
    let r = get(&format!("{}&login_hint=presenter", sign_in.redirect_to));
    let cb = callback(&r.location.unwrap());
    good.finish_sign_in(&sign_in.pending, &cb).unwrap();
    assert!(matches!(good.finish_sign_in(&sign_in.pending, &cb), Err(IdentityError::NotAuthenticated(_))));
}

#[test]
fn reg_070a_the_cli_flow_obtains_an_access_token_the_verifier_accepts() {
    let idp = start("127.0.0.1:0");
    let cli = cli_client(&idp);
    let sign_in = cli.start_sign_in(CLI_REDIRECT).unwrap();
    let r = get(&format!("{}&login_hint=presenter", sign_in.redirect_to));
    assert_eq!(r.status, 302);
    let raw = cli.finish_sign_in_raw(&sign_in.pending, &callback(&r.location.unwrap())).unwrap();
    assert!(raw.id_token_nonce_checked);
    // The ID token verified (the nonce included), and the access token verifies at the API.
    let person = api_verifier(&idp).verify_access_token(&raw.access_token).unwrap();
    assert_eq!(person, raw.person);
    assert_eq!(person.role_names, ["collector", "operator", "results-reader"]);
    assert!(person.authentication.phishing_resistant);
    // The access token is a JWT with the header type at+jwt and no nonce.
    let mut parts = raw.access_token.split('.');
    let header = String::from_utf8(fieldseal_registration::domain::wire::base64url_decode(parts.next().unwrap()).unwrap()).unwrap();
    let claims = String::from_utf8(fieldseal_registration::domain::wire::base64url_decode(parts.next().unwrap()).unwrap()).unwrap();
    assert!(header.contains("\"at+jwt\"") && header.contains("\"ES256\""), "{header}");
    assert!(claims.contains("\"fieldseal-factory-api\"") && claims.contains("\"client_id\":\"fieldseal-cli\"") && claims.contains("\"jti\""), "{claims}");
    assert!(!claims.contains("nonce"), "{claims}");
}

#[test]
fn reg_070a_a_portal_clients_access_token_is_refused_at_the_api() {
    let idp = start("127.0.0.1:0");
    let oidc = factory_client(&idp);
    let sign_in = oidc.start_sign_in(FACTORY_CALLBACK).unwrap();
    let r = get(&format!("{}&login_hint=presenter", sign_in.redirect_to));
    let raw = oidc.finish_sign_in_raw(&sign_in.pending, &callback(&r.location.unwrap())).unwrap();
    // Its audience is the API's, but it was issued to the factory portal, not to the CLI.
    assert!(matches!(api_verifier(&idp).verify_access_token(&raw.access_token), Err(IdentityError::NotAuthenticated(_))));
}

#[test]
fn reg_070a_login_hint_approves_without_a_page() {
    let idp = start("127.0.0.1:0");
    let sign_in = cli_client(&idp).start_sign_in(CLI_REDIRECT).unwrap();
    let r = get(&format!("{}&login_hint=collector1", sign_in.redirect_to));
    assert_eq!(r.status, 302);
    let cb = callback(&r.location.unwrap());
    assert!(cb.contains_key("code"));
    assert_eq!(cb["state"], sign_in.pending.state);
    assert_eq!(cb["iss"], idp.issuer());
}

#[test]
fn reg_070a_without_a_login_hint_the_login_page_lists_the_logins() {
    let idp = start("127.0.0.1:0");
    let cli = cli_client(&idp);
    for hint in ["", "&login_hint=nobody"] {
        let sign_in = cli.start_sign_in(CLI_REDIRECT).unwrap();
        let r = get(&format!("{}{hint}", sign_in.redirect_to));
        assert_eq!(r.status, 200);
        assert!(r.location.is_none());
        assert!(r.body.contains("presenter") && r.body.contains("collector1"), "{}", r.body);
        // A link carries the request on with the chosen login; following it signs that login in.
        let href = r.body.split("href=\"").nth(2).unwrap().split('"').next().unwrap().replace("&amp;", "&");
        assert!(href.contains("login_hint=collector1"), "{href}");
        let r = get(&href);
        assert_eq!(r.status, 302);
        let raw = cli.finish_sign_in_raw(&sign_in.pending, &callback(&r.location.unwrap())).unwrap();
        assert_eq!(raw.person.role_names, ["collector"]);
    }
}

#[test]
fn reg_002_pkce_s256_is_required() {
    let idp = start("127.0.0.1:0");
    let cli = cli_client(&idp);
    let url = cli.start_sign_in(CLI_REDIRECT).unwrap().redirect_to;
    // Without a challenge, or with the plain method, the client is sent back an error.
    let (base, _) = url.split_once('?').unwrap();
    let common = format!("{base}?response_type=code&client_id=fieldseal-cli&redirect_uri={}&state=s-1&login_hint=presenter", percent_encode(CLI_REDIRECT));
    for extra in ["", "&code_challenge=abc", "&code_challenge=abc&code_challenge_method=plain"] {
        let r = get(&format!("{common}{extra}"));
        assert_eq!(r.status, 302, "{extra}");
        let cb = callback(&r.location.unwrap());
        assert_eq!(cb["error"], "invalid_request", "{extra}");
        assert_eq!(cb["state"], "s-1");
        assert!(!cb.contains_key("code"));
    }
    // A wrong verifier does not exchange the code.
    let sign_in = cli.start_sign_in(CLI_REDIRECT).unwrap();
    let r = get(&format!("{}&login_hint=presenter", sign_in.redirect_to));
    let cb = callback(&r.location.unwrap());
    let form = [
        ("grant_type", "authorization_code"),
        ("code", cb["code"].as_str()),
        ("redirect_uri", CLI_REDIRECT),
        ("client_id", "fieldseal-cli"),
        ("code_verifier", "a-verifier-that-was-never-sent-to-the-authorization-endpoint"),
    ];
    let r = seen(agent().post(&format!("{}/protocol/openid-connect/token", idp.issuer())).send_form(form).unwrap());
    assert_eq!(r.status, 400);
    assert!(r.body.contains("invalid_grant"), "{}", r.body);
}

#[test]
fn reg_002_an_unregistered_redirect_uri_is_refused() {
    let idp = start("127.0.0.1:0");
    let base = format!("{}/protocol/openid-connect/auth", idp.issuer());
    let ask = |client: &str, redirect: &str| {
        get(&format!(
            "{base}?response_type=code&client_id={client}&redirect_uri={}&state=s&code_challenge=c&code_challenge_method=S256&login_hint=presenter",
            percent_encode(redirect)
        ))
    };
    // Refused with a page and never a redirect, so a code cannot be sent anywhere new.
    for (client, redirect) in [
        ("fieldseal-factory", "http://localhost:8080/elsewhere"),
        ("fieldseal-factory", "http://evil.example/sign-in/callback"),
        ("fieldseal-factory", "http://localhost:8080/sign-in/callback/"),
        ("fieldseal-intake", "http://localhost:8080/sign-in/callback"),
        ("fieldseal-cli", "http://localhost:41234/callback"),
        ("fieldseal-cli", "http://127.0.0.1.evil.example:41234/callback"),
        ("fieldseal-cli", "https://127.0.0.1:41234/callback"),
        ("fieldseal-cli", "http://127.0.0.1/callback"),
        ("unknown-client", "http://localhost:8080/sign-in/callback"),
    ] {
        let r = ask(client, redirect);
        assert_eq!((r.status, r.location), (400, None), "{client} {redirect}");
    }
    // The registered ones, and the public client's loopback redirect on any port, are not.
    assert_eq!(ask("fieldseal-factory", FACTORY_CALLBACK).status, 302);
    assert_eq!(ask("fieldseal-intake", "http://localhost:8481/sign-in/callback").status, 302);
    assert_eq!(ask("fieldseal-cli", "http://127.0.0.1:1/cb").status, 302);
    assert_eq!(ask("fieldseal-cli", "http://127.0.0.1:65000/any/path").status, 302);
}

#[test]
fn reg_002_the_issuer_follows_the_bind_address() {
    for host in ["127.0.0.1", "localhost"] {
        let idp = start(&format!("{host}:0"));
        let port = idp.local_addr().port();
        assert_eq!(idp.issuer(), format!("http://{host}:{port}/realms/fieldseal"));
        let doc = get(&format!("{}/.well-known/openid-configuration", idp.issuer()));
        assert_eq!(doc.status, 200);
        let doc: serde_json::Value = serde_json::from_str(&doc.body).unwrap();
        assert_eq!(doc["issuer"], idp.issuer());
        assert_eq!(doc["authorization_endpoint"], format!("{}/protocol/openid-connect/auth", idp.issuer()));
        assert_eq!(doc["token_endpoint"], format!("{}/protocol/openid-connect/token", idp.issuer()));
        let certs = get(doc["jwks_uri"].as_str().unwrap());
        let certs: serde_json::Value = serde_json::from_str(&certs.body).unwrap();
        assert_eq!(certs["keys"][0]["alg"], "ES256");
        assert!(certs["keys"][0].get("d").is_none(), "the private scalar must never be served");
    }
}

#[test]
fn reg_002_only_loopback_addresses_bind() {
    for bad in ["0.0.0.0:8180", "192.168.1.5:8180", "example.com:8180", "[::]:8180", "8180", "localhost:notaport", "localhost:99999"] {
        assert!(fieldseal_dev_idp::parse_bind(bad).is_err(), "{bad}");
        assert!(DevIdp::start(config(), bad).is_err(), "{bad}");
    }
    for good in ["localhost:8180", "127.0.0.1:0", "[::1]:8180"] {
        assert!(fieldseal_dev_idp::parse_bind(good).is_ok(), "{good}");
    }
}

#[test]
fn reg_002_the_configuration_is_strict_and_a_missing_secret_is_named() {
    let file = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../examples/deployments/dev-idp.yaml")).unwrap();
    let err = Config::parse(&file, |_| None).unwrap_err();
    assert!(err.contains("FIELDSEAL_SECRET_FACTORY_OIDC_CLIENT_SECRET is not set"), "{err}");
    let all = |n: &str| n.starts_with("FIELDSEAL_SECRET_").then(|| "s".to_owned());
    assert!(Config::parse(&file, all).is_ok());
    let err = Config::parse(&file.replace("apiAudience:", "apiAudienc:"), all).unwrap_err();
    assert!(err.contains("apiAudienc"), "{err}");
    let err = Config::parse(&format!("{file}\nextra: 1\n"), all).unwrap_err();
    assert!(err.contains("extra"), "{err}");
    let err = Config::parse(&file.replace("public: true", "public: true\n    secretRef: x"), all).unwrap_err();
    assert!(err.contains("public client has no secretRef"), "{err}");
}

/// The account an operator's assignment lands on is the account the person signs in as
/// (REG-046): the operator sends the bare subject, and the factory maps it with the OIDC
/// adapter's own rule.
#[test]
fn reg_046_an_assignment_for_a_subject_reaches_the_tenancy_that_person_registers() {
    use std::collections::BTreeSet;

    use fieldseal_adapters_factory_http::{BearerError, BearerVerifier, FactoryHttp, HttpConfig, Request};
    use fieldseal_adapters_memory::policy::{BuiltInPolicyEngine, MemoryDecisionLog};
    use fieldseal_adapters_memory::registration::{MemoryFleetRegistry, MemoryNotifier, MemoryReceivedProgress, MemoryRegistryStore, SoftwareDevice, dev_authority};
    use fieldseal_adapters_memory::trust::{FixedClock, SeededRandom, SoftwareAttestationVerifier};
    use fieldseal_kernel::id::CohortId;
    use fieldseal_kernel::time::AuthorityTime;
    use fieldseal_kernel::{Value, cbor};
    use fieldseal_policy::fixtures::{DocBuilder, effective};
    use fieldseal_registration::application::{Factory, FactoryConfig, FactoryPorts, OperatorPorts, Submission};
    use fieldseal_registration::domain::checks::UnattestedKeys;
    use fieldseal_registration::domain::{AccountId, AuthenticatedPerson, RegistrationRoute, TenancyState, TenancyTerms, Window};
    use fieldseal_registration::ports::{CohortDirectory, RegistryStore, SurveyDirectory};

    /// The factory's Bearer check over the production OIDC adapter.
    struct Bearer(OidcIdentityProvider);
    impl BearerVerifier for Bearer {
        fn verify(&self, token: &str) -> Result<AuthenticatedPerson, BearerError> {
            self.0.verify_access_token(token).map_err(|e| BearerError::Invalid(format!("{e:?}")))
        }
        fn account_for_subject(&self, sub: &str) -> AccountId {
            self.0.account_for_subject(sub)
        }
        fn subject_of_account(&self, account: &AccountId) -> Option<String> {
            self.0.subject_of_account(account)
        }
    }
    struct Surveys;
    impl SurveyDirectory for Surveys {
        fn exists(&self, name: &str) -> bool {
            name == "survey-a"
        }
    }
    struct Cohorts(BTreeSet<&'static str>);
    impl CohortDirectory for Cohorts {
        fn exists(&self, cohort: &CohortId) -> bool {
            self.0.contains(cohort.as_str())
        }
    }

    let idp = start("127.0.0.1:0");
    // The operator signs in at the CLI; the collector signs in at the portal.
    let cli = cli_client(&idp);
    let sign_in = cli.start_sign_in(CLI_REDIRECT).unwrap();
    let r = get(&format!("{}&login_hint=presenter", sign_in.redirect_to));
    let operator_token = cli.finish_sign_in_raw(&sign_in.pending, &callback(&r.location.unwrap())).unwrap().access_token;
    let portal = factory_client(&idp);
    let sign_in = portal.start_sign_in(FACTORY_CALLBACK).unwrap();
    let r = get(&format!("{}&login_hint=collector1", sign_in.redirect_to));
    let collector = portal.finish_sign_in(&sign_in.pending, &callback(&r.location.unwrap())).unwrap();
    let subject = "00000000-0000-4000-8000-000000000002";

    let t0 = AuthorityTime(1_800_000_000_000);
    let authority = dev_authority(SeededRandom::new(1), t0, &["fieldseal-simulator"]).unwrap();
    let config = FactoryConfig {
        factory_url: "https://factory.example.org".into(),
        signing_key: *authority.signing.key_id(),
        sealing_key: *authority.sealing.key_id(),
        terms: TenancyTerms {
            record_key: *authority.record.key_id(),
            window: Window { not_before: t0, not_after: AuthorityTime(t0.0 + 90 * AuthorityTime::DAY), grace_ms: 30 * AuthorityTime::DAY },
            cohorts: vec![],
        },
        unattested: UnattestedKeys::AllowNonProduction,
        posture_nonce_ttl_ms: 600_000,
        access_token_ttl_ms: 600_000,
    };
    let (store, verifier, engine, log, clock, random) =
        (MemoryRegistryStore::new(), SoftwareAttestationVerifier, BuiltInPolicyEngine, MemoryDecisionLog::new(), FixedClock::new(t0), SeededRandom::new(2));
    let (progress, fleet, notifier) = (MemoryReceivedProgress::new(), MemoryFleetRegistry::new(), MemoryNotifier::new());
    let policy = effective(&[DocBuilder::deployment("test", "1.0.0").build()]);
    let cohorts = Cohorts(BTreeSet::from(["cohort-a"]));
    struct NoRosters;
    impl fieldseal_registration::ports::RosterIssuer for NoRosters {
        fn issue(&self, _: &CohortId, _: &[u8]) -> fieldseal_registration::ports::IssueOutcome {
            fieldseal_registration::ports::IssueOutcome::Invalid("not used".into())
        }
    }
    let factory = Factory::new(
        FactoryPorts {
            store: &store,
            custody: &authority.custody,
            verifiers: vec![&verifier],
            engine: &engine,
            log: &log,
            clock: &clock,
            random: &random,
            progress: &progress,
            fleet: Some(&fleet),
            notifier: Some(&notifier),
        },
        &authority.bundle,
        &policy,
        &config,
    )
    .unwrap()
    .with_operator_ports(OperatorPorts { rosters: &NoRosters, surveys: &Surveys, cohorts: &cohorts });
    let bearer = Bearer(api_verifier(&idp));
    let http = FactoryHttp::new(&factory, &portal, HttpConfig { public_url: "https://factory.example.org".into(), session_ttl_ms: 3_600_000 })
        .with_operator_api(&bearer, fieldseal_adapters_factory_http::no_reconcile(), std::sync::Arc::new(|_| {}));

    // The operator sends the bare subject.
    let body = cbor::encode(&cbor::map([
        ("account", Value::Text(subject.into())),
        ("survey", Value::Text("survey-a".into())),
        ("cohort", Value::Text("cohort-a".into())),
    ]))
    .unwrap();
    let headers = BTreeMap::from([("authorization".to_owned(), format!("Bearer {operator_token}")), ("content-type".to_owned(), "application/cbor".to_owned())]);
    let made = http.handle(&Request::new("POST", "/v1/assignments", headers.clone(), body));
    assert_eq!(made.status, 200, "{}", String::from_utf8_lossy(&made.body));
    let held = store.assignments().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].account, collector.account, "the record names the account the person signs in as");
    assert_eq!(held[0].account.0, format!("{}|{subject}", idp.issuer()));
    let listed = http.handle(&Request::new("GET", "/v1/assignments", headers, vec![]));
    let rows: serde_json::Value = serde_json::from_slice(&listed.body).unwrap();
    assert_eq!(rows["assignments"][0]["account"], subject, "the list shows the subject the operator sent");

    // That person registers a device: the tenancy carries the cohort, and so does its certificate.
    let device = SoftwareDevice::new(&random);
    let token = factory.issue_token(&collector, RegistrationRoute::Online, 1).unwrap();
    let sealed = device.seal(&random, &authority.bundle, t0, &device.body(&token.token, Some("blue")), None);
    let submitted = factory.submit(&sealed, Submission::Online).unwrap();
    let record = factory.confirm(&collector.account, &submitted.tenancy.id).unwrap();
    assert_eq!(record.state, TenancyState::Registered);
    assert_eq!(record.cohorts.iter().map(|c| c.cohort.as_str()).collect::<Vec<_>>(), vec!["cohort-a"]);
    assert_eq!(factory.certificate(&record.id).unwrap().cohorts, record.cohorts);
}
