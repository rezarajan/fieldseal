//! `fieldseal-dev-idp`: the development-only OpenID Connect provider of `just web`.
//!
//! It starts only when all of these hold, and exits `2` otherwise:
//!
//! * `--development-tool` is given, so that nobody starts it by accident;
//! * `FIELDSEAL_ENVIRONMENT` is `development` (any other value, `production` included, is refused);
//! * the `--bind` address is loopback (`localhost`, `127.0.0.1` or `[::1]`).
//!
//! | Flag | Meaning |
//! |---|---|
//! | `--development-tool` | required |
//! | `--config <file>` | logins, clients and the API audience (default `examples/deployments/dev-idp.yaml`) |
//! | `--bind <addr:port>` | where to listen (default `localhost:8180`); the issuer is `http://<addr:port>/realms/fieldseal` |
//!
//! A confidential client's secret is read from `FIELDSEAL_SECRET_<REFERENCE>`, as the factory
//! reads its own.

use std::process::ExitCode;

use fieldseal_dev_idp::{Config, DevIdp, parse_bind};

const HELP: &str = "fieldseal-dev-idp: a development-only OpenID Connect provider (stands where Keycloak stands in `just web`)\n\nUsage: fieldseal-dev-idp --development-tool [--config <file>] [--bind <addr:port>]\n\n  --development-tool   required: this is a development tool, never a service\n  --config <file>      logins, clients and the API audience (default examples/deployments/dev-idp.yaml)\n  --bind <addr:port>   loopback address to listen on (default localhost:8180)\n\nEnvironment:\n  FIELDSEAL_ENVIRONMENT=development   required; any other value is refused\n  FIELDSEAL_SECRET_<REFERENCE>        the secret of the confidential client that names <REFERENCE>\n\nExit codes: 0 help; 2 refused to start or unusable configuration.\n";

fn refuse(what: &str) -> ExitCode {
    eprintln!("fieldseal-dev-idp event=error what=refused detail={what:?}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut tool = false;
    let mut config_path = "examples/deployments/dev-idp.yaml".to_owned();
    let mut bind = "localhost:8180".to_owned();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "--development-tool" => tool = true,
            "--config" | "--bind" => {
                let Some(value) = args.next() else { return refuse(&format!("{arg} needs a value")) };
                if arg == "--config" { config_path = value } else { bind = value }
            }
            other => return refuse(&format!("unknown argument {other}; see --help")),
        }
    }
    if !tool {
        return refuse("this is a development tool and starts only with --development-tool");
    }
    match std::env::var("FIELDSEAL_ENVIRONMENT").as_deref() {
        Ok("development") => {}
        Ok(other) => return refuse(&format!("FIELDSEAL_ENVIRONMENT={other}: the development identity provider starts only in development")),
        Err(_) => return refuse("FIELDSEAL_ENVIRONMENT must be set to development"),
    }
    if let Err(e) = parse_bind(&bind) {
        return refuse(&e);
    }
    let text = match std::fs::read_to_string(&config_path) {
        Ok(t) => t,
        Err(e) => return refuse(&format!("{config_path}: {e}")),
    };
    let config = match Config::parse(&text, |k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => return refuse(&format!("{config_path}: {e}")),
    };
    let idp = match DevIdp::start(config, &bind) {
        Ok(i) => i,
        Err(e) => return refuse(&e),
    };
    eprintln!("fieldseal-dev-idp: DEVELOPMENT ONLY. Anyone who can reach this address can sign in as any login, with no password.");
    // The shared start-up event (DEP-051): what is running, and that production refuses it. The issuer and the address follow on the next line.
    eprintln!("{}", fieldseal_deployment::events::development_adapters_event("fieldseal-dev-idp", &[("IdentityProvider", "dev-idp")]));
    eprintln!("fieldseal-dev-idp: issuer {}, listening on {}", idp.issuer(), idp.local_addr());
    idp.wait();
    ExitCode::SUCCESS
}
