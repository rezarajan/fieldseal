//! The ports bound to development adapters (Technical Plan 10.1), the start-up event that
//! lists them, and the refusal to start in production with any of them.
//!
//! `landing-files` is not a development adapter and is not listed.

use fieldseal_deployment::events::development_adapters_event;

use crate::config::{Config, Custody, Identity};

/// Every port of this configuration that is bound to a development adapter, as
/// (port, adapter).
pub fn list(c: &Config) -> Vec<(&'static str, &'static str)> {
    let mut out = vec![(
        "RecordKeyUnsealer",
        match c.custody {
            Custody::MemoryDev => "memory-dev",
            Custody::FileDev { .. } => "file-dev",
        },
    )];
    out.push(("SubmissionStore", if c.submissions_dir.is_some() { "file-dev" } else { "memory" }));
    out.push(("RosterHistory", if c.rosters_dir.is_some() { "file-dev" } else { "memory" }));
    out.push(("InstrumentSource", "file-dev"));
    out.push(("TenancyRegistry", "file-dev"));
    if c.identity == Identity::Dev {
        out.push(("IdentityProvider", "dev"));
    }
    out.push(("ExportKey", "file-dev"));
    out
}

/// Exit `2` in production while any development adapter is in use: there is no production
/// adapter for these ports yet, so the app cannot start in production (as the factory).
pub fn refuse_in_production(c: &Config) -> Result<(), String> {
    if !c.production {
        return Ok(());
    }
    let used = list(c);
    let first = used.first().map(|(p, a)| format!("{p}={a}")).unwrap_or_default();
    let all: Vec<String> = used.iter().map(|(p, a)| format!("{p}={a}")).collect();
    Err(format!("the development adapters {} are not allowed in production ({first} first); there is no production adapter for these ports yet", all.join(", ")))
}

/// Exit `2` when the development login is configured and the portal is bound to an address
/// that is not loopback: the development login signs anyone in as a user who may read results,
/// so only the machine's own users may reach it.
pub fn refuse_exposed_dev_login(c: &Config) -> Result<(), String> {
    let loopback = c.portal_bind.parse::<std::net::SocketAddr>().is_ok_and(|a| a.ip().is_loopback());
    if c.identity == Identity::Dev && !loopback {
        return Err(format!("FIELDSEAL_IDENTITY=dev signs anyone in, so FIELDSEAL_INTAKE_PORTAL_BIND must be a loopback address, not {}", c.portal_bind));
    }
    Ok(())
}

/// The `development-adapters` event this app prints at every start (DEP-051).
pub fn event(c: &Config) -> String {
    development_adapters_event("fieldseal-intake", &list(c))
}
