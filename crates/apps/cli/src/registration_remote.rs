//! `fieldseal registration submit|status|wait` (CLI §5 `registration`, REG-050, REG-051):
//! the device side of registration over the network. A sealed request built by `registration
//! request` is submitted to the factory, the factory's decision is read back, and when the
//! tenancy is registered the tenancy certificate is fetched with a proof-of-possession token
//! made by the device's own key.
//!
//! The factory is reached through the transport-neutral [`FactoryClient`] port; the address
//! is `--factory-url` or `FIELDSEAL_FACTORY_URL`, and its scheme selects the transport.

use std::time::{Duration, Instant};

use fieldseal_kernel::Value;
use fieldseal_kernel::time::AuthorityTime;
use fieldseal_registration::domain::wire::TenancyCertificate;
use fieldseal_trust::ports::RandomSource;

use crate::args::Args;
use crate::clients::{ClientError, FactoryClient, RegistrationStatus, connect_factory, report};
use crate::custody::OsRandom;
use crate::device_dir::DeviceDir;
use crate::messages::msg;
use crate::outcome::{Outcome, exit};
use crate::support::{Res, fail, now, read, run_command, setting, usage};

const COMMON: &[&str] = &["--factory-url", "--device-dir", "--trust-bundle", "--at"];

/// Runs `registration <verb>` for the network verbs; `None` if the verb is not one of them.
pub fn run(verb: &str, raw: &[String]) -> Option<u8> {
    let with = |extra: &[&'static str]| -> Vec<&'static str> { COMMON.iter().chain(extra).copied().collect() };
    Some(match verb {
        "submit" => run_command("registration submit", raw, &with(&[]), &[], submit),
        "status" => run_command("registration status", raw, &with(&[]), &[], status),
        "wait" => run_command("registration wait", raw, &with(&["--timeout", "--interval"]), &[], wait),
        _ => return None,
    })
}

fn factory(args: &Args, out: &mut Outcome) -> Option<(String, Box<dyn FactoryClient>)> {
    let Some(url) = setting(args, "--factory-url", "FIELDSEAL_FACTORY_URL") else {
        fail(out, exit::CONFIG, "no-factory-url", &[]);
        return None;
    };
    match connect_factory(&url) {
        Ok(c) => Some((url, c)),
        Err(e) => {
            report(out, &url, &e);
            None
        }
    }
}

fn is_tenancy(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn show(out: &mut Outcome, s: &RegistrationStatus) {
    out.set("tenancy", Value::Text(s.tenancy.clone()));
    out.set("state", Value::Text(s.state.clone()));
    out.set("reasons", Value::Array(s.reasons.iter().cloned().map(Value::Text).collect()));
    if !s.words.is_empty() {
        out.set("words", Value::Text(s.words.clone()));
    }
}

fn submit(args: &Args, out: &mut Outcome) -> Res {
    let file = args.file("registration submit")?;
    let Some((url, client)) = factory(args, out) else { return Ok(()) };
    let Some(bytes) = read(file, out) else { return Ok(()) };
    match client.submit(&bytes) {
        Ok(s) => {
            out.lines.push(msg("registration-submitted", &[("file", file), ("url", &url), ("tenancy", &s.tenancy), ("state", &s.state), ("words", &s.words)]));
            show(out, &s);
            if s.state == "rejected" {
                for r in &s.reasons {
                    out.raw_finding("REG", "error", file, "", r);
                }
            }
        }
        Err(e) => report(out, &url, &e),
    }
    Ok(())
}

/// The tenancy named by the positional argument, else the device directory's.
fn tenancy_of(args: &Args, command: &str) -> Res<String> {
    let t = match args.positionals.as_slice() {
        [t] => t.clone(),
        [] => args.value("--device-dir").and_then(|d| DeviceDir::new(d).tenancy()).ok_or_else(|| usage("missing-file", &[("command", command)]))?,
        [_, extra, ..] => return Err(usage("extra-argument", &[("argument", extra)])),
    };
    if is_tenancy(&t) { Ok(t) } else { Err(usage("bad-tenancy", &[("value", &t)])) }
}

fn status(args: &Args, out: &mut Outcome) -> Res {
    let tenancy = tenancy_of(args, "registration status")?;
    let Some((url, client)) = factory(args, out) else { return Ok(()) };
    match client.status(&tenancy) {
        Ok(s) => {
            out.lines.push(msg("registration-state", &[("tenancy", &tenancy), ("state", &s.state)]));
            show(out, &s);
        }
        Err(e) => report(out, &url, &e),
    }
    Ok(())
}

/// States from which a tenancy never becomes registered.
fn ended(state: &str) -> bool {
    matches!(state, "rejected" | "lost" | "closing" | "closed" | "retired")
}

fn secs(args: &Args, flag: &str, default: u64) -> Res<u64> {
    match args.value(flag) {
        Some(v) => v.parse().map_err(|_| usage("bad-number", &[("flag", flag), ("value", v)])),
        None => Ok(default),
    }
}

fn wait(args: &Args, out: &mut Outcome) -> Res {
    let tenancy = tenancy_of(args, "registration wait")?;
    let (timeout, interval) = (secs(args, "--timeout", 60)?, secs(args, "--interval", 1)?.max(1));
    let at = now(args)?;
    let Some((url, client)) = factory(args, out) else { return Ok(()) };
    let started = Instant::now();
    let last = loop {
        match client.status(&tenancy) {
            Ok(s) if s.state == "registered" => break s,
            Ok(s) if ended(&s.state) => {
                fail(out, exit::FAILED, "registration-ended", &[("tenancy", &tenancy), ("state", &s.state)]);
                for r in &s.reasons {
                    out.raw_finding("REG", "error", &tenancy, "", r);
                }
                show(out, &s);
                return Ok(());
            }
            Ok(s) if started.elapsed() >= Duration::from_secs(timeout) => {
                fail(out, exit::FAILED, "registration-timeout", &[("tenancy", &tenancy), ("state", &s.state), ("seconds", &timeout.to_string())]);
                show(out, &s);
                return Ok(());
            }
            Ok(_) => std::thread::sleep(Duration::from_secs(interval)),
            // The factory may still be starting: keep trying until the timeout.
            Err(ClientError::Unreachable(_)) if started.elapsed() < Duration::from_secs(timeout) => std::thread::sleep(Duration::from_secs(interval)),
            Err(e) => {
                report(out, &url, &e);
                return Ok(());
            }
        }
    };
    show(out, &last);
    // With a device directory, prove possession of the tenancy's key and keep the certificate.
    let Some(dir) = args.value("--device-dir").map(DeviceDir::new) else {
        out.lines.push(msg("registration-state", &[("tenancy", &tenancy), ("state", "registered")]));
        return Ok(());
    };
    let Some(device) = dir.software_device() else {
        fail(out, exit::NOT_FOUND, "device-not-registered", &[("dir", &dir.path().to_string_lossy())]);
        return Ok(());
    };
    if hex(device.tenancy().as_bytes()) != tenancy {
        fail(out, exit::FAILED, "device-not-registered", &[("dir", &dir.path().to_string_lossy())]);
        return Ok(());
    }
    let mut jti = [0u8; 16];
    OsRandom.fill(&mut jti);
    let endpoint = format!("{}/v1/certificate", url.trim_end_matches('/'));
    let header = device.pop_token(device.tenancy(), "GET", &endpoint, AuthorityTime(at.0), jti, None).to_header();
    let bytes = match client.certificate(&header) {
        Ok(b) => b,
        Err(e) => {
            report(out, &url, &e);
            return Ok(());
        }
    };
    let cert = match TenancyCertificate::decode(&bytes) {
        Ok(c) => c,
        Err(e) => {
            out.raw_finding("WIRE-130", "error", "(certificate)", "", &e.to_string());
            return Ok(());
        }
    };
    if cert.tenancy != device.tenancy() {
        out.raw_finding("REG-033", "error", "(certificate)", "tenancy", "the certificate is for another tenancy");
        return Ok(());
    }
    // With a trust bundle, check the factory's signature as a device does (REG-033).
    if setting(args, "--trust-bundle", "FIELDSEAL_TRUST_BUNDLE").is_some() {
        let Some(bundle) = crate::trust_cmd::load_bundle(args, out) else { return Ok(()) };
        if let Err(e) = cert.verify(&bundle) {
            out.raw_finding("REG-033", "error", "(certificate)", "", &e.to_string());
            return Ok(());
        }
        out.set("certificateVerified", Value::Bool(true));
    }
    if let Err(e) = dir.save_certificate(&bytes) {
        fail(out, exit::CONFIG, "write-failed", &[("file", "tenancy.certificate"), ("reason", &e)]);
        return Ok(());
    }
    let file = dir.path().join("tenancy.certificate").to_string_lossy().into_owned();
    out.lines.push(msg("registration-waited", &[("tenancy", &tenancy), ("state", "registered"), ("file", &file)]));
    out.set("certificate", Value::Text(file));
    out.set("handle", Value::Text(hex(cert.handle.as_bytes())));
    Ok(())
}

fn hex(b: &[u8]) -> String {
    crate::support::hex(b)
}
