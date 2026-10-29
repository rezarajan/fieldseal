//! `fieldseal-dev-idp`: a development-only OpenID Connect provider. It stands where Keycloak
//! stands in `just web`, so the factory, the intake app and the CLI run the same `oidc`
//! adapter against it as against Keycloak or a real provider; there is no second sign-in code
//! path. It is a tool, not an adapter: it is in no image, no compose file and no deployment
//! manifest, and it refuses to start outside development (see `main.rs`).
//!
//! * [`config`]: logins, clients and the API audience, from `examples/deployments/dev-idp.yaml`.
//! * [`server`]: discovery, authorization with PKCE `S256`, token and the key set.
//! * [`tokens`]: ES256 signing and the ID and access tokens.

pub mod config;
pub mod server;
pub mod tokens;

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

pub use config::Config;
use server::Provider;

/// The number of threads taking requests.
const WORKERS: usize = 4;

/// The host and port of `--bind <addr:port>`. Only loopback hosts are accepted (`localhost`,
/// `127.0.0.1` and `[::1]`), so the provider cannot be reached from another machine.
pub fn parse_bind(bind: &str) -> Result<(String, u16), String> {
    let (host, port) = bind.rsplit_once(':').ok_or_else(|| format!("--bind {bind}: use <address>:<port>"))?;
    if !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
        return Err(format!("--bind {bind}: only loopback addresses are accepted (localhost, 127.0.0.1 or [::1])"));
    }
    let port = port.parse::<u16>().map_err(|_| format!("--bind {bind}: the port is not a number from 0 to 65535"))?;
    Ok((host.to_owned(), port))
}

/// A running provider.
pub struct DevIdp {
    provider: Arc<Provider>,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl DevIdp {
    /// Binds `bind` (port `0` picks a free one) and starts serving. The issuer is
    /// `http://<host>:<port>/realms/fieldseal`, with the host as written in `bind` and the port
    /// actually bound, so that the default `localhost:8180` is the issuer the stack's Keycloak
    /// uses.
    pub fn start(config: Config, bind: &str) -> Result<Self, String> {
        let (host, port) = parse_bind(bind)?;
        let ip = if host == "[::1]" { "::1" } else { "127.0.0.1" };
        let listener = TcpListener::bind((ip, port)).map_err(|e| format!("--bind {bind}: {e}"))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let server = Arc::new(tiny_http::Server::from_listener(listener, None).map_err(|e| e.to_string())?);
        let provider = Arc::new(Provider::new(format!("http://{host}:{}/realms/fieldseal", addr.port()), config));
        let stop = Arc::new(AtomicBool::new(false));
        let workers = (0..WORKERS)
            .map(|_| {
                let (server, provider, stop) = (server.clone(), provider.clone(), stop.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        if let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(100)) {
                            let reply = provider.handle(&mut request);
                            let _ = request.respond(reply);
                        }
                    }
                })
            })
            .collect();
        Ok(Self { provider, addr, stop, workers })
    }

    /// The issuer URL.
    pub fn issuer(&self) -> &str {
        self.provider.issuer()
    }

    /// The address it listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Serves until the process is stopped.
    pub fn wait(mut self) {
        for w in std::mem::take(&mut self.workers) {
            let _ = w.join();
        }
    }
}

impl Drop for DevIdp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for w in std::mem::take(&mut self.workers) {
            let _ = w.join();
        }
    }
}
