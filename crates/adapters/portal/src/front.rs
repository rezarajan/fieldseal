//! Serving one listener without ever waiting on a client (SR-2, SR-5).
//!
//! `tiny_http` offers no socket timeouts, so a request body is read on a thread of its own,
//! under a byte-rate floor, and only a complete body reaches the serving thread. The same goes
//! for writing the answer. The serving thread (which owns the listener's non-`Send` ports)
//! therefore never blocks on a slow client: it takes requests, hands each to a reader, handles
//! what the readers finish, and hands the answer to a writer.
//!
//! What this does not do: a client that goes completely silent keeps its own reader thread
//! until it closes the connection (the thread is blocked in a read that cannot be interrupted).
//! At most [`MAX_IN_FLIGHT`] readers per listener are alive; past that a new request gets
//! `503` at once. The other listener is not affected either way.

use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// How many requests may be waiting for their body on one listener.
pub const MAX_IN_FLIGHT: usize = 128;

/// The least a client must keep sending while it sends a request body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BodyLimits {
    /// How long a body may take to start, whatever its rate.
    pub grace: Duration,
    /// After the grace period, the bytes per second a body must have averaged so far.
    pub min_bytes_per_second: u64,
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self { grace: Duration::from_secs(10), min_bytes_per_second: 8 * 1024 }
    }
}

/// A response ready to be written.
pub type Answer = tiny_http::Response<Cursor<Vec<u8>>>;

/// An answer, and anything that must stay alive until the writer thread has finished with it
/// (a place in a cap on large writes, say). The guard is dropped when the write ends, however
/// it ends.
pub struct Reply {
    /// What to send.
    pub answer: Answer,
    /// What to keep alive until the write ends.
    pub guard: Option<Box<dyn Send>>,
}

impl From<Answer> for Reply {
    fn from(answer: Answer) -> Self {
        Self { answer, guard: None }
    }
}

/// An empty answer with `status`.
pub fn plain(status: u16) -> Answer {
    tiny_http::Response::from_data(Vec::new()).with_status_code(status)
}

/// Writes `answer` on a thread of its own, so a client that does not read it holds nothing.
fn respond_later(req: tiny_http::Request, reply: Reply) {
    std::thread::spawn(move || {
        let _guard = reply.guard;
        let _ = req.respond(reply.answer);
    });
}

enum Body {
    Complete(Vec<u8>),
    TooBig,
    Stalled,
}

/// Reads the body of `req`, at most `max` bytes, at no less than the floor in `limits`. The
/// floor is checked each time a read returns.
fn read_body(req: &mut tiny_http::Request, max: usize, limits: BodyLimits) -> Body {
    let (started, mut body, mut chunk) = (Instant::now(), Vec::new(), [0u8; 16 * 1024]);
    let reader = req.as_reader();
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Body::Complete(body),
            Ok(n) if body.len() + n > max => return Body::TooBig,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => return Body::Stalled,
        }
        let late = started.elapsed().saturating_sub(limits.grace);
        if !late.is_zero() && (body.len() as u128) * 1000 < late.as_millis() * u128::from(limits.min_bytes_per_second) {
            return Body::Stalled;
        }
    }
}

/// Counts a reader while it lives.
struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serves `server` on this thread until `stopped` says so. `answer` is the listener's handler:
/// it gets a request whose body is read already (`None` for a body over `max_body`).
pub fn serve(server: &tiny_http::Server, max_body: usize, limits: BodyLimits, stopped: &dyn Fn() -> bool, answer: &dyn Fn(&tiny_http::Request, Option<Vec<u8>>) -> Answer) {
    serve_screened(server, max_body, limits, stopped, &|_| None, &|req, body| answer(req, body).into());
}

/// Like [`serve`], with two additions. `screen` sees each request before any of its body is
/// read, and an answer from it is sent without the body being read at all (authorisation that
/// must come first). The handler returns a [`Reply`], whose guard lives as long as the write.
pub fn serve_screened(
    server: &tiny_http::Server,
    max_body: usize,
    limits: BodyLimits,
    stopped: &dyn Fn() -> bool,
    screen: &dyn Fn(&tiny_http::Request) -> Option<Answer>,
    answer: &dyn Fn(&tiny_http::Request, Option<Vec<u8>>) -> Reply,
) {
    let (finished, done) = mpsc::channel::<(tiny_http::Request, Option<Vec<u8>>)>();
    let in_flight = Arc::new(AtomicUsize::new(0));
    while !stopped() {
        // Waiting for a request is also the pause between rounds.
        if let Ok(Some(mut req)) = server.recv_timeout(Duration::from_millis(5)) {
            if let Some(refused) = screen(&req) {
                respond_later(req, refused.into());
            } else if in_flight.load(Ordering::SeqCst) >= MAX_IN_FLIGHT {
                respond_later(req, plain(503).into());
            } else {
                in_flight.fetch_add(1, Ordering::SeqCst);
                let (counted, finished) = (InFlight(in_flight.clone()), finished.clone());
                std::thread::spawn(move || {
                    match read_body(&mut req, max_body, limits) {
                        Body::Complete(body) => {
                            drop(counted);
                            let _ = finished.send((req, Some(body)));
                        }
                        Body::TooBig => {
                            drop(counted);
                            let _ = finished.send((req, None));
                        }
                        Body::Stalled => {
                            drop(counted);
                            let _ = req.respond(plain(408));
                        }
                    }
                });
            }
        }
        while let Ok((req, body)) = done.try_recv() {
            let out = answer(&req, body);
            respond_later(req, out);
        }
    }
}

/// Sets a flag when dropped, including when the thread unwinds: when one listener's thread
/// ends, the other follows.
pub struct HaltOnDrop<'a>(pub &'a AtomicBool);

impl Drop for HaltOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
