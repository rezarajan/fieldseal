//! A small blocking HTTP/1.1 server around [`fieldseal_adapters_translog::handle`]: one
//! request per connection (`Connection: close`), bounded request line, headers and body,
//! read and write timeouts, and a bounded number of concurrent connections.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use fieldseal_adapters_translog::{FileLogStore, handle};

/// The largest request line plus headers accepted.
pub const MAX_HEAD: usize = 8 * 1024;
/// The most connections served at once; more are answered `503`.
pub const MAX_CONNECTIONS: usize = 64;
/// How long a connection may stall on a read or write.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A parsed request head.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Head {
    /// The method.
    pub method: String,
    /// The request target (a path; no query is accepted by the API).
    pub target: String,
    /// The declared body length (0 if none).
    pub content_length: usize,
}

/// Parses a request head (everything before the blank line): the request line and headers.
/// On failure returns the status and reason to answer with.
pub fn parse_head(head: &[u8]) -> Result<Head, (u16, &'static str)> {
    let text = std::str::from_utf8(head).map_err(|_| (400, "request head is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or("");
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err((400, "malformed request line"));
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err((505, "HTTP/1.0 or HTTP/1.1 only"));
    }
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) || !target.starts_with('/') || target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err((400, "malformed request line"));
    }
    let mut content_length = None;
    for header in lines {
        let (name, value) = header.split_once(':').ok_or((400, "malformed header"))?;
        if name.is_empty() || name.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err((400, "malformed header name"));
        }
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                let v = value.trim();
                if content_length.is_some() || v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                    return Err((400, "bad Content-Length"));
                }
                content_length = Some(v.parse::<usize>().map_err(|_| (413, "request body too large"))?);
            }
            "transfer-encoding" => return Err((501, "Transfer-Encoding is not supported; send Content-Length")),
            _ => {}
        }
    }
    Ok(Head { method: method.into(), target: target.into(), content_length: content_length.unwrap_or(0) })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Internal Server Error",
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let kind = if status == 200 { "application/octet-stream" } else { "text/plain; charset=utf-8" };
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(body)).and_then(|()| stream.flush());
}

/// Reads one request from `stream` and answers it.
fn serve(mut stream: TcpStream, store: &FileLogStore, max_body: usize) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return respond(&mut stream, 400, b"request head too large");
        }
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return respond(&mut stream, 408, b"request timed out"),
        }
    };
    if end > MAX_HEAD {
        return respond(&mut stream, 400, b"request head too large");
    }
    let head = match parse_head(&buf[..end]) {
        Ok(h) => h,
        Err((status, why)) => return respond(&mut stream, status, why.as_bytes()),
    };
    if head.content_length > max_body {
        return respond(&mut stream, 413, b"request body too large");
    }
    let mut body = buf.split_off(end + 4);
    if body.len() > head.content_length {
        return respond(&mut stream, 400, b"unexpected bytes after the body");
    }
    while body.len() < head.content_length {
        let want = (head.content_length - body.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => return respond(&mut stream, 400, b"body shorter than Content-Length"),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => return respond(&mut stream, 408, b"request timed out"),
        }
    }
    let response = handle(store, &head.method, &head.target, &body, max_body);
    respond(&mut stream, response.status, &response.body);
}

/// A running server: accepts connections until [`ShutdownHandle::shutdown`].
pub struct Server {
    listener: TcpListener,
    store: Arc<FileLogStore>,
    max_body: usize,
    stop: Arc<AtomicBool>,
}

/// Stops a [`Server`] from another thread.
#[derive(Clone)]
pub struct ShutdownHandle {
    stop: Arc<AtomicBool>,
    addr: SocketAddr,
}

impl ShutdownHandle {
    /// Asks the server to stop accepting and return once in-flight requests finish.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocked accept.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
    }
}

impl Server {
    /// Binds `addr` (port 0 picks a free port) to serve `store`.
    pub fn bind(addr: &str, store: Arc<FileLogStore>, max_body: usize) -> std::io::Result<Self> {
        Ok(Self { listener: TcpListener::bind(addr)?, store, max_body, stop: Arc::default() })
    }

    /// The bound address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// A handle that stops [`Self::run`].
    pub fn shutdown_handle(&self) -> std::io::Result<ShutdownHandle> {
        Ok(ShutdownHandle { stop: self.stop.clone(), addr: self.local_addr()? })
    }

    /// Serves until shut down, one thread per connection (at most [`MAX_CONNECTIONS`]),
    /// then waits for in-flight requests.
    pub fn run(self) {
        let active = Arc::new(AtomicUsize::new(0));
        for stream in self.listener.incoming() {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = stream else { continue };
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::SeqCst);
                respond(&mut stream, 503, b"too many connections");
                continue;
            }
            let (store, active, max_body) = (self.store.clone(), active.clone(), self.max_body);
            std::thread::spawn(move || {
                serve(stream, &store, max_body);
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        let deadline = std::time::Instant::now() + IO_TIMEOUT;
        while active.load(Ordering::SeqCst) > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

