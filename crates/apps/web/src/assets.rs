//! Static files: embedded assets and the WASM bundle served from a configured directory.
//! To add an asset, add a row to [`ASSETS`].

use crate::http::{Request, Response};
use crate::state::AppState;

/// Where an asset's bytes come from.
pub enum Source {
    /// Compiled into the binary.
    Embedded(&'static str),
    /// Binary bytes compiled into the binary (fonts).
    Bytes(&'static [u8]),
    /// A file of that name in the WASM directory.
    Wasm(&'static str),
}

/// The asset table: path, content type, source.
pub const ASSETS: &[(&str, &str, Source)] = &[
    ("/assets/tokens.css", "text/css; charset=utf-8", Source::Embedded(include_str!("../assets/tokens.css"))),
    ("/assets/nunito-sans.css", "text/css; charset=utf-8", Source::Embedded(include_str!("../assets/nunito-sans.css"))),
    ("/assets/fonts/nunito-sans-400.woff2", "font/woff2", Source::Bytes(include_bytes!("../assets/fonts/nunito-sans-400.woff2"))),
    ("/assets/fonts/nunito-sans-600.woff2", "font/woff2", Source::Bytes(include_bytes!("../assets/fonts/nunito-sans-600.woff2"))),
    ("/assets/fonts/nunito-sans-700.woff2", "font/woff2", Source::Bytes(include_bytes!("../assets/fonts/nunito-sans-700.woff2"))),
    ("/assets/fonts/nunito-sans-800.woff2", "font/woff2", Source::Bytes(include_bytes!("../assets/fonts/nunito-sans-800.woff2"))),
    ("/assets/tabs.js", "text/javascript; charset=utf-8", Source::Embedded(include_str!("../assets/tabs.js"))),
    ("/assets/app.css", "text/css; charset=utf-8", Source::Embedded(include_str!("../assets/app.css"))),
    ("/assets/instrument.js", "text/javascript; charset=utf-8", Source::Embedded(include_str!("../assets/instrument.js"))),
    ("/assets/demo.css", "text/css; charset=utf-8", Source::Embedded(include_str!("../assets/demo.css"))),
    ("/assets/demo.js", "text/javascript; charset=utf-8", Source::Embedded(include_str!("../assets/demo.js"))),
    ("/assets/answers.js", "text/javascript; charset=utf-8", Source::Embedded(include_str!("../assets/answers.js"))),
    ("/assets/device.css", "text/css; charset=utf-8", Source::Embedded(include_str!("../assets/device.css"))),
    ("/assets/device.js", "text/javascript; charset=utf-8", Source::Embedded(include_str!("../assets/device.js"))),
    ("/assets/device-worker.js", "text/javascript; charset=utf-8", Source::Embedded(include_str!("../assets/device-worker.js"))),
    ("/assets/wasm/fieldseal_wasm.js", "text/javascript; charset=utf-8", Source::Wasm("fieldseal_wasm.js")),
    ("/assets/wasm/fieldseal_wasm_bg.wasm", "application/wasm", Source::Wasm("fieldseal_wasm_bg.wasm")),
];

/// Serves `GET` of an asset path.
pub fn handle(state: &AppState, req: &Request) -> Option<Response> {
    if req.method != "GET" || !req.path.starts_with("/assets/") {
        return None;
    }
    let (_, content_type, source) = ASSETS.iter().find(|(p, _, _)| *p == req.path)?;
    Some(match source {
        Source::Embedded(text) => Response::new(200, content_type, text.as_bytes().to_vec()),
        Source::Bytes(bytes) => Response::new(200, content_type, bytes.to_vec()),
        Source::Wasm(file) => match state.wasm_dir.as_ref().map(|d| d.join(file)).and_then(|p| std::fs::read(p).ok()) {
            Some(bytes) => Response::new(200, content_type, bytes),
            None => Response::text(404, format!("{file} is not available: set FIELDSEAL_WEB_WASM_DIR to the wasm-bindgen output directory")),
        },
    })
}
