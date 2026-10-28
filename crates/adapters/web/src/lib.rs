//! Adapters shared by the web app server and the WebAssembly binding (ADR 0036).
//!
//! - [`workbench`]: loads an instrument and its layouts, compiles and draws the render plan
//!   exactly as `fieldseal instrument preview` does (CLI-011), and evaluates rules over a set
//!   of answers. The server and the browser call the same code.
//!
//! Development only: the `web` platform profile (PLAT-100 and following) is refused in
//! production by deployment validation.

pub mod device;
pub mod json;
pub mod platform;
pub mod workbench;
