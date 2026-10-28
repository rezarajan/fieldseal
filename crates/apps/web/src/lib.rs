//! The Fieldseal showcase web app (ADR 0036): a plain, server-rendered viewer for instruments,
//! with live rule evaluation in the browser through the WebAssembly core, and pages for the
//! other services. Development only; the binary refuses to start in production.
//!
//! Every route is a function of a [`http::Request`] to a [`http::Response`], so the whole
//! app is tested without sockets. To add a page, add a module with
//! `pub fn handle(state, req) -> Option<Response>` and one line in [`routes::dispatch`].

pub mod assets;
pub mod catalogue;
pub mod device;
pub mod http;
pub mod instruments;
pub mod intake;
pub mod panels;
pub mod publishing;
pub mod registration;
pub mod routes;
pub mod stack;
pub mod state;
pub mod ui;
