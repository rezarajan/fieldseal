//! The `development-adapters` start-up event (DEP-051, Technical Plan 10.1). Each service
//! prints it once at start, so the intake app, the factory and the transparency-log server
//! report their development adapters in the same shape. It names ports and adapters only and
//! holds no personal data.

/// The event as one line of JSON: the service, then each port with the development adapter
/// bound to it, in the order given.
pub fn development_adapters_event(service: &str, adapters: &[(&str, &str)]) -> String {
    let quote = |s: &str| format!("{s:?}");
    let list: Vec<String> = adapters.iter().map(|(port, adapter)| format!("{{\"port\":{},\"adapter\":{}}}", quote(port), quote(adapter))).collect();
    format!("{{\"event\":\"development-adapters\",\"service\":{},\"adapters\":[{}]}}", quote(service), list.join(","))
}
