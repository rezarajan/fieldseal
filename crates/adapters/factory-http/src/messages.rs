//! The portal's message catalogue (ADR 0034, PLAT-050 style): every user-facing string,
//! keyed by a stable message ID. Pages never build sentences by concatenation; a message
//! may hold named placeholders (`{name}`) filled by [`format`], with values HTML-escaped.
//!
//! Only the reference language (English) exists so far; a translated catalogue replaces
//! [`CATALOGUE`] entry for entry, keeping every placeholder.

use crate::html::escape;

/// The reference catalogue: message ID and text.
pub const CATALOGUE: &[(&str, &str)] = &[
    ("portal.title", "Fieldseal factory"),
    ("portal.skip", "Skip to main content"),
    ("portal.signin.heading", "Sign in"),
    ("portal.signin.intro", "Sign in with your organisation account to register devices."),
    ("portal.signin.button", "Sign in"),
    ("portal.signout.button", "Sign out"),
    ("portal.signedin", "Signed in as {account}."),
    ("portal.signin.failed", "Sign-in failed: {reason}"),
    ("portal.signin.weak", "Your sign-in method isn't strong enough to register devices. Sign in again with a passkey or security key."),
    ("portal.token.heading", "Register a device"),
    ("portal.token.route", "How the device connects"),
    ("portal.token.route.online", "The device is online"),
    ("portal.token.route.airgapped", "The device has no network (files and QR codes)"),
    ("portal.token.uses", "Number of devices (operators only)"),
    ("portal.token.button", "Get a registration token"),
    ("portal.token.issued.heading", "Your registration token"),
    ("portal.token.warning", "Do not share this token. Anyone who has it can try to register a device to your account. Scan it only with your own device."),
    ("portal.token.expires", "It expires at {expires} (factory time)."),
    ("portal.token.text", "Token as text"),
    ("portal.token.qr", "Token as a QR code"),
    ("portal.token.back", "Back to your devices"),
    ("portal.pending.heading", "Requests waiting for you"),
    ("portal.pending.none", "There are no requests waiting."),
    ("portal.pending.compare", "Compare these words with the words on your device. Confirm only if all four words and numbers match."),
    ("portal.pending.words", "Fingerprint words"),
    ("portal.pending.device", "Device"),
    ("portal.pending.confirm", "The words match: register this device"),
    ("portal.pending.batch", "Batch token"),
    ("portal.devices.heading", "Your devices"),
    ("portal.devices.none", "You have no registered devices."),
    ("portal.devices.nickname", "Nickname"),
    ("portal.devices.words", "Fingerprint words"),
    ("portal.devices.state", "State"),
    ("portal.devices.lastseen", "Last seen"),
    ("portal.devices.actions", "Actions"),
    ("portal.devices.lost", "Mark as lost"),
    ("portal.devices.retire", "Retire"),
    ("portal.devices.roll", "To roll keys, get a new token and start the key roll on the device."),
    ("portal.devices.certificate", "Download certificate"),
    ("portal.devices.limit", "You have reached your device limit. Retire a device before registering another."),
    ("portal.upload.heading", "Upload a request file"),
    ("portal.upload.intro", "For a device with no network: upload the request file it saved."),
    ("portal.upload.file", "Request file"),
    ("portal.upload.button", "Upload"),
    ("portal.upload.done", "Request received. Compare the words below with your device, then confirm."),
    ("portal.close.heading", "Close certificate"),
    ("portal.close.intro", "The device is closed from record {cutoff} onwards. Show this to the device, or keep it with your records."),
    ("portal.never", "never"),
    ("portal.error.heading", "Something went wrong"),
    ("portal.error.csrf", "The form expired. Go back and try again."),
    ("portal.error.notfound", "Not found."),
    ("portal.error.denied", "Refused: {reason}"),
    ("api.unknown-survey", "No published survey has this name."),
    ("api.unknown-cohort", "No roster is stored for this cohort."),
    ("api.version-taken", "A different roster is already stored at this version."),
    ("api.not-newer", "The roster version is not higher than the latest stored for the cohort."),
    ("state.pending", "Waiting for confirmation"),
    ("state.held", "Held for review"),
    ("state.rejected", "Rejected"),
    ("state.registered", "Registered"),
    ("state.flagged", "Registered, flagged"),
    ("state.lost", "Lost"),
    ("state.closing", "Closing"),
    ("state.closed", "Closed"),
    ("state.retired", "Retired"),
];

/// The text of message `id`. An unknown ID is a programming error and shows the ID itself,
/// so it is visible rather than silently empty.
pub fn text(id: &str) -> &str {
    CATALOGUE.iter().find(|(k, _)| *k == id).map(|(_, v)| *v).unwrap_or(id)
}

/// Message `id`, HTML-escaped, with each `{name}` placeholder replaced by its escaped value.
pub fn format(id: &str, args: &[(&str, &str)]) -> String {
    let mut out = escape(text(id));
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), &escape(value));
    }
    out
}

/// Message `id`, HTML-escaped.
pub fn t(id: &str) -> String {
    escape(text(id))
}
