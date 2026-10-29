//! WEB-192 (WCAG 2.2 AA). The full conformance test is `just a11y <url>` (axe-core and the 2.2
//! checks axe cannot make); these pin the parts a static check can.

/// 3.3.8: PIN fields let password managers fill them, never `autocomplete="off"`.
#[test]
fn web_192_pin_fields_allow_password_managers() {
    let src = include_str!("../src/device.rs");
    for line in src.lines().filter(|l| l.contains("type=\"password\"")) {
        assert!(line.contains("autocomplete=\"new-password\"") || line.contains("autocomplete=\"current-password\""), "{line}");
        assert!(!line.contains("autocomplete=\"off\""), "{line}");
    }
}

/// 2.1.1: every sideways-scrolling table can be reached and scrolled with the keyboard.
#[test]
fn web_192_scrollable_tables_are_keyboard_reachable() {
    for src in [include_str!("../src/demo_steps.rs"), include_str!("../src/panels.rs"), include_str!("../src/publishing.rs"), include_str!("../src/registration.rs")] {
        for (i, _) in src.match_indices("class=\\\"scroll\\\"") {
            let tag = &src[i..i + 120];
            assert!(tag.contains("tabindex=\\\"0\\\"") && tag.contains("role=\\\"region\\\"") && tag.contains("aria-label="), "{tag}");
        }
    }
}
