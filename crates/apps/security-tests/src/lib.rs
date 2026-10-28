//! Adversarial tests for Fieldseal (issue #59). This crate has no production code: the
//! shared helpers here (a seeded generator and a canary scanner) serve the integration
//! tests under `tests/`, which are named after the requirement or attack they cover.

pub mod decoders;

/// A small seeded generator (xorshift64*), so every property test is reproducible.
#[derive(Clone, Debug)]
pub struct Seeded(u64);

impl Seeded {
    /// A generator from a seed; zero is mapped to a fixed non-zero state.
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in `0..n` (`n` of zero gives zero).
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }

    /// `n` random bytes.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

/// Canary values planted in fixtures. A leak scan fails if any appears in an output that
/// must not carry it.
pub const CANARIES: &[&str] = &["CANARY-PERSON-Zelda-Quartermain", "CANARY-SECRET-hunter2-9f3a", "CANARY-PIN-482913", "CANARY-NATIONAL-ID-7731905"];

/// Asserts that none of the canaries (nor their hex or UTF-16 forms) appear in `haystack`.
pub fn assert_no_canary(what: &str, haystack: &[u8]) {
    for c in CANARIES {
        let hex: String = c.bytes().map(|b| format!("{b:02x}")).collect();
        let text = String::from_utf8_lossy(haystack);
        assert!(!text.contains(c), "{what}: canary {c} leaked in the clear");
        assert!(!text.to_ascii_lowercase().contains(&hex), "{what}: canary {c} leaked as hex");
        assert!(!haystack.windows(c.len()).any(|w| w == c.as_bytes()), "{what}: canary {c} leaked as bytes");
    }
}

/// Turns a low-`s` ECDSA signature (`r ‖ s`, 64 bytes) into its high-`s` twin, `n - s`. The
/// result still verifies mathematically; Fieldseal must refuse it (WIRE-022, malleability).
pub fn to_high_s(signature: &[u8]) -> Vec<u8> {
    // The order of the P-256 group.
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e,
        0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    assert_eq!(signature.len(), 64);
    let mut out = signature.to_vec();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(N[i]) - i16::from(signature[32 + i]) - borrow;
        borrow = i16::from(d < 0);
        if d < 0 {
            d += 256;
        }
        out[32 + i] = d as u8;
    }
    out
}
