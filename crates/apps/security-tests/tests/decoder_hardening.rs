//! Decoder hardening (issue #59, ADR 0007 "assume every input is hostile").
//!
//! Every decoder that reads untrusted bytes is driven with a seeded generator: pure noise,
//! and mutations (bit flips, truncation, extension, splices, length bombs) of every valid
//! object in the repository's golden vectors. For each input the decoder must (1) not
//! panic, (2) return within a time bound, and (3) when it accepts, re-encode to exactly the
//! input (canonical form, WIRE-001/002). Peak resident memory of the whole run is bounded.
//!
//! The same targets are exposed to `cargo fuzz` under `fuzz/` (see `fuzz/README.md`).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fieldseal_kernel::cbor;

use fieldseal_security_tests::Seeded;
use fieldseal_security_tests::decoders::targets;

/// Every even-length hex string of at least 8 digits in the repository's vector files.
fn corpus() -> Vec<Vec<u8>> {
    fn walk(v: &serde_json::Value, out: &mut Vec<Vec<u8>>) {
        match v {
            serde_json::Value::String(s) => {
                if s.len() >= 8 && s.len() % 2 == 0 && s.bytes().all(|c| c.is_ascii_hexdigit()) {
                    out.push((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect());
                } else if s.len() >= 8 {
                    out.push(s.as_bytes().to_vec());
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            serde_json::Value::Object(m) => m.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut dirs: Vec<PathBuf> = vec![root.join("kernel/tests/vectors"), root.join("adapters/memory/tests/vectors")];
    for ctx in std::fs::read_dir(root.join("contexts")).expect("contexts") {
        dirs.push(ctx.expect("entry").path().join("tests/vectors"));
    }
    let mut out = Vec::new();
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for f in rd.flatten() {
            if let Ok(text) = std::fs::read_to_string(f.path())
                && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            {
                walk(&json, &mut out);
            }
        }
    }
    out.sort();
    out.dedup();
    out.truncate(600);
    out
}

fn mutate(rng: &mut Seeded, seed: &[u8], pool: &[Vec<u8>]) -> Vec<u8> {
    let mut b = seed.to_vec();
    match rng.below(8) {
        0 => {
            for _ in 0..=rng.below(4) {
                if !b.is_empty() {
                    let i = rng.below(b.len());
                    b[i] ^= 1 << rng.below(8);
                }
            }
        }
        1 => {
            if !b.is_empty() {
                let i = rng.below(b.len());
                b[i] = rng.next_u64() as u8;
            }
        }
        2 => b.truncate(rng.below(b.len() + 1)),
        3 => {
            let n = 1 + rng.below(32);
            b.extend(rng.bytes(n));
        }
        4 => {
            // A length bomb: overwrite a run with 0xff, which reads as a maximal length.
            if b.len() > 4 {
                let i = rng.below(b.len() - 4);
                b[i..i + 4].fill(0xff);
            }
        }
        5 => {
            let other = &pool[rng.below(pool.len())];
            let cut = rng.below(b.len() + 1);
            b.truncate(cut);
            b.extend_from_slice(&other[rng.below(other.len() + 1)..]);
        }
        6 => {
            let i = rng.below(b.len() + 1);
            let n = 1 + rng.below(8);
            b.splice(i..i, rng.bytes(n));
        }
        _ => {
            // Deep nesting and wide arrays: CBOR heads that promise a lot.
            let head = [0x81u8, 0x9f, 0xa1, 0x5b, 0x7b, 0x9b, 0xbb][rng.below(7)];
            let mut v = vec![head; 1 + rng.below(200)];
            v.extend(b.iter().take(16));
            b = v;
        }
    }
    b
}

fn peak_rss_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let l = s.lines().find(|l| l.starts_with("VmHWM:"))?;
    l.split_whitespace().nth(1)?.parse().ok()
}

fn run_one(name: &str, f: fn(&[u8]) -> Option<Vec<u8>>, input: &[u8]) {
    let started = Instant::now();
    let out = catch_unwind(AssertUnwindSafe(|| f(input)));
    let took = started.elapsed();
    let hex: String = input.iter().take(64).map(|b| format!("{b:02x}")).collect();
    let out = out.unwrap_or_else(|_| panic!("{name} panicked on {} bytes starting {hex}", input.len()));
    assert!(took < Duration::from_secs(2), "{name}: {} bytes took {took:?} (unbounded work)", input.len());
    if let Some(re) = out {
        assert_eq!(re, input, "{name}: accepted a non-canonical encoding (WIRE-001); input starts {hex}");
    }
}

/// WIRE-001..007, WIRE-160, ADR 0007: no decoder panics, hangs or accepts a non-canonical
/// form, whatever bytes arrive.
#[test]
fn wire_160_every_decoder_survives_seeded_hostile_input() {
    let pool = corpus();
    assert!(pool.len() > 50, "the vector corpus was found ({} objects)", pool.len());
    let mut rng = Seeded::new(0xF1E1_D5EA_1000_0059);
    let mut total = 0usize;
    for (name, f) in targets() {
        // The valid corpus itself first: whatever a decoder accepts must be canonical.
        for seed in &pool {
            run_one(name, f, seed);
            for _ in 0..12 {
                let m = mutate(&mut rng, seed, &pool);
                run_one(name, f, &m);
                total += 1;
            }
        }
        for _ in 0..1500 {
            let n = rng.below(300);
            run_one(name, f, &rng.bytes(n));
            total += 1;
        }
        // CBOR-shaped noise: bytes drawn from the structural heads.
        for _ in 0..1500 {
            let n = rng.below(120);
            let heads = [0x00u8, 0x18, 0x20, 0x40, 0x58, 0x60, 0x78, 0x80, 0x98, 0xa0, 0xb8, 0xc4, 0xf4, 0xf6, 0xf9, 0xff, 0x1b, 0x5b, 0x7b, 0x9b, 0xbb];
            let v: Vec<u8> = (0..n).map(|_| if rng.below(2) == 0 { heads[rng.below(heads.len())] } else { rng.next_u64() as u8 }).collect();
            run_one(name, f, &v);
            total += 1;
        }
    }
    eprintln!("hostile inputs tried: {total}");
    if let Some(kib) = peak_rss_kib() {
        assert!(kib < 1_500_000, "peak resident memory {kib} KiB over the run is unbounded-looking");
    }
}

/// WIRE-160: a declared length is checked before anything is allocated. A 5-byte head that
/// promises 4 GiB must fail quickly, for CBOR and for the frame and export framings.
#[test]
fn wire_160_length_bombs_are_refused_without_allocating() {
    let started = Instant::now();
    for bomb in [
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
        &[0x7b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
        &[0x9b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff][..],
        &[0xbb, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff][..],
    ] {
        assert!(cbor::decode(bomb).is_err());
    }
    // Nesting well past the depth limit.
    let deep = vec![0x81u8; 100_000];
    assert!(cbor::decode(&deep).is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// WIRE-122 (found by this suite): scanned or pasted text-form tokens may hold multi-byte
/// characters anywhere; `text::decode` once sliced the string at a byte offset and panicked.
#[test]
fn wire_122_non_ascii_text_forms_are_refused_not_a_panic() {
    for s in ["FS1T:é", "FS1T:\u{1F600}\u{1F600}", "  \u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}  ", "FS1T:ABCDE\u{00e9}", "FS1\u{00e9}T:0000", "\u{FFFD} \u{FFFD}"] {
        assert!(fieldseal_kernel::text::decode("FS1T", s).is_err(), "{s:?}");
    }
}

/// Authoring files (YAML/JSON) are untrusted too: seeded mutations of every example file
/// decode without panic in bounded time, and whatever decodes is validated without panic
/// (instrument, layout and policy validators read the decoded value).
// covers: WIRE-164, INS-007, ADR-0007
#[test]
fn ins_authoring_mutated_examples_never_panic_the_decoders_or_validators() {
    use fieldseal_adapters_authoring::{Format, decode as authoring_decode};
    use fieldseal_instrument::application::validate_instrument;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples");
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    let mut stack = vec![root];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).expect("examples").flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "yaml" || x == "json") {
                seeds.push(std::fs::read(&p).expect("read"));
            }
        }
    }
    assert!(seeds.len() >= 8, "examples found: {}", seeds.len());
    let mut rng = Seeded::new(0xA07_0059);
    let started = Instant::now();
    for seed in &seeds {
        for round in 0..60 {
            let m = mutate(&mut rng, seed, &seeds);
            for format in [Format::Yaml, Format::Json] {
                let t = Instant::now();
                let r = catch_unwind(AssertUnwindSafe(|| authoring_decode(&m, format).ok().map(|v| validate_instrument(&v).is_ok())));
                assert!(r.is_ok(), "authoring/validator panicked on round {round} ({format:?}), {} bytes", m.len());
                assert!(t.elapsed() < Duration::from_secs(2), "{format:?}: {:?}", t.elapsed());
            }
        }
    }
    eprintln!("authoring mutations took {:?}", started.elapsed());
}
