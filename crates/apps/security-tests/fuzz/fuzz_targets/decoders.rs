#![no_main]
//! One target for every untrusted-bytes decoder: the first input byte selects the decoder.
//! Properties: no panic, and an accepted input re-encodes to itself (canonical form).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let targets = fieldseal_security_tests::decoders::targets();
    let Some((&first, rest)) = data.split_first() else { return };
    let (name, decode) = targets[usize::from(first) % targets.len()];
    if let Some(re) = decode(rest) {
        assert_eq!(re, rest, "{name}: accepted a non-canonical encoding");
    }
});
