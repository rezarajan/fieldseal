//! The kernel's golden wire vectors (WIRE §8), checked in-process.
//!
//! The vectors are embedded from `crates/kernel/tests/vectors/`; each case names the
//! requirement it tests, and the result is reported against that ID.

use fieldseal_kernel::cbor;
use fieldseal_kernel::crc::crc32c;
use fieldseal_kernel::crypto::{DomainTag, P256PublicKey, Signature};
use fieldseal_kernel::digest::{instrument_fingerprint, key_id, lower_hex, sha256};
use fieldseal_kernel::export::{ExportFile, repair, salvage_frames};
use fieldseal_kernel::frame::{frame, read_frames};
use fieldseal_kernel::id::{ContentAddress, Salt};
use fieldseal_kernel::record::read_journal;
use fieldseal_kernel::seal::{RecipientSecret, SealedBox, Suite, open};
use fieldseal_kernel::sign::{SigningKey, signed_message, verify};
use fieldseal_kernel::{Decimal, ErrorCode, Value};
use serde_json::Value as J;

use super::harness::{Chk, Collector, ensure, label, requirement_ids, same, unhex};
use super::Unit;
use fieldseal_kernel::id::TenancyId;
use fieldseal_kernel::local_record::{LocalEntry, MAX_ENCRYPTIONS, derive_session_key, local_record_aad};
use fieldseal_kernel::pop::PopToken;
use fieldseal_kernel::qr_sequence::{CHUNK_BYTES, Frame, MAX_FRAME_CHARS, Reassembler, encode_sequence, message_id};
use fieldseal_kernel::WireError;

const CBOR: &str = include_str!("../../../../kernel/tests/vectors/cbor.json");
const IDENTIFIERS: &str = include_str!("../../../../kernel/tests/vectors/identifiers.json");
const SIGNATURES: &str = include_str!("../../../../kernel/tests/vectors/signatures.json");
const SEALS: &str = include_str!("../../../../kernel/tests/vectors/seals.json");
const FRAMES: &str = include_str!("../../../../kernel/tests/vectors/frames.json");
const RECORDS: &str = include_str!("../../../../kernel/tests/vectors/records.json");
const EXPORTS: &str = include_str!("../../../../kernel/tests/vectors/exports.json");
const LOCAL_RECORDS: &str = include_str!("../../../../kernel/tests/vectors/local_records.json");
const QR_SEQUENCES: &str = include_str!("../../../../kernel/tests/vectors/qr_sequences.json");
const POP_TOKENS: &str = include_str!("../../../../kernel/tests/vectors/pop_tokens.json");
const RECEIPTS: &str = include_str!("../../../../contexts/intake/tests/vectors/receipts.json");
const TIME_TOKENS: &str = include_str!("../../../../contexts/distribution/tests/vectors/time_tokens.json");
const RECEIVER_CHALLENGE: &str = include_str!("../../../../contexts/delivery/tests/vectors/receiver_challenge.json");

/// The units of the `wire` suite.
pub fn units() -> Vec<Unit> {
    vec![
        Unit::new("wire:cbor", &["wire"], cbor_vectors),
        Unit::new("wire:identifiers", &["wire"], identifiers),
        Unit::new("wire:signatures", &["wire"], signatures),
        Unit::new("wire:seals", &["wire"], seals),
        Unit::new("wire:frames", &["wire"], frames),
        Unit::new("wire:records", &["wire"], records),
        Unit::new("wire:exports", &["wire"], exports),
        Unit::new("wire:local-records", &["wire"], local_records),
        Unit::new("wire:qr-sequences", &["wire"], qr_sequences),
        Unit::new("wire:pop-tokens", &["wire"], pop_tokens),
        Unit::new("wire:receipts", &["wire"], receipts),
        Unit::new("wire:time-tokens", &["wire"], time_tokens),
        Unit::new("wire:receiver-challenge", &["wire"], receiver_challenge),
    ]
}

fn load(text: &str) -> Result<J, String> {
    serde_json::from_str(text).c()
}

fn s<'a>(j: &'a J, key: &str) -> Result<&'a str, String> {
    j[key].as_str().ok_or_else(|| format!("field `{key}` is missing"))
}

fn bytes(j: &J, key: &str) -> Result<Vec<u8>, String> {
    unhex(s(j, key)?)
}

fn list<'a>(j: &'a J, key: &str) -> &'a [J] {
    j[key].as_array().map_or(&[], Vec::as_slice)
}

fn num(j: &J, key: &str) -> Result<u64, String> {
    j[key].as_u64().ok_or_else(|| format!("field `{key}` is missing"))
}

fn code(j: &J) -> Result<ErrorCode, String> {
    ErrorCode::parse(s(j, "error")?).c()
}

/// A decimal integer: an optional `-` and ASCII digits only (no `+`, no spaces).
fn signed(text: &str) -> Result<i128, String> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("not an integer: {text}"));
    }
    text.parse().map_err(|_| format!("integer out of range: {text}"))
}

/// The typed JSON form of a [`Value`] (see the kernel's vector generator).
fn value(j: &J) -> Result<Value, String> {
    let (kind, inner) = j.as_object().and_then(|o| o.iter().next()).c()?;
    Ok(match kind.as_str() {
        "int" => Value::Int(signed(inner.as_str().c()?)?),
        "decimal" => Value::Decimal(Decimal { exponent: inner["exponent"].as_i64().c()? as i32, mantissa: signed(inner["mantissa"].as_str().c()?)? }),
        "bytes" => Value::Bytes(unhex(inner.as_str().c()?)?),
        "text" => Value::Text(inner.as_str().c()?.to_owned()),
        "bool" => Value::Bool(inner.as_bool().c()?),
        "array" => Value::Array(inner.as_array().c()?.iter().map(value).collect::<Result<_, _>>()?),
        "map" => Value::Map(inner.as_object().c()?.iter().map(|(k, v)| value(v).map(|v| (k.clone(), v))).collect::<Result<_, _>>()?),
        other => return Err(format!("unknown typed value {other}")),
    })
}

fn cbor_vectors(c: &mut Collector) {
    let Ok(v) = load(CBOR) else { return c.case(&["WIRE-001".into()], "load", || Err("cbor.json does not parse".into())) };
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-001"]), format!("valid {}", label(case, i)), || {
            let expected = value(&case["value"])?;
            let cbor_bytes = bytes(case, "cbor")?;
            same!(cbor::encode(&expected).c()?, cbor_bytes, "encoding");
            same!(cbor::decode(&cbor_bytes).c()?, expected, "decoding");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-001"]), format!("invalid {}", label(case, i)), || {
            let Err(e) = cbor::decode(&bytes(case, "cbor")?) else { return Err("the decoder accepted it".into()) };
            same!(e.code, code(case)?, "error code");
            same!(e.offset as u64, num(case, "offset")?, "error offset");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_encode").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-001"]), format!("invalid encode {}", label(case, i)), || {
            let Err(e) = cbor::encode(&value(&case["value"])?) else { return Err("the encoder accepted it".into()) };
            same!(e.code, code(case)?, "error code");
            Ok(())
        });
    }
    for (i, case) in list(&v, "from_json").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-006"]), format!("from json {}", label(case, i)), || {
            same!(lower_hex(&cbor::encode(&value(&case["value"])?).c()?), s(case, "cbor")?.to_owned(), "encoding");
            Ok(())
        });
    }
}

fn identifiers(c: &mut Collector) {
    let Ok(v) = load(IDENTIFIERS) else { return c.case(&["WIRE-010".into()], "load", || Err("identifiers.json does not parse".into())) };
    for (i, case) in list(&v, "content_addresses").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-011"]), format!("content address {}", label(case, i)), || {
            let a = ContentAddress::of(&bytes(case, "bytes")?);
            same!(a.to_text(), s(case, "address")?.to_owned(), "text form");
            same!(ContentAddress::parse_text(s(case, "address")?).c()?, a, "round trip");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_content_addresses").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-011"]), format!("invalid address {}", label(case, i)), || {
            let Err(e) = ContentAddress::parse_text(s(case, "text")?) else { return Err("accepted".into()) };
            same!(e.code, code(case)?, "error code");
            Ok(())
        });
    }
    for (i, case) in list(&v, "key_ids").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-010"]), format!("key id {}", label(case, i)), || {
            same!(lower_hex(key_id(&bytes(case, "public_key")?).as_bytes()), s(case, "key_id")?.to_owned(), "key id");
            Ok(())
        });
    }
    let mut seen = Vec::new();
    for (i, case) in list(&v, "fingerprints").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-185"]), format!("fingerprint {}", label(case, i)), || {
            let salt = Salt::from_bytes(&bytes(case, "salt")?).c()?;
            let fp = instrument_fingerprint(&salt, &bytes(case, "canonical")?);
            same!(lower_hex(fp.as_bytes()), s(case, "fingerprint")?.to_owned(), "fingerprint");
            same!(fp.short_form(), s(case, "short_form")?.to_owned(), "short form");
            seen.push(fp);
            Ok(())
        });
    }
    c.case(&["WIRE-185".into()], "the same content under different salts has different fingerprints", || {
        ensure!(seen.len() >= 2 && seen[0] != seen[1], "fingerprints do not differ by salt");
        Ok(())
    });
}

fn signatures(c: &mut Collector) {
    let Ok(v) = load(SIGNATURES) else { return c.case(&["WIRE-020".into()], "load", || Err("signatures.json does not parse".into())) };
    let setup = (|| -> Result<(SigningKey, P256PublicKey), String> {
        let key = SigningKey::from_scalar(&bytes(&v, "private_key")?).c()?;
        let public = P256PublicKey::from_bytes(&bytes(&v, "public_key")?).c()?;
        ensure!(key.public_key() == public, "the private key does not match the public key");
        Ok((key, public))
    })();
    let Ok((key, public)) = setup else { return c.case(&["WIRE-020".into()], "keys", || Err("the vector keys do not load".into())) };
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-021"]), format!("valid {}", label(case, i)), || {
            let tag = DomainTag::known(s(case, "tag")?).c()?;
            let structure = value(&case["structure"])?;
            let sig = Signature(bytes(case, "signature")?);
            same!(lower_hex(&signed_message(&tag, &structure).c()?), s(case, "message")?.to_owned(), "signed message");
            verify(&public, &tag, &structure, &sig).c()?;
            same!(key.sign(&tag, &structure).c()?, sig, "deterministic signing");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-020"]), format!("invalid {}", label(case, i)), || {
            let structure = value(&case["structure"])?;
            let sig = Signature(bytes(case, "signature")?);
            let e = match DomainTag::known(s(case, "tag")?) {
                Ok(tag) => match verify(&public, &tag, &structure, &sig) {
                    Err(e) => e,
                    Ok(()) => return Err("the signature verified".into()),
                },
                Err(e) => e,
            };
            same!(e.code, code(case)?, "error code");
            Ok(())
        });
    }
}

fn seals(c: &mut Collector) {
    let Ok(v) = load(SEALS) else { return c.case(&["WIRE-023".into()], "load", || Err("seals.json does not parse".into())) };
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-023"]), format!("valid {}", label(case, i)), || {
            let suite = Suite::parse(s(case, "suite")?).c()?;
            let secret = RecipientSecret::from_bytes(suite, &bytes(case, "recipient_private_key")?).c()?;
            let public = secret.public().c()?;
            same!(lower_hex(public.encoded()), s(case, "recipient_public_key")?.to_owned(), "public key");
            same!(lower_hex(public.key_id().as_bytes()), s(case, "recipient_key_id")?.to_owned(), "key id");
            let tag = DomainTag::known(s(case, "tag")?).c()?;
            let sealed = SealedBox::decode(&bytes(case, "sealed")?).c()?;
            same!(lower_hex(&sealed.enc), s(case, "enc")?.to_owned(), "encapsulated key");
            same!(lower_hex(&sealed.ct), s(case, "ct")?.to_owned(), "ciphertext");
            let plaintext = bytes(case, "plaintext")?;
            let opened = open(&secret, &tag, &sealed).c()?;
            same!(opened.as_slice(), plaintext.as_slice(), "opened plaintext");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-024"]), format!("invalid {}", label(case, i)), || {
            let suite = Suite::parse(s(case, "suite_of_key")?).c()?;
            let secret = RecipientSecret::from_bytes(suite, &bytes(case, "recipient_private_key")?).c()?;
            let outcome = DomainTag::known(s(case, "tag")?)
                .and_then(|tag| SealedBox::decode(&bytes(case, "sealed").unwrap_or_default()).and_then(|b| open(&secret, &tag, &b).map(|_| ())));
            let Err(e) = outcome else { return Err("opened".into()) };
            same!(e.code, code(case)?, "error code");
            Ok(())
        });
    }
}

fn frames(c: &mut Collector) {
    let Ok(v) = load(FRAMES) else { return c.case(&["WIRE-031".into()], "load", || Err("frames.json does not parse".into())) };
    for (i, case) in list(&v, "crc32c").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-031"]), format!("crc32c {}", label(case, i)), || {
            same!(format!("{:08x}", crc32c(&bytes(case, "bytes")?)), s(case, "crc32c")?.to_owned(), "checksum");
            Ok(())
        });
    }
    for (i, case) in list(&v, "frames").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-031"]), format!("frame {}", label(case, i)), || {
            same!(lower_hex(&frame(&bytes(case, "body")?).c()?), s(case, "frame")?.to_owned(), "frame");
            Ok(())
        });
    }
    for (i, case) in list(&v, "scans").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-032"]), format!("scan {}", label(case, i)), || {
            let journal = bytes(case, "journal")?;
            let scan = read_frames(&journal);
            let got: Vec<(u64, String)> = scan.frames.iter().map(|f| (f.offset as u64, lower_hex(f.body))).collect();
            let want: Vec<(u64, String)> =
                list(case, "frames").iter().map(|f| Ok((num(f, "offset")?, s(f, "body")?.to_owned()))).collect::<Result<_, String>>()?;
            same!(got, want, "frames");
            let got: Vec<(ErrorCode, u64)> = scan.damage.iter().map(|e| (e.code, e.offset as u64)).collect();
            let want: Vec<(ErrorCode, u64)> = list(case, "damage").iter().map(|d| Ok((code(d)?, num(d, "offset")?))).collect::<Result<_, String>>()?;
            same!(got, want, "damage");
            Ok(())
        });
    }
}

fn records(c: &mut Collector) {
    let Ok(v) = load(RECORDS) else { return c.case(&["WIRE-030".into()], "load", || Err("records.json does not parse".into())) };
    let Ok(public) = bytes(&v, "tenancy_public_key").and_then(|b| P256PublicKey::from_bytes(&b).c()) else {
        return c.case(&["WIRE-030".into()], "keys", || Err("the vector key does not load".into()));
    };
    c.case(&["WIRE-030".into(), "WIRE-033".into()], "the journal reads clean and its records match", || {
        let journal = bytes(&v, "journal")?;
        let report = read_journal(&journal, std::slice::from_ref(&public), &[]);
        ensure!(report.is_clean(), "errors: {:?}", report.errors);
        let records = list(&v, "records");
        same!(report.entries.len(), records.len(), "record count");
        for (entry, case) in report.entries.iter().zip(records) {
            same!(lower_hex(entry.hash.as_bytes()), s(case, "hash")?.to_owned(), "record hash");
            same!(lower_hex(&entry.record.encode().c()?), s(case, "body")?.to_owned(), "record body");
            ensure!(fieldseal_kernel::record::is_uuid_v4(&entry.record.header.record_id), "the record id is not a version-4 UUID");
        }
        Ok(())
    });
    for (i, case) in list(&v, "invalid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-030"]), format!("invalid {}", label(case, i)), || {
            // The unknown-signer case is read with a key that signed nothing in the journal.
            let keys = if s(case, "id")? == "unknown-signer" {
                let seed = sha256(b"fieldseal.dev/vectors/authority-signing-key");
                vec![SigningKey::from_scalar(seed.as_bytes()).c()?.public_key()]
            } else {
                vec![public.clone()]
            };
            let report = read_journal(&bytes(case, "journal")?, &keys, &[]);
            let got: Vec<(ErrorCode, u64)> = report.errors.iter().map(|e| (e.code, e.offset as u64)).collect();
            let want: Vec<(ErrorCode, u64)> = list(case, "errors").iter().map(|e| Ok((code(e)?, num(e, "offset")?))).collect::<Result<_, String>>()?;
            ensure!(!want.is_empty(), "the vector names no error");
            same!(got, want, "errors");
            Ok(())
        });
    }
}

fn exports(c: &mut Collector) {
    let Ok(v) = load(EXPORTS) else { return c.case(&["WIRE-100".into()], "load", || Err("exports.json does not parse".into())) };
    let Ok(public) = bytes(&v, "tenancy_public_key").and_then(|b| P256PublicKey::from_bytes(&b).c()) else {
        return c.case(&["WIRE-100".into()], "keys", || Err("the vector key does not load".into()));
    };
    let (Ok(plain), Ok(file)) = (bytes(&v, "without_parity"), bytes(&v, "with_parity")) else {
        return c.case(&["WIRE-100".into()], "files", || Err("the vector files do not load".into()));
    };
    c.case(&["WIRE-100".into(), "WIRE-101".into()], "both files decode, verify and re-encode to the same bytes", || {
        for f in [&plain, &file] {
            let parsed = ExportFile::decode(f).c()?;
            same!(parsed.parts.len() as u64, parsed.header.parts, "part count");
            parsed.parts[0].verify(&parsed.header, &public).c()?;
            same!(&parsed.encode(parsed.parts[0].parity.is_some()).c()?, f, "re-encoding");
            ensure!(read_journal(&parsed.parts[0].journal, std::slice::from_ref(&public), &[]).is_clean(), "the journal is not clean");
        }
        Ok(())
    });
    c.case(&["WIRE-108".into()], "parity is not signed: adding or stripping it leaves the signature valid", || {
        same!(ExportFile::decode(&plain).c()?.parts[0].signature, ExportFile::decode(&file).c()?.parts[0].signature, "signature");
        same!(ExportFile::decode(&plain).c()?.encode(true).c()?, file, "adding parity");
        same!(ExportFile::decode(&file).c()?.encode(false).c()?, plain, "stripping parity");
        Ok(())
    });
    for (i, case) in list(&v, "repairs").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-109"]), format!("repair {}", label(case, i)), || {
            let mut damaged = file.clone();
            for off in list(case, "flip_offsets") {
                damaged[off.as_u64().c()? as usize] ^= 0xff;
            }
            same!(ExportFile::decode(&damaged).err().map(|e| e.code), Some(ErrorCode::Crc), "damage is detected");
            match repair(&damaged) {
                Ok((repaired, n)) => {
                    same!(n as u64, num(case, "repaired_shards")?, "repaired shards");
                    same!(repaired, file, "repaired file");
                    let parsed = ExportFile::decode(&repaired).c()?;
                    parsed.parts[0].verify(&parsed.header, &public).c()?;
                }
                Err(e) => {
                    same!(e.code, code(case)?, "error code");
                    same!(salvage_frames(&damaged).len() as u64, num(case, "salvaged_frames")?, "salvaged frames");
                }
            }
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-100"]), format!("invalid {}", label(case, i)), || {
            let f = bytes(case, "file")?;
            let e = match ExportFile::decode(&f) {
                Ok(parsed) => match parsed.parts[0].verify(&parsed.header, &public) {
                    Err(e) => e,
                    Ok(()) => return Err("the file verified".into()),
                },
                Err(e) => e,
            };
            same!(e.code, code(case)?, "error code");
            same!(e.offset as u64, num(case, "offset")?, "error offset");
            Ok(())
        });
    }
}

fn tenancy(j: &J, key: &str) -> Result<TenancyId, String> {
    Ok(TenancyId::from(<[u8; 32]>::try_from(bytes(j, key)?).map_err(|_| format!("`{key}` is not 32 bytes"))?))
}

fn fixed<const N: usize>(j: &J, key: &str) -> Result<[u8; N], String> {
    <[u8; N]>::try_from(bytes(j, key)?).map_err(|_| format!("`{key}` is not {N} bytes"))
}

fn same_error(e: &WireError, case: &J) -> Result<(), String> {
    same!(e.code, code(case)?, "error code");
    same!(e.offset as u64, num(case, "offset")?, "error offset");
    Ok(())
}

fn local_records(c: &mut Collector) {
    let Ok(v) = load(LOCAL_RECORDS) else { return c.case(&["WIRE-080".into()], "load", || Err("local_records.json does not parse".into())) };
    c.case(&["WIRE-082".into()], "the key-rotation limit is 2^32 encryptions", || {
        same!(num(&v, "max_encryptions")?, MAX_ENCRYPTIONS, "limit");
        same!(MAX_ENCRYPTIONS, 1u64 << 32, "limit");
        Ok(())
    });
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-080", "WIRE-081"]), format!("valid {}", label(case, i)), || {
            let t = tenancy(&v, "tenancy")?;
            let key = derive_session_key(&bytes(&v, "unwrapped_secret")?, &fixed(&v, "pin_hash")?, &t);
            let seq = num(case, "seq")?;
            let plaintext = bytes(case, "plaintext")?;
            same!(lower_hex(&local_record_aad(&t, seq)), s(case, "aad")?.to_owned(), "additional data");
            same!(lower_hex(&LocalEntry::seal(&key, &t, seq, fixed(case, "nonce")?, &plaintext).encode()), s(case, "cbor")?.to_owned(), "entry");
            let entry = LocalEntry::decode(&bytes(case, "cbor")?).c()?;
            same!(&entry.open(&key, &t).c()?[..], &plaintext[..], "plaintext");
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-080"]), format!("invalid {}", label(case, i)), || {
            let t = tenancy(case, "tenancy")?;
            let key = derive_session_key(&bytes(case, "unwrapped_secret")?, &fixed(case, "pin_hash")?, &t);
            let e = match (s(case, "stage")?, LocalEntry::decode(&bytes(case, "cbor")?)) {
                ("decode", Err(e)) => e,
                ("open", Ok(entry)) => match entry.open(&key, &t) {
                    Err(e) => e,
                    Ok(_) => return Err("the entry opened".into()),
                },
                (stage, _) => return Err(format!("not rejected at the {stage} stage")),
            };
            same_error(&e, case)
        });
    }
}

/// What a fresh receiver makes of `frames`: the object it completes, or the first failure,
/// with the index of the frame that caused it.
fn feed(frames: &[String]) -> J {
    let mut r = Reassembler::new();
    for (i, f) in frames.iter().enumerate() {
        match r.push(f) {
            Err(e) => return serde_json::json!({"error": e.code.as_str(), "offset": e.offset, "at_frame": i}),
            Ok(Some(o)) => return serde_json::json!({"object": lower_hex(&o), "at_frame": i}),
            Ok(None) => {}
        }
    }
    serde_json::json!({"incomplete": true})
}

fn strings(j: &J, key: &str) -> Vec<String> {
    list(j, key).iter().filter_map(|f| f.as_str().map(str::to_owned)).collect()
}

fn qr_sequences(c: &mut Collector) {
    let Ok(v) = load(QR_SEQUENCES) else { return c.case(&["WIRE-175".into()], "load", || Err("qr_sequences.json does not parse".into())) };
    c.case(&["WIRE-176".into()], "the limits match the vectors", || {
        same!(num(&v, "chunk_bytes")? as usize, CHUNK_BYTES, "chunk size");
        same!(num(&v, "max_frame_chars")? as usize, MAX_FRAME_CHARS, "frame limit");
        Ok(())
    });
    for (i, case) in list(&v, "sequences").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-175", "WIRE-176"]), format!("sequence {}", label(case, i)), || {
            let object = bytes(case, "object")?;
            let frames = strings(case, "frames");
            same!(encode_sequence(&object).c()?, frames, "frames");
            same!(lower_hex(&message_id(&object)), s(case, "message_id")?.to_owned(), "message ID");
            ensure!(frames.iter().all(|f| f.len() <= MAX_FRAME_CHARS), "a frame is over {MAX_FRAME_CHARS} characters");
            same!(feed(&frames), serde_json::json!({"object": s(case, "object")?, "at_frame": frames.len() - 1}), "reassembly");
            Ok(())
        });
    }
    for (i, case) in list(&v, "orders").iter().chain(list(&v, "reassembly_errors")).enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-177"]), format!("reassembly {}", label(case, i)), || {
            same!(feed(&strings(case, "frames")), case["result"].clone(), "result");
            Ok(())
        });
    }
    c.case(&["WIRE-177".into()], "interleaved messages are reassembled by message ID", || {
        let mut r = Reassembler::new();
        let mut done = Vec::new();
        for f in strings(&v["interleaved"], "frames") {
            done.extend(r.push(&f).c()?.map(|o| lower_hex(&o)));
        }
        same!(done, strings(&v["interleaved"], "objects"), "completed objects");
        Ok(())
    });
    for (i, case) in list(&v, "invalid_frames").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-175"]), format!("invalid frame {}", label(case, i)), || {
            let Err(e) = Frame::parse(s(case, "frame")?) else { return Err("the frame parsed".into()) };
            same_error(&e, &case["result"])
        });
    }
}

fn pop_tokens(c: &mut Collector) {
    let Ok(v) = load(POP_TOKENS) else { return c.case(&["WIRE-170".into()], "load", || Err("pop_tokens.json does not parse".into())) };
    let Ok(public) = bytes(&v, "device_public_key").and_then(|b| P256PublicKey::from_bytes(&b).c()) else {
        return c.case(&["WIRE-170".into()], "keys", || Err("the vector key does not load".into()));
    };
    for (i, case) in list(&v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-170", "WIRE-172"]), format!("valid {}", label(case, i)), || {
            let t = PopToken::decode(&bytes(case, "cbor")?).c()?;
            same!(PopToken::from_header(s(case, "header")?).c()?, t, "header and CBOR");
            same!(lower_hex(&t.encode()), s(case, "cbor")?.to_owned(), "re-encoding");
            same!(t.to_header(), s(case, "header")?.to_owned(), "header");
            same!(lower_hex(&t.message()), s(case, "message")?.to_owned(), "signed message");
            t.verify_signature(&public).c()
        });
    }
    for (i, case) in list(&v, "invalid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-170"]), format!("invalid {}", label(case, i)), || {
            let decoded = match s(case, "form")? {
                "cbor" => PopToken::decode(&bytes(case, "input")?),
                _ => PopToken::from_header(s(case, "input")?),
            };
            let e = match decoded.and_then(|t| t.verify_signature(&public)) {
                Err(e) => e,
                Ok(()) => return Err("the token was accepted".into()),
            };
            same_error(&e, case)
        });
    }
}

/// The cases shared by the receipt and time-token files: valid objects read from CBOR and
/// text agree and re-encode, and invalid inputs fail with their codes. `read` decodes and
/// verifies one input of the given form, returning its canonical CBOR and text form.
fn small_signed_object(c: &mut Collector, file: &str, v: &J, fallback: &[&str], read: impl Fn(&str, &str, &P256PublicKey) -> Result<(Vec<u8>, String), WireError>) {
    let Ok(public) = bytes(v, "receipt_public_key").and_then(|b| P256PublicKey::from_bytes(&b).c()) else {
        return c.case(&[fallback[0].into()], "keys", || Err(format!("the {file} key does not load")));
    };
    for (i, case) in list(v, "valid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), fallback), format!("valid {}", label(case, i)), || {
            let (cbor, text) = read("cbor", s(case, "cbor")?, &public).c()?;
            same!(lower_hex(&cbor), s(case, "cbor")?.to_owned(), "re-encoding");
            same!(text.clone(), s(case, "text")?.to_owned(), "text form");
            ensure!(cbor.len() <= fieldseal_kernel::text::MAX_QR_OBJECT, "over 300 bytes (WIRE-144)");
            same!(read("text", &text, &public).c()?.0, cbor, "text and CBOR agree");
            Ok(())
        });
    }
    for (i, case) in list(v, "invalid").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), fallback), format!("invalid {}", label(case, i)), || {
            let Err(e) = read(s(case, "form")?, s(case, "input")?, &public) else { return Err("the input was accepted".into()) };
            same_error(&e, case)
        });
    }
}

fn receipts(c: &mut Collector) {
    use fieldseal_intake::wire::Receipt;
    let Ok(v) = load(RECEIPTS) else { return c.case(&["WIRE-142".into()], "load", || Err("receipts.json does not parse".into())) };
    small_signed_object(c, "receipts.json", &v, &["WIRE-142", "WIRE-144"], |form, input, public| {
        let r = if form == "cbor" { Receipt::decode(&unhex(input).map_err(|_| WireError::new(ErrorCode::UnknownField, 0, "not hex"))?)? } else { Receipt::from_text(input)? };
        verify(public, &fieldseal_kernel::crypto::tags::RECEIPT, &r.signed_structure(), &r.sig)?;
        Ok((r.encode()?, r.to_text()?))
    });
}

fn time_tokens(c: &mut Collector) {
    use fieldseal_distribution::domain::TimeToken;
    let Ok(v) = load(TIME_TOKENS) else { return c.case(&["WIRE-143".into()], "load", || Err("time_tokens.json does not parse".into())) };
    small_signed_object(c, "time_tokens.json", &v, &["WIRE-143", "WIRE-144"], |form, input, public| {
        let t = if form == "cbor" { TimeToken::decode(&unhex(input).map_err(|_| WireError::new(ErrorCode::UnknownField, 0, "not hex"))?)? } else { TimeToken::from_text(input)? };
        verify(public, &fieldseal_kernel::crypto::tags::TIME_TOKEN, &t.signed_structure(), &t.signature)?;
        Ok((t.encode(), t.to_text()))
    });
}

fn receiver_challenge(c: &mut Collector) {
    use fieldseal_delivery::domain::{ReceiverChallenge, ReceiverProof};
    use fieldseal_kernel::crypto::{Purpose, tags};
    let Ok(v) = load(RECEIVER_CHALLENGE) else { return c.case(&["WIRE-180".into()], "load", || Err("receiver_challenge.json does not parse".into())) };
    let check_proof = |input: &[u8], challenge: &ReceiverChallenge| -> Result<ReceiverProof, WireError> {
        let p = ReceiverProof::decode(input)?;
        if p.certificate.purpose() != Some(Purpose::Receiver) {
            return Err(WireError::new(ErrorCode::Sig, 0, "the certificate is not a receiver key"));
        }
        let key = p.certificate.public_key().as_p256().ok_or(WireError::new(ErrorCode::Sig, 0, "not a P-256 key"))?;
        verify(key, &tags::RECEIVER_CHALLENGE, &challenge.to_value(), &p.signature)?;
        Ok(p)
    };
    for (i, case) in list(&v, "challenges").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-180"]), format!("challenge {}", label(case, i)), || {
            let ch = ReceiverChallenge::decode(&bytes(case, "cbor")?).c()?;
            same!(lower_hex(&ch.encode()), s(case, "cbor")?.to_owned(), "re-encoding");
            same!(lower_hex(ch.nonce().as_bytes()), s(case, "nonce")?.to_owned(), "nonce");
            same!(lower_hex(ch.tenancy_handle().as_bytes()), s(case, "tenancy_handle")?.to_owned(), "tenancy handle");
            Ok(())
        });
    }
    for (i, case) in list(&v, "proofs").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-181", "WIRE-182"]), format!("proof {}", label(case, i)), || {
            let ch = ReceiverChallenge::decode(&bytes(case, "challenge")?).c()?;
            let input = bytes(case, "cbor")?;
            let p = check_proof(&input, &ch).c()?;
            same!(p.encode(), input, "re-encoding");
            for a in list(case, "addresses") {
                let a = a.as_str().c()?.as_bytes();
                ensure!(!input.windows(a.len()).any(|w| w == a), "the answer contains an address (WIRE-182)");
            }
            Ok(())
        });
    }
    for (i, case) in list(&v, "invalid_challenges").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-180"]), format!("invalid challenge {}", label(case, i)), || {
            let Err(e) = ReceiverChallenge::decode(&bytes(case, "cbor")?) else { return Err("the challenge was accepted".into()) };
            same_error(&e, case)
        });
    }
    for (i, case) in list(&v, "invalid_proofs").iter().enumerate() {
        c.case(&requirement_ids(case.get("requirement"), &["WIRE-181"]), format!("invalid proof {}", label(case, i)), || {
            let ch = ReceiverChallenge::decode(&bytes(case, "challenge")?).c()?;
            let Err(e) = check_proof(&bytes(case, "cbor")?, &ch) else { return Err("the answer was accepted".into()) };
            same_error(&e, case)
        });
    }
}
