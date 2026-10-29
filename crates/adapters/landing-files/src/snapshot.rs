//! Reads `observations.csv` back into landed observations, for
//! [`FileDataPlatform::open_read_only`](crate::FileDataPlatform::open_read_only).
//!
//! The reader is strict (INT-072): the header must be exactly [`LONG_COLUMNS`], every cell
//! must have the type and the enumeration of its column, and a row that does not fit is an
//! error that names its line. Nothing is skipped silently.

use std::collections::BTreeSet;

use fieldseal_intake::data_contract::LONG_COLUMNS;
use fieldseal_intake::domain::{LandedObservation, Nonresponse, Observation, ObservedValue, Reading};
use fieldseal_kernel::id::{ContentAddress, Fingerprint, Generation, ItemPath, RecordId, Seq, SubjectId, TenancyId};
use fieldseal_kernel::payload::Layout;
use fieldseal_kernel::time::AuthorityTime;

use crate::long_header;

/// Splits CSV text into records of fields (RFC 4180): quoted fields may hold commas, quotes
/// (doubled) and line ends.
fn records(text: &str) -> Result<Vec<Vec<String>>, String> {
    let (mut out, mut record, mut field) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut was_quoted) = (false, false);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            '"' if quoted => quoted = false,
            '"' if field.is_empty() && !was_quoted => (quoted, was_quoted) = (true, true),
            ',' if !quoted => {
                record.push(std::mem::take(&mut field));
                was_quoted = false;
            }
            '\n' if !quoted => {
                record.push(std::mem::take(&mut field));
                out.push(std::mem::take(&mut record));
                was_quoted = false;
            }
            c => field.push(c),
        }
    }
    if quoted {
        return Err("a quoted field is never closed".into());
    }
    if !field.is_empty() || !record.is_empty() {
        return Err("the last line has no line end".into());
    }
    Ok(out)
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn flag(text: &str) -> Option<bool> {
    match text {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn is_decimal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let (whole, fraction) = digits.split_once('.').unwrap_or((digits, "0"));
    let all_digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    all_digits(whole) && all_digits(fraction)
}

fn split(text: &str) -> Vec<String> {
    if text.is_empty() { Vec::new() } else { text.split('|').map(str::to_owned).collect() }
}

const VALUE_TYPES: [&str; 9] = ["integer", "decimal", "money", "string", "code", "codes", "boolean", "date", "evidence"];

fn observation(f: &[String]) -> Result<LandedObservation, String> {
    let bad = |column: &str| format!("the {column} column holds a value of the wrong form");
    let [instrument, layout, lang, subject, item, value, value_type, nonresponse, retracted, unit, record, tenancy, generation, seq, not_before, not_after, basis, flags, excluded, reason] =
        <&[String; 20]>::try_from(f).map_err(|_| format!("{} columns, expected 20", f.len()))?;
    let value_type: &'static str = VALUE_TYPES.iter().find(|t| **t == value_type).ok_or_else(|| bad("value_type"))?;
    let retracted = flag(retracted).ok_or_else(|| bad("retracted"))?;
    let reading = match (retracted, nonresponse.as_str()) {
        (true, "") if value.is_empty() => Reading::Retracted,
        (false, "dont-know") if value.is_empty() => Reading::Nonresponse(Nonresponse::DontKnow),
        (false, "refused") if value.is_empty() => Reading::Nonresponse(Nonresponse::Refused),
        (false, "not-applicable") if value.is_empty() => Reading::Nonresponse(Nonresponse::NotApplicable),
        (false, "") => Reading::Value(match value_type {
            "integer" => ObservedValue::Int(value.parse().map_err(|_| bad("value"))?),
            "decimal" | "money" if is_decimal(value) => ObservedValue::Decimal(value.clone()),
            "boolean" => ObservedValue::Bool(flag(value).ok_or_else(|| bad("value"))?),
            "codes" => ObservedValue::Codes(split(value)),
            "code" => ObservedValue::Code(value.clone()),
            "string" | "date" | "evidence" => ObservedValue::Text(value.clone()),
            _ => return Err(bad("value")),
        }),
        _ => return Err(bad("nonresponse")),
    };
    let excluded_flag = flag(excluded).ok_or_else(|| bad("excluded"))?;
    if !excluded_flag && !reason.is_empty() {
        return Err(bad("exclusion_reason"));
    }
    let number = |text: &String, column: &str| text.parse::<u64>().map_err(|_| bad(column));
    Ok(LandedObservation {
        observation: Observation {
            instrument: Fingerprint::from(unhex::<32>(instrument).ok_or_else(|| bad("instrument"))?),
            layout: if layout == "default" { Layout::Default } else { Layout::Published(ContentAddress::from(unhex::<32>(layout).ok_or_else(|| bad("layout"))?)) },
            lang: split(lang),
            subject: SubjectId::new(subject.clone()).map_err(|_| bad("subject"))?,
            item: ItemPath::new(item.clone()).map_err(|_| bad("item_path"))?,
            reading,
            value_type,
            unit: (!unit.is_empty()).then(|| unit.clone()),
            source: RecordId::from(unhex::<16>(record).ok_or_else(|| bad("record_id"))?),
            tenancy: TenancyId::from(unhex::<32>(tenancy).ok_or_else(|| bad("tenancy"))?),
            generation: Generation(generation.parse().map_err(|_| bad("generation"))?),
            seq: Seq(number(seq, "seq")?),
            not_before: if not_before.is_empty() { None } else { Some(AuthorityTime(number(not_before, "tick_lower_bound")?)) },
            not_after: AuthorityTime(number(not_after, "received_at")?),
            consent_basis: basis.clone(),
            flags: split(flags).into_iter().collect::<BTreeSet<_>>(),
        },
        excluded: excluded_flag.then(|| reason.clone()),
    })
}

/// The landed observations in `observations.csv` text, in file order.
pub(crate) fn parse(text: &str) -> Result<Vec<LandedObservation>, String> {
    let records = records(text)?;
    let (header, rows) = records.split_first().ok_or("the file is empty")?;
    if header.join(",") != long_header() {
        return Err(format!("the header is not the {} columns of the long format", LONG_COLUMNS.len()));
    }
    rows.iter().enumerate().map(|(i, r)| observation(r).map_err(|e| format!("line {}: {e}", i + 2))).collect()
}
