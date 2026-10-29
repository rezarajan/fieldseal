//! Fixtures and a separate small CSV and JSON Lines parser for the read-back tests.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fieldseal_adapters_landing_files::export::{ExportOptions, ExportTable, Format, IdentitySubject, SubjectMapper, write_export};
use fieldseal_intake::contract::sample_observation;
use fieldseal_intake::data_contract::{DataContract, generate_data_contract};
use fieldseal_intake::domain::{LandedObservation, Nonresponse, ObservedValue, Reading};
use fieldseal_kernel::id::{ContentAddress, Fingerprint, ItemPath, RecordId};
use fieldseal_kernel::time::AuthorityTime;

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A fresh scratch directory.
pub fn scratch(name: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("fieldseal-landing-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// The instrument fingerprint the fixtures land under.
pub fn fingerprint() -> Fingerprint {
    Fingerprint::from([0xab; 32])
}

/// The data contract of the bundled water survey, under [`fingerprint`].
pub fn contract() -> DataContract {
    let doc = fieldseal_adapters_authoring::decode_path(&repo().join("examples/surveys/household-water-access")).expect("the survey decodes");
    let instrument = fieldseal_instrument::application::validate_instrument(&doc).expect("the survey is valid").instrument;
    generate_data_contract(fingerprint(), &instrument)
}

pub fn contracts() -> BTreeMap<Fingerprint, DataContract> {
    BTreeMap::from([(fingerprint(), contract())])
}

/// One answered or unanswered row of the fixtures.
pub fn row(record: u8, item: &str, value_type: &'static str, reading: Reading) -> LandedObservation {
    let mut o = sample_observation(0xab, record);
    o.item = ItemPath::new(item).expect("path");
    o.value_type = value_type;
    o.reading = reading;
    o.unit = None;
    o.instrument = fingerprint();
    o.not_before = Some(AuthorityTime(1_000 + u64::from(record)));
    LandedObservation { observation: o, excluded: None }
}

pub fn value(record: u8, item: &str, value_type: &'static str, v: ObservedValue) -> LandedObservation {
    row(record, item, value_type, Reading::Value(v))
}

/// All nine item types answered, the three nonresponses, a retraction, an excluded row and a
/// free-text answer, for the subjects given (the first is used for most rows).
pub fn table_rows(subject: &str) -> Vec<LandedObservation> {
    let mut rows = vec![
        value(1, "a.integer", "integer", ObservedValue::Int(-5)),
        value(1, "a.decimal", "decimal", ObservedValue::Decimal("0.1000000001".into())),
        {
            let mut m = value(1, "a.money", "money", ObservedValue::Decimal("12.50".into()));
            m.observation.unit = Some("EUR".into());
            m
        },
        value(1, "a.string", "string", ObservedValue::Text("walks to the well, twice a day".into())),
        value(1, "a.code", "code", ObservedValue::Code("piped".into())),
        value(1, "a.codes", "codes", ObservedValue::Codes(vec!["well".into(), "river".into()])),
        value(1, "a.boolean", "boolean", ObservedValue::Bool(true)),
        value(1, "a.date", "date", ObservedValue::Text("2026-03-04".into())),
        value(1, "a.evidence", "evidence", ObservedValue::Text("blob:0123".into())),
        row(2, "b.dont_know", "integer", Reading::Nonresponse(Nonresponse::DontKnow)),
        row(2, "b.refused", "string", Reading::Nonresponse(Nonresponse::Refused)),
        row(2, "b.not_applicable", "code", Reading::Nonresponse(Nonresponse::NotApplicable)),
        row(2, "b.retracted", "decimal", Reading::Retracted),
        value(3, "c.integer", "integer", ObservedValue::Int(7)),
    ];
    let mut excluded = value(4, "d.integer", "integer", ObservedValue::Int(99));
    excluded.excluded = Some("consent-pending".into());
    rows.push(excluded);
    for r in &mut rows {
        r.observation.subject = fieldseal_kernel::id::SubjectId::new(subject).expect("subject");
    }
    rows
}

/// A table of `rows` under [`contracts`], with fixed publications.
pub fn table(rows: Vec<LandedObservation>, mapper: &dyn SubjectMapper) -> ExportTable {
    ExportTable::from_observations(rows, contracts(), mapper)
        .expect("a table")
        .with_publications(BTreeMap::from([(fingerprint(), ContentAddress::from([0xcd; 32]))]), [ContentAddress::from([0xee; 32]), ContentAddress::from([0xdd; 32]), ContentAddress::from([0xee; 32])])
}

pub fn both() -> ExportOptions {
    ExportOptions { formats: BTreeSet::from([Format::Jsonl, Format::Csv]), subject: Box::new(IdentitySubject) }
}

/// Writes the export of `rows` (identity subjects) into a fresh directory.
pub fn export(name: &str, rows: Vec<LandedObservation>) -> PathBuf {
    let out = scratch(name);
    write_export(&table(rows, &IdentitySubject), &both(), &out).expect("export");
    out
}

pub fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

pub fn record(n: u8) -> String {
    fieldseal_kernel::digest::lower_hex(RecordId::from([n; 16]).as_bytes())
}

// ---- a separate small CSV parser ------------------------------------------------------------

/// Records of fields; the first record is the header.
pub fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let (mut out, mut record, mut field, mut quoted) = (Vec::new(), Vec::new(), String::new(), false);
    let cs: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        if quoted {
            if c == '"' && cs.get(i + 1) == Some(&'"') {
                field.push('"');
                i += 1;
            } else if c == '"' {
                quoted = false;
            } else {
                field.push(c);
            }
        } else if c == '"' {
            quoted = true;
        } else if c == ',' {
            record.push(std::mem::take(&mut field));
        } else if c == '\n' {
            record.push(std::mem::take(&mut field));
            out.push(std::mem::take(&mut record));
        } else {
            field.push(c);
        }
        i += 1;
    }
    assert!(field.is_empty() && record.is_empty(), "the CSV ends with a line end");
    out
}

/// A CSV file as rows keyed by column name; a leading `'` of a guarded text cell is stripped.
pub fn csv_rows(text: &str, guarded: &[&str]) -> Vec<BTreeMap<String, String>> {
    let records = parse_csv(text);
    let (header, rows) = records.split_first().expect("a header");
    rows.iter()
        .map(|r| {
            header
                .iter()
                .zip(r)
                .map(|(h, v)| {
                    let strip = guarded.contains(&h.as_str()) && v.len() > 1 && v.starts_with('\'') && v[1..].starts_with(['=', '+', '-', '@']);
                    (h.clone(), if strip { v[1..].to_owned() } else { v.clone() })
                })
                .collect()
        })
        .collect()
}

// ---- a separate small JSON parser -------------------------------------------------------------

#[derive(Clone, PartialEq, Debug)]
pub enum J {
    Null,
    Bool(bool),
    /// A number, as written.
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn get(&self, key: &str) -> &J {
        match self {
            J::Obj(o) => &o.iter().find(|(k, _)| k == key).unwrap_or_else(|| panic!("no key {key}")).1,
            _ => panic!("not an object"),
        }
    }

    pub fn keys(&self) -> Vec<&str> {
        match self {
            J::Obj(o) => o.iter().map(|(k, _)| k.as_str()).collect(),
            _ => panic!("not an object"),
        }
    }

    /// The cell as a CSV would hold it: null is empty, arrays are `|`-joined.
    pub fn cell(&self) -> String {
        match self {
            J::Null => String::new(),
            J::Bool(b) => b.to_string(),
            J::Num(n) => n.clone(),
            J::Str(s) => s.clone(),
            J::Arr(a) => a.iter().map(J::cell).collect::<Vec<_>>().join("|"),
            J::Obj(_) => panic!("an object in a cell"),
        }
    }
}

pub fn parse_json(text: &str) -> J {
    let cs: Vec<char> = text.strip_suffix('\n').unwrap_or(text).chars().collect();
    let mut i = 0;
    let v = value_at(&cs, &mut i);
    assert_eq!(i, cs.len(), "trailing text after the JSON value");
    v
}

fn value_at(cs: &[char], i: &mut usize) -> J {
    match cs[*i] {
        'n' => lit(cs, i, "null", J::Null),
        't' => lit(cs, i, "true", J::Bool(true)),
        'f' => lit(cs, i, "false", J::Bool(false)),
        '"' => J::Str(string_at(cs, i)),
        '[' => {
            *i += 1;
            let mut a = Vec::new();
            while cs[*i] != ']' {
                a.push(value_at(cs, i));
                if cs[*i] == ',' {
                    *i += 1;
                }
            }
            *i += 1;
            J::Arr(a)
        }
        '{' => {
            *i += 1;
            let mut o = Vec::new();
            while cs[*i] != '}' {
                let k = string_at(cs, i);
                assert_eq!(cs[*i], ':');
                *i += 1;
                o.push((k, value_at(cs, i)));
                if cs[*i] == ',' {
                    *i += 1;
                }
            }
            *i += 1;
            J::Obj(o)
        }
        _ => {
            let start = *i;
            while *i < cs.len() && (cs[*i].is_ascii_digit() || matches!(cs[*i], '-' | '.' | 'e' | 'E' | '+')) {
                *i += 1;
            }
            assert!(*i > start, "unexpected character {:?}", cs[start]);
            J::Num(cs[start..*i].iter().collect())
        }
    }
}

fn lit(cs: &[char], i: &mut usize, word: &str, v: J) -> J {
    assert_eq!(cs[*i..*i + word.len()].iter().collect::<String>(), word);
    *i += word.len();
    v
}

fn string_at(cs: &[char], i: &mut usize) -> String {
    assert_eq!(cs[*i], '"');
    *i += 1;
    let mut s = String::new();
    while cs[*i] != '"' {
        if cs[*i] == '\\' {
            *i += 1;
            match cs[*i] {
                'n' => s.push('\n'),
                'r' => s.push('\r'),
                't' => s.push('\t'),
                'u' => {
                    let code: String = cs[*i + 1..*i + 5].iter().collect();
                    s.push(char::from_u32(u32::from_str_radix(&code, 16).expect("hex")).expect("char"));
                    *i += 4;
                }
                c => s.push(c),
            }
        } else {
            s.push(cs[*i]);
        }
        *i += 1;
    }
    *i += 1;
    s
}

pub fn jsonl_rows(text: &str) -> Vec<J> {
    text.lines().map(parse_json).collect()
}
