//! Controls: typed values, their kinds, merge rules and the meaning of "tighter".

use std::collections::BTreeMap;

use fieldseal_kernel::value::{Decimal, Value};

use super::units::{ByteSize, Date, Duration};

/// Argon2id parameters for the session key (INV-9).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Argon2Params {
    /// Memory cost.
    pub memory: ByteSize,
    /// Iterations (time cost).
    pub iterations: u64,
    /// Parallelism.
    pub parallelism: u64,
}

/// An `m`-of-`n` signature threshold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Threshold {
    /// Signatures needed.
    pub m: u64,
    /// Keys listed.
    pub n: u64,
}

/// One control's value, typed by its schema entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ControlValue {
    /// A boolean.
    Bool(bool),
    /// A non-negative integer.
    Int(u64),
    /// A decimal fraction between 0 and 1 inclusive.
    Ratio(Decimal),
    /// A duration.
    Duration(Duration),
    /// A size.
    Size(ByteSize),
    /// A date.
    Date(Date),
    /// One of an enumerated set of words.
    Choice(String),
    /// Free text of a constrained shape.
    Text(String),
    /// An ordered list of durations.
    Durations(Vec<Duration>),
    /// A set of words, kept sorted and without duplicates.
    Set(Vec<String>),
    /// Argon2id parameters.
    Argon2(Argon2Params),
    /// An `m`-of-`n` threshold.
    Threshold(Threshold),
}

impl ControlValue {
    /// The value as it is written in a policy document.
    pub fn to_value(&self) -> Value {
        match self {
            Self::Bool(b) => Value::Bool(*b),
            Self::Int(i) => Value::Int(i128::from(*i)),
            Self::Ratio(d) => Value::Decimal(*d),
            Self::Duration(d) => Value::Text(d.to_string()),
            Self::Size(s) => Value::Text(s.to_string()),
            Self::Date(d) => Value::Text(d.to_string()),
            Self::Choice(t) | Self::Text(t) => Value::Text(t.clone()),
            Self::Durations(ds) => Value::Array(ds.iter().map(|d| Value::Text(d.to_string())).collect()),
            Self::Set(items) => Value::Array(items.iter().cloned().map(Value::Text).collect()),
            Self::Argon2(a) => Value::Map(BTreeMap::from([
                ("memory".to_owned(), Value::Text(a.memory.to_string())),
                ("iterations".to_owned(), Value::Int(i128::from(a.iterations))),
                ("parallelism".to_owned(), Value::Int(i128::from(a.parallelism))),
            ])),
            Self::Threshold(t) => Value::Map(BTreeMap::from([
                ("m".to_owned(), Value::Int(i128::from(t.m))),
                ("n".to_owned(), Value::Int(i128::from(t.n))),
            ])),
        }
    }

    /// Whether two values are the same, comparing decimals by numeric value.
    pub fn same_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ratio(a), Self::Ratio(b)) => a.numeric_cmp(*b) == Some(std::cmp::Ordering::Equal),
            _ => self == other,
        }
    }
}

/// Which words an item of a [`Kind::Set`] may take.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SetItems {
    /// Only these words.
    Words(&'static [&'static str]),
    /// Lower-case words with hyphens and digits (identifiers such as roles or formats).
    Token,
    /// Any non-empty text without whitespace or control characters (URLs, identities).
    Opaque,
    /// A semver comparator range such as `>=1.0.0 <2.0.0`. A set of ranges means all of them.
    Range,
}

/// What a text control may hold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TextShape {
    /// 1 to 32 ASCII letters, digits, `-` or `_`: nothing that identifies a person.
    FilePrefix,
    /// 1 to 16 lower-case ASCII letters or digits.
    FileExtension,
}

/// A control's type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A boolean.
    Bool,
    /// An integer between the bounds, inclusive. Bounds are structural; invariant floors are
    /// checked separately so that breaches name the invariant.
    Int {
        /// Smallest accepted.
        min: u64,
        /// Largest accepted.
        max: u64,
    },
    /// A decimal from 0.0 to 1.0.
    Ratio,
    /// A duration.
    Duration,
    /// A size.
    Size,
    /// A date.
    Date,
    /// One of these words, loosest first.
    Choice(&'static [&'static str]),
    /// Text of a constrained shape.
    Text(TextShape),
    /// A non-empty list of durations.
    Durations,
    /// A set of words.
    Set(SetItems),
    /// Argon2id parameters.
    Argon2,
    /// An `m`-of-`n` threshold with `1 <= m <= n`.
    Threshold,
}

/// Which direction is stricter for a `tighten` control.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// Lower values are stricter (maximums, lifetimes). For booleans, `false` is stricter.
    Lower,
    /// Higher values are stricter (minimums, counts required). For booleans, `true` is stricter.
    /// Choices and dates always use this direction: later in the list, or later in time, is stricter.
    Higher,
}

/// How a control combines across layers (POL-020).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Merge {
    /// The stricter value wins; a later layer may not loosen.
    Tighten(Direction),
    /// The later layer's value wins.
    Override,
    /// Only values present in every layer survive.
    Intersect,
    /// Values from every layer combine.
    Union,
}

/// How a new value compares with an old one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tightness {
    /// Weaker than before.
    Looser,
    /// The same.
    Same,
    /// Stricter than before.
    Tighter,
}

fn ord_tightness<T: Ord>(direction: Direction, old: T, new: T) -> Tightness {
    match (new.cmp(&old), direction) {
        (std::cmp::Ordering::Equal, _) => Tightness::Same,
        (std::cmp::Ordering::Greater, Direction::Higher) | (std::cmp::Ordering::Less, Direction::Lower) => {
            Tightness::Tighter
        }
        _ => Tightness::Looser,
    }
}

fn set_tightness(old: &[String], new: &[String], smaller_is_tighter: bool) -> Tightness {
    let new_in_old = new.iter().all(|i| old.contains(i));
    let old_in_new = old.iter().all(|i| new.contains(i));
    match (new_in_old, old_in_new) {
        (true, true) => Tightness::Same,
        (true, false) if smaller_is_tighter => Tightness::Tighter,
        (false, true) if !smaller_is_tighter => Tightness::Tighter,
        _ => Tightness::Looser,
    }
}

/// Compares `new` with `old` for a control with the given merge rule. Values that cannot be
/// ordered (mismatched types, or parts that move in opposite directions) are `Looser`:
/// the safest reading.
///
/// The rules, per type, for `tighten`:
/// - numbers, durations, sizes: by [`Direction`];
/// - booleans: `true` is stricter for [`Direction::Higher`], `false` for [`Direction::Lower`];
/// - choices: later in the schema's list is stricter (`off` < `optional` < `required`);
/// - dates: later is stricter (a higher minimum patch level);
/// - duration lists (`pin.lockoutSteps`): stricter or equal when at least as long and no step
///   shorter than the old step at the same position;
/// - Argon2id parameters: stricter or equal when no component is lower;
/// - thresholds: by `m`.
pub fn compare(kind: Kind, merge: Merge, old: &ControlValue, new: &ControlValue) -> Tightness {
    use ControlValue as V;
    match merge {
        Merge::Override => {
            if old.same_as(new) {
                Tightness::Same
            } else {
                Tightness::Looser
            }
        }
        Merge::Intersect | Merge::Union => match (old, new) {
            (V::Set(o), V::Set(n)) => {
                // Ranges intersect as a conjunction, so more ranges is stricter.
                let smaller_is_tighter = merge == Merge::Intersect && !matches!(kind, Kind::Set(SetItems::Range));
                set_tightness(o, n, smaller_is_tighter)
            }
            _ => Tightness::Looser,
        },
        Merge::Tighten(direction) => match (old, new) {
            (V::Bool(o), V::Bool(n)) => ord_tightness(direction, *o, *n),
            (V::Int(o), V::Int(n)) => ord_tightness(direction, *o, *n),
            (V::Duration(o), V::Duration(n)) => ord_tightness(direction, *o, *n),
            (V::Size(o), V::Size(n)) => ord_tightness(direction, *o, *n),
            (V::Date(o), V::Date(n)) => ord_tightness(Direction::Higher, *o, *n),
            (V::Ratio(o), V::Ratio(n)) => match o.numeric_cmp(*n) {
                Some(ordering) => ord_tightness(direction, std::cmp::Ordering::Equal, ordering),
                None => Tightness::Looser,
            },
            (V::Threshold(o), V::Threshold(n)) => ord_tightness(Direction::Higher, o.m, n.m),
            (V::Choice(o), V::Choice(n)) => match kind {
                Kind::Choice(words) => compare_choice(words, o, n),
                _ => Tightness::Looser,
            },
            (V::Durations(o), V::Durations(n)) => {
                if o == n {
                    Tightness::Same
                } else if n.len() >= o.len() && o.iter().zip(n).all(|(a, b)| b >= a) {
                    Tightness::Tighter
                } else {
                    Tightness::Looser
                }
            }
            (V::Argon2(o), V::Argon2(n)) => {
                if o == n {
                    Tightness::Same
                } else if n.memory >= o.memory && n.iterations >= o.iterations && n.parallelism >= o.parallelism {
                    Tightness::Tighter
                } else {
                    Tightness::Looser
                }
            }
            _ => Tightness::Looser,
        },
    }
}

/// Compares two choices by their position in `words` (loosest first).
fn compare_choice(words: &[&str], old: &str, new: &str) -> Tightness {
    let position = |w: &str| words.iter().position(|x| *x == w);
    match (position(old), position(new)) {
        (Some(o), Some(n)) => ord_tightness(Direction::Higher, o, n),
        _ => Tightness::Looser,
    }
}

/// An error decoding one control value, as a message.
pub type DecodeError = String;

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_opaque(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

fn is_range(s: &str) -> bool {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    if tokens.is_empty() {
        return false;
    }
    tokens.iter().all(|t| {
        let t = t.trim_end_matches(',');
        let t = t.trim_start_matches(['>', '<', '=', '^', '~']);
        let parts: Vec<&str> = t.split('.').collect();
        t == "*" || (parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())))
    })
}

fn expect_text(value: &Value) -> Result<&str, DecodeError> {
    value
        .as_text()
        .ok_or_else(|| format!("expected text, found {}", value.kind()))
}

fn expect_uint(value: &Value) -> Result<u64, DecodeError> {
    let i = value
        .as_int()
        .ok_or_else(|| format!("expected an integer, found {}", value.kind()))?;
    u64::try_from(i).map_err(|_| format!("{i} is out of range"))
}

/// Decodes `value` as the given kind.
pub fn decode_value(kind: Kind, value: &Value) -> Result<ControlValue, DecodeError> {
    match kind {
        Kind::Bool => value
            .as_bool()
            .map(ControlValue::Bool)
            .ok_or_else(|| format!("expected a boolean, found {}", value.kind())),
        Kind::Int { min, max } => {
            let n = expect_uint(value)?;
            if n < min || n > max {
                return Err(format!("{n} is outside {min} to {max}"));
            }
            Ok(ControlValue::Int(n))
        }
        Kind::Ratio => {
            // A ratio is written as a decimal; an integer is not silently widened.
            let Value::Decimal(d) = value else {
                return Err(format!("expected a decimal from 0.0 to 1.0, found {}", value.kind()));
            };
            let d = *d;
            let zero = Decimal { mantissa: 0, exponent: 0 };
            let one = Decimal { mantissa: 1, exponent: 0 };
            let in_range = d.numeric_cmp(zero).is_some_and(|o| o.is_ge()) && d.numeric_cmp(one).is_some_and(|o| o.is_le());
            if !in_range {
                return Err(format!("{d} is outside 0.0 to 1.0"));
            }
            Ok(ControlValue::Ratio(d))
        }
        Kind::Duration => Duration::parse(expect_text(value)?).map(ControlValue::Duration),
        Kind::Size => ByteSize::parse(expect_text(value)?).map(ControlValue::Size),
        Kind::Date => Date::parse(expect_text(value)?).map(ControlValue::Date),
        Kind::Choice(words) => {
            let t = expect_text(value)?;
            if words.contains(&t) {
                Ok(ControlValue::Choice(t.to_owned()))
            } else {
                Err(format!("`{t}` is not one of: {}", words.join(", ")))
            }
        }
        Kind::Text(shape) => {
            let t = expect_text(value)?;
            let ok = match shape {
                TextShape::FilePrefix => {
                    (1..=32).contains(&t.len())
                        && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                }
                TextShape::FileExtension => {
                    (1..=16).contains(&t.len())
                        && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                }
            };
            if ok {
                Ok(ControlValue::Text(t.to_owned()))
            } else {
                Err(format!("`{t}` is not an acceptable {shape:?}"))
            }
        }
        Kind::Durations => {
            let items = value
                .as_array()
                .ok_or_else(|| format!("expected a list of durations, found {}", value.kind()))?;
            if items.is_empty() {
                return Err("the list must not be empty".to_owned());
            }
            items
                .iter()
                .map(|v| Duration::parse(expect_text(v)?))
                .collect::<Result<Vec<_>, _>>()
                .map(ControlValue::Durations)
        }
        Kind::Set(items) => {
            let list: Vec<&Value> = match (items, value) {
                (SetItems::Range, Value::Text(_)) => vec![value],
                (_, Value::Array(a)) => a.iter().collect(),
                _ => return Err(format!("expected a list, found {}", value.kind())),
            };
            let mut out: Vec<String> = Vec::new();
            for v in list {
                let t = expect_text(v)?;
                let ok = match items {
                    SetItems::Words(words) => words.contains(&t),
                    SetItems::Token => is_token(t),
                    SetItems::Opaque => is_opaque(t),
                    SetItems::Range => is_range(t),
                };
                if !ok {
                    return Err(match items {
                        SetItems::Words(words) => format!("`{t}` is not one of: {}", words.join(", ")),
                        _ => format!("`{t}` is not an acceptable {items:?} item"),
                    });
                }
                if out.iter().any(|x| x == t) {
                    return Err(format!("`{t}` is listed twice"));
                }
                out.push(t.to_owned());
            }
            out.sort();
            Ok(ControlValue::Set(out))
        }
        Kind::Argon2 => {
            let map = value
                .as_map()
                .ok_or_else(|| format!("expected {{memory, iterations, parallelism}}, found {}", value.kind()))?;
            for key in map.keys() {
                if !["memory", "iterations", "parallelism"].contains(&key.as_str()) {
                    return Err(format!("unknown field `{key}`"));
                }
            }
            let field = |name: &str| map.get(name).ok_or_else(|| format!("missing `{name}`"));
            Ok(ControlValue::Argon2(Argon2Params {
                memory: ByteSize::parse(expect_text(field("memory")?)?)?,
                iterations: expect_uint(field("iterations")?)?,
                parallelism: expect_uint(field("parallelism")?)?,
            }))
        }
        Kind::Threshold => {
            let map = value
                .as_map()
                .ok_or_else(|| format!("expected {{m, n}}, found {}", value.kind()))?;
            for key in map.keys() {
                if !["m", "n"].contains(&key.as_str()) {
                    return Err(format!("unknown field `{key}`"));
                }
            }
            let field = |name: &str| map.get(name).ok_or_else(|| format!("missing `{name}`"));
            let (m, n) = (expect_uint(field("m")?)?, expect_uint(field("n")?)?);
            if m == 0 || m > n {
                return Err(format!("need 1 <= m <= n, found m={m}, n={n}"));
            }
            Ok(ControlValue::Threshold(Threshold { m, n }))
        }
    }
}
