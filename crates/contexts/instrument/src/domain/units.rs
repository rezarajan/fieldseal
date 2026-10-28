//! Units of measure (UCUM) and currencies (ISO 4217) (INS-160–INS-163).
//!
//! General UCUM parsing is out of scope. A unit is any syntactically plausible UCUM code;
//! conversions are exact and limited to the table in [`CONVERSIONS`]. Annotation units
//! (`{each}`, `{portion_250ml}`, or any code containing `{…}`) never convert.

use std::fmt;

use super::num::Num;

/// A UCUM unit code, for example `kg`, `[lb_av]` or `{each}`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Unit(String);

/// Why a unit code was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a UCUM unit code")]
pub struct UnitError(pub String);

/// The physical dimension of a convertible unit.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Dimension {
    /// Mass, in grams.
    Mass,
    /// Length, in metres.
    Length,
    /// Volume, in litres.
    Volume,
    /// Time, in seconds.
    Time,
}

/// The units this core converts between, with their exact factor to the dimension's base
/// unit (g, m, L, s), as decimal text. Factors are UCUM's definitions: the avoirdupois pound
/// is exactly 0.45359237 kg, the international inch exactly 2.54 cm, the US cup exactly
/// 236.5882365 mL, the US gallon exactly 3.785411784 L.
pub const CONVERSIONS: [(&str, Dimension, &str); 20] = [
    ("g", Dimension::Mass, "1"),
    ("kg", Dimension::Mass, "1000"),
    ("mg", Dimension::Mass, "0.001"),
    ("[lb_av]", Dimension::Mass, "453.59237"),
    ("[oz_av]", Dimension::Mass, "28.349523125"),
    ("m", Dimension::Length, "1"),
    ("cm", Dimension::Length, "0.01"),
    ("mm", Dimension::Length, "0.001"),
    ("[in_i]", Dimension::Length, "0.0254"),
    ("[ft_i]", Dimension::Length, "0.3048"),
    ("L", Dimension::Volume, "1"),
    ("l", Dimension::Volume, "1"),
    ("dL", Dimension::Volume, "0.1"),
    ("mL", Dimension::Volume, "0.001"),
    ("[cup_us]", Dimension::Volume, "0.2365882365"),
    ("[foz_us]", Dimension::Volume, "0.0295735295625"),
    ("[gal_us]", Dimension::Volume, "3.785411784"),
    ("s", Dimension::Time, "1"),
    ("min", Dimension::Time, "60"),
    ("h", Dimension::Time, "3600"),
];

impl Unit {
    /// Accepts a code made of printable ASCII without spaces, with balanced `[ ]` and `{ }`
    /// that don't nest. This is a plausibility check, not a UCUM parser.
    pub fn parse(code: &str) -> Result<Self, UnitError> {
        let err = || UnitError(code.to_owned());
        if code.is_empty() || code.len() > 64 {
            return Err(err());
        }
        let mut open: Option<char> = None;
        for c in code.chars() {
            if !c.is_ascii_graphic() {
                return Err(err());
            }
            match (open, c) {
                (None, '[') => open = Some(']'),
                (None, '{') => open = Some('}'),
                (Some(close), _) if c == close => open = None,
                (Some(_), '[' | '{' | ']') => return Err(err()),
                (Some('}'), _) => {}
                (Some(_), '}') => return Err(err()),
                (None, ']' | '}') => return Err(err()),
                _ => {}
            }
        }
        if open.is_some() {
            return Err(err());
        }
        Ok(Self(code.to_owned()))
    }

    /// The code.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the code contains a `{…}` annotation, so never converts.
    pub fn is_annotation(&self) -> bool {
        self.0.contains('{')
    }

    /// Whether readers need a `unitLabel` (INS-160): codes with `[…]` square-bracket atoms.
    pub fn needs_label(&self) -> bool {
        self.0.contains('[')
    }

    /// The dimension and exact factor to the base unit, if this unit is in the table.
    pub fn conversion(&self) -> Option<(Dimension, Num)> {
        if self.is_annotation() {
            return None;
        }
        CONVERSIONS
            .iter()
            .find(|(code, _, _)| *code == self.0)
            .and_then(|(_, dim, factor)| Some((*dim, Num::parse(factor)?)))
    }

    /// The exact factor `f` such that a value in `self` times `f` is the value in `to`, if
    /// both are in the table and share a dimension.
    pub fn factor_to(&self, to: &Unit) -> Option<Num> {
        if self == to {
            return Some(Num::ONE);
        }
        let (d1, f1) = self.conversion()?;
        let (d2, f2) = to.conversion()?;
        if d1 != d2 {
            return None;
        }
        f1.div(f2).ok()
    }

    /// Converts `value` from `self` to `to`, exactly.
    pub fn convert(&self, value: Num, to: &Unit) -> Option<Num> {
        value.mul(self.factor_to(to)?).ok()
    }
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An active ISO 4217 currency with its number of minor-unit digits.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Currency {
    code: String,
    minor_digits: u32,
}

/// Currencies with other than two minor-unit digits (ISO 4217 list one, 2025).
const MINOR_DIGITS: [(&str, u32); 26] = [
    ("BIF", 0), ("CLP", 0), ("DJF", 0), ("GNF", 0), ("ISK", 0), ("JPY", 0), ("KMF", 0), ("KRW", 0),
    ("PYG", 0), ("RWF", 0), ("UGX", 0), ("UYI", 0), ("VND", 0), ("VUV", 0), ("XAF", 0), ("XOF", 0),
    ("XPF", 0), ("BHD", 3), ("IQD", 3), ("JOD", 3), ("KWD", 3), ("LYD", 3), ("OMR", 3), ("TND", 3),
    ("CLF", 4), ("UYW", 4),
];

/// Active ISO 4217 currency codes (list one, 2025), excluding funds and precious metals
/// that have no minor unit.
const ACTIVE: &str = "AED AFN ALL AMD AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BOV BRL \
BSD BTN BWP BYN BZD CAD CDF CHE CHF CHW CLF CLP CNY COP COU CRC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB \
EUR FJD FKP GBP GEL GHS GIP GMD GNF GTQ GYD HKD HNL HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS \
KHR KMF KPW KRW KWD KYD KZT LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MXV \
MYR MZN NAD NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD SCR SDG SEK \
SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TND TOP TRY TTD TWD TZS UAH UGX USD USN UYI UYU UYW \
UZS VED VES VND VUV WST XAF XCD XCG XOF XPF YER ZAR ZMW ZWG";

/// Why a currency code was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not an active ISO 4217 currency code")]
pub struct CurrencyError(pub String);

impl Currency {
    /// Looks up an active ISO 4217 code.
    pub fn parse(code: &str) -> Result<Self, CurrencyError> {
        if code.len() != 3 || !ACTIVE.split(' ').any(|c| c == code) {
            return Err(CurrencyError(code.to_owned()));
        }
        let minor_digits = MINOR_DIGITS.iter().find(|(c, _)| *c == code).map_or(2, |(_, d)| *d);
        Ok(Self { code: code.to_owned(), minor_digits })
    }

    /// The code, for example `TTD`.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The number of minor-unit digits (INS-162).
    pub fn minor_digits(&self) -> u32 {
        self.minor_digits
    }
}
