//! Locale-aware display and input of numbers, dates, currencies and plural forms (INS-088,
//! [ADR 0034](../../../../../docs/explanation/adr/0034-internationalisation-and-localisation.md)).
//!
//! Display uses CLDR data through ICU4X (pure Rust, compiled data): decimal patterns and
//! symbols, the numbering system, medium date patterns and cardinal plural rules. Input does
//! the reverse: [`LocaleFormatter::parse_number`] accepts the locale's decimal and grouping
//! separators and its native digits and returns the locale-free [`Decimal`] that records hold
//! (WIRE-052). Nothing here reads a clock, the environment or a file.
//!
//! Pseudo-locales (`en-XA`, `ar-XB`, ADR 0034) format as their base language, and a tag the
//! data doesn't know formats as English.
//!
//! Currencies: the amount is formatted with the locale's decimal rules at the currency's minor
//! digits, and the ISO 4217 code is placed where the locale's currency pattern puts its symbol
//! (before the number in `en` and `hi`, after it, with a no-break space, in `es`, `fr` and `ar`).
//! Symbols such as `$` are not used: they are ambiguous across locales, and ICU4X's currency
//! formatter is still experimental.

use fieldseal_kernel::Decimal;
use fixed_decimal::{Decimal as Fixed, SignDisplay};
use icu_calendar::{Date, Gregorian};
use icu_datetime::FixedCalendarDateTimeFormatter;
use icu_datetime::fieldsets::YMD;
use icu_decimal::options::{DecimalFormatterOptions, GroupingStrategy};
use icu_decimal::DecimalFormatter;
use icu_locale_core::Locale;
use icu_plurals::{PluralCategory, PluralRules};

/// The locales whose formatting is covered by tests. Any other tag works with the same data
/// (ICU4X compiled data covers CLDR's locales); these are the ones checked in `tests`.
pub const TESTED_LOCALES: [&str; 5] = ["en", "es", "fr", "ar", "hi"];

/// Arabic-Indic digits, accepted in any locale's input (they are unambiguous).
const ARABIC_INDIC: [char; 10] = ['٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩'];
/// Extended Arabic-Indic (Persian, Urdu) digits.
const EXTENDED_ARABIC_INDIC: [char; 10] = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];

/// A plural category (CLDR cardinal rules).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Plural {
    /// `zero`.
    Zero,
    /// `one`.
    One,
    /// `two`.
    Two,
    /// `few`.
    Few,
    /// `many`.
    Many,
    /// `other`.
    Other,
}

impl Plural {
    /// The category's name as MessageFormat 2 variant keys write it.
    pub const fn name(self) -> &'static str {
        match self {
            Plural::Zero => "zero",
            Plural::One => "one",
            Plural::Two => "two",
            Plural::Few => "few",
            Plural::Many => "many",
            Plural::Other => "other",
        }
    }
}

/// Why typed text isn't a number in the locale.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("not a number in this locale: {0:?}")]
pub struct ParseNumberError(pub String);

/// Formats and parses values for one locale.
pub struct LocaleFormatter {
    tag: String,
    grouped: DecimalFormatter,
    plain: DecimalFormatter,
    plurals: PluralRules,
    dates: Option<FixedCalendarDateTimeFormatter<Gregorian, YMD>>,
    digits: [char; 10],
    decimal: String,
    group: String,
    minus: String,
    /// Whether the currency code comes before the number.
    currency_first: bool,
    rtl: bool,
}

/// Formatting to a `String` without ICU4X's optional `alloc` feature.
trait FormatStr {
    fn format_str(&self, v: &Fixed) -> String;
}

impl FormatStr for DecimalFormatter {
    fn format_str(&self, v: &Fixed) -> String {
        self.format(v).to_string()
    }
}

fn locale_of(tag: &str) -> Locale {
    tag.parse().unwrap_or(Locale::UNKNOWN)
}

fn fixed(d: Decimal) -> Fixed {
    Fixed::try_from_str(&d.to_string()).unwrap_or_default()
}

/// Languages written right to left, for placing the currency and isolating the amount.
fn is_rtl(language: &str) -> bool {
    matches!(language, "ar" | "he" | "fa" | "ur" | "ps" | "sd" | "ug" | "yi" | "dv" | "ckb")
}

impl LocaleFormatter {
    /// A formatter for a BCP 47 `tag`. An unreadable tag formats as English.
    pub fn new(tag: &str) -> Self {
        let mut loc = locale_of(tag);
        // Pseudo-locales use their base language's data (ADR 0034).
        if loc.id.region.is_some_and(|r| matches!(r.as_str(), "XA" | "XB")) {
            loc.id.region = None;
        }
        // CLDR's `ar` data defaults to Latin digits; the preview and the collectors it stands
        // for expect Arabic-Indic digits, so ask for them unless the tag chooses a system.
        if loc.id.language.as_str() == "ar"
            && loc.extensions.unicode.keywords.is_empty()
            && let Ok(k) = "nu".parse::<icu_locale_core::extensions::unicode::Key>()
            && let Ok(v) = "arab".parse::<icu_locale_core::extensions::unicode::Value>()
        {
            loc.extensions.unicode.keywords.set(k, v);
        }
        let build = |l: &Locale, grouping: GroupingStrategy| {
            let mut o = DecimalFormatterOptions::default();
            o.grouping_strategy = Some(grouping);
            DecimalFormatter::try_new(l.into(), o)
        };
        let fmt = |l: &Locale| -> Option<(DecimalFormatter, DecimalFormatter)> {
            Some((build(l, GroupingStrategy::Auto).ok()?, build(l, GroupingStrategy::Never).ok()?))
        };
        let (loc, (grouped, plain)) = match fmt(&loc) {
            Some(f) => (loc, f),
            None => {
                let en = icu_locale_core::locale!("en");
                let f = fmt(&en).expect("the English decimal data is compiled in");
                (en, f)
            }
        };
        let plurals = PluralRules::try_new_cardinal((&loc).into())
            .or_else(|_| PluralRules::try_new_cardinal((&icu_locale_core::locale!("en")).into()))
            .expect("the English plural data is compiled in");
        let dates = FixedCalendarDateTimeFormatter::<Gregorian, _>::try_new((&loc).into(), YMD::medium()).ok();

        // Probe the formatter for its symbols, so the parser and the display agree by
        // construction.
        let mut digits = ['0'; 10];
        for (i, slot) in digits.iter_mut().enumerate() {
            let s = plain.format_str(&Fixed::from(i as i64));
            *slot = s.chars().find(|c| c.is_alphanumeric()).unwrap_or(char::from(b'0' + i as u8));
        }
        let is_digit = |c: char| digits.contains(&c);
        let non_digits = |s: String| s.chars().filter(|c| !is_digit(*c)).collect::<String>();
        let decimal = non_digits(plain.format_str(&Fixed::try_from_str("1.5").unwrap_or_default()));
        let group = non_digits(grouped.format_str(&Fixed::from(1_000_000i64)))
            .chars()
            .next()
            .map(String::from)
            .unwrap_or_default();
        let mut neg = Fixed::from(1i64);
        neg.apply_sign_display(SignDisplay::Always);
        neg.set_sign(fixed_decimal::Sign::Negative);
        let minus = non_digits(plain.format_str(&neg));
        let language = loc.id.language.as_str().to_owned();
        let currency_first = matches!(language.as_str(), "en" | "hi" | "zh" | "ja" | "ko" | "he" | "th");
        Self {
            tag: loc.to_string(),
            grouped,
            plain,
            plurals,
            dates,
            digits,
            decimal,
            group,
            minus,
            currency_first,
            rtl: is_rtl(&language),
        }
    }

    /// The locale this formatter really uses (after pseudo-locale and fallback handling).
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The locale's digits 0 to 9.
    pub fn digits(&self) -> [char; 10] {
        self.digits
    }

    /// The locale's decimal separator.
    pub fn decimal_separator(&self) -> &str {
        &self.decimal
    }

    /// The locale's grouping separator.
    pub fn grouping_separator(&self) -> &str {
        &self.group
    }

    /// The locale's minus sign.
    pub fn minus_sign(&self) -> &str {
        &self.minus
    }

    /// A number for display: grouped, in the locale's digits.
    pub fn number(&self, d: Decimal) -> String {
        self.grouped.format_str(&fixed(d))
    }

    /// A number for an input field: the locale's decimal separator and digits, no grouping.
    pub fn input_number(&self, d: Decimal) -> String {
        self.plain.format_str(&fixed(d))
    }

    /// An amount for display at `minor_digits` fraction digits, with the ISO 4217 `code`
    /// placed as the locale's currency pattern places a symbol. The amount is rounded half
    /// even to the currency's minor digits.
    pub fn money(&self, amount: Decimal, code: &str, minor_digits: u32) -> String {
        let mut f = fixed(amount);
        f.round_with_mode(-(minor_digits as i16), fixed_decimal::SignedRoundingMode::Unsigned(fixed_decimal::UnsignedRoundingMode::HalfEven));
        f.pad_end(-(minor_digits as i16));
        let n = self.grouped.format_str(&f);
        let nbsp = '\u{a0}';
        let joined = if self.currency_first { format!("{code}{nbsp}{n}") } else { format!("{n}{nbsp}{code}") };
        // The amount keeps its own direction inside right-to-left text.
        if self.rtl { format!("\u{2067}{joined}\u{2069}") } else { joined }
    }

    /// An ISO 8601 calendar date (`2026-10-27`) in the locale's medium date pattern, or
    /// `None` when `iso` isn't a date.
    pub fn date(&self, iso: &str) -> Option<String> {
        let mut parts = iso.split('-');
        let y: i32 = parts.next()?.parse().ok()?;
        let m: u8 = parts.next()?.parse().ok()?;
        let d: u8 = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        let date = Date::try_new_gregorian(y, m, d).ok()?;
        Some(self.dates.as_ref()?.format(&date).to_string())
    }

    /// The CLDR cardinal plural category of a number.
    pub fn plural(&self, d: Decimal) -> Plural {
        match self.plurals.category_for(&fixed(d)) {
            PluralCategory::Zero => Plural::Zero,
            PluralCategory::One => Plural::One,
            PluralCategory::Two => Plural::Two,
            PluralCategory::Few => Plural::Few,
            PluralCategory::Many => Plural::Many,
            PluralCategory::Other => Plural::Other,
        }
    }

    /// Reads typed text as a number (INS-088): the locale's digits or ASCII digits, its
    /// decimal separator and its grouping separator (also its space-like variants), and a
    /// leading minus sign. Bidirectional marks are ignored. Grouping must look like grouping:
    /// a first group of one to three digits, then groups of two or three. Returns the
    /// locale-free value.
    pub fn parse_number(&self, text: &str) -> Result<Decimal, ParseNumberError> {
        let err = || ParseNumberError(text.to_owned());
        let t: String = text
            .chars()
            .filter(|c| !matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}' | '\u{2066}'..='\u{2069}'))
            .collect();
        let mut t = t.trim();
        let mut negative = false;
        if let Some(rest) = t.strip_prefix(self.minus.as_str()).or_else(|| t.strip_prefix('-')).or_else(|| t.strip_prefix('\u{2212}')) {
            negative = true;
            t = rest.trim_start();
        }
        let group_chars: Vec<char> = {
            let mut g: Vec<char> = self.group.chars().collect();
            if g.iter().any(|c| c.is_whitespace()) {
                g.extend(['\u{20}', '\u{a0}', '\u{202f}', '\u{2009}']);
            }
            g
        };
        let decimal_chars: Vec<char> = self.decimal.chars().collect();
        let mut whole = String::new();
        let mut fraction = String::new();
        let mut seen_decimal = false;
        let mut groups: Vec<usize> = vec![0];
        for c in t.chars() {
            let digit = self
                .digits
                .iter()
                .position(|d| *d == c)
                .or_else(|| ARABIC_INDIC.iter().chain(&EXTENDED_ARABIC_INDIC).position(|d| *d == c).map(|p| p % 10))
                .or_else(|| c.to_digit(10).filter(|_| c.is_ascii_digit()).map(|d| d as usize));
            if let Some(d) = digit {
                let ch = char::from(b'0' + d as u8);
                if seen_decimal {
                    fraction.push(ch);
                } else {
                    whole.push(ch);
                    *groups.last_mut().ok_or_else(err)? += 1;
                }
            } else if decimal_chars.contains(&c) && !seen_decimal {
                seen_decimal = true;
            } else if group_chars.contains(&c) && !seen_decimal {
                groups.push(0);
            } else {
                return Err(err());
            }
        }
        let grouped_ok = groups.len() == 1
            || (groups[0] >= 1 && groups[0] <= 3 && groups[1..].iter().all(|g| (2..=3).contains(g)) && groups.last().is_some_and(|g| *g == 3 || groups.len() > 2));
        if whole.is_empty() || !grouped_ok || (seen_decimal && fraction.is_empty()) {
            return Err(err());
        }
        let canonical = if seen_decimal { format!("{whole}.{fraction}") } else { whole };
        let d = Decimal::parse(&canonical).map_err(|_| err())?;
        Ok(if negative { Decimal { mantissa: -d.mantissa, exponent: d.exponent } } else { d })
    }
}
