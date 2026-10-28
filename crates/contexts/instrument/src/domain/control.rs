//! The control catalogue v1 (INS §5.3) and each control's configuration.

use fieldseal_kernel::Decimal;

use super::codes::CodeList;
use super::text::LocalisedText;
use super::units::{Currency, Unit};

/// The control types in catalogue v1 (INS §5.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum ControlType {
    /// One code from a list.
    Choice,
    /// A set of codes, written as a whole set.
    MultiChoice,
    /// An ordinal scale.
    Scale,
    /// A decimal on a grid of `step`.
    Stepper,
    /// A typed decimal.
    Number,
    /// An amount of money in one currency.
    Money,
    /// Two readings that must agree within a tolerance.
    MeasurementPair,
    /// Free text.
    Text,
    /// A coded list with an `other` option and text.
    CodedListWithOther,
    /// Yes or no.
    YesNo,
    /// A collector-declared date.
    Date,
    /// An evidence photo.
    PhotoEvidence,
    /// A consent attestation, used only by the consent step.
    ConsentAttestation,
}

impl ControlType {
    /// Every control in catalogue v1.
    pub const V1: [ControlType; 13] = [
        Self::Choice,
        Self::MultiChoice,
        Self::Scale,
        Self::Stepper,
        Self::Number,
        Self::Money,
        Self::MeasurementPair,
        Self::Text,
        Self::CodedListWithOther,
        Self::YesNo,
        Self::Date,
        Self::PhotoEvidence,
        Self::ConsentAttestation,
    ];

    /// The control's name in instrument documents.
    pub fn name(self) -> &'static str {
        match self {
            Self::Choice => "choice",
            Self::MultiChoice => "multi-choice",
            Self::Scale => "scale",
            Self::Stepper => "stepper",
            Self::Number => "number",
            Self::Money => "money",
            Self::MeasurementPair => "measurement-pair",
            Self::Text => "text",
            Self::CodedListWithOther => "coded-list-with-other",
            Self::YesNo => "yes-no",
            Self::Date => "date",
            Self::PhotoEvidence => "photo-evidence",
            Self::ConsentAttestation => "consent-attestation",
        }
    }

    /// The control named `name` in documents.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::V1.into_iter().find(|c| c.name() == name)
    }

    /// Whether every part of the item is written together (INS-030).
    pub fn is_atomic(self) -> bool {
        matches!(self, Self::MeasurementPair | Self::MultiChoice | Self::CodedListWithOther)
    }
}

/// Where a coded control's options come from (INS-131).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Options {
    /// Inline `options` (or `steps` for a scale).
    Inline(CodeList),
    /// A named code list, `codes: <id>`.
    Named(String),
}

/// A numeric control's unit, with a label for codes readers can't read (INS-160).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnitSpec {
    /// The UCUM code values are recorded in.
    pub unit: Unit,
    /// Its localised label.
    pub label: Option<LocalisedText>,
}

/// How a `scale` is drawn.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ScalePresentation {
    /// A slider.
    Slider,
    /// Segmented buttons.
    Segments,
}

/// How a `yes-no` is drawn.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum YesNoPresentation {
    /// A switch.
    Switch,
    /// Two buttons.
    Buttons,
}

/// How a `money` control is drawn.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MoneyPresentation {
    /// A stepper on a grid of `step`.
    Stepper,
    /// Typed entry.
    Entry,
}

/// A control presentation a catalogue may or may not render (INS-025).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum ControlPresentation {
    /// `scale`: a slider.
    ScaleSlider,
    /// `scale`: segmented buttons.
    ScaleSegments,
    /// `yes-no`: a switch.
    YesNoSwitch,
    /// `yes-no`: two buttons.
    YesNoButtons,
    /// `money`: a stepper.
    MoneyStepper,
    /// `money`: typed entry.
    MoneyEntry,
}

impl ControlPresentation {
    /// Every presentation in catalogue v1.
    pub const V1: [ControlPresentation; 6] = [
        Self::ScaleSlider,
        Self::ScaleSegments,
        Self::YesNoSwitch,
        Self::YesNoButtons,
        Self::MoneyStepper,
        Self::MoneyEntry,
    ];

    /// The control type this presentation belongs to.
    pub fn control_type(self) -> ControlType {
        match self {
            Self::ScaleSlider | Self::ScaleSegments => ControlType::Scale,
            Self::YesNoSwitch | Self::YesNoButtons => ControlType::YesNo,
            Self::MoneyStepper | Self::MoneyEntry => ControlType::Money,
        }
    }
}

/// A stepper's grid (INS-163).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Stepper {
    /// The lowest value.
    pub min: Decimal,
    /// The highest value.
    pub max: Decimal,
    /// The value the first press sets.
    pub start: Decimal,
    /// The grid step; values are `start + k × step`.
    pub step: Decimal,
    /// The unit.
    pub unit: Option<UnitSpec>,
}

/// A typed number (INS-161).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NumberEntry {
    /// The lowest value, in `unit`.
    pub min: Option<Decimal>,
    /// The highest value, in `unit`.
    pub max: Option<Decimal>,
    /// The most fraction digits accepted.
    pub decimals: u32,
    /// The unit values are recorded in.
    pub unit: Option<UnitSpec>,
    /// Units the collector may enter instead (INS-161).
    pub entry_units: Vec<Unit>,
}

/// An amount of money (INS-162).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Money {
    /// The ISO 4217 currency.
    pub currency: Currency,
    /// The lowest amount.
    pub min: Option<Decimal>,
    /// The highest amount.
    pub max: Option<Decimal>,
    /// The grid step, if amounts move in steps.
    pub step: Option<Decimal>,
    /// The presentation, if fixed.
    pub presentation: Option<MoneyPresentation>,
}

/// Two independent readings (INS-026).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MeasurementPair {
    /// Each reading as a number entry.
    pub reading: NumberEntry,
    /// The largest allowed difference between readings, in `unit`.
    pub tolerance: Decimal,
}

/// A catalogue control with its configuration (INS §5.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Control {
    /// One code.
    Choice {
        /// The options.
        options: Options,
    },
    /// A set of codes (INS-133, INS-134).
    MultiChoice {
        /// The options.
        options: Options,
        /// The most codes that may be selected.
        max: Option<u32>,
    },
    /// An ordinal scale over an ordered list (INS-135).
    Scale {
        /// The steps.
        steps: Options,
        /// The presentation, if fixed.
        presentation: Option<ScalePresentation>,
    },
    /// A stepper.
    Stepper(Stepper),
    /// A typed number.
    Number(NumberEntry),
    /// Money.
    Money(Money),
    /// Two readings.
    MeasurementPair(MeasurementPair),
    /// Free text.
    Text {
        /// The longest text, in characters.
        max_length: Option<u32>,
        /// Whether line breaks are allowed.
        multiline: bool,
    },
    /// A code, or `other` with text.
    CodedListWithOther {
        /// The options (without the `other` code).
        options: CodeList,
        /// The label of the `other` option.
        other_label: LocalisedText,
        /// The longest `other` text.
        max_length: u32,
    },
    /// Yes or no.
    YesNo {
        /// The presentation, if fixed.
        presentation: Option<YesNoPresentation>,
    },
    /// A date `YYYY-MM-DD`.
    Date {
        /// The earliest date.
        min: Option<String>,
        /// The latest date.
        max: Option<String>,
    },
    /// An evidence photo.
    PhotoEvidence {
        /// The longest side in pixels.
        max_dimension: Option<u32>,
    },
}

/// The code recorded for the `other` option of `coded-list-with-other`.
pub const OTHER_CODE: &str = "other";

impl Control {
    /// The control's type.
    pub fn control_type(&self) -> ControlType {
        match self {
            Control::Choice { .. } => ControlType::Choice,
            Control::MultiChoice { .. } => ControlType::MultiChoice,
            Control::Scale { .. } => ControlType::Scale,
            Control::Stepper(_) => ControlType::Stepper,
            Control::Number(_) => ControlType::Number,
            Control::Money(_) => ControlType::Money,
            Control::MeasurementPair(_) => ControlType::MeasurementPair,
            Control::Text { .. } => ControlType::Text,
            Control::CodedListWithOther { .. } => ControlType::CodedListWithOther,
            Control::YesNo { .. } => ControlType::YesNo,
            Control::Date { .. } => ControlType::Date,
            Control::PhotoEvidence { .. } => ControlType::PhotoEvidence,
        }
    }

    /// The presentation the instrument fixes for this control, if it fixes one (INS-025).
    pub fn presentation(&self) -> Option<ControlPresentation> {
        match self {
            Control::Scale { presentation, .. } => presentation.map(|p| match p {
                ScalePresentation::Slider => ControlPresentation::ScaleSlider,
                ScalePresentation::Segments => ControlPresentation::ScaleSegments,
            }),
            Control::YesNo { presentation } => presentation.map(|p| match p {
                YesNoPresentation::Switch => ControlPresentation::YesNoSwitch,
                YesNoPresentation::Buttons => ControlPresentation::YesNoButtons,
            }),
            Control::Money(m) => m.presentation.map(|p| match p {
                MoneyPresentation::Stepper => ControlPresentation::MoneyStepper,
                MoneyPresentation::Entry => ControlPresentation::MoneyEntry,
            }),
            _ => None,
        }
    }

    /// The options of a coded control, if any.
    pub fn options(&self) -> Option<&Options> {
        match self {
            Control::Choice { options } | Control::MultiChoice { options, .. } => Some(options),
            Control::Scale { steps, .. } => Some(steps),
            _ => None,
        }
    }

    /// The unit values are recorded in, for numeric controls.
    pub fn unit(&self) -> Option<&UnitSpec> {
        match self {
            Control::Stepper(s) => s.unit.as_ref(),
            Control::Number(n) => n.unit.as_ref(),
            Control::MeasurementPair(m) => m.reading.unit.as_ref(),
            _ => None,
        }
    }

    /// The entry units, for `number` and `measurement-pair`.
    pub fn entry_units(&self) -> &[Unit] {
        match self {
            Control::Number(n) => &n.entry_units,
            Control::MeasurementPair(m) => &m.reading.entry_units,
            _ => &[],
        }
    }
}
