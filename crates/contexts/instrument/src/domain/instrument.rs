//! The `Instrument` aggregate (INS §2).

use std::collections::BTreeMap;

use fieldseal_kernel::Value;

use super::codes::{CodeList, Nonresponse};
use super::compiled::CompiledInstrument;
use super::definitions::{FieldCheckDef, RuleDef};
use super::element::Element;
use super::metadata::{AtomicGroup, ConsentRequirement, DerivedDef, InstrumentMetadata, Languages, LookupTable, MediaAsset};
use super::version::{SchemaRange, SemVer};

/// An instrument as authored, decoded from its document: every part, before compilation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InstrumentDefinition {
    /// `metadata.name`: a label only (INS-101).
    pub name: String,
    /// `metadata.version`: a label only (INS-101).
    pub version: SemVer,
    /// `spec.schema` (INS-091).
    pub schema: SchemaRange,
    /// Descriptive metadata (INS-110–INS-113).
    pub metadata: InstrumentMetadata,
    /// Languages and translations (INS-080, INS-083).
    pub languages: Languages,
    /// The default nonresponse codes (INS-140).
    pub default_nonresponse: Vec<Nonresponse>,
    /// The consent requirement (INS-060).
    pub consent: ConsentRequirement,
    /// Named code lists (INS-131).
    pub code_lists: BTreeMap<String, CodeList>,
    /// Embedded media (INS-180).
    pub media: BTreeMap<String, MediaAsset>,
    /// Lookup tables (INS-043).
    pub tables: BTreeMap<String, LookupTable>,
    /// Declared derived values (INS-045).
    pub derived: Vec<DerivedDef>,
    /// The element tree (INS-120).
    pub elements: Vec<Element>,
    /// Instrument-level rules.
    pub rules: Vec<RuleDef>,
    /// Instrument-level field checks.
    pub field_checks: Vec<FieldCheckDef>,
    /// Declared atomic groups (INS-031).
    pub atomic_groups: Vec<AtomicGroup>,
}

/// A validated instrument: its definition, its compiled form, and the canonical document
/// it was read from. Constructed only by `ValidateInstrument`; immutable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Instrument {
    definition: InstrumentDefinition,
    compiled: CompiledInstrument,
    document: Value,
}

impl Instrument {
    pub(crate) fn new(definition: InstrumentDefinition, compiled: CompiledInstrument, document: Value) -> Self {
        Self { definition, compiled, document }
    }

    /// The authored parts.
    pub fn definition(&self) -> &InstrumentDefinition {
        &self.definition
    }

    /// The compiled form: expanded questions, scoped rules and the evaluation order.
    pub fn compiled(&self) -> &CompiledInstrument {
        &self.compiled
    }

    /// The canonical value tree of the instrument (INS-002): the validated authoring
    /// document. The format core encodes it to canonical bytes and computes the salted
    /// fingerprint from them (WIRE §canonical-encoding, INS-100); this context doesn't hash.
    pub fn to_value(&self) -> Value {
        self.document.clone()
    }

    /// The code list `id`.
    pub fn code_list(&self, id: &str) -> Option<&CodeList> {
        self.definition.code_lists.get(id)
    }
}
