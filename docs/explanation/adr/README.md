# Architecture decision records

Fieldseal's decisions, one per file ([ADR 0001](./0001-record-architecture-decisions.md)). Each has a MoSCoW **priority** for the current delivery and uses RFC 2119 key words. All are **Proposed** until approved in the architecture review issue. Detail is in the [specs](../../reference/spec/README.md); terms are in the [glossary](../../reference/glossary.md).

| ADR | Priority | In one line | Status |
|---|---|---|---|
| [0001](./0001-record-architecture-decisions.md) | Must | Record each decision as a short ADR with a MoSCoW priority and RFC 2119 wording; specs hold the detail. | Accepted |
| [0002](./0002-name-fieldseal.md) | Must | Name the system Fieldseal; resources use `apiVersion: fieldseal.dev/v1alpha1`; no programme names in specs or code. | Accepted |
| [0003](./0003-ddd-and-hexagonal-architecture.md) | Must | Build each part as a hexagon: pure domain, use cases, ports, and swappable adapters per technology. | Accepted |
| [0004](./0004-bounded-contexts.md) | Must | Split the domain into 10 bounded contexts sharing one set of wire formats. | Accepted |
| [0005](./0005-format-core.md) | Must | Implement formats, cryptography and rules once, in a Rust core bound to every platform. | Accepted |
| [0006](./0006-cli-reference-implementation.md) | Must | The `fieldseal` CLI performs every protocol operation and is the reference for conformance. | Accepted |
| [0007](./0007-zero-trust-posture.md) | Must | Trust no network, transport or storage: authenticate before parsing, seal every output end to end. | Accepted |
| [0008](./0008-trust-hierarchy.md) | Must | An offline root per authority certifies purpose-tagged keys; one runtime build trusts any authority via configuration. | Accepted |
| [0009](./0009-publishing-with-provenance.md) | Must | Instruments and policies are reviewed, signed by a publisher threshold, logged in a transparency log, and verified on the device. | Accepted |
| [0010](./0010-declarative-instruments.md) | Must | Instruments are declarative documents rendered from a fixed control catalogue, with a bounded rule language and semver. | Accepted |
| [0011](./0011-policy-as-signed-files.md) | Must | Every tunable control is a signed policy file; layers may only tighten security; code-level invariants can't be loosened. | Accepted |
| [0012](./0012-local-first-device-keys.md) | Must | Devices make and use hardware-backed keys at once; only releasing rosters waits for registration. | Accepted |
| [0013](./0013-registration-via-authority-tokens.md) | Must | Collectors sign in only at the portal (any IdP); the portal's one-time token goes to the device, never a code from the device. | Accepted |
| [0014](./0014-multi-device-and-air-gapped.md) | Should | Each device registers separately (limits by policy); every exchange also works air-gapped via QR codes and files. | Accepted |
| [0015](./0015-bundles-sealed-per-device.md) | Must | The factory seals each bundle to one device key and signs it; the device verifies before loading. | Accepted |
| [0016](./0016-tenancies-with-crypto-erase.md) | Must | A tenancy is one collector on one device for a window; closing it crypto-erases everything except sealed data awaiting delivery. | Accepted |
| [0017](./0017-runtime-authentication.md) | Must | The runtime has its own hardware-bound PIN, separate from the device lock, with no biometric unlock. | Accepted |
| [0018](./0018-dual-write-records.md) | Must | Seal each record twice: to the authority's journal (source of truth) and to a local record the collector can read. | Accepted |
| [0019](./0019-review-until-clear.md) | Must | Collectors can review all their records, with field checks, until delivery is confirmed and they explicitly clear. | Superseded by 0029 |
| [0020](./0020-monotonic-ticks.md) | Should | Order and bound record times with Cardano-style ticks (signed anchors plus an unsettable elapsed counter). | Accepted |
| [0021](./0021-export-upload-receipts.md) | Must | Send records to any destination that proves it holds an authority-certified receiver key; addresses are hints from anywhere, never baked in or canonical. | Accepted |
| [0022](./0022-consent-bases.md) | Must | Consent is granted, refused or unknown; collectors may attest unknown consent with optional photo evidence; intake reviews by risk. | Accepted |
| [0023](./0023-generic-intake-and-landing.md) | Must | Intake verifies every export in a fixed order and lands any instrument in one generic long format. | Accepted |
| [0024](./0024-platform-profiles.md) | Must | Each OS gets a platform profile of adapters; Android first, other platforms later. | Accepted |
| [0025](./0025-twelve-factor-deployments.md) | Must | Apply all twelve factors to every component (services fully, runtime and CLI wherever meaningful), with docs generated per release. | Accepted |
| [0026](./0026-supersede-v0-designs.md) | Must | Archive the v0.x design; only ADRs and specs are normative. | Accepted |
| [0027](./0027-salted-instrument-fingerprints.md) | Must | Every instrument version is identified only by a salted SHA-256 fingerprint of its contents; names and versions are labels, so look-alike sheets never collide. | Accepted |
| [0028](./0028-clean-architecture.md) | Must | Within every context, source dependencies point only inward (domain ← use cases ← adapters ← frameworks), and CI fails any build that breaks this. | Accepted |
| [0029](./0029-clear-anytime-with-pin-confirmation.md) | Must | Collectors review everything until they clear; clearing is always allowed after entering their PIN twice, and is offered automatically once the authority's receipt arrives. | Accepted |
| [0030](./0030-public-transparency-log.md) | Must | Publications are logged in a public transparency log through a port whose entry type can only hold a hash, a signature and a pseudonymous key, so nothing sensitive can ever be logged; Rekor is one adapter. | Accepted |
| [0031](./0031-device-management-adapters.md) | Must | Device lock-down sits behind a DevicePolicy port with a self-managed adapter (runtime as device owner, default) and an EMM adapter; either way the runtime verifies at start-up that the restrictions are really in force. | Accepted |
| [0032](./0032-standard-survey-elements.md) | Must | Make the elements that survey standards share (metadata, nested groups, repeats, code lists, nonresponse, text roles, units, concepts, media) first-class in the instrument schema. | Accepted |
| [0033](./0033-presentation-layouts.md) | Must | Presentation is a separate signed layout that partitions the instrument's ordered questions into screens but never reorders or changes them; the core compiles it into one render plan, and records name the layout used. | Accepted |
| [0034](./0034-internationalisation-and-localisation.md) | Must | Any language, script and locale from the first release: catalogued UI strings, CLDR formatting, right-to-left, reviewed translations, and the language each answer was asked in recorded. | Accepted |
| [0035](./0035-service-contracts-and-transports.md) | Should | Define each service's operations once as a protobuf contract with canonical CBOR as opaque bytes; HTTP and gRPC are adapters of it, chosen by URL scheme and held to one conformance suite. | Accepted |
| [0036](./0036-showcase-web-app-and-web-device.md) | Should | A server-rendered showcase web app and a development-only `web` platform profile: the real core compiled to WebAssembly runs as an unattested software device in the browser, refused in production. | Proposed |
| [0037](./0037-extensions-and-strict-schema-enforcement.md) | Must | The tool derives and converts nothing; units come from a versioned UCUM, ISO 4217 and household-measure catalogue that signed, additive-only `Extension` artefacts extend (carried in every bundle that needs them); every document has a closed schema and every reader and UI enforces it, including declared control constraints at entry. | Accepted |
| [0038](./0038-authority-key-custody-classes.md) | Must | Authority keys have a custody on two axes, an operating mode (`cold` or `hot`) and an assurance (`development`, `custody-bound` or `attested`), fixed at issuance with the existing `KeyCustody`, `AttestationVerifier` and CSR proof of possession, kept privately, and enforced by tighten-only policy minimums and deployment validation; never on the wire, and a development key can never be promoted. | Accepted |
| [0039](./0039-authoring-language-and-developer-experience.md) | Should | A strict YAML authoring dialect with generators, templates, `forEach`, modules and external PO/MF2 message catalogues compiles deterministically to the unchanged canonical instrument. | Superseded by 0041 |
| [0040](./0040-compact-declarations-and-twelve-factor-config.md) | Must | Every declarative asset is compact YAML of typed keys compiled to the unchanged artefacts; a deployment manifest says only what it runs and serves, and every per-deploy value is one environment variable (Proposed) |
| [0041](./0041-survey-source-tree-and-authoring-toolchain.md) | Must | A survey is one folder (instrument, layouts, `.po` catalogues) with one home file for each setting, translated by `msgctxt` keys and authored layout ids, checked against one declarative schema that also generates the editor schema, and moved without changing any address. | Proposed |
