# Glossary

Fieldseal's terms are domain-neutral: a deployment maps them to its own words in its documentation, never in Fieldseal's specs or code. Specs and ADRs use these terms exactly. A term in *italics* inside a definition is itself defined here.

## People and organisations

| Term | Meaning |
|---|---|
| **Authority** | The organisation that runs a deployment: it operates the *factory* and *intake*, owns the collected data, and is the only party that can decrypt *records*. |
| **Collector** | A person who collects data on a *device*. |
| **Subject** | A person a *record* is about. |
| **Author** | A person who writes an *instrument* or a *policy*. |
| **Reviewer** | A person who approves an *artefact* for publishing. |
| **Publisher** | A role that signs a reviewed *artefact*, making it publishable. Holds a *publisher key*. |
| **Custodian** | The authority's role responsible for data access, consent decisions and retention. |
| **Operator** | A person who runs a *deployment*: configures it, releases it, and handles exceptions. |

## Components

| Term | Meaning |
|---|---|
| **Fieldseal** | The system: *factory*, *runtime*, *intake*, *publishing* and the `fieldseal` CLI, sharing one format core. |
| **Factory** | The authority's service that registers *device keys*, evaluates *factory policy*, and builds *bundles* from published artefacts. |
| **Portal** | The factory's web front end, where collectors sign in through the *identity provider*. |
| **Identity provider (IdP)** | Whatever authenticates people at the portal (for example Entra ID or Keycloak), behind an adapter. Never seen by the runtime. |
| **Runtime** | The application on a device that verifies bundles, renders instruments, and writes records. |
| **Intake** | The authority's service that verifies exports and lands records. |
| **Transparency log** | An append-only, Merkle-tree log of published artefacts, so anyone can check that an artefact was published and has not been swapped. |
| **CLI** | `fieldseal`: the reference implementation of every protocol operation, used by authors, operators, CI and conformance tests. |

## Architecture

| Term | Meaning |
|---|---|
| **Bounded context** | A part of the domain with its own model and language (for example *Collection*, *Intake*). Specs are written per bounded context. |
| **Port** | An interface a bounded context defines for what it needs (*driven port*, for example `KeyStore`) or what it offers (*driving port*, for example `RegisterDevice`). |
| **Adapter** | One implementation of a port for one technology (for example an Android keystore adapter, an OIDC adapter). |
| **Platform profile** | The set of adapters that lets a runtime run on one operating system, and the requirements those adapters must meet. |
| **Shared kernel** | The wire formats every context agrees on byte for byte, implemented once in the format core. |

## Artefacts

| Term | Meaning |
|---|---|
| **Artefact** | Anything published through the publishing flow: an *instrument*, a *layout*, a *policy*, a *trust bundle* or a *deployment manifest*. Content-addressed. |
| **Instrument** | A declarative definition of what to collect: *groups*, *items*, *display elements*, *code lists*, *controls*, *rules*, *field checks*, consent requirements. Content only; presentation is a *layout*. |
| **Group** | A labelled set of elements in an instrument that prefixes its items' paths; may *repeat* over a *code list*. |
| **Repeat** | A group expanded once per code of a code list, for example one row of questions per food. |
| **Code list** | A named, reusable list of answer codes with labels, optionally ordered and with numeric values. |
| **Display element** | Instrument text or media that records nothing, such as instructions. |
| **Nonresponse** | An explicit *don't know* or *refused*, recorded as such; *not applicable* is derived from skip logic. Never a number. |
| **Layout** | A separate published artefact that groups one instrument's items into steps, tabs, cards and rows, without changing content. |
| **Render plan** | The platform-neutral tree the format core compiles from an instrument and a layout, which every platform draws the same way. |
| **Locale** | A language and region (a BCP 47 tag) that selects text and the formatting of numbers, dates and currencies. |
| **Language of administration** | The language a question was actually shown in; recorded with every record. |
| **Message catalogue** | The translated user-facing strings of the runtime, portal or CLI, keyed by message ID; a deployment may publish one as a *Localisation* artefact. |
| **Standard catalogue** | The versioned, content-addressed set of units shipped with the format core: UCUM measures, household measures (cup, slice, handful) with no conversion factors, and ISO 4217 currencies. |
| **Extension** | A signed, published, additive-only artefact that adds custom units, code lists or concept schemes to what an instrument may refer to; carried in every bundle that needs it. |
| **Custody** | How an authority key's private part is held, on two axes: mode (`cold` or `hot`) and assurance (`development`, `custody-bound` or `attested`). Fixed at issuance and kept privately by the authority; never in a certificate. |
| **Item** | One question or measurement in an instrument, addressed by an *item path* (for example `body.weight`). |
| **Control** | A UI element from the runtime's fixed catalogue that an item uses (for example `choice`, `stepper`, `measurement-pair`). |
| **Rule** | A declarative, bounded validation or skip rule in an instrument. |
| **Field check** | A rule over many records in the *local record*, shown during *review* to catch failures in the field (for example a drifting scale). |
| **Policy** | A signed, versioned set of controls, evaluated by the factory (*factory policy*), the runtime (*runtime policy*) or intake (*intake policy*). |
| **Invariant** | A security property in code that no policy can switch off or loosen. |
| **Trust bundle** | The set of roots and certificates a component is allowed to trust. |
| **Fingerprint** | An instrument version's identifier: a salted SHA-256 of its canonical contents. Names and versions are only labels. |
| **Provenance** | A signed statement of where an artefact came from: source revision, builder, reviewers. |
| **Roster** | The list of subjects in a *cohort*, with pseudonymous IDs and consent state. Sensitive; never published, only sealed into bundles. |
| **Cohort** | A group of subjects assigned together. |
| **Bundle** | What the factory builds for one device key: instrument with its publishing evidence, rosters, runtime policy, trust material. Sealed to that device, signed by the factory. |

## Devices, keys and registration

| Term | Meaning |
|---|---|
| **Device** | A physical endpoint running the runtime. May be shared with other people. |
| **Tenancy** | One collector, on one device, for one time window. Owns its keys, local record and journal. |
| **Device key** | A key the runtime generates in the platform's secure key store: a *signing key* and an *agreement key* per tenancy. |
| **Attestation evidence** | Platform-specific proof that a device key lives in secure hardware and was created by an approved runtime build. |
| **Registration** | Binding a tenancy's device keys to a collector's account at the factory, with attestation evidence and proof of possession. |
| **Registration token** | A single-use, short-lived token the portal issues to a signed-in collector, carried to the device. |
| **Fingerprint words** | Four words derived from a registration request, shown on the device and the portal for comparison. |
| **Session** | An unlocked period of runtime use, opened by the collector's runtime PIN and closed by lock rules. |

## Data

| Term | Meaning |
|---|---|
| **Record** | One immutable, signed unit in the journal: item values, a status, a consent attestation, evidence, an anchor, a checkpoint or a closing entry. |
| **Journal** | The tenancy's append-only, hash-chained sequence of records, each sealed to the authority. The source of truth. |
| **Local record** | The runtime's readable copy of the tenancy's records, encrypted under the session key, kept until *cleared*. |
| **Review** | Viewing the local record, with field checks, before export and clear. |
| **Clear** | Deleting the local record and journal through a sequence number already safely delivered, leaving a *checkpoint* record. |
| **Export** | One signed file carrying the journal to the authority by any route. |
| **Receiver key** | An authority-certified key that a destination uses to prove it may receive uploads. Destinations are authorised by this key, never by address. |
| **Receipt** | The authority's signed acknowledgement of what it received. |
| **Tick** | A record's monotonic time: an *anchor*, a slot count and a boot count. |
| **Anchor** | An authority-signed artefact carrying authority time, chained into the journal. |
| **Consent basis** | Why a record about a subject may be collected: the roster's consent state, or a collector's attestation with optional evidence. |

## Deployment

| Term | Meaning |
|---|---|
| **Deployment** | One authority's running Fieldseal: its configuration, adapters, published artefacts and documentation. |
| **Deployment manifest** | The declarative description of a deployment (`kind: Deployment`), separate from code. |
| **Release** | An immutable combination of a build and a deployment manifest, with its generated documentation. |
