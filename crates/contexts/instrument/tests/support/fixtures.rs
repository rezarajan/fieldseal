//! Instrument fixtures in the test notation.

use fieldseal_kernel::Value;

use super::doc;

/// The excerpt of `docs/reference/spec/instrument.md` §6.1, transcribed field for field.
/// The media placeholders (`"…"`) are replaced by a WebP header and a well-formed digest,
/// and question 10a is reworded to keep setting-specific words out of the tests.
pub fn spec_example() -> Value {
    doc(r#"
{
  apiVersion: fieldseal.dev/v1alpha1,
  kind: Instrument,
  metadata: { name: food-intake-baseline, version: 1.0.0 },
  spec: {
    schema: "^1.0",
    title: { en: "Baseline food, snack and drink survey" },
    administration: interviewer,
    publisher: Example Authority,
    copyright: { notice: "© The instrument's authors", licence: LicenseRef-authority-use },
    derivedFrom: [ { title: Diet Quality Questionnaire, citation: "Global Diet Quality Project, DQQ" } ],
    languages: [en],
    defaultLanguage: en,
    nonresponse: [dont-know],
    consent: {
      required: true,
      bases: [ { code: form-seen, label: { en: Signed form seen } } ],
      statement: { version: 1, text: { en: "I confirm consent was given for this person." } },
      evidence: optional,
    },
    codeLists: {
      freq-month: {
        ordered: true,
        codes: [
          { code: never, label: { en: Never }, value: 0 },
          { code: m_le1, label: { en: "≤1/month" }, value: 0.033 },
          { code: m_2_3, label: { en: "2–3/month" }, value: 0.083 },
          { code: w_1_2, label: { en: "1–2/week" }, value: 0.214 },
          { code: w_3_4, label: { en: "3–4/week" }, value: 0.5 },
          { code: w_5_6, label: { en: "5–6/week" }, value: 0.786 },
          { code: d_1, label: { en: "1/day" }, value: 1 },
          { code: d_2_3, label: { en: "2–3/day" }, value: 2.5 },
          { code: d_gt3, label: { en: ">3/day" }, value: 4 },
        ],
      },
      staples: {
        ordered: false,
        other: { code: other, label: { en: Other staple }, maxLength: 40 },
        codes: [
          { code: bread, label: { en: Bread }, description: { en: "White, wholewheat, hops, coconut bake" }, media: bread },
          { code: cassava, label: { en: Cassava }, description: { en: "Boiled, fried, in soup" } },
          { code: rice, label: { en: Rice }, description: { en: "White, pelau, fried rice" } },
          { code: other, label: { en: Other staple } },
        ],
      },
      sex: {
        ordered: false,
        codes: [
          { code: male, label: { en: Male }, icon: "👦" },
          { code: female, label: { en: Female }, icon: "👧" },
        ],
      },
    },
    media: {
      bread: {
        mediaType: image/webp,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        bytes: x"524946461a00000057454250565038200e000000",
        alt: { en: A loaf of bread },
      },
    },
    elements: [
      {
        kind: group, id: about, label: { en: General information },
        elements: [
          { kind: question, path: sex, prefix: "2", label: { en: Sex }, control: { type: choice, codes: sex }, data: { type: code } },
          {
            kind: question, path: weight, prefix: "6", label: { en: Weight },
            guidance: { en: "Weigh twice. The two readings must match." },
            control: { type: measurement-pair, unit: "[lb_av]", unitLabel: { en: lbs }, entryUnits: [kg], min: 40, max: 300, decimals: 1, tolerance: 0.2 },
            data: { type: decimal, unit: "[lb_av]", concept: [ { system: "http://loinc.org", code: 29463-7 } ] },
          },
          { kind: question, path: money_gets, prefix: 10a, label: { en: Do you get spending money? }, help: { en: Not travel money }, control: { type: yes-no }, data: { type: boolean } },
          {
            kind: question, path: money_per_day, prefix: 10b, label: { en: How much money do you get to spend each day? },
            when: '$about.money_gets == true', disabledDisplay: protected,
            control: { type: money, currency: TTD, min: 0, max: 200, step: 5 }, data: { type: money },
          },
        ],
      },
      { kind: display, id: diet_intro, role: instruction, text: { en: "These questions are about foods and drinks over the past month or week, and yesterday." } },
      {
        kind: group, id: staples, label: { en: Staples }, referencePeriod: { en: in the last month },
        repeat: { over: staples },
        elements: [
          { kind: question, path: freq, label: { en: How often? }, control: { type: scale, codes: freq-month, presentation: segments }, data: { type: code, codeList: freq-month } },
          {
            kind: question, path: amount, label: { en: Amount each time }, when: '@freq != "never"', disabledDisplay: protected,
            control: { type: stepper, min: 0.5, max: 20, start: 1, step: 0.5, unit: "[oz_av]", unitLabel: { en: oz } },
            data: { type: decimal, unit: "[oz_av]" },
          },
          { kind: question, path: yesterday, label: { en: Had it yesterday? }, control: { type: yes-no, presentation: switch }, data: { type: boolean } },
        ],
        rules: [
          {
            id: never-but-yesterday, kind: soft, when: '@freq == "never" and @yesterday == true',
            message: { en: "Never, but had it yesterday. Ask again." },
            reasons: [ { code: unusual-day, label: { en: Unusual day } }, { code: not-sure, label: { en: Not sure } } ],
          },
        ],
      },
    ],
    fieldChecks: [
      { id: weight-drift, type: drift, path: about.weight, window: 10, threshold: 2.0, message: { en: "Weights are rising steadily. Check the scale." } },
    ],
  },
}
"#)
}

/// An outpatient clinic-visit instrument: a different domain, exercising what the food
/// questionnaire doesn't (two languages with MessageFormat variables and plural selection,
/// multi-choice with `exclusive` and `other`, money in a zero-decimal currency, dates, free
/// text, `refused`, concepts, displays, nested groups, a protected group, a lookup table,
/// a derived value, entry units, skip, hard and soft rules, and field checks).
pub fn clinic_visit() -> Value {
    doc(r#"
{
  apiVersion: fieldseal.dev/v1alpha1,
  kind: Instrument,
  metadata: { name: clinic-visit, version: 0.3.0 },
  spec: {
    schema: "^1.0",
    title: { en: Outpatient clinic visit, fr: Consultation externe },
    description: { en: "A short record of one outpatient visit.", fr: "Un bref relevé d'une consultation externe." },
    purpose: { en: To monitor outpatient care., fr: Suivre les soins externes. },
    publisher: Example Health Service,
    administration: interviewer,
    languages: [en, fr],
    defaultLanguage: en,
    translations: { fr: { method: machine-assisted, reviewedBy: 1, notes: Reviewed by one clinician. } },
    nonresponse: [refused],
    consent: {
      required: true,
      bases: [ { code: verbal, label: { en: Verbal consent, fr: Consentement verbal } } ],
      statement: { version: 2, text: { en: "The patient agreed to this record.", fr: "Le patient a accepté ce relevé." } },
      evidence: none,
    },
    codeLists: {
      symptoms: {
        ordered: false,
        other: { code: other, label: { en: Other symptom, fr: Autre symptôme }, maxLength: 60 },
        codes: [
          { code: fever, label: { en: Fever, fr: Fièvre }, concept: [ { system: "http://snomed.info/sct", code: "386661006", display: Fever } ] },
          { code: cough, label: { en: Cough, fr: Toux } },
          { code: rash, label: { en: Rash, fr: Éruption } },
          { code: other, label: { en: Something else, fr: Autre chose } },
          { code: none, label: { en: None of these, fr: Aucun de ceux-ci }, exclusive: true },
        ],
      },
      medicines: {
        ordered: false,
        codes: [
          { code: paracetamol, label: { en: Paracetamol, fr: Paracétamol } },
          { code: ors, label: { en: Oral rehydration salts, fr: Sels de réhydratation orale } },
        ],
      },
      pain: {
        ordered: true,
        codes: [
          { code: p0, label: { en: No pain, fr: Pas de douleur }, value: 0 },
          { code: p1, label: { en: Mild, fr: Légère }, value: 1 },
          { code: p2, label: { en: Moderate, fr: Modérée }, value: 2 },
          { code: p3, label: { en: Severe, fr: Sévère }, value: 3 },
        ],
      },
      visit-types: {
        ordered: false,
        codes: [ { code: new, label: { en: New problem, fr: Nouveau problème } }, { code: follow_up, label: { en: Follow-up, fr: Suivi } } ],
      },
    },
    tables: {
      fever_threshold: { rows: [ { key: child, value: 37.5 }, { key: adult, value: 38.0 } ] },
    },
    derived: [
      { path: vitals.bmi, label: { en: Body-mass index, fr: Indice de masse corporelle }, data: { type: decimal, unit: "kg/m2" } },
    ],
    elements: [
      { kind: display, id: welcome, role: introduction, text: { en: "Visit of {$roster.given_name}.", fr: "Consultation de {$roster.given_name}." } },
      {
        kind: group, id: visit, label: { en: The visit, fr: La consultation },
        elements: [
          { kind: question, path: date, label: { en: Date of the visit, fr: Date de la consultation }, control: { type: date, min: "2020-01-01", max: "2030-12-31" }, data: { type: date } },
          { kind: question, path: type, label: { en: Reason for the visit, fr: Motif de la consultation }, control: { type: choice, codes: visit-types }, data: { type: code, codeList: visit-types } },
          {
            kind: question, path: age_band, label: { en: Age band, fr: Tranche d'âge },
            control: { type: choice, options: [ { code: child, label: { en: Under 15, fr: Moins de 15 ans } }, { code: adult, label: { en: 15 or over, fr: 15 ans ou plus } } ] },
            data: { type: code },
          },
          {
            kind: question, path: fee, label: { en: Fee paid, fr: Frais payés }, nonresponse: [refused],
            control: { type: money, currency: XOF, min: 0, max: 50000, step: 500, presentation: entry }, data: { type: money },
          },
        ],
      },
      {
        kind: group, id: vitals, label: { en: Vital signs, fr: Signes vitaux },
        concept: [ { system: "http://loinc.org", code: "85353-1", display: Vital signs panel } ],
        elements: [
          {
            kind: question, path: temperature, label: { en: Temperature, fr: Température },
            control: { type: number, min: 30, max: 45, decimals: 1, unit: Cel },
            data: { type: decimal, unit: Cel, concept: [ { system: "http://loinc.org", code: "8310-5", display: Body temperature } ] },
          },
          {
            kind: question, path: weight, label: { en: Weight, fr: Poids },
            control: { type: measurement-pair, unit: kg, entryUnits: ["[lb_av]"], min: 2, max: 250, decimals: 1, tolerance: 0.5 },
            data: { type: decimal, unit: kg },
          },
          {
            kind: question, path: height, label: { en: Height, fr: Taille },
            control: { type: number, unit: cm, entryUnits: ["[in_i]"], min: 40, max: 230, decimals: 1 },
            data: { type: decimal, unit: cm },
          },
          {
            kind: group, id: bp, label: { en: Blood pressure, fr: Tension artérielle },
            when: '$visit.age_band == "adult"', disabledDisplay: protected,
            elements: [
              { kind: question, path: systolic, label: { en: Systolic, fr: Systolique }, control: { type: number, min: 60, max: 260, unit: "mm[Hg]", unitLabel: { en: mmHg, fr: mmHg } }, data: { type: integer, unit: "mm[Hg]" } },
              { kind: question, path: diastolic, label: { en: Diastolic, fr: Diastolique }, control: { type: number, min: 30, max: 160, unit: "mm[Hg]", unitLabel: { en: mmHg, fr: mmHg } }, data: { type: integer, unit: "mm[Hg]" } },
            ],
            rules: [
              { id: diastolic-above-systolic, kind: hard, when: '$vitals.bp.diastolic >= $vitals.bp.systolic', message: { en: Diastolic must be below systolic., fr: La diastolique doit être inférieure à la systolique. } },
            ],
          },
        ],
      },
      {
        kind: group, id: complaint, label: { en: Complaint, fr: Plainte },
        elements: [
          {
            kind: question, path: symptoms,
            label: { en: "Which symptoms does {$roster.given_name} have?", fr: "Quels symptômes {$roster.given_name} a-t-il ?" },
            control: { type: multi-choice, codes: symptoms }, data: { type: codes, codeList: symptoms },
          },
          { kind: question, path: pain, label: { en: Pain, fr: Douleur }, control: { type: scale, codes: pain, presentation: segments }, data: { type: code, codeList: pain } },
          {
            kind: question, path: days, label: { en: How many days has it lasted?, fr: Depuis combien de jours ? },
            nonresponse: [dont-know, refused], control: { type: stepper, min: 1, max: 60, start: 1 }, data: { type: integer },
          },
          {
            kind: display, id: days_note, role: note, when: 'is_set($complaint.days)',
            text: {
              en: ".input {$complaint.days :integer}\n.match $complaint.days\n1 {{Ill for one day.}}\n* {{Ill for {$complaint.days} days.}}",
              fr: ".input {$complaint.days :integer}\n.match $complaint.days\n1 {{Malade depuis un jour.}}\n* {{Malade depuis {$complaint.days} jours.}}",
            },
          },
          { kind: question, path: notes, label: { en: Notes, fr: Remarques }, optional: true, control: { type: text, maxLength: 200, multiline: true }, data: { type: string } },
        ],
      },
      {
        kind: group, id: treatment, label: { en: Treatment, fr: Traitement },
        elements: [
          {
            kind: group, id: given, label: { en: Medicines given, fr: Médicaments donnés },
            repeat: { over: medicines },
            overrides: { ors: { doses: { unit: "{sachet}", unitLabel: { en: sachets, fr: sachets }, max: 10 } } },
            elements: [
              { kind: question, path: given, label: { en: Given?, fr: Donné ? }, control: { type: yes-no }, data: { type: boolean } },
              {
                kind: question, path: doses, label: { en: Doses, fr: Doses }, when: '@given == true',
                control: { type: stepper, min: 1, max: 4, start: 1, unit: "{dose}", unitLabel: { en: doses, fr: doses } },
                data: { type: integer, unit: "{dose}" },
              },
            ],
            rules: [
              {
                id: many-doses, kind: soft, when: '@doses > 3',
                message: { en: More than three doses. Check., fr: Plus de trois doses. Vérifiez. },
                reasons: [ { code: prescribed, label: { en: As prescribed, fr: Selon l'ordonnance } } ],
              },
            ],
          },
        ],
      },
      { kind: display, id: done, role: end, text: { en: Thank you., fr: Merci. } },
    ],
    rules: [
      { id: bmi, kind: derive, target: vitals.bmi, value: 'round($vitals.weight / ($vitals.height / 100 * ($vitals.height / 100)), 1)' },
      {
        id: fever-not-reported, kind: soft,
        when: '$vitals.temperature >= lookup("fever_threshold", $visit.age_band) and not ("fever" in $complaint.symptoms)',
        message: { en: High temperature but no fever reported. Ask again., fr: Température élevée sans fièvre signalée. Redemandez. },
        reasons: [ { code: after-medicine, label: { en: Measured after medicine, fr: Mesurée après un médicament } } ],
      },
      { id: implausible-bmi, kind: hard, when: '$vitals.bmi < 10', message: { en: Check weight and height., fr: Vérifiez le poids et la taille. } },
      { id: nothing-to-ask, kind: skip, when: '"none" in $complaint.symptoms', targets: [complaint.pain, complaint.days] },
    ],
    fieldChecks: [
      { id: same-person, type: duplicates, paths: [visit.date, vitals.weight, vitals.height], minMatch: 3, message: { en: These records may be the same person., fr: Ces relevés concernent peut-être la même personne. } },
      { id: thin-vitals, type: completeness, group: vitals, threshold: 0.5, message: { en: Most vital signs are missing., fr: La plupart des signes vitaux manquent. } },
      { id: temperatures, type: distribution, path: vitals.temperature, expected: { min: 35.5, max: 38.5 }, minCount: 3, message: { en: Temperatures look off. Check the thermometer., fr: Les températures semblent anormales. } },
      { id: rushed, type: timing, minSeconds: 120, message: { en: This visit was recorded very quickly., fr: Cette consultation a été saisie très vite. } },
    ],
  },
}
"#)
}

/// The smallest valid instrument, for invalid-fixture tests to mutate.
pub fn minimal() -> Value {
    doc(r#"
{
  apiVersion: fieldseal.dev/v1alpha1,
  kind: Instrument,
  metadata: { name: mini, version: 1.0.0 },
  spec: {
    schema: "^1.0",
    title: { en: Mini },
    administration: self,
    languages: [en],
    defaultLanguage: en,
    consent: { required: false },
    codeLists: { ab: { ordered: false, codes: [ { code: a, label: { en: A } }, { code: b, label: { en: B } } ] } },
    elements: [
      {
        kind: group, id: g, label: { en: G },
        elements: [
          { kind: question, path: q, label: { en: Q }, control: { type: number, min: 0, max: 10 }, data: { type: integer } },
          { kind: question, path: c, label: { en: C }, control: { type: choice, codes: ab }, data: { type: code, codeList: ab } },
        ],
      },
    ],
  },
}
"#)
}
