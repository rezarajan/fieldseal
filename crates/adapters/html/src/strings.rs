//! The page's own text: navigation, nonresponse actions and hints. Instrument texts come
//! from the plan; these are platform text (the plan carries nonresponse codes only, INS §5.21),
//! looked up by the plan's language with English as the fallback.
//!
//! This is the renderer's small built-in catalogue, keyed by language. A full runtime UI
//! catalogue (PLAT-050) replaces it when one exists.

/// Every string the page uses besides instrument content.
#[derive(Debug)]
pub struct Strings {
    /// Banner shown above the form.
    pub preview: &'static str,
    /// The stepper's accessible name.
    pub progress: &'static str,
    /// "Step {n} of {total}", with `{n}` and `{total}` replaced.
    pub step_of: &'static str,
    /// Previous-step button.
    pub back: &'static str,
    /// Next-step button.
    pub next: &'static str,
    /// The review step's title.
    pub review: &'static str,
    /// The review step's introduction.
    pub review_intro: &'static str,
    /// A question without an answer, in the review.
    pub not_answered: &'static str,
    /// The `dont-know` nonresponse.
    pub dont_know: &'static str,
    /// The `refused` nonresponse.
    pub refused: &'static str,
    /// The accessible name of the nonresponse buttons.
    pub nonresponse: &'static str,
    /// The heading of collector guidance.
    pub guidance: &'static str,
    /// The optional-question badge.
    pub optional: &'static str,
    /// The badge of a protected (visibly disabled) element.
    pub protected: &'static str,
    /// Yes.
    pub yes: &'static str,
    /// No.
    pub no: &'static str,
    /// First reading of a measurement pair.
    pub reading_1: &'static str,
    /// Second reading of a measurement pair.
    pub reading_2: &'static str,
    /// "The two readings must agree within {n}".
    pub tolerance: &'static str,
    /// "Choose up to {n}".
    pub choose_up_to: &'static str,
    /// "Choose any that apply".
    pub choose_any: &'static str,
    /// Marks an exclusive option.
    pub exclusive: &'static str,
    /// The accessible name of the short fingerprint in the header (INS-104).
    pub fingerprint: &'static str,
    /// The entry-unit selector.
    pub entry_unit: &'static str,
    /// "Longest side {n} px".
    pub max_side: &'static str,
    /// A value read from the roster.
    pub from_roster: &'static str,
    /// The first column of a table: the repeated item.
    pub item: &'static str,
    /// The layout label in the page header.
    pub layout: &'static str,
    /// The default layout's name.
    pub default_layout: &'static str,
    /// "Between {min} and {max}".
    pub between: &'static str,
    /// "At least {min}".
    pub at_least: &'static str,
    /// "At most {max}".
    pub at_most: &'static str,
    /// "Up to {n} characters".
    pub max_chars: &'static str,
    /// "{n} of {max} chosen": the live count under a multi-choice with a maximum (INS-025).
    pub chosen_of: &'static str,
    /// "At most {n} decimal places" (INS-070, INS-162).
    pub decimals_max: &'static str,
    /// "Enter a number".
    pub not_a_number: &'static str,
    /// "Use steps of {step}" (INS-163).
    pub on_step: &'static str,
    /// The accessible name of a stepper's decrease button.
    pub decrease: &'static str,
    /// The accessible name of a stepper's increase button.
    pub increase: &'static str,
}

const EN: Strings = Strings {
    preview: "Preview. Nothing entered here is saved.",
    progress: "Progress",
    step_of: "Step {n} of {total}",
    back: "Back",
    next: "Next",
    review: "Review",
    review_intro: "Check the answers before finishing.",
    not_answered: "Not answered",
    dont_know: "Don't know",
    refused: "Refused",
    nonresponse: "No answer",
    guidance: "For the collector",
    optional: "Optional",
    protected: "Not applicable now",
    yes: "Yes",
    no: "No",
    reading_1: "First reading",
    reading_2: "Second reading",
    tolerance: "The two readings must agree within {n}.",
    choose_up_to: "Choose up to {n}.",
    choose_any: "Choose all that apply.",
    exclusive: "only this",
    fingerprint: "Fingerprint",
    entry_unit: "Unit",
    max_side: "Longest side {n} px.",
    from_roster: "From the roster",
    item: "Item",
    layout: "Layout",
    default_layout: "default",
    between: "Between {min} and {max}.",
    at_least: "At least {min}.",
    at_most: "At most {max}.",
    max_chars: "Up to {n} characters.",
    chosen_of: "{n} of {max} chosen",
    decimals_max: "At most {n} decimal places.",
    not_a_number: "Enter a number.",
    on_step: "Use steps of {step}.",
    decrease: "Decrease",
    increase: "Increase",
};

const ES: Strings = Strings {
    preview: "Vista previa. Nada de lo que se escribe aquí se guarda.",
    progress: "Progreso",
    step_of: "Paso {n} de {total}",
    back: "Atrás",
    next: "Siguiente",
    review: "Revisión",
    review_intro: "Revise las respuestas antes de terminar.",
    not_answered: "Sin respuesta",
    dont_know: "No sabe",
    refused: "No responde",
    nonresponse: "Sin respuesta",
    guidance: "Para quien entrevista",
    optional: "Opcional",
    protected: "No aplica ahora",
    yes: "Sí",
    no: "No",
    reading_1: "Primera lectura",
    reading_2: "Segunda lectura",
    tolerance: "Las dos lecturas deben coincidir con un margen de {n}.",
    choose_up_to: "Elija hasta {n}.",
    choose_any: "Elija todas las que correspondan.",
    exclusive: "solo esta",
    fingerprint: "Huella",
    entry_unit: "Unidad",
    max_side: "Lado mayor {n} px.",
    from_roster: "Del registro",
    item: "Elemento",
    layout: "Diseño",
    default_layout: "predeterminado",
    between: "Entre {min} y {max}.",
    at_least: "Al menos {min}.",
    at_most: "Como máximo {max}.",
    max_chars: "Hasta {n} caracteres.",
    chosen_of: "{n} de {max} elegidas",
    decimals_max: "Como máximo {n} decimales.",
    not_a_number: "Escriba un número.",
    on_step: "Use pasos de {step}.",
    decrease: "Disminuir",
    increase: "Aumentar",
};

const FR: Strings = Strings {
    preview: "Aperçu. Rien de ce qui est saisi ici n'est enregistré.",
    progress: "Progression",
    step_of: "Étape {n} sur {total}",
    back: "Retour",
    next: "Suivant",
    review: "Vérification",
    review_intro: "Vérifiez les réponses avant de terminer.",
    not_answered: "Sans réponse",
    dont_know: "Ne sait pas",
    refused: "Refus",
    nonresponse: "Pas de réponse",
    guidance: "Pour l'enquêteur",
    optional: "Facultatif",
    protected: "Sans objet pour l'instant",
    yes: "Oui",
    no: "Non",
    reading_1: "Première mesure",
    reading_2: "Deuxième mesure",
    tolerance: "Les deux mesures doivent concorder à {n} près.",
    choose_up_to: "Choisissez-en jusqu'à {n}.",
    choose_any: "Choisissez toutes les réponses qui s'appliquent.",
    exclusive: "seulement celle-ci",
    fingerprint: "Empreinte",
    entry_unit: "Unité",
    max_side: "Plus grand côté {n} px.",
    from_roster: "Du registre",
    item: "Élément",
    layout: "Mise en page",
    default_layout: "par défaut",
    between: "Entre {min} et {max}.",
    at_least: "Au moins {min}.",
    at_most: "Au plus {max}.",
    max_chars: "Jusqu'à {n} caractères.",
    chosen_of: "{n} sur {max} choisies",
    decimals_max: "Au plus {n} décimales.",
    not_a_number: "Saisissez un nombre.",
    on_step: "Utilisez des pas de {step}.",
    decrease: "Diminuer",
    increase: "Augmenter",
};

const AR: Strings = Strings {
    preview: "معاينة. لا يُحفظ أي شيء يُدخل هنا.",
    progress: "التقدم",
    step_of: "الخطوة {n} من {total}",
    back: "السابق",
    next: "التالي",
    review: "المراجعة",
    review_intro: "راجع الإجابات قبل الإنهاء.",
    not_answered: "بلا إجابة",
    dont_know: "لا أعرف",
    refused: "رفض الإجابة",
    nonresponse: "بلا إجابة",
    guidance: "لجامع البيانات",
    optional: "اختياري",
    protected: "لا ينطبق الآن",
    yes: "نعم",
    no: "لا",
    reading_1: "القراءة الأولى",
    reading_2: "القراءة الثانية",
    tolerance: "يجب ألا يتجاوز الفرق بين القراءتين {n}.",
    choose_up_to: "اختر حتى {n}.",
    choose_any: "اختر كل ما ينطبق.",
    exclusive: "هذا فقط",
    fingerprint: "البصمة",
    entry_unit: "الوحدة",
    max_side: "أطول ضلع {n} بكسل.",
    from_roster: "من السجل",
    item: "البند",
    layout: "التخطيط",
    default_layout: "افتراضي",
    between: "بين {min} و{max}.",
    at_least: "على الأقل {min}.",
    at_most: "على الأكثر {max}.",
    max_chars: "حتى {n} حرفًا.",
    chosen_of: "تم اختيار {n} من {max}",
    decimals_max: "حتى {n} منازل عشرية.",
    not_a_number: "أدخل رقمًا.",
    on_step: "استخدم خطوات قدرها {step}.",
    decrease: "إنقاص",
    increase: "زيادة",
};

/// The strings for a language tag: its primary subtag's catalogue, else English.
pub fn for_language(tag: &str) -> &'static Strings {
    let primary = tag.split('-').next().unwrap_or("").to_ascii_lowercase();
    match primary.as_str() {
        "es" => &ES,
        "fr" => &FR,
        "ar" => &AR,
        _ => &EN,
    }
}

/// `template` with each `{key}` replaced by its value. Values are inserted as they are; the
/// caller escapes the result.
pub fn fill(template: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = template.to_owned();
    for (k, v) in pairs {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}
