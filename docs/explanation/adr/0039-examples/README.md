# ADR 0039 worked example (INCOMPLETE)

The food instrument rewritten in the proposed dialect. Present: `fieldseal.yaml`, `instrument.yaml` (158 lines), `layouts/` (compact, expanded, shared). Missing (see the ADR, "Unfinished"): the `en` and `es` catalogues, the `.pot`, the line-count table and the construct-by-construct compile walkthrough.

Line counts so far: current instrument 830 plus layouts 117 = 947; new structure files 16 + 158 + 54 = 228 before catalogues (wording is unchanged and moves to `i18n/en/*.po`).
The ladder generator was checked: it reproduces every `value` and all but one code (`d_1` becomes `d1`) of the two current ladders.
