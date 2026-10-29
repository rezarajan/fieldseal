# Invalid-document corpus (WIRE-213)

One directory per schema, `survey/` and `layout/`. Every document here is wrong in exactly one way, and the second line of each file says how: `# expect: <Kind> <JSON Pointer>`, where the kind is one of the six WIRE-211 kinds (`UnknownField`, `MissingField`, `TypeMismatch`, `EnumValue`, `DuplicateKey`, `CoercionRefused`).

For each schema the corpus holds a document for an unknown field at every nesting level, a missing required field, a wrong type, a value outside an enumeration, a repeated key and a refused value. Every reader must reject every document with the finding it names:

- `fieldseal conformance run --suite strict-schema` runs the authoring decoder and the kernel validator over the files (they are embedded in the binary, `crates/apps/cli/src/conformance_cmd/strict_schema.rs`).
- `crates/adapters/authoring/tests/schema_differential.rs` runs the decoder and the generated JSON Schema over the same files.

A repeated key and a refused value never become a document, so the JSON Schema and the validator do not see them; the decoder rejects them while reading.

Adding a file here needs a line for it in `strict_schema.rs`; `crates/apps/cli/tests/strict_schema_corpus.rs` fails when the two disagree.
