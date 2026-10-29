//! Errors in a compact document carry the real line and column of the mistake (WIRE-211).

use std::path::{Path, PathBuf};

use fieldseal_adapters_authoring::{ErrorKind, Format, Position, decode, decode_path, decode_with_spans};
use fieldseal_kernel::schema::SchemaErrorKind;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/errors").join(name)
}

/// The `# expect: <Kind> <pointer> column <n>` comment of a fixture and the line after it, where
/// the mistake is.
fn expectation(name: &str) -> (SchemaErrorKind, String, Position) {
    let text = std::fs::read_to_string(fixture(name)).expect("fixture");
    let (index, line) = text.lines().enumerate().find(|(_, l)| l.trim_start().starts_with("# expect:")).expect("an expect comment");
    let words: Vec<&str> = line.trim_start().trim_start_matches("# expect:").split_whitespace().collect();
    let [kind, pointer, "column", column] = words[..] else { panic!("expect comment: {line}") };
    let kind = SchemaErrorKind::parse(kind).expect("one of the six kinds");
    (kind, pointer.to_owned(), Position { line: index + 2, column: column.parse().expect("a column") })
}

fn check(name: &str) {
    let (kind, pointer, position) = expectation(name);
    let path = fixture(name);
    let e = decode_path(&path).expect_err("the fixture has a mistake");
    assert_eq!(e.kind, ErrorKind::Compact);
    assert_eq!((e.line, e.column), (position.line, position.column), "{e}");
    assert_eq!(e.position, Some(position));
    let finding = e.findings.iter().find(|f| f.pointer == pointer).unwrap_or_else(|| panic!("no finding at {pointer}: {:?}", e.findings));
    assert_eq!(finding.kind, kind);
    assert_eq!(finding.position, position);
    assert_eq!(finding.file.as_deref(), Some(path.display().to_string().as_str()));
    assert!(finding.to_string().starts_with(&format!("{}:{}:{}:", path.display(), position.line, position.column)), "{finding}");
}

#[test]
fn wire_211_a_misspelled_key_reports_its_line_and_column() {
    check("misspelled-key.yaml");
}

#[test]
fn wire_211_a_wrong_type_reports_the_value_position() {
    check("wrong-type.yaml");
}

#[test]
fn wire_211_an_out_of_range_enum_reports_the_value_position() {
    check("bad-enum.yaml");
}

#[test]
fn wire_211_findings_carry_a_json_pointer_and_one_of_the_six_kinds() {
    // Several mistakes at once: every one is a finding, in the order they appear in the text.
    let text = "survey: {name: x}\nextra: 1\nsections:\n- q:\n    type: text\n    label: 7\n";
    let e = decode(text.as_bytes(), Format::Yaml).expect_err("three mistakes");
    let found: Vec<(SchemaErrorKind, &str, usize)> = e.findings.iter().map(|f| (f.kind, f.pointer.as_str(), f.position.line)).collect();
    assert_eq!(
        found,
        [
            (SchemaErrorKind::MissingField, "/survey/version", 1),
            (SchemaErrorKind::UnknownField, "/extra", 2),
            (SchemaErrorKind::TypeMismatch, "/sections/0/q/label", 6),
        ]
    );
    assert!(e.findings.iter().all(|f| f.pointer.starts_with('/') && SchemaErrorKind::ALL.contains(&f.kind)));
    // The error itself reports the first.
    assert_eq!((e.line, e.column), (1, 1));
    assert!(e.message.starts_with("/survey/version: "), "{}", e.message);
}

#[test]
fn wire_211_a_repeated_key_reports_duplicate_key_at_its_position() {
    for (format, text, line, column) in [
        (Format::Yaml, "survey: {name: x, version: 1}\nsections:\n- q:\n    type: text\n    label: a\n    label: b\n", 6, 5),
        (Format::Json, "{\n  \"survey\": {},\n  \"survey\": {}\n}", 3, 3),
    ] {
        let e = decode(text.as_bytes(), format).expect_err("a repeated key");
        assert_eq!(e.kind, ErrorKind::DuplicateKey);
        assert_eq!((e.line, e.column), (line, column), "{e}");
        let [finding] = &e.findings[..] else { panic!("one finding: {:?}", e.findings) };
        assert_eq!(finding.kind, SchemaErrorKind::DuplicateKey);
        assert_eq!(finding.position, Position { line, column });
        assert!(finding.pointer == "/sections/0/q/label" || finding.pointer == "/survey", "{}", finding.pointer);
    }
}

#[test]
fn wire_211_a_refused_value_is_a_coercion_finding() {
    for (format, text, pointer, line, column) in [
        (Format::Yaml, "survey: {name: x, version: 1}\nsections:\n- q:\n    type: text\n    max-length: 1e3\n", "/sections/0/q/max-length", 5, 17),
        (Format::Json, "{\n  \"a\": [1, null]\n}", "/a/1", 2, 12),
    ] {
        let e = decode(text.as_bytes(), format).expect_err("a refused value");
        let [finding] = &e.findings[..] else { panic!("one finding: {:?}", e.findings) };
        assert_eq!(finding.kind, SchemaErrorKind::CoercionRefused);
        assert_eq!((finding.pointer.as_str(), finding.position), (pointer, Position { line, column }));
    }
}

#[test]
fn wire_211_spans_give_the_key_and_the_value_of_each_pointer() {
    let (_, spans) = decode_with_spans("a:\n  b: [x, y]\n  c: z\n", Format::Yaml).expect("decodes");
    assert_eq!(spans.key("/a"), Some(Position { line: 1, column: 1 }));
    assert_eq!(spans.key("/a/c"), Some(Position { line: 3, column: 3 }));
    assert_eq!(spans.value("/a/c"), Some(Position { line: 3, column: 6 }));
    assert_eq!(spans.value("/a/b/1"), Some(Position { line: 2, column: 10 }));
    let (_, spans) = decode_with_spans("{\n  \"a\": {\"b/c\": [1, 2]}\n}", Format::Json).expect("decodes");
    assert_eq!(spans.key("/a/b~1c"), Some(Position { line: 2, column: 9 }));
    assert_eq!(spans.value("/a/b~1c/1"), Some(Position { line: 2, column: 20 }));
    assert_eq!(spans.nearest("/a/missing"), Position { line: 2, column: 3 });
}

#[test]
fn wire_211_an_io_error_keeps_position_zero_and_names_the_file() {
    let path = fixture("does-not-exist.yaml");
    let e = decode_path(&path).expect_err("no such file");
    assert_eq!((e.line, e.column, e.position), (0, 0, None));
    assert!(e.findings.is_empty());
    assert!(e.message.contains("does-not-exist.yaml"), "{}", e.message);
}
