# rules

## Overview

The rule language of the Instrument context (spec INS section 5.5): syntax tree, parser, static type checker and evaluator for `when`, `hard`, `soft`, `skip` and `derive` expressions. Pure and deterministic: no I/O, clock, randomness or floating point (arithmetic uses the exact rational `domain::num::Num`).

Spec: [instrument.md](../../../../../../docs/reference/spec/instrument.md).

## Interface

- `parse_expr(&str) -> Result<Expr, ParseError>` and `parse_target(&str) -> Option<PathRef>` (`$path`, `@ident` or plain item path), in `parse.rs`.
- `Expr`, `PathRef` (`Item`, `Sibling`, `Roster`), `BinOp`, `Function` (`is_set`, `is_nr`, `abs`, `min`, `max`, `count_set`, `round`, `lookup`, `value`) in `ast.rs`; `Expr::node_count`, `paths`, `visit`, `map_paths`.
- `check::check(&Expr, &dyn CheckScope, in_derive) -> (Ty, Vec<CheckError>)`; types `Ty`, `PathInfo`, `TableShape`, `CheckErrorKind` (`UnknownPath`, `Invalid`, `UnknownTable`, `DeriveInput`). Callers implement the `CheckScope` trait (`path`, `table`).
- `evaluate(&Expr, &dyn EvalScope) -> Result<Val, EvaluationLimitExceeded>`; `Val` (`Unset`, `Bool`, `Num`, `Text`, `List`), `Slot`, and the `EvalScope` trait (`item`, `roster`, `lookup`).
- Constants `MAX_NODES` (256, in `eval.rs`) and `MAX_RULE_NODES` (256, in `mod.rs`).

## Invariants

- The function set is closed: only the nine built-ins (INS-040).
- Any operator applied to an unset operand yields unset, except `is_set`, `is_nr` and `count_set`; a nonresponse is unset to everything but `is_nr` (INS-041, INS-048).
- Evaluation visits at most `MAX_NODES` nodes, else `EvaluationLimitExceeded` (INS-044). Arithmetic overflow also yields that error; division by zero and run-time type mismatches (roster fields only) yield unset.
- Parsing is bounded: nesting of parentheses, lists and calls is limited to 64; comparisons do not chain; the parser never panics on malformed text and reports a character position.
- `check` requires every `PathRef::Sibling` to have been resolved to an `Item` first (INS-047); a `derive` may not read another derived value (INS-045).

## Side Effects

None. All functions are pure; scope data comes in through the `EvalScope` and `CheckScope` traits, which the domain and application layers implement over a compiled instrument.

## Verification

`cargo test -p fieldseal-instrument` (repo-wide: `just test`).
