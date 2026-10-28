//! The instrument rule language: grammar and evaluation golden cases (INS-040 to INS-048),
//! checked in-process against the evaluator with a fixed scope.

use std::collections::BTreeMap;

use fieldseal_instrument::domain::Nonresponse;
use fieldseal_instrument::domain::num::Num;
use fieldseal_instrument::domain::rules::{EvalScope, Slot, Val, evaluate, parse_expr};

use super::harness::{Chk, Collector, same};
use super::Unit;

/// The units of the `ins-rules` and `ins-eval` suites.
pub fn units() -> Vec<Unit> {
    vec![Unit::new("ins:rules", &["ins-rules", "ins-eval"], run)]
}

#[derive(Default)]
struct Scope {
    items: BTreeMap<String, Slot>,
    roster: BTreeMap<String, Val>,
    table: BTreeMap<String, Val>,
}

impl EvalScope for Scope {
    fn item(&self, path: &str) -> Option<&Slot> {
        self.items.get(path)
    }
    fn roster(&self, field: &str) -> Val {
        self.roster.get(field).cloned().unwrap_or(Val::Unset)
    }
    fn lookup(&self, table: &str, key: &Val) -> Val {
        match (table, key) {
            ("t", Val::Text(k)) => self.table.get(k).cloned().unwrap_or(Val::Unset),
            _ => Val::Unset,
        }
    }
}

fn num(t: &str) -> Result<Val, String> {
    Ok(Val::Num(Num::parse(t).c()?))
}

fn scope() -> Result<Scope, String> {
    let mut s = Scope::default();
    s.items.insert("a".into(), Slot { value: num("2")?, ..Slot::default() });
    s.items.insert("b".into(), Slot { value: num("0.5")?, ..Slot::default() });
    s.items.insert("f".into(), Slot { value: Val::Text("w_1_2".into()), code_value: Some(Num::parse("0.214").c()?), ..Slot::default() });
    s.items.insert("dk".into(), Slot { value: Val::Unset, nonresponse: Some(Nonresponse::DontKnow), code_value: None });
    s.items.insert("set".into(), Slot { value: Val::List(vec![Val::Text("x".into()), Val::Text("y".into())]), ..Slot::default() });
    s.roster.insert("age".into(), num("9")?);
    s.table.insert("w_1_2".into(), num("7")?);
    Ok(s)
}

fn eval(text: &str, scope: &Scope) -> Result<Val, String> {
    evaluate(&parse_expr(text).c()?, scope).c()
}

fn run(c: &mut Collector) {
    let Ok(scope) = scope() else { return c.case(&["INS-041".into()], "scope", || Err("the fixed scope does not build".into())) };
    let id = |s: &str| vec![s.to_owned()];

    // INS-041: unset propagates through every operator; `is_set` and `count_set` observe it.
    for text in [
        "$missing + 1", "$missing == 1", "not ($missing == 1)", "$missing > 1 or true", "false and $missing", "-$missing",
        "[1, $missing]", "1 in [$missing]", "min(1, $missing)", "abs($missing)", "round($missing)",
    ] {
        c.case(&id("INS-041"), format!("unset propagates: {text}"), || {
            same!(eval(text, &scope)?, Val::Unset, "result of {text}");
            Ok(())
        });
    }
    c.case(&id("INS-041"), "is_set and count_set observe unset values", || {
        same!(eval("is_set($missing)", &scope)?, Val::Bool(false), "is_set of a missing item");
        same!(eval("is_set($a)", &scope)?, Val::Bool(true), "is_set of a set item");
        same!(eval("count_set($a, $missing, $b)", &scope)?, num("2")?, "count_set");
        Ok(())
    });
    c.case(&id("INS-042"), "an unset `when` is false, so a rule over unset items doesn't run", || {
        same!(eval("$missing == 1", &scope)?.truthy(), false, "truthiness of unset");
        Ok(())
    });
    // INS-043: lookup reads declared tables; a miss is unset.
    c.case(&id("INS-043"), "lookup reads a table and a miss is unset", || {
        same!(eval("lookup(\"t\", $f) * 2", &scope)?, num("14")?, "hit");
        same!(eval("lookup(\"t\", \"nope\")", &scope)?, Val::Unset, "miss");
        same!(eval("lookup(\"t\", $missing)", &scope)?, Val::Unset, "unset key");
        Ok(())
    });
    // INS-044: evaluation is bounded.
    c.case(&id("INS-044"), "an expression over 256 nodes and an integer overflow abort evaluation", || {
        let long = (0..200).map(|_| "1").collect::<Vec<_>>().join(" + ");
        same!(evaluate(&parse_expr(&long).c()?, &scope).is_err(), true, "node bound");
        same!(evaluate(&parse_expr("170141183460469231731687303715884105727 + 1").c()?, &scope).is_err(), true, "overflow");
        Ok(())
    });
    // INS-040: the grammar accepts what it defines and rejects the rest.
    for text in ["1 +", "$a ===", "frobnicate(1)", "(", "round(", "[1, ]", "$"] {
        c.case(&id("INS-040"), format!("grammar rejects: {text}"), || {
            same!(parse_expr(text).is_err(), true, "`{text}` is refused");
            Ok(())
        });
    }
    // INS-046/INS-048: exact decimal arithmetic and nonresponse semantics.
    c.case(&id("INS-046"), "arithmetic is exact decimal and division by zero is unset", || {
        same!(eval("$a / 3 * 3 == 2", &scope)?, Val::Bool(true), "thirds");
        same!(eval("0.1 + 0.2 == 0.3", &scope)?, Val::Bool(true), "tenths");
        same!(eval("round($a / 3, 2)", &scope)?, num("0.67")?, "round");
        same!(eval("$a / 0", &scope)?, Val::Unset, "divide by zero");
        same!(eval("min($a, $b, [3, 0.25])", &scope)?, num("0.25")?, "min");
        Ok(())
    });
    c.case(&id("INS-048"), "a nonresponse is unset to everything but is_nr, and value() reads the code value", || {
        same!(eval("is_nr($dk)", &scope)?, Val::Bool(true), "is_nr of a nonresponse");
        same!(eval("is_nr($a)", &scope)?, Val::Bool(false), "is_nr of an answer");
        same!(eval("is_set($dk)", &scope)?, Val::Bool(false), "is_set of a nonresponse");
        same!(eval("$dk == 1", &scope)?, Val::Unset, "comparison with a nonresponse");
        same!(eval("value($f)", &scope)?, num("0.214")?, "value of a code");
        same!(eval("value($dk)", &scope)?, Val::Unset, "value of a nonresponse");
        Ok(())
    });
}
