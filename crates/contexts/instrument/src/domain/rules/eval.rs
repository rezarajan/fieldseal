//! The rule evaluator (INS-041, INS-046, INS-048).
//!
//! Deterministic and total: no floating point, no clock, no I/O. Every operator applied to
//! *unset* yields *unset* (INS-041), except `is_set`, `is_nr` and `count_set`, which exist to
//! observe unset values. A nonresponse is *unset* to everything but `is_nr` (INS-048).
//! Operands of the wrong type at run time (possible only through roster fields, whose types
//! aren't declared) and division by zero also yield *unset*.

use std::cmp::Ordering;

use super::ast::{BinOp, Expr, Function, PathRef};
use crate::domain::codes::Nonresponse;
use crate::domain::num::{Num, NumError};
use crate::domain::paths::is_date;

/// The most expression nodes one evaluation may visit (INS-044).
pub const MAX_NODES: usize = 256;

/// A run-time value.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum Val {
    /// Not set (INS-041).
    #[default]
    Unset,
    /// A boolean.
    Bool(bool),
    /// An exact number.
    Num(Num),
    /// Text: a code, a date `YYYY-MM-DD` or free text.
    Text(String),
    /// A list, for example a set of codes.
    List(Vec<Val>),
}

impl Val {
    /// Whether the value is set.
    pub fn is_set(&self) -> bool {
        !matches!(self, Val::Unset)
    }

    /// Whether the value is `true`: how a `when` reads its result (unset is false, INS-041).
    pub fn truthy(&self) -> bool {
        matches!(self, Val::Bool(true))
    }
}

/// What the evaluator knows about one item.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Slot {
    /// Its value; [`Val::Unset`] for a nonresponse.
    pub value: Val,
    /// The nonresponse it holds, if any.
    pub nonresponse: Option<Nonresponse>,
    /// The numeric `value` of the code it holds (INS-132), if any.
    pub code_value: Option<Num>,
}

/// Where an expression's paths and tables are read from.
pub trait EvalScope {
    /// The item at `path`; `None` is unset.
    fn item(&self, path: &str) -> Option<&Slot>;
    /// The roster field `field`; unset if absent.
    fn roster(&self, field: &str) -> Val;
    /// The value for `key` in table `table`; unset if absent (INS-043).
    fn lookup(&self, table: &str, key: &Val) -> Val;
}

/// Evaluation was aborted (INS-044).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("evaluation limit exceeded: {0}")]
pub struct EvaluationLimitExceeded(pub String);

/// Evaluates `expr`, counting visited nodes against [`MAX_NODES`].
pub fn evaluate(expr: &Expr, scope: &dyn EvalScope) -> Result<Val, EvaluationLimitExceeded> {
    let mut budget = MAX_NODES;
    Evaluator { scope, budget: &mut budget }.eval(expr)
}

struct Evaluator<'a> {
    scope: &'a dyn EvalScope,
    budget: &'a mut usize,
}

fn arith(r: Result<Num, NumError>) -> Result<Val, EvaluationLimitExceeded> {
    match r {
        Ok(n) => Ok(Val::Num(n)),
        Err(NumError::DivisionByZero) => Ok(Val::Unset),
        Err(NumError::Overflow) => Err(EvaluationLimitExceeded("arithmetic overflow".into())),
    }
}

/// Equality of two set values; `None` when the types differ.
fn equal(a: &Val, b: &Val) -> Option<bool> {
    match (a, b) {
        (Val::Num(x), Val::Num(y)) => Some(x.cmp_num(*y) == Ordering::Equal),
        (Val::Text(x), Val::Text(y)) => Some(x == y),
        (Val::Bool(x), Val::Bool(y)) => Some(x == y),
        (Val::List(x), Val::List(y)) => {
            if x.len() != y.len() {
                return Some(false);
            }
            let mut all = true;
            for (p, q) in x.iter().zip(y) {
                all &= equal(p, q)?;
            }
            Some(all)
        }
        _ => None,
    }
}

fn order(a: &Val, b: &Val) -> Option<Ordering> {
    match (a, b) {
        (Val::Num(x), Val::Num(y)) => Some(x.cmp_num(*y)),
        (Val::Text(x), Val::Text(y)) if is_date(x) && is_date(y) => Some(x.cmp(y)),
        _ => None,
    }
}

impl Evaluator<'_> {
    fn tick(&mut self) -> Result<(), EvaluationLimitExceeded> {
        if *self.budget == 0 {
            return Err(EvaluationLimitExceeded(format!("more than {MAX_NODES} expression nodes")));
        }
        *self.budget -= 1;
        Ok(())
    }

    fn path(&self, p: &PathRef) -> Val {
        match p {
            PathRef::Item(path) => self.scope.item(path).map_or(Val::Unset, |s| s.value.clone()),
            PathRef::Roster(field) => self.scope.roster(field),
            PathRef::Sibling(_) => Val::Unset,
        }
    }

    fn slot(&self, e: &Expr) -> Option<&Slot> {
        match e {
            Expr::Path(PathRef::Item(path)) => self.scope.item(path),
            _ => None,
        }
    }

    fn eval(&mut self, e: &Expr) -> Result<Val, EvaluationLimitExceeded> {
        self.tick()?;
        Ok(match e {
            Expr::Number(n) => Val::Num(*n),
            Expr::Text(t) => Val::Text(t.clone()),
            Expr::Bool(b) => Val::Bool(*b),
            Expr::Path(p) => self.path(p),
            Expr::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                for i in items {
                    let v = self.eval(i)?;
                    if !v.is_set() {
                        return Ok(Val::Unset);
                    }
                    out.push(v);
                }
                Val::List(out)
            }
            Expr::Neg(inner) => match self.eval(inner)? {
                Val::Num(n) => return arith(n.neg()),
                _ => Val::Unset,
            },
            Expr::Not(inner) => match self.eval(inner)? {
                Val::Bool(b) => Val::Bool(!b),
                _ => Val::Unset,
            },
            Expr::Binary(op, a, b) => {
                let a = self.eval(a)?;
                let b = self.eval(b)?;
                return self.binary(*op, a, b);
            }
            Expr::Call(f, args) => return self.call(*f, args),
        })
    }

    fn binary(&mut self, op: BinOp, a: Val, b: Val) -> Result<Val, EvaluationLimitExceeded> {
        if !a.is_set() || !b.is_set() {
            return Ok(Val::Unset);
        }
        Ok(match op {
            BinOp::And | BinOp::Or => match (a, b) {
                (Val::Bool(x), Val::Bool(y)) => Val::Bool(if op == BinOp::And { x && y } else { x || y }),
                _ => Val::Unset,
            },
            BinOp::Eq | BinOp::Ne => match equal(&a, &b) {
                Some(eq) => Val::Bool(if op == BinOp::Eq { eq } else { !eq }),
                None => Val::Unset,
            },
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => match order(&a, &b) {
                Some(o) => Val::Bool(match op {
                    BinOp::Lt => o == Ordering::Less,
                    BinOp::Le => o != Ordering::Greater,
                    BinOp::Gt => o == Ordering::Greater,
                    _ => o != Ordering::Less,
                }),
                None => Val::Unset,
            },
            BinOp::In => match b {
                Val::List(items) => {
                    let mut found = false;
                    for item in &items {
                        match equal(&a, item) {
                            Some(true) => found = true,
                            Some(false) => {}
                            None => return Ok(Val::Unset),
                        }
                    }
                    Val::Bool(found)
                }
                _ => Val::Unset,
            },
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div => {
                let (Val::Num(x), Val::Num(y)) = (a, b) else { return Ok(Val::Unset) };
                return arith(match op {
                    BinOp::Add => x.add(y),
                    BinOp::Sub => x.sub(y),
                    BinOp::Mul => x.mul(y),
                    _ => x.div(y),
                });
            }
        })
    }

    fn numbers(&mut self, args: &[Expr]) -> Result<Option<Vec<Num>>, EvaluationLimitExceeded> {
        let mut out = Vec::new();
        for a in args {
            match self.eval(a)? {
                Val::Num(n) => out.push(n),
                Val::List(items) => {
                    for i in items {
                        let Val::Num(n) = i else { return Ok(None) };
                        out.push(n);
                    }
                }
                _ => return Ok(None),
            }
        }
        Ok(Some(out))
    }

    fn call(&mut self, f: Function, args: &[Expr]) -> Result<Val, EvaluationLimitExceeded> {
        Ok(match f {
            Function::IsSet => Val::Bool(match args.first() {
                Some(a) => self.eval(a)?.is_set(),
                None => false,
            }),
            Function::IsNr => {
                for _ in args {
                    self.tick()?;
                }
                Val::Bool(args.first().and_then(|a| self.slot(a)).is_some_and(|s| s.nonresponse.is_some()))
            }
            Function::Value => {
                for _ in args {
                    self.tick()?;
                }
                match args.first().and_then(|a| self.slot(a)) {
                    Some(Slot { value, code_value: Some(n), .. }) if value.is_set() => Val::Num(*n),
                    _ => Val::Unset,
                }
            }
            Function::Abs => match args.first().map(|a| self.eval(a)).transpose()? {
                Some(Val::Num(n)) => return arith(n.abs()),
                _ => Val::Unset,
            },
            Function::Min | Function::Max => match self.numbers(args)? {
                Some(nums) if !nums.is_empty() => {
                    let pick = if f == Function::Min { nums.into_iter().min() } else { nums.into_iter().max() };
                    pick.map_or(Val::Unset, Val::Num)
                }
                _ => Val::Unset,
            },
            Function::CountSet => {
                let mut count = 0;
                for a in args {
                    if self.eval(a)?.is_set() {
                        count += 1;
                    }
                }
                Val::Num(Num::int(count))
            }
            Function::Round => {
                let x = match args.first() {
                    Some(a) => self.eval(a)?,
                    None => Val::Unset,
                };
                let digits = match args.get(1) {
                    Some(a) => self.eval(a)?,
                    None => Val::Num(Num::ZERO),
                };
                match (x, digits) {
                    (Val::Num(n), Val::Num(d)) if d.is_integer() && (0..=18).contains(&d.numerator()) => {
                        let rounded = n.round(u32::try_from(d.numerator()).unwrap_or(0));
                        match rounded.ok().and_then(Num::from_decimal) {
                            Some(r) => Val::Num(r),
                            None => return Err(EvaluationLimitExceeded("arithmetic overflow".into())),
                        }
                    }
                    _ => Val::Unset,
                }
            }
            Function::Lookup => {
                let (Some(Expr::Text(table)), Some(key)) = (args.first(), args.get(1)) else { return Ok(Val::Unset) };
                self.tick()?;
                let key = self.eval(key)?;
                if !key.is_set() {
                    return Ok(Val::Unset);
                }
                self.scope.lookup(table, &key)
            }
        })
    }
}
