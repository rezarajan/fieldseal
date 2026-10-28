//! Static checks of rule expressions: unknown paths, types, function arguments, tables and
//! codes (INS-040, INS-043, INS-045, INS-047, INS-048).

use std::collections::BTreeSet;
use std::rc::Rc;

use super::ast::{BinOp, Expr, Function, PathRef};
use crate::domain::paths::is_date;

/// The static type of an expression.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Ty {
    /// `true` or `false`.
    Bool,
    /// A number.
    Num,
    /// Text.
    Text,
    /// A calendar date (recorded as `YYYY-MM-DD` text).
    Date,
    /// One code of a known set.
    Code(Rc<BTreeSet<String>>),
    /// A set of codes of a known set.
    Codes(Rc<BTreeSet<String>>),
    /// A list.
    List(Box<Ty>),
    /// An evidence reference: only `is_set` applies.
    Evidence,
    /// Unknown until evaluation (roster fields).
    Any,
}

impl Ty {
    fn name(&self) -> &'static str {
        match self {
            Ty::Bool => "boolean",
            Ty::Num => "number",
            Ty::Text => "text",
            Ty::Date => "date",
            Ty::Code(_) => "code",
            Ty::Codes(_) => "set of codes",
            Ty::List(_) => "list",
            Ty::Evidence => "evidence",
            Ty::Any => "any",
        }
    }

    fn texty(&self) -> bool {
        matches!(self, Ty::Text | Ty::Code(_) | Ty::Date | Ty::Any)
    }

    fn element(&self) -> Option<Ty> {
        match self {
            Ty::List(t) => Some((**t).clone()),
            Ty::Codes(set) => Some(Ty::Code(set.clone())),
            Ty::Any => Some(Ty::Any),
            _ => None,
        }
    }
}

/// What a path refers to, for checking.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PathInfo {
    /// A question.
    Question {
        /// Its value's type.
        ty: Ty,
        /// Whether it accepts a nonresponse (so `is_nr` can be true).
        nonresponse: bool,
        /// Whether its codes have numeric values (so `value()` can be set).
        coded_values: bool,
    },
    /// The `.other` text of a question.
    OtherText,
    /// The target of a `derive` rule.
    Derived(Ty),
}

/// A declared lookup table's shape.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TableShape {
    /// The type of each key column.
    pub keys: Vec<Ty>,
    /// The type of the values.
    pub value: Ty,
}

/// What a checked expression may refer to.
pub trait CheckScope {
    /// The item at `path`, if one exists.
    fn path(&self, path: &str) -> Option<PathInfo>;
    /// The table `name`, if declared.
    fn table(&self, name: &str) -> Option<TableShape>;
}

/// The class of a static-check error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckErrorKind {
    /// A path that doesn't exist (`UnknownItemPath`).
    UnknownPath,
    /// A type, argument or code error.
    Invalid,
    /// A table that isn't declared (INS-043).
    UnknownTable,
    /// A derived value used as input to another `derive` (INS-045).
    DeriveInput,
}

/// One static-check error.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CheckError {
    /// The class.
    pub kind: CheckErrorKind,
    /// What is wrong.
    pub message: String,
}

/// Checks `expr`, returning its type and any errors. `in_derive` forbids derived inputs
/// (INS-045). Every [`PathRef::Sibling`] must already have been resolved (INS-047).
pub fn check(expr: &Expr, scope: &dyn CheckScope, in_derive: bool) -> (Ty, Vec<CheckError>) {
    let mut c = Checker { scope, in_derive, errors: Vec::new() };
    let ty = c.expr(expr);
    (ty, c.errors)
}

struct Checker<'a> {
    scope: &'a dyn CheckScope,
    in_derive: bool,
    errors: Vec<CheckError>,
}

impl Checker<'_> {
    fn invalid(&mut self, message: String) -> Ty {
        self.errors.push(CheckError { kind: CheckErrorKind::Invalid, message });
        Ty::Any
    }

    fn path(&mut self, p: &PathRef) -> Ty {
        match p {
            PathRef::Roster(_) => Ty::Any,
            // Compilation resolves `@` paths and reports those it can't (INS-047).
            PathRef::Sibling(_) => Ty::Any,
            PathRef::Item(path) => match self.scope.path(path) {
                None => {
                    self.errors.push(CheckError { kind: CheckErrorKind::UnknownPath, message: format!("unknown item path `${path}`") });
                    Ty::Any
                }
                Some(PathInfo::Question { ty, .. }) => ty,
                Some(PathInfo::OtherText) => Ty::Text,
                Some(PathInfo::Derived(ty)) => {
                    if self.in_derive {
                        self.errors.push(CheckError {
                            kind: CheckErrorKind::DeriveInput,
                            message: format!("`${path}` is a derived value and can't be an input to another derive rule (INS-045)"),
                        });
                    }
                    ty
                }
            },
        }
    }

    fn expect(&mut self, ty: &Ty, want: &Ty, what: &str) {
        let ok = match want {
            Ty::Num => matches!(ty, Ty::Num | Ty::Any),
            Ty::Bool => matches!(ty, Ty::Bool | Ty::Any),
            _ => true,
        };
        if !ok {
            self.invalid(format!("{what} needs a {}, not a {}", want.name(), ty.name()));
        }
    }

    /// Checks that a text literal compared with a code (or a date) is valid.
    fn literal_against(&mut self, lit: &Expr, ty: &Ty) {
        let Expr::Text(text) = lit else { return };
        match ty {
            Ty::Code(set) if !set.contains(text) => {
                self.invalid(format!("\"{text}\" is not one of the item's codes"));
            }
            Ty::Date if !is_date(text) => {
                self.invalid(format!("\"{text}\" is not a date YYYY-MM-DD"));
            }
            _ => {}
        }
    }

    fn literals_in(&mut self, list: &Expr, elem: &Ty) {
        if let Expr::List(items) = list {
            for item in items {
                self.literal_against(item, elem);
            }
        }
    }

    fn comparable(a: &Ty, b: &Ty) -> bool {
        match (a, b) {
            (Ty::Any, _) | (_, Ty::Any) => true,
            (Ty::Num, Ty::Num) | (Ty::Bool, Ty::Bool) => true,
            (x, y) if x.texty() && y.texty() => true,
            (Ty::List(_) | Ty::Codes(_), Ty::List(_) | Ty::Codes(_)) => true,
            _ => false,
        }
    }

    fn expr(&mut self, e: &Expr) -> Ty {
        match e {
            Expr::Number(_) => Ty::Num,
            Expr::Text(_) => Ty::Text,
            Expr::Bool(_) => Ty::Bool,
            Expr::Path(p) => self.path(p),
            Expr::List(items) => {
                let tys: Vec<Ty> = items.iter().map(|i| self.expr(i)).collect();
                let elem = tys.iter().find(|t| **t != Ty::Any).cloned().unwrap_or(Ty::Any);
                if tys.iter().any(|t| !Self::comparable(t, &elem)) {
                    return self.invalid("a list's elements must all have the same type".into());
                }
                Ty::List(Box::new(if elem.texty() && elem != Ty::Any { Ty::Text } else { elem }))
            }
            Expr::Neg(inner) => {
                let t = self.expr(inner);
                self.expect(&t, &Ty::Num, "`-`");
                Ty::Num
            }
            Expr::Not(inner) => {
                let t = self.expr(inner);
                self.expect(&t, &Ty::Bool, "`not`");
                Ty::Bool
            }
            Expr::Binary(op, a, b) => self.binary(*op, a, b),
            Expr::Call(f, args) => self.call(*f, args),
        }
    }

    fn binary(&mut self, op: BinOp, a: &Expr, b: &Expr) -> Ty {
        let ta = self.expr(a);
        let tb = self.expr(b);
        match op {
            BinOp::Or | BinOp::And => {
                self.expect(&ta, &Ty::Bool, op.symbol());
                self.expect(&tb, &Ty::Bool, op.symbol());
                Ty::Bool
            }
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div => {
                self.expect(&ta, &Ty::Num, op.symbol());
                self.expect(&tb, &Ty::Num, op.symbol());
                Ty::Num
            }
            BinOp::Eq | BinOp::Ne => {
                if !Self::comparable(&ta, &tb) {
                    return self.invalid(format!("can't compare a {} with a {}", ta.name(), tb.name()));
                }
                self.literal_against(b, &ta);
                self.literal_against(a, &tb);
                if let (Ty::Codes(set), Expr::List(_)) = (&ta, b) {
                    self.literals_in(b, &Ty::Code(set.clone()));
                }
                Ty::Bool
            }
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                let ordered = |t: &Ty| matches!(t, Ty::Num | Ty::Date | Ty::Any);
                let ok = match (&ta, &tb) {
                    (Ty::Num, Ty::Num) | (Ty::Date, Ty::Date) => true,
                    (Ty::Date, Ty::Text) | (Ty::Text, Ty::Date) => true,
                    (x, y) => ordered(x) && ordered(y) && (*x == Ty::Any || *y == Ty::Any),
                };
                if !ok {
                    return self.invalid(format!(
                        "`{}` orders numbers or dates, not a {} and a {}; use value() to order codes",
                        op.symbol(),
                        ta.name(),
                        tb.name()
                    ));
                }
                self.literal_against(b, &ta);
                self.literal_against(a, &tb);
                Ty::Bool
            }
            BinOp::In => {
                let Some(elem) = tb.element() else {
                    return self.invalid(format!("`in` needs a list or a set of codes on the right, not a {}", tb.name()));
                };
                if !Self::comparable(&ta, &elem) {
                    return self.invalid(format!("can't look for a {} in a list of {}", ta.name(), elem.name()));
                }
                self.literal_against(a, &elem);
                self.literals_in(b, &ta);
                Ty::Bool
            }
        }
    }

    fn arity(&mut self, f: Function, args: &[Expr], min: usize, max: usize) -> bool {
        if args.len() < min || args.len() > max {
            let want = if min == max { format!("{min}") } else if max == usize::MAX { format!("at least {min}") } else { format!("{min} to {max}") };
            self.invalid(format!("{}() takes {want} argument(s), not {}", f.name(), args.len()));
            return false;
        }
        true
    }

    fn path_arg<'e>(&mut self, f: Function, args: &'e [Expr]) -> Option<&'e str> {
        match args.first() {
            Some(Expr::Path(PathRef::Item(p))) => Some(p),
            Some(Expr::Path(PathRef::Sibling(_))) => {
                self.expr(&args[0]);
                None
            }
            _ => {
                self.invalid(format!("{}() takes an item path, such as {}($a.b)", f.name(), f.name()));
                None
            }
        }
    }

    fn call(&mut self, f: Function, args: &[Expr]) -> Ty {
        match f {
            Function::IsSet => {
                if self.arity(f, args, 1, 1) {
                    self.expr(&args[0]);
                }
                Ty::Bool
            }
            Function::IsNr => {
                if self.arity(f, args, 1, 1)
                    && let Some(p) = self.path_arg(f, args) {
                        match self.scope.path(p) {
                            Some(PathInfo::Question { .. }) => {}
                            None => {
                                self.errors.push(CheckError { kind: CheckErrorKind::UnknownPath, message: format!("unknown item path `${p}`") });
                            }
                            Some(_) => {
                                self.invalid(format!("is_nr() needs a question; `${p}` is not one"));
                            }
                        }
                    }
                Ty::Bool
            }
            Function::Value => {
                if self.arity(f, args, 1, 1)
                    && let Some(p) = self.path_arg(f, args) {
                        match self.scope.path(p) {
                            Some(PathInfo::Question { ty: Ty::Code(_), coded_values: true, .. }) => {}
                            Some(PathInfo::Question { ty: Ty::Code(_), .. }) => {
                                self.invalid(format!("value() needs codes with numeric values; `${p}`'s codes have none (INS-132)"));
                            }
                            None => {
                                self.errors.push(CheckError { kind: CheckErrorKind::UnknownPath, message: format!("unknown item path `${p}`") });
                            }
                            Some(_) => {
                                self.invalid(format!("value() needs a single-code question; `${p}` is not one"));
                            }
                        }
                    }
                Ty::Num
            }
            Function::Abs => {
                if self.arity(f, args, 1, 1) {
                    let t = self.expr(&args[0]);
                    self.expect(&t, &Ty::Num, "abs()");
                }
                Ty::Num
            }
            Function::Min | Function::Max => {
                if self.arity(f, args, 1, usize::MAX) {
                    for a in args {
                        let t = self.expr(a);
                        let t = if let Ty::List(inner) = t { *inner } else { t };
                        self.expect(&t, &Ty::Num, &format!("{}()", f.name()));
                    }
                }
                Ty::Num
            }
            Function::CountSet => {
                if self.arity(f, args, 1, usize::MAX) {
                    for a in args {
                        self.expr(a);
                    }
                }
                Ty::Num
            }
            Function::Round => {
                if self.arity(f, args, 1, 2) {
                    let t = self.expr(&args[0]);
                    self.expect(&t, &Ty::Num, "round()");
                    if let Some(digits) = args.get(1) {
                        let ok = matches!(digits, Expr::Number(n) if n.is_integer() && !n.is_negative() && n.numerator() <= 18);
                        if !ok {
                            self.invalid("round()'s second argument must be a whole number 0 to 18".into());
                        }
                    }
                }
                Ty::Num
            }
            Function::Lookup => {
                if !self.arity(f, args, 2, 2) {
                    return Ty::Any;
                }
                let Expr::Text(name) = &args[0] else {
                    return self.invalid("lookup()'s first argument must be a table name in quotes (INS-043)".into());
                };
                let Some(shape) = self.scope.table(name) else {
                    self.errors.push(CheckError { kind: CheckErrorKind::UnknownTable, message: format!("no table \"{name}\" in spec.tables (INS-043)") });
                    for a in &args[1..] {
                        self.expr(a);
                    }
                    return Ty::Any;
                };
                if shape.keys.len() != args.len() - 1 {
                    return self.invalid(format!("table \"{name}\" has {} key(s); lookup() gave {}", shape.keys.len(), args.len() - 1));
                }
                for (a, key_ty) in args[1..].iter().zip(&shape.keys) {
                    let t = self.expr(a);
                    if !Self::comparable(&t, key_ty) {
                        self.invalid(format!("table \"{name}\" is keyed by {}, not {}", key_ty.name(), t.name()));
                    }
                }
                shape.value
            }
        }
    }
}
