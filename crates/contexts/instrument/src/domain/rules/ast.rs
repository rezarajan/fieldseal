//! The rule language's syntax tree (INS §5.5).

use std::collections::BTreeSet;
use std::fmt;

use crate::domain::num::Num;

/// A reference to a value.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum PathRef {
    /// `$item.path`: an item of the instrument.
    Item(String),
    /// `@ident`: a sibling question of the same repeat instance (INS-047). Compilation
    /// replaces every sibling reference with an [`PathRef::Item`].
    Sibling(String),
    /// `roster.ident`: a read-only roster field.
    Roster(String),
}

/// The built-in functions; there are no others (INS-040).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Function {
    /// `is_set(x)`: whether `x` is set.
    IsSet,
    /// `is_nr(path)`: whether the item holds a nonresponse (INS-048).
    IsNr,
    /// `abs(x)`.
    Abs,
    /// `min(x, …)`: the least of numbers or lists of numbers.
    Min,
    /// `max(x, …)`.
    Max,
    /// `count_set(x, …)`: how many arguments are set.
    CountSet,
    /// `round(x)` or `round(x, digits)`: half away from zero.
    Round,
    /// `lookup("table", key, …)`: a value from a declared table (INS-043).
    Lookup,
    /// `value(path)`: the numeric value of the code the item holds (INS-048, INS-132).
    Value,
}

impl Function {
    /// The function named `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "is_set" => Self::IsSet,
            "is_nr" => Self::IsNr,
            "abs" => Self::Abs,
            "min" => Self::Min,
            "max" => Self::Max,
            "count_set" => Self::CountSet,
            "round" => Self::Round,
            "lookup" => Self::Lookup,
            "value" => Self::Value,
            _ => return None,
        })
    }

    /// The function's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::IsSet => "is_set",
            Self::IsNr => "is_nr",
            Self::Abs => "abs",
            Self::Min => "min",
            Self::Max => "max",
            Self::CountSet => "count_set",
            Self::Round => "round",
            Self::Lookup => "lookup",
            Self::Value => "value",
        }
    }
}

/// A binary operator.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BinOp {
    /// `or`.
    Or,
    /// `and`.
    And,
    /// `==`.
    Eq,
    /// `!=`.
    Ne,
    /// `<`.
    Lt,
    /// `<=`.
    Le,
    /// `>`.
    Gt,
    /// `>=`.
    Ge,
    /// `in`.
    In,
    /// `+`.
    Add,
    /// `-`.
    Sub,
    /// `*`.
    Mul,
    /// `/`.
    Div,
}

impl BinOp {
    /// The operator as written.
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Or => "or",
            Self::And => "and",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::In => "in",
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
        }
    }
}

/// An expression.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Expr {
    /// A number literal.
    Number(Num),
    /// A string literal.
    Text(String),
    /// `true` or `false`.
    Bool(bool),
    /// A path.
    Path(PathRef),
    /// `[a, b, …]`.
    List(Vec<Expr>),
    /// `-x`.
    Neg(Box<Expr>),
    /// `not x`.
    Not(Box<Expr>),
    /// `a op b`.
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// `f(a, …)`.
    Call(Function, Vec<Expr>),
}

impl Expr {
    /// The number of nodes in the tree (INS-044).
    pub fn node_count(&self) -> usize {
        1 + match self {
            Expr::Number(_) | Expr::Text(_) | Expr::Bool(_) | Expr::Path(_) => 0,
            Expr::List(items) | Expr::Call(_, items) => items.iter().map(Expr::node_count).sum(),
            Expr::Neg(e) | Expr::Not(e) => e.node_count(),
            Expr::Binary(_, a, b) => a.node_count() + b.node_count(),
        }
    }

    /// Every path the expression references.
    pub fn paths(&self) -> BTreeSet<PathRef> {
        let mut out = BTreeSet::new();
        self.visit(&mut |e| {
            if let Expr::Path(p) = e {
                out.insert(p.clone());
            }
        });
        out
    }

    /// Calls `f` on every node, parents first.
    pub fn visit(&self, f: &mut impl FnMut(&Expr)) {
        f(self);
        match self {
            Expr::List(items) | Expr::Call(_, items) => items.iter().for_each(|e| e.visit(f)),
            Expr::Neg(e) | Expr::Not(e) => e.visit(f),
            Expr::Binary(_, a, b) => {
                a.visit(f);
                b.visit(f);
            }
            _ => {}
        }
    }

    /// The same expression with every path rewritten by `f`.
    pub fn map_paths(&self, f: &mut impl FnMut(&PathRef) -> PathRef) -> Expr {
        match self {
            Expr::Path(p) => Expr::Path(f(p)),
            Expr::List(items) => Expr::List(items.iter().map(|e| e.map_paths(f)).collect()),
            Expr::Call(func, items) => Expr::Call(*func, items.iter().map(|e| e.map_paths(f)).collect()),
            Expr::Neg(e) => Expr::Neg(Box::new(e.map_paths(f))),
            Expr::Not(e) => Expr::Not(Box::new(e.map_paths(f))),
            Expr::Binary(op, a, b) => Expr::Binary(*op, Box::new(a.map_paths(f)), Box::new(b.map_paths(f))),
            other => other.clone(),
        }
    }
}

impl fmt::Display for PathRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathRef::Item(p) => write!(f, "${p}"),
            PathRef::Sibling(p) => write!(f, "@{p}"),
            PathRef::Roster(p) => write!(f, "roster.{p}"),
        }
    }
}

impl fmt::Display for Expr {
    /// Fully parenthesised, so the printed form re-parses to the same tree.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Number(n) => write!(f, "{n}"),
            Expr::Text(t) => write!(f, "\"{}\"", t.replace('\\', "\\\\").replace('"', "\\\"")),
            Expr::Bool(b) => write!(f, "{b}"),
            Expr::Path(p) => write!(f, "{p}"),
            Expr::List(items) => {
                write!(f, "[")?;
                for (i, e) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{e}")?;
                }
                write!(f, "]")
            }
            Expr::Neg(e) => write!(f, "-({e})"),
            Expr::Not(e) => write!(f, "not ({e})"),
            Expr::Binary(op, a, b) => write!(f, "({a} {} {b})", op.symbol()),
            Expr::Call(func, items) => {
                write!(f, "{}(", func.name())?;
                for (i, e) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{e}")?;
                }
                write!(f, ")")
            }
        }
    }
}
