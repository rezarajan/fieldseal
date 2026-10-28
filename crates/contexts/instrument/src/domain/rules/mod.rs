//! The rule language (INS §5.5): syntax tree, parser, static checks and evaluator.

pub mod ast;
pub mod check;
pub mod eval;
pub mod parse;

pub use ast::{BinOp, Expr, Function, PathRef};
pub use check::{CheckError, CheckErrorKind, CheckScope, PathInfo, TableShape, Ty};
pub use eval::{EvalScope, EvaluationLimitExceeded, Slot, Val, MAX_NODES, evaluate};
pub use parse::{ParseError, parse_expr, parse_target};

/// The most nodes a rule's expression tree may have (INS-044).
pub const MAX_RULE_NODES: usize = 256;
