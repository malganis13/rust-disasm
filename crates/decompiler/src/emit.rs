//! C pseudocode emitter.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::ir::*;
use crate::lift::ARG_REGS_SYSV;
use crate::structure::CStmt;
use crate::types::{CType, Signature};

struct Emitter<'a> {
    out: String,
    indent: usize,
    callees: &'a BTreeMap<u64, String>,
}

/// Pretty variable name: live-in argument registers become `a1..a6`,
/// stack slots become `var_N`/`arg_N`, other SSA values keep `reg_version`.
pub fn var_name(v: &Var) -> String {
    if let (Location::Reg(r), 0) = (&v.loc, v.version) {
        if let Some(i) = ARG_REGS_SYSV.iter().position(|a| a == r) {
            return format!("a{}", i + 1);
        }
    }
    match &v.loc {
        Location::Stack(_) => v.loc.to_string(),
        _ if v.version == 0 => format!("{}_in", v.loc),
        _ => format!("{}_{}", v.loc, v.version),
    }
}

/// Render an expression as C.
pub fn expr_c(e: &Expr) -> String {
    match e {
        Expr::Const(c) if (-9..=9).contains(c) => c.to_string(),
        Expr::Const(c) if *c < 0 => format!("-{:#x}", c.unsigned_abs()),
        Expr::Const(c) => format!("{c:#x}"),
        Expr::Var(v) => var_name(v),
        Expr::Bin(BinOp::And, a, b) if matches!(b.as_ref(), Expr::Const(0xffff_ffff)) => {
            format!("(uint32_t){}", expr_c(a))
        }
        Expr::Bin(op, a, b) => format!("({} {} {})", expr_c(a), op.c_operator(), expr_c(b)),
        Expr::Un(UnOp::Neg, a) => format!("-{}", expr_c(a)),
        Expr::Un(UnOp::Not, a) => match a.as_ref() {
            Expr::Bin(op, ..) if op.is_compare() => format!("!{}", expr_c(a)),
            _ => format!("~{}", expr_c(a)),
        },
        Expr::Load(a, w) => format!("*({} *){}", width_ctype(*w), expr_c(a)),
        Expr::AddrOf(l) => format!("&{l}"),
        Expr::Unknown(s) => format!("__{s}()"),
    }
}

/// Strip one level of redundant outer parentheses (for conditions).
fn cond_c(e: &Expr) -> String {
    let s = expr_c(e);
    if s.starts_with('(') && s.ends_with(')') && balanced_inner(&s) {
        s[1..s.len() - 1].to_owned()
    } else {
        s
    }
}

fn balanced_inner(s: &str) -> bool {
    let mut depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && i != s.len() - 1 {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

impl Emitter<'_> {
    fn line(&mut self, s: &str) {
        for _ in 0..self.indent {
            self.out.push_str("    ");
        }
        self.out.push_str(s);
        self.out.push('\n');
    }

    fn callee(&self, c: &Callee) -> String {
        match c {
            Callee::Direct(a) => self
                .callees
                .get(a)
                .cloned()
                .unwrap_or_else(|| format!("sub_{a:x}")),
            Callee::Indirect(e) => format!("(*{})", expr_c(e)),
        }
    }

    fn stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Assign(v, e) => self.line(&format!("{} = {};", var_name(v), cond_c(e))),
            Stmt::Store { addr, value, width } => self.line(&format!(
                "*({} *){} = {};",
                width_ctype(*width),
                expr_c(addr),
                cond_c(value)
            )),
            Stmt::Call { target, args, ret } => {
                let args: Vec<String> = args.iter().map(expr_c).collect();
                let call = format!("{}({})", self.callee(target), args.join(", "));
                match ret {
                    Some(r) => self.line(&format!("{} = {call};", var_name(r))),
                    None => self.line(&format!("{call};")),
                }
            }
            Stmt::Phi(v, srcs) => {
                let s: Vec<String> = srcs.iter().map(|(_, v)| var_name(v)).collect();
                self.line(&format!("// {} = phi({})", var_name(v), s.join(", ")));
            }
            Stmt::Asm(a) => self.line(&format!("__asm__(\"{}\");", a.replace('"', "'"))),
        }
    }

    fn body(&mut self, stmts: &[CStmt]) {
        for s in stmts {
            self.cstmt(s);
        }
    }

    fn cstmt(&mut self, s: &CStmt) {
        match s {
            CStmt::Block(v) => v.iter().for_each(|s| self.stmt(s)),
            CStmt::If { cond, then, els } => {
                let (cond, then, els) = if then.is_empty() && !els.is_empty() {
                    (Expr::Un(UnOp::Not, Box::new(cond.clone())), els, then)
                } else {
                    (cond.clone(), then, els)
                };
                self.line(&format!("if ({}) {{", cond_c(&cond)));
                self.indent += 1;
                self.body(then);
                self.indent -= 1;
                if els.is_empty() {
                    self.line("}");
                } else if let [inner @ CStmt::If { .. }] = els.as_slice() {
                    // else-if chain
                    let mut tmp = Emitter {
                        out: String::new(),
                        indent: self.indent,
                        callees: self.callees,
                    };
                    tmp.cstmt(inner);
                    let trimmed = tmp.out.trim_start().to_owned();
                    self.out.push_str(&"    ".repeat(self.indent));
                    self.out.push_str("} else ");
                    self.out.push_str(&trimmed);
                } else {
                    self.line("} else {");
                    self.indent += 1;
                    self.body(els);
                    self.indent -= 1;
                    self.line("}");
                }
            }
            CStmt::While { cond, body } => {
                self.line(&format!("while ({}) {{", cond_c(cond)));
                self.indent += 1;
                self.body(body);
                self.indent -= 1;
                self.line("}");
            }
            CStmt::DoWhile { body, cond } => {
                self.line("do {");
                self.indent += 1;
                self.body(body);
                self.indent -= 1;
                self.line(&format!("}} while ({});", cond_c(cond)));
            }
            CStmt::Switch { value, cases } => {
                self.line(&format!("switch ({}) {{", cond_c(value)));
                for (i, body) in cases {
                    self.line(&format!("case {i}:"));
                    self.indent += 1;
                    self.body(body);
                    self.indent -= 1;
                }
                self.line("}");
            }
            CStmt::Return(Some(e)) if !matches!(e, Expr::Var(v) if v.version == 0) => {
                self.line(&format!("return {};", cond_c(e)))
            }
            CStmt::Return(_) => self.line("return;"),
            CStmt::Break => self.line("break;"),
            CStmt::Continue => self.line("continue;"),
            CStmt::Goto(a) => self.line(&format!("goto loc_{a:x};")),
            CStmt::Label(a) => {
                self.indent = self.indent.saturating_sub(1);
                self.line(&format!("loc_{a:x}:"));
                self.indent += 1;
            }
        }
    }
}

/// Collect every variable name defined in the function for declarations.
fn declared_vars(f: &IrFunction) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for b in &f.blocks {
        for s in &b.stmts {
            if let Some(v) = s.def() {
                out.insert(var_name(v));
            }
        }
    }
    out
}

/// Emit a complete C function.
pub fn emit_function(name: &str, f: &IrFunction, sig: &Signature, ast: &[CStmt]) -> String {
    let mut e = Emitter {
        out: String::new(),
        indent: 0,
        callees: &f.callee_names,
    };
    let params = if sig.params.is_empty() {
        "void".to_owned()
    } else {
        sig.params
            .iter()
            .map(|(n, t)| format!("{t} {n}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = writeln!(e.out, "// address: {:#x}", f.entry_addr);
    let _ = writeln!(e.out, "{} {}({})\n{{", sig.ret, name, params);
    e.indent = 1;
    for v in declared_vars(f) {
        let ty = sig.locals.get(&v).cloned().unwrap_or(CType::Int(8));
        e.line(&format!("{ty} {v};"));
    }
    if !e.out.ends_with("{\n") {
        e.out.push('\n');
    }
    e.body(ast);
    e.out.push_str("}\n");
    e.out
}
