//! C pseudocode emitter in Hex-Rays style:
//! `__int64 __fastcall sub_140001000(__int64 a1, int a2)`, locals `v1..vN`
//! annotated with their register, `*(_DWORD *)(a1 + 8)`, `dword_140003000`,
//! named callees with arguments and string literals.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

use crate::context::Context;
use crate::ir::*;
use crate::structure::CStmt;
use crate::types::{CType, Signature};

/// Hex-Rays memory-width type for a dereference.
pub fn width_type(w: u8) -> &'static str {
    match w {
        1 => "_BYTE",
        2 => "_WORD",
        4 => "_DWORD",
        _ => "_QWORD",
    }
}

fn global_prefix(w: u8) -> &'static str {
    match w {
        1 => "byte",
        2 => "word",
        4 => "dword",
        _ => "qword",
    }
}

fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o
}

/// Strip one level of redundant outer parentheses.
fn strip_parens(s: String) -> String {
    if !(s.starts_with('(') && s.ends_with(')')) {
        return s;
    }
    let mut depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && i != s.len() - 1 {
                    return s;
                }
            }
            _ => {}
        }
    }
    s[1..s.len() - 1].to_owned()
}

struct Emitter<'a> {
    out: String,
    indent: usize,
    ctx: &'a Context,
    /// SSA variable → display name (`v1`, `a2`, …).
    names: HashMap<Var, String>,
}

impl Emitter<'_> {
    fn var(&self, v: &Var) -> String {
        if let Some(n) = self.names.get(v) {
            return n.clone();
        }
        match &v.loc {
            Location::Stack(_) => v.loc.to_string(),
            Location::Reg(r) if v.version == 0 => {
                match self.ctx.conv.arg_regs().iter().position(|a| a == r) {
                    Some(i) => format!("a{}", i + 1),
                    None => r.to_string(),
                }
            }
            _ => format!("{}_{}", v.loc, v.version),
        }
    }

    fn konst(&self, c: i64) -> String {
        let a = c as u64;
        if let Some(s) = self.ctx.strings.get(&a) {
            return format!("\"{}\"", escape(s));
        }
        if self.ctx.is_code(a) {
            if let Some(n) = self.ctx.name_of(a) {
                return n.to_owned();
            }
            return format!("sub_{a:X}");
        }
        if self.ctx.is_data(a) && a > 0xffff {
            return match self.ctx.name_of(a) {
                Some(n) => format!("&{n}"),
                None => format!("&unk_{a:X}"),
            };
        }
        match c {
            -9..=9 => c.to_string(),
            c if c < 0 => format!("-{:#X}", c.unsigned_abs()).replace("0X", "0x"),
            c => format!("{:#X}", c).replace("0X", "0x"),
        }
    }

    /// `dword_140003000` / import name for a dereferenced constant address.
    fn global(&self, a: u64, w: u8) -> Option<String> {
        if let Some(n) = self.ctx.name_of(a) {
            return Some(n.to_owned());
        }
        (self.ctx.is_data(a) && a > 0xffff).then(|| format!("{}_{a:X}", global_prefix(w)))
    }

    fn expr(&self, e: &Expr) -> String {
        match e {
            Expr::Const(c) => self.konst(*c),
            Expr::Var(v) => self.var(v),
            Expr::Bin(BinOp::And, a, b) if matches!(b.as_ref(), Expr::Const(0xffff_ffff)) => {
                format!("(unsigned int){}", self.expr(a))
            }
            Expr::Bin(BinOp::And, a, b) if matches!(b.as_ref(), Expr::Const(0xff)) => {
                format!("(unsigned __int8){}", self.expr(a))
            }
            Expr::Bin(op, a, b) => {
                // `x + -c` prints as `x - c`.
                format!("({} {} {})", self.expr(a), op.c_operator(), self.expr(b))
            }
            Expr::Un(UnOp::Neg, a) => format!("-{}", self.expr(a)),
            Expr::Un(UnOp::Not, a) => match a.as_ref() {
                Expr::Bin(op, ..) if op.is_compare() => format!("!{}", self.expr(a)),
                _ => format!("~{}", self.expr(a)),
            },
            Expr::Load(a, w) => match a.as_ref() {
                Expr::Const(c) => match self.global(*c as u64, *w) {
                    Some(g) => g,
                    None => format!("*({} *){}", width_type(*w), self.expr(a)),
                },
                Expr::Var(_) if *w == 8 => format!("*(_QWORD *){}", self.expr(a)),
                _ => format!("*({} *){}", width_type(*w), self.expr(a)),
            },
            Expr::AddrOf(l) => format!("&{l}"),
            Expr::Unknown("undef") => "__undefined()".into(),
            Expr::Unknown(s) => format!("__{s}()"),
        }
    }

    fn cond(&self, e: &Expr) -> String {
        strip_parens(self.expr(e))
    }

    fn line(&mut self, s: &str) {
        for _ in 0..self.indent {
            self.out.push_str("  ");
        }
        self.out.push_str(s);
        self.out.push('\n');
    }

    fn callee(&self, c: &Callee) -> String {
        match c {
            Callee::Direct(a) => self
                .ctx
                .name_of(*a)
                .map_or_else(|| format!("sub_{a:X}"), str::to_owned),
            Callee::Indirect(Expr::Load(a, _)) => match a.as_ref() {
                // call [IAT slot] → import name.
                Expr::Const(slot) => self.ctx.name_of(*slot as u64).map_or_else(
                    || format!("((void (*)(void))qword_{:X})", *slot as u64),
                    str::to_owned,
                ),
                other => format!("(*(void (**)(void)){})", self.expr(other)),
            },
            Callee::Indirect(e) => format!("((void (*)(void)){})", self.expr(e)),
        }
    }

    fn stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Assign(v, e) => {
                let l = format!("{} = {};", self.var(v), self.cond(e));
                self.line(&l)
            }
            Stmt::Store { addr, value, width } => {
                let lhs = match addr {
                    Expr::Const(c) => self
                        .global(*c as u64, *width)
                        .unwrap_or_else(|| format!("*({} *){}", width_type(*width), self.expr(addr))),
                    _ => format!("*({} *){}", width_type(*width), self.expr(addr)),
                };
                let l = format!("{lhs} = {};", self.cond(value));
                self.line(&l)
            }
            Stmt::Call { target, args, ret } => {
                let args: Vec<String> = args.iter().map(|a| self.cond(a)).collect();
                let call = format!("{}({})", self.callee(target), args.join(", "));
                let l = match ret {
                    Some(r) => format!("{} = {call};", self.var(r)),
                    None => format!("{call};"),
                };
                self.line(&l)
            }
            Stmt::Phi(..) => {}
            Stmt::Asm(a) => self.line(&format!("__asm {{ {} }}", a)),
        }
    }

    fn body(&mut self, stmts: &[CStmt]) {
        for s in stmts {
            self.cstmt(s);
        }
    }

    fn block_in_braces(&mut self, head: &str, body: &[CStmt]) {
        self.line(head);
        self.line("{");
        self.indent += 1;
        self.body(body);
        self.indent -= 1;
        self.line("}");
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
                let head = format!("if ( {} )", self.cond(&cond));
                self.block_in_braces(&head, then);
                if !els.is_empty() {
                    if let [inner @ CStmt::If { .. }] = els.as_slice() {
                        let mut tmp = Emitter {
                            out: String::new(),
                            indent: self.indent,
                            ctx: self.ctx,
                            names: self.names.clone(),
                        };
                        tmp.cstmt(inner);
                        let pad = "  ".repeat(self.indent);
                        self.out.push_str(&pad);
                        self.out.push_str("else ");
                        self.out.push_str(tmp.out.trim_start());
                    } else {
                        self.block_in_braces("else", els);
                    }
                }
            }
            CStmt::While { cond, body } => {
                let head = match cond {
                    Expr::Const(1) => "while ( 1 )".to_owned(),
                    c => format!("while ( {} )", self.cond(c)),
                };
                self.block_in_braces(&head, body);
            }
            CStmt::DoWhile { body, cond } => {
                self.line("do");
                self.line("{");
                self.indent += 1;
                self.body(body);
                self.indent -= 1;
                let l = format!("}} while ( {} );", self.cond(cond));
                self.line(&l);
            }
            CStmt::Switch { value, cases } => {
                let head = format!("switch ( {} )", self.cond(value));
                self.line(&head);
                self.line("{");
                self.indent += 1;
                for (i, body) in cases {
                    self.line(&format!("case {i}:"));
                    self.indent += 1;
                    self.body(body);
                    self.indent -= 1;
                }
                self.indent -= 1;
                self.line("}");
            }
            CStmt::Return(Some(e)) if !matches!(e, Expr::Var(v) if v.version == 0) => {
                let l = format!("return {};", self.cond(e));
                self.line(&l)
            }
            CStmt::Return(_) => self.line("return;"),
            CStmt::Break => self.line("break;"),
            CStmt::Continue => self.line("continue;"),
            CStmt::Goto(a) => self.line(&format!("goto LABEL_{a:X};")),
            CStmt::Label(a) => {
                let saved = self.indent;
                self.indent = 0;
                self.line(&format!("LABEL_{a:X}:"));
                self.indent = saved;
            }
        }
    }
}

fn collect_defs(stmts: &[CStmt], out: &mut Vec<Var>) {
    let push = |v: &Var, out: &mut Vec<Var>| {
        if !out.contains(v) {
            out.push(v.clone());
        }
    };
    for s in stmts {
        match s {
            CStmt::Block(v) => {
                for st in v {
                    if let Some(d) = st.def() {
                        push(d, out);
                    }
                }
            }
            CStmt::If { then, els, .. } => {
                collect_defs(then, out);
                collect_defs(els, out);
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => collect_defs(body, out),
            CStmt::Switch { cases, .. } => cases.iter().for_each(|(_, b)| collect_defs(b, out)),
            _ => {}
        }
    }
}

/// Emit a complete C function.
pub fn emit_function(name: &str, f: &IrFunction, sig: &Signature, ast: &[CStmt], ctx: &Context) -> String {
    let mut defs = Vec::new();
    collect_defs(ast, &mut defs);

    // Hex-Rays naming: registers → v1.., stack slots keep var_/arg_ names.
    let mut names = HashMap::new();
    let mut decls: BTreeMap<usize, (String, String, String)> = BTreeMap::new();
    let mut stack_decl: BTreeMap<String, String> = BTreeMap::new();
    let mut n = 0;
    for v in &defs {
        match &v.loc {
            Location::Stack(off) => {
                let nm = v.loc.to_string();
                let ty = sig.locals.get(&nm).cloned().unwrap_or(CType::Int(8));
                stack_decl.entry(nm).or_insert(format!("{ty}; // [rsp{off:+#x}]"));
            }
            loc => {
                n += 1;
                let nm = format!("v{n}");
                names.insert(v.clone(), nm.clone());
                decls.insert(n, (CType::Int(8).to_string(), nm, loc.to_string()));
            }
        }
    }

    let mut e = Emitter {
        out: String::new(),
        indent: 0,
        ctx,
        names,
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
    let _ = writeln!(e.out, "// {:#x}", f.entry_addr);
    let _ = writeln!(e.out, "{} {} {}({})", sig.ret, ctx.conv.keyword(), name, params);
    e.out.push_str("{\n");
    e.indent = 1;
    for (nm, decl) in &stack_decl {
        let (ty, comment) = decl.split_once(';').unwrap_or((decl, ""));
        e.line(&format!("{ty} {nm};{comment}"));
    }
    for (ty, nm, reg) in decls.values() {
        e.line(&format!("{ty} {nm}; // {reg}"));
    }
    if !stack_decl.is_empty() || !decls.is_empty() {
        e.out.push('\n');
    }
    e.body(ast);
    e.out.push_str("}\n");
    e.out
}
