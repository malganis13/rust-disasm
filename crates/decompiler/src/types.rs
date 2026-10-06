//! Lightweight type and signature inference.
//!
//! This is deliberately conservative: it recovers the integer width of local
//! variables from their defining expressions and reconstructs a plausible
//! function signature from the SysV / Win64 argument registers that are read
//! before being written.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::*;
use crate::lift::ARG_REGS_SYSV;

/// A recovered C type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CType {
    Void,
    Int(u8),
    UInt(u8),
    Ptr,
}

impl std::fmt::Display for CType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CType::Void => write!(f, "void"),
            CType::Int(w) => write!(f, "int{}_t", *w as u32 * 8),
            CType::UInt(w) => write!(f, "uint{}_t", *w as u32 * 8),
            CType::Ptr => write!(f, "void *"),
        }
    }
}

/// A reconstructed function signature.
#[derive(Debug, Clone)]
pub struct Signature {
    pub ret: CType,
    pub params: Vec<(String, CType)>,
    /// Inferred type of each local variable name.
    pub locals: BTreeMap<String, CType>,
}

/// Infer a signature and local variable types for a lifted function.
pub fn infer(f: &IrFunction, bits: u32) -> Signature {
    let ptr = (bits / 8) as u8;

    // 1. Which argument registers are read before any write? => parameters.
    let mut params = Vec::new();
    let read_args = live_in_args(f);
    // Parameters are positional: include every register up to the last one used.
    let last = ARG_REGS_SYSV.iter().rposition(|r| read_args.contains(*r));
    if let Some(last) = last {
        for i in 0..=last {
            params.push((format!("a{}", i + 1), CType::Int(ptr.min(8))));
        }
    }

    // 2. Does any path return a value derived from rax? Heuristic: if every
    //    Return carries an expression, assume it returns an int; else void.
    let mut returns_value = false;
    let mut has_return = false;
    for b in &f.blocks {
        if let Terminator::Return(e) = &b.term {
            has_return = true;
            // `return rax_0` means rax was never written: a void function.
            if let Some(e) = e {
                if !matches!(e, Expr::Var(v) if v.version == 0) {
                    returns_value = true;
                }
            }
        }
    }
    let ret = if returns_value {
        CType::Int(ptr.min(8))
    } else {
        CType::Void
    };
    let _ = has_return;

    // 3. Local variable widths from stack-slot stores / loads.
    let mut locals: BTreeMap<String, CType> = BTreeMap::new();
    for b in &f.blocks {
        for s in &b.stmts {
            collect_local_types(s, ptr, &mut locals);
        }
    }

    Signature { ret, params, locals }
}

fn collect_local_types(s: &Stmt, ptr: u8, out: &mut BTreeMap<String, CType>) {
    match s {
        Stmt::Assign(v, e) => {
            if let Location::Stack(_) = v.loc {
                let ty = expr_type(e, ptr);
                out.entry(v.loc.to_string()).or_insert(ty);
            }
        }
        Stmt::Store { addr, width, .. } => {
            if let Expr::AddrOf(Location::Stack(_)) = addr {
                out.entry(addr_name(addr)).or_insert(CType::UInt(*width));
            }
        }
        _ => {}
    }
}

fn addr_name(e: &Expr) -> String {
    match e {
        Expr::AddrOf(l) => l.to_string(),
        _ => "?".into(),
    }
}

fn expr_type(e: &Expr, ptr: u8) -> CType {
    match e {
        Expr::AddrOf(_) => CType::Ptr,
        Expr::Load(_, w) => CType::UInt(*w),
        Expr::Const(c) if *c < 0 => CType::Int(4),
        Expr::Bin(op, _, _) if op.is_compare() => CType::Int(4),
        Expr::Bin(_, a, b) => {
            let (ta, tb) = (expr_type(a, ptr), expr_type(b, ptr));
            if ta == CType::Ptr || tb == CType::Ptr {
                CType::Ptr
            } else {
                CType::Int(ptr.min(8))
            }
        }
        _ => CType::Int(ptr.min(8)),
    }
}

/// Argument registers used with SSA version 0, i.e. read before any
/// definition dominates the use: the function's live-in parameters.
fn live_in_args(f: &IrFunction) -> BTreeSet<&'static str> {
    let mut read: BTreeSet<&'static str> = BTreeSet::new();
    let mut visit = |v: &Var| {
        if let (Location::Reg(r), 0) = (&v.loc, v.version) {
            read.insert(r);
        }
    };
    for b in &f.blocks {
        for s in &b.stmts {
            s.for_each_use(&mut visit);
        }
        b.term.for_each_use(&mut visit);
    }
    ARG_REGS_SYSV.into_iter().filter(|r| read.contains(r)).collect()
}
