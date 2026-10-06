//! SSA optimisation passes: constant folding, copy propagation and
//! dead-code elimination, iterated to a fixed point.

use std::collections::{HashMap, HashSet};

use crate::ir::*;

/// Maximum expression weight we are willing to inline during propagation.
const MAX_INLINE_WEIGHT: usize = 12;

/// Run all passes until nothing changes (bounded).
pub fn optimize(f: &mut IrFunction) {
    for _ in 0..16 {
        let mut changed = false;
        changed |= constant_fold(f);
        changed |= copy_propagate(f);
        changed |= dead_code_elim(f);
        if !changed {
            break;
        }
    }
}

/// Clean-up after SSA destruction: propagation restricted to single-definition
/// variables, then DCE.
pub fn post_destruct(f: &mut IrFunction) {
    for _ in 0..4 {
        let c = copy_propagate(f) | constant_fold(f) | dead_code_elim(f);
        if !c {
            break;
        }
    }
}

/// Fold a single expression bottom-up.
pub fn fold(e: &mut Expr) -> bool {
    let mut changed = match e {
        Expr::Bin(_, a, b) => fold(a) | fold(b),
        Expr::Un(_, a) | Expr::Load(a, _) => fold(a),
        _ => false,
    };
    let new = match e {
        Expr::Bin(op, a, b) => match (op, a.as_ref(), b.as_ref()) {
            (op, Expr::Const(x), Expr::Const(y)) => eval(*op, *x, *y).map(Expr::Const),
            (
                BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor | BinOp::Shl | BinOp::Shr | BinOp::Sar,
                _,
                Expr::Const(0),
            ) => Some((**a).clone()),
            (BinOp::Add | BinOp::Or | BinOp::Xor, Expr::Const(0), _) => Some((**b).clone()),
            (BinOp::Mul, _, Expr::Const(1)) => Some((**a).clone()),
            (BinOp::Mul | BinOp::And, _, Expr::Const(0)) => Some(Expr::Const(0)),
            (BinOp::Sub | BinOp::Xor, x, y) if x == y && !matches!(x, Expr::Load(..)) => Some(Expr::Const(0)),
            // (x + c1) + c2  =>  x + (c1 + c2)
            (BinOp::Add, Expr::Bin(BinOp::Add, x, c1), Expr::Const(c2)) => match c1.as_ref() {
                Expr::Const(c1) => Some(Expr::bin(
                    BinOp::Add,
                    (**x).clone(),
                    Expr::Const(c1.wrapping_add(*c2)),
                )),
                _ => None,
            },
            // x + (-c) => x - c  (readability)
            (BinOp::Add, x, Expr::Const(c)) if *c < 0 && *c != i64::MIN => {
                Some(Expr::bin(BinOp::Sub, x.clone(), Expr::Const(-c)))
            }
            // Comparisons of (a - b) against 0 => a ? b
            (op, Expr::Bin(BinOp::Sub, x, y), Expr::Const(0)) if op.is_compare() => {
                Some(Expr::bin(*op, (**x).clone(), (**y).clone()))
            }
            _ => None,
        },
        Expr::Un(UnOp::Neg, a) => match a.as_ref() {
            Expr::Const(x) => Some(Expr::Const(x.wrapping_neg())),
            _ => None,
        },
        Expr::Un(UnOp::Not, a) => match a.as_ref() {
            Expr::Const(x) => Some(Expr::Const(!x)),
            _ => None,
        },
        _ => None,
    };
    if let Some(n) = new {
        *e = n;
        changed = true;
    }
    changed
}

fn eval(op: BinOp, x: i64, y: i64) -> Option<i64> {
    use BinOp::*;
    let (ux, uy) = (x as u64, y as u64);
    Some(match op {
        Add => x.wrapping_add(y),
        Sub => x.wrapping_sub(y),
        Mul => x.wrapping_mul(y),
        UDiv => ux.checked_div(uy)? as i64,
        SDiv => x.checked_div(y)?,
        URem => ux.checked_rem(uy)? as i64,
        SRem => x.checked_rem(y)?,
        And => x & y,
        Or => x | y,
        Xor => x ^ y,
        Shl => x.wrapping_shl(y as u32),
        Shr => ux.wrapping_shr(y as u32) as i64,
        Sar => x.wrapping_shr(y as u32),
        Eq => (x == y) as i64,
        Ne => (x != y) as i64,
        Ult => (ux < uy) as i64,
        Ule => (ux <= uy) as i64,
        Ugt => (ux > uy) as i64,
        Uge => (ux >= uy) as i64,
        Slt => (x < y) as i64,
        Sle => (x <= y) as i64,
        Sgt => (x > y) as i64,
        Sge => (x >= y) as i64,
    })
}

/// Fold every expression in the function.
pub fn constant_fold(f: &mut IrFunction) -> bool {
    let mut changed = false;
    for b in &mut f.blocks {
        for s in &mut b.stmts {
            changed |= match s {
                Stmt::Assign(_, e) => fold(e),
                Stmt::Store { addr, value, .. } => fold(addr) | fold(value),
                Stmt::Call {
                    target: Callee::Indirect(e),
                    args,
                    ..
                } => fold(e) | args.iter_mut().fold(false, |c, a| fold(a) | c),
                _ => false,
            };
        }
        changed |= match &mut b.term {
            Terminator::Branch { cond, .. } => fold(cond),
            Terminator::Return(Some(e)) => fold(e),
            Terminator::Switch { value, .. } => fold(value),
            _ => false,
        };
        // Branch on a constant becomes an unconditional jump.
        if let Terminator::Branch {
            cond: Expr::Const(c),
            t,
            f: fb,
        } = b.term
        {
            b.term = Terminator::Jump(if c != 0 { t } else { fb });
            changed = true;
        }
    }
    if changed {
        f.recompute_preds();
    }
    changed
}

fn use_counts(f: &IrFunction) -> HashMap<Var, usize> {
    let mut uses: HashMap<Var, usize> = HashMap::new();
    for b in &f.blocks {
        for s in &b.stmts {
            s.for_each_use(&mut |v| *uses.entry(v.clone()).or_default() += 1);
        }
        b.term
            .for_each_use(&mut |v| *uses.entry(v.clone()).or_default() += 1);
    }
    uses
}

fn is_pure(e: &Expr) -> bool {
    match e {
        Expr::Load(..) | Expr::Unknown(_) => false,
        Expr::Bin(_, a, b) => is_pure(a) && is_pure(b),
        Expr::Un(_, a) => is_pure(a),
        _ => true,
    }
}

fn is_trivial(e: &Expr) -> bool {
    matches!(e, Expr::Const(_) | Expr::Var(_) | Expr::AddrOf(_))
}

/// Copy / expression propagation over SSA definitions.
///
/// * Trivial right-hand sides (constants, copies, stack addresses) are
///   propagated into every use.
/// * Small pure expressions are inlined into their single use.
/// * A `Load` is inlined into its single use only when that use is the
///   very next statement in the same block (no intervening stores).
pub fn copy_propagate(f: &mut IrFunction) -> bool {
    let uses = use_counts(f);
    let phi_used: HashSet<Var> = f
        .blocks
        .iter()
        .flat_map(|b| b.stmts.iter())
        .filter_map(|s| match s {
            Stmt::Phi(_, srcs) => Some(srcs.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>()),
            _ => None,
        })
        .flatten()
        .collect();

    // After SSA destruction a variable may have several definitions
    // (lowered φ copies); never propagate those or expressions reading them.
    let mut def_count: HashMap<Var, usize> = HashMap::new();
    for b in &f.blocks {
        for s in &b.stmts {
            if let Some(v) = s.def() {
                *def_count.entry(v.clone()).or_default() += 1;
            }
        }
    }
    let multi = |e: &Expr| {
        let mut m = false;
        e.for_each_var(&mut |w| m |= def_count.get(w).copied().unwrap_or(0) > 1);
        m
    };

    let mut defs: HashMap<Var, Expr> = HashMap::new();
    for b in &f.blocks {
        for (i, s) in b.stmts.iter().enumerate() {
            let Stmt::Assign(v, e) = s else { continue };
            if v.version == 0 || phi_used.contains(v) || def_count[v] > 1 || multi(e) {
                continue;
            }
            let n = uses.get(v).copied().unwrap_or(0);
            let ok = if is_trivial(e) {
                true
            } else if is_pure(e) {
                n == 1 && e.weight() <= MAX_INLINE_WEIGHT
            } else if matches!(e, Expr::Load(..)) && n == 1 {
                // Only when the next statement (or terminator) is the sole user.
                let mut used_next = false;
                match b.stmts.get(i + 1) {
                    Some(next) => next.for_each_use(&mut |u| used_next |= u == v),
                    None => b.term.for_each_use(&mut |u| used_next |= u == v),
                }
                used_next && !matches!(b.stmts.get(i + 1), Some(Stmt::Phi(..)))
            } else {
                false
            };
            if ok {
                defs.insert(v.clone(), e.clone());
            }
        }
    }
    if defs.is_empty() {
        return false;
    }

    // Resolve chains (a = b; b = c) with a bounded depth.
    let mut subst = |v: &Var| -> Option<Expr> {
        let mut e = defs.get(v)?.clone();
        for _ in 0..8 {
            let changed = e.substitute(&mut |w| defs.get(w).cloned());
            if !changed {
                break;
            }
        }
        Some(e)
    };

    let mut changed = false;
    for b in &mut f.blocks {
        for s in &mut b.stmts {
            if !matches!(s, Stmt::Phi(..)) {
                changed |= s.substitute_uses(&mut subst);
            }
        }
        changed |= b.term.substitute_uses(&mut subst);
    }
    changed
}

/// Remove definitions without uses and without side effects.
pub fn dead_code_elim(f: &mut IrFunction) -> bool {
    let mut changed = false;
    loop {
        let uses = use_counts(f);
        let mut round = false;
        for b in &mut f.blocks {
            let before = b.stmts.len();
            b.stmts.retain(|s| match s {
                Stmt::Assign(v, _) | Stmt::Phi(v, _) => v.version == 0 || uses.contains_key(v),
                _ => true,
            });
            round |= b.stmts.len() != before;
            for s in &mut b.stmts {
                if let Stmt::Call { ret: r @ Some(_), .. } = s {
                    if r.as_ref()
                        .is_some_and(|v| v.version != 0 && !uses.contains_key(v))
                    {
                        *r = None;
                        round = true;
                    }
                }
            }
        }
        if !round {
            break;
        }
        changed = true;
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_constants() {
        let mut e = Expr::bin(
            BinOp::Add,
            Expr::Const(2),
            Expr::bin(BinOp::Mul, Expr::Const(3), Expr::Const(4)),
        );
        assert!(fold(&mut e));
        assert_eq!(e, Expr::Const(14));
    }

    #[test]
    fn identity_simplifications() {
        let x = Expr::Var(Var::new(Location::Reg("rdi")));
        let mut e = Expr::bin(BinOp::Xor, x.clone(), Expr::Const(0));
        fold(&mut e);
        assert_eq!(e, x);
        let mut z = Expr::bin(BinOp::Sub, x.clone(), x);
        fold(&mut z);
        assert_eq!(z, Expr::Const(0));
    }
}
