//! Minimal pruned SSA construction and destruction.
//!
//! Uses the classic dominance-frontier algorithm (Cytron et al.) to place
//! φ-functions, then renames definitions and uses. Memory (`Store`/`Load`)
//! is intentionally left out of SSA — only register and stack-slot
//! [`Location`]s are versioned.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::*;

fn is_ssa_loc(loc: &Location) -> bool {
    matches!(
        loc,
        Location::Reg(_) | Location::Stack(_) | Location::Temp(_) | Location::Flags
    )
}

/// Dominance frontiers for every block.
fn dominance_frontiers(f: &IrFunction, idom: &[usize]) -> Vec<BTreeSet<usize>> {
    let mut df = vec![BTreeSet::new(); f.blocks.len()];
    for b in 0..f.blocks.len() {
        if f.blocks[b].preds.len() < 2 {
            continue;
        }
        for &p in &f.blocks[b].preds {
            let mut runner = p;
            while runner != usize::MAX && runner != idom[b] {
                df[runner].insert(b);
                if idom[runner] == runner {
                    break;
                }
                runner = idom[runner];
            }
        }
    }
    df
}

/// Construct pruned SSA in place.
pub fn construct(f: &mut IrFunction) {
    let idom = f.idoms();
    let df = dominance_frontiers(f, &idom);

    // Collect definition sites per location.
    let mut defsites: BTreeMap<Location, BTreeSet<usize>> = BTreeMap::new();
    let mut all_locs: BTreeSet<Location> = BTreeSet::new();
    for (b, blk) in f.blocks.iter().enumerate() {
        for s in &blk.stmts {
            if let Some(v) = s.def() {
                if is_ssa_loc(&v.loc) {
                    defsites.entry(v.loc.clone()).or_default().insert(b);
                    all_locs.insert(v.loc.clone());
                }
            }
        }
    }

    // Place φ-functions.
    for (loc, sites) in &defsites {
        let mut worklist: Vec<usize> = sites.iter().copied().collect();
        let mut has_phi: BTreeSet<usize> = BTreeSet::new();
        let mut defined: BTreeSet<usize> = sites.clone();
        while let Some(x) = worklist.pop() {
            for &y in &df[x] {
                if has_phi.insert(y) {
                    let preds = f.blocks[y].preds.clone();
                    let srcs = preds.into_iter().map(|p| (p, Var::new(loc.clone()))).collect();
                    f.blocks[y]
                        .stmts
                        .insert(0, Stmt::Phi(Var::new(loc.clone()), srcs));
                    if defined.insert(y) {
                        worklist.push(y);
                    }
                }
            }
        }
    }

    // Rename.
    let idom_children = children(&idom);
    let mut counter: BTreeMap<Location, u32> = BTreeMap::new();
    let mut stacks: BTreeMap<Location, Vec<u32>> = all_locs.iter().map(|l| (l.clone(), vec![])).collect();
    rename(f, f.entry, &idom_children, &mut counter, &mut stacks);
}

fn children(idom: &[usize]) -> Vec<Vec<usize>> {
    let mut ch = vec![Vec::new(); idom.len()];
    for b in 0..idom.len() {
        if idom[b] != usize::MAX && idom[b] != b {
            ch[idom[b]].push(b);
        }
    }
    ch
}

fn fresh(
    loc: &Location,
    counter: &mut BTreeMap<Location, u32>,
    stacks: &mut BTreeMap<Location, Vec<u32>>,
) -> u32 {
    let c = counter.entry(loc.clone()).or_insert(0);
    *c += 1;
    let v = *c;
    stacks.entry(loc.clone()).or_default().push(v);
    v
}

fn top(loc: &Location, stacks: &BTreeMap<Location, Vec<u32>>) -> u32 {
    stacks.get(loc).and_then(|s| s.last().copied()).unwrap_or(0)
}

fn rename(
    f: &mut IrFunction,
    b: usize,
    children: &[Vec<usize>],
    counter: &mut BTreeMap<Location, u32>,
    stacks: &mut BTreeMap<Location, Vec<u32>>,
) {
    let mut pushed: Vec<Location> = Vec::new();

    let mut stmts = std::mem::take(&mut f.blocks[b].stmts);
    for s in &mut stmts {
        if !matches!(s, Stmt::Phi(..)) {
            s.substitute_uses(&mut |v| {
                if is_ssa_loc(&v.loc) {
                    Some(Expr::Var(Var {
                        loc: v.loc.clone(),
                        version: top(&v.loc, stacks),
                    }))
                } else {
                    None
                }
            });
        }
        if let Some(d) = s.def_mut() {
            if is_ssa_loc(&d.loc) {
                let v = fresh(&d.loc, counter, stacks);
                pushed.push(d.loc.clone());
                d.version = v;
            }
        }
    }
    let mut term = f.blocks[b].term.clone();
    term.substitute_uses(&mut |v| {
        if is_ssa_loc(&v.loc) {
            Some(Expr::Var(Var {
                loc: v.loc.clone(),
                version: top(&v.loc, stacks),
            }))
        } else {
            None
        }
    });
    f.blocks[b].stmts = stmts;
    f.blocks[b].term = term;

    // Fill φ-operands in successors.
    let succs = f.successors(b);
    for s in succs {
        let preds = f.blocks[s].preds.clone();
        let j = preds.iter().position(|&p| p == b).unwrap_or(0);
        for st in &mut f.blocks[s].stmts {
            if let Stmt::Phi(_, srcs) = st {
                if let Some(entry) = srcs.get_mut(j) {
                    entry.1.version = top(&entry.1.loc, stacks);
                }
            }
        }
    }

    for &c in &children[b] {
        rename(f, c, children, counter, stacks);
    }
    for loc in pushed {
        if let Some(st) = stacks.get_mut(&loc) {
            st.pop();
        }
    }
}

/// Destruct SSA by lowering each φ-node into copies at the end of its
/// predecessor blocks (`dst = src`), then removing the φ-nodes.
/// Trivial self-copies are elided.
pub fn destruct(f: &mut IrFunction) {
    let mut copies: Vec<(usize, Stmt)> = Vec::new();
    for blk in &f.blocks {
        for st in &blk.stmts {
            if let Stmt::Phi(dst, srcs) = st {
                for (p, src) in srcs {
                    if src != dst && src.version != 0 {
                        copies.push((*p, Stmt::Assign(dst.clone(), Expr::Var(src.clone()))));
                    }
                }
            }
        }
    }
    for blk in &mut f.blocks {
        blk.stmts.retain(|s| !matches!(s, Stmt::Phi(..)));
    }
    for (p, c) in copies {
        if let Some(b) = f.blocks.get_mut(p) {
            b.stmts.push(c);
        }
    }
}
