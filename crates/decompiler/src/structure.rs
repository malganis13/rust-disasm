//! Control-flow structuring: recover `if`/`else`, `while` and `do`/`while`
//! from the IR CFG using an interval / dominator-guided scheme inspired by
//! the Relooper and "No More Gotos" algorithms. Irreducible or unrecognised
//! control flow degrades gracefully to labelled blocks with `goto`.

use std::collections::BTreeSet;

use crate::ir::*;

/// A structured statement in the recovered AST.
#[derive(Debug, Clone)]
pub enum CStmt {
    /// Straight-line IR statements copied from one basic block.
    Block(Vec<Stmt>),
    If {
        cond: Expr,
        then: Vec<CStmt>,
        els: Vec<CStmt>,
    },
    While {
        cond: Expr,
        body: Vec<CStmt>,
    },
    DoWhile {
        body: Vec<CStmt>,
        cond: Expr,
    },
    Switch {
        value: Expr,
        cases: Vec<(usize, Vec<CStmt>)>,
    },
    Return(Option<Expr>),
    Break,
    Continue,
    Goto(u64),
    Label(u64),
}

/// Negate a boolean condition for `if`/loop inversion.
fn negate(e: &Expr) -> Expr {
    if let Expr::Bin(op, a, b) = e {
        if let Some(n) = op.negate_compare() {
            return Expr::bin(n, (**a).clone(), (**b).clone());
        }
    }
    Expr::Un(UnOp::Not, Box::new(e.clone()))
}

struct Structurer<'a> {
    f: &'a IrFunction,
    idom: Vec<usize>,
    loop_header: Vec<Option<usize>>,
    loop_follow: Vec<Option<usize>>,
    visited: BTreeSet<usize>,
    emit_label: BTreeSet<u64>,
    /// Active loop stack: (header, follow, body).
    loops: Vec<(usize, Option<usize>, BTreeSet<usize>)>,
    loop_bodies: Vec<Option<BTreeSet<usize>>>,
}

/// Structure a lifted function into an AST.
///
/// Runs twice: the first pass discovers which blocks are `goto` targets so the
/// second pass can emit their labels.
pub fn structure(f: &IrFunction) -> Vec<CStmt> {
    let first = structure_pass(f, BTreeSet::new());
    let mut labels = BTreeSet::new();
    collect_gotos(&first.0, &mut labels);
    if labels.is_empty() {
        return first.0;
    }
    structure_pass(f, labels).0
}

fn collect_gotos(stmts: &[CStmt], out: &mut BTreeSet<u64>) {
    for s in stmts {
        match s {
            CStmt::Goto(a) => {
                out.insert(*a);
            }
            CStmt::If { then, els, .. } => {
                collect_gotos(then, out);
                collect_gotos(els, out);
            }
            CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => collect_gotos(body, out),
            CStmt::Switch { cases, .. } => cases.iter().for_each(|(_, b)| collect_gotos(b, out)),
            _ => {}
        }
    }
}

fn structure_pass(f: &IrFunction, labels: BTreeSet<u64>) -> (Vec<CStmt>, ()) {
    let idom = f.idoms();
    let n = f.blocks.len();
    let mut s = Structurer {
        f,
        idom,
        loop_header: vec![None; n],
        loop_follow: vec![None; n],
        visited: BTreeSet::new(),
        emit_label: labels,
        loops: Vec::new(),
        loop_bodies: vec![None; n],
    };
    s.detect_loops();
    let mut out = Vec::new();
    s.structure_region(f.entry, None, &mut out);
    (out, ())
}

/// Maximum statements in a terminal block we are willing to duplicate.
const TAIL_DUP_MAX: usize = 6;

impl Structurer<'_> {
    /// Identify natural loops from back edges (`latch -> header`, header
    /// dominates latch) and compute each loop's follow block.
    fn detect_loops(&mut self) {
        for b in 0..self.f.blocks.len() {
            for succ in self.f.successors(b) {
                if IrFunction::dominates(&self.idom, succ, b) {
                    // succ is a loop header, b is a latch.
                    let body = self.loop_body(succ, b);
                    for &n in &body {
                        if self.loop_header[n].is_none() {
                            self.loop_header[n] = Some(succ);
                        }
                    }
                    self.loop_header[succ] = Some(succ);
                    // Follow = a successor of the header or latch outside the body.
                    let follow = self
                        .f
                        .successors(succ)
                        .into_iter()
                        .chain(self.f.successors(b))
                        .find(|t| !body.contains(t));
                    self.loop_follow[succ] = follow;
                    match &mut self.loop_bodies[succ] {
                        Some(existing) => existing.extend(body),
                        slot @ None => *slot = Some(body),
                    }
                }
            }
        }
    }

    fn loop_body(&self, header: usize, latch: usize) -> BTreeSet<usize> {
        let mut body = BTreeSet::from([header]);
        let mut stack = vec![latch];
        while let Some(x) = stack.pop() {
            if body.insert(x) {
                stack.extend(self.f.blocks[x].preds.iter().copied());
            }
        }
        body
    }

    fn block_stmts(&self, b: usize) -> CStmt {
        CStmt::Block(self.f.blocks[b].stmts.clone())
    }

    /// Structure the region starting at `b`, stopping when reaching `stop`
    /// (a follow block) or a block outside the current loop.
    fn structure_region(&mut self, mut b: usize, stop: Option<usize>, out: &mut Vec<CStmt>) {
        loop {
            if Some(b) == stop {
                return;
            }
            if let Some((h, follow, _)) = self.loops.last() {
                if b == *h {
                    out.push(CStmt::Continue);
                    return;
                }
                if Some(b) == *follow {
                    out.push(CStmt::Break);
                    return;
                }
            }
            if self.visited.contains(&b) {
                // Tail duplication: re-emit small terminal blocks instead of `goto`.
                let blk = &self.f.blocks[b];
                if blk.stmts.len() <= TAIL_DUP_MAX {
                    match &blk.term {
                        Terminator::Return(e) => {
                            out.push(self.block_stmts(b));
                            out.push(CStmt::Return(e.clone()));
                            return;
                        }
                        Terminator::Exit => {
                            out.push(self.block_stmts(b));
                            return;
                        }
                        _ => {}
                    }
                }
                out.push(CStmt::Goto(blk.addr));
                return;
            }

            // Loop header starting a new loop (only when we reach it top-down).
            if self.loop_header[b] == Some(b) && !self.visited.contains(&b) {
                b = match self.emit_loop(b, out) {
                    Some(follow) => follow,
                    None => return,
                };
                continue;
            }

            self.visited.insert(b);
            if self.emit_label.contains(&self.f.blocks[b].addr) {
                out.push(CStmt::Label(self.f.blocks[b].addr));
            }

            match self.f.blocks[b].term.clone() {
                Terminator::Return(e) => {
                    out.push(self.block_stmts(b));
                    out.push(CStmt::Return(e));
                    return;
                }
                Terminator::Exit => {
                    out.push(self.block_stmts(b));
                    return;
                }
                Terminator::Jump(t) => {
                    out.push(self.block_stmts(b));
                    b = t;
                }
                Terminator::Switch { value, targets } => {
                    out.push(self.block_stmts(b));
                    let follow = self.idom_follow(b).or(stop);
                    let mut cases = Vec::new();
                    for (i, t) in targets.into_iter().enumerate() {
                        let mut body = Vec::new();
                        self.structure_region(t, follow, &mut body);
                        body.push(CStmt::Break);
                        cases.push((i, body));
                    }
                    out.push(CStmt::Switch { value, cases });
                    match follow {
                        Some(f) => b = f,
                        None => return,
                    }
                }
                Terminator::Branch { cond, t, f: fb } => {
                    out.push(self.block_stmts(b));
                    let follow = self.branch_follow(b, t, fb).or(stop);
                    let (cond, t, fb) = self.orient(cond, t, fb, follow);

                    let mut then = Vec::new();
                    if Some(t) != follow {
                        self.structure_region(t, follow, &mut then);
                    }
                    let mut els = Vec::new();
                    if Some(fb) != follow {
                        self.structure_region(fb, follow, &mut els);
                    }
                    out.push(CStmt::If { cond, then, els });
                    match follow {
                        Some(f) => b = f,
                        None => return,
                    }
                }
            }
        }
    }

    /// Emit a loop headed at `h`; returns the follow block to continue with.
    fn emit_loop(&mut self, h: usize, out: &mut Vec<CStmt>) -> Option<usize> {
        let follow = self.loop_follow[h];
        let body_set = self.loop_bodies[h].clone().unwrap_or_default();
        self.loops.push((h, follow, body_set));
        self.visited.insert(h);

        let mut body = vec![self.block_stmts(h)];
        match self.f.blocks[h].term.clone() {
            Terminator::Branch { cond, t, f } if Some(t) == follow || Some(f) == follow => {
                let (exit_cond, inside) = if Some(t) == follow {
                    (cond, f)
                } else {
                    (negate(&cond), t)
                };
                body.push(CStmt::If {
                    cond: exit_cond,
                    then: vec![CStmt::Break],
                    els: vec![],
                });
                self.structure_region(inside, None, &mut body);
            }
            Terminator::Jump(t) => self.structure_region(t, None, &mut body),
            Terminator::Return(e) => body.push(CStmt::Return(e)),
            Terminator::Exit => {}
            Terminator::Branch { cond, t, f } => {
                let mut then = Vec::new();
                self.structure_region(t, None, &mut then);
                let mut els = Vec::new();
                self.structure_region(f, None, &mut els);
                body.push(CStmt::If { cond, then, els });
            }
            Terminator::Switch { value, targets } => {
                let mut cases = Vec::new();
                for (i, t) in targets.into_iter().enumerate() {
                    let mut c = Vec::new();
                    self.structure_region(t, None, &mut c);
                    cases.push((i, c));
                }
                body.push(CStmt::Switch { value, cases });
            }
        }
        self.loops.pop();
        out.push(simplify_loop(body));
        follow
    }

    fn reachable(&self, from: usize, to: usize) -> bool {
        let mut seen = BTreeSet::new();
        let mut stack = vec![from];
        while let Some(x) = stack.pop() {
            if x == to {
                return true;
            }
            if seen.insert(x) {
                stack.extend(self.f.successors(x));
            }
        }
        false
    }

    fn in_current_loop(&self, b: usize) -> bool {
        match self.loops.last() {
            Some((h, f, body)) => b != *h && Some(b) != *f && body.contains(&b),
            None => true,
        }
    }

    /// Follow (join) block of a two-way conditional at `b`.
    fn branch_follow(&self, b: usize, t: usize, f: usize) -> Option<usize> {
        if t == f {
            return Some(t);
        }
        // if-then: one arm flows into the other.
        if self.in_current_loop(f) && self.reachable(t, f) && !self.reachable(f, t) {
            return Some(f);
        }
        if self.in_current_loop(t) && self.reachable(f, t) && !self.reachable(t, f) {
            return Some(t);
        }
        // if-then-else: nearest join point dominated by b.
        self.idom_follow(b)
            .filter(|&j| j != t && j != f || self.f.blocks[j].preds.len() > 1)
    }

    /// Nearest block immediately dominated by `b` with ≥ 2 predecessors.
    fn idom_follow(&self, b: usize) -> Option<usize> {
        let rpo = self.f.rpo();
        rpo.into_iter().find(|&c| {
            c != b
                && self.idom[c] == b
                && self.f.blocks[c].preds.len() >= 2
                && self.in_current_loop(c)
                && !self.visited.contains(&c)
        })
    }

    /// Orient a branch so the `then` arm is the non-follow successor.
    fn orient(&self, cond: Expr, t: usize, f: usize, follow: Option<usize>) -> (Expr, usize, usize) {
        if Some(t) == follow {
            (negate(&cond), f, t)
        } else {
            (cond, t, f)
        }
    }
}

/// Turn `while(1){ [empty]; if(c) break; rest }` into `while(!c){ rest }`
/// and `while(1){ body; if(c) continue; break; }` into `do { body } while(c)`.
fn simplify_loop(mut body: Vec<CStmt>) -> CStmt {
    body.retain(|s| !matches!(s, CStmt::Block(v) if v.is_empty()));

    // while (!c)
    if let Some(CStmt::If { cond, then, els }) = body.first() {
        if els.is_empty() && matches!(then.as_slice(), [CStmt::Break]) {
            let cond = negate(cond);
            let mut rest: Vec<CStmt> = body.drain(1..).collect();
            if matches!(rest.last(), Some(CStmt::Continue)) {
                rest.pop();
            }
            return CStmt::While { cond, body: rest };
        }
    }
    // do { } while (c)
    if let Some(CStmt::If { cond, then, els }) = body.last() {
        let cont = matches!(then.as_slice(), [CStmt::Continue]);
        let brk = matches!(els.as_slice(), [CStmt::Break] | []);
        if cont && brk {
            let cond = cond.clone();
            body.pop();
            return CStmt::DoWhile { body, cond };
        }
        let cont_e = matches!(els.as_slice(), [CStmt::Continue]);
        let brk_t = matches!(then.as_slice(), [CStmt::Break]);
        if cont_e && brk_t {
            let cond = negate(cond);
            body.pop();
            return CStmt::DoWhile { body, cond };
        }
    }
    if matches!(body.last(), Some(CStmt::Continue)) {
        body.pop();
    }
    CStmt::While {
        cond: Expr::Const(1),
        body,
    }
}
