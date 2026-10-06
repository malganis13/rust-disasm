//! Target-agnostic SSA intermediate representation (three-address code).

use std::collections::BTreeMap;
use std::fmt;

/// A storage location before SSA renaming.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Location {
    /// A machine register canonicalised to its 64-bit container (e.g. `eax` → `rax`).
    Reg(&'static str),
    /// A stack slot at `rsp`-relative or `rbp`-relative offset.
    Stack(i64),
    /// A unique temporary introduced by the lifter.
    Temp(u32),
    /// The synthetic flags pseudo-register holding the last compare operands.
    Flags,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::Reg(r) => write!(f, "{r}"),
            Location::Stack(o) if *o < 0 => write!(f, "var_{:x}", -o),
            Location::Stack(o) => write!(f, "arg_{o:x}"),
            Location::Temp(t) => write!(f, "t{t}"),
            Location::Flags => write!(f, "flags"),
        }
    }
}

/// An SSA variable: a [`Location`] plus a version. Version 0 means "unversioned".
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Var {
    pub loc: Location,
    pub version: u32,
}

impl Var {
    pub fn new(loc: Location) -> Self {
        Self { loc, version: 0 }
    }
}

impl fmt::Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.version == 0 {
            write!(f, "{}", self.loc)
        } else {
            write!(f, "{}_{}", self.loc, self.version)
        }
    }
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    URem,
    SRem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

impl BinOp {
    pub fn c_operator(self) -> &'static str {
        use BinOp::*;
        match self {
            Add => "+",
            Sub => "-",
            Mul => "*",
            UDiv | SDiv => "/",
            URem | SRem => "%",
            And => "&",
            Or => "|",
            Xor => "^",
            Shl => "<<",
            Shr | Sar => ">>",
            Eq => "==",
            Ne => "!=",
            Ult | Slt => "<",
            Ule | Sle => "<=",
            Ugt | Sgt => ">",
            Uge | Sge => ">=",
        }
    }

    pub fn is_compare(self) -> bool {
        use BinOp::*;
        matches!(self, Eq | Ne | Ult | Ule | Ugt | Uge | Slt | Sle | Sgt | Sge)
    }

    /// Logical negation of a comparison operator.
    pub fn negate_compare(self) -> Option<BinOp> {
        use BinOp::*;
        Some(match self {
            Eq => Ne,
            Ne => Eq,
            Ult => Uge,
            Uge => Ult,
            Ule => Ugt,
            Ugt => Ule,
            Slt => Sge,
            Sge => Slt,
            Sle => Sgt,
            Sgt => Sle,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
}

/// An SSA expression (pure, side-effect free).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Const(i64),
    Var(Var),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Un(UnOp, Box<Expr>),
    /// Dereference `*(base)` of the given byte width.
    Load(Box<Expr>, u8),
    /// Address of a stack slot.
    AddrOf(Location),
    /// Opaque value produced by an unmodelled instruction.
    Unknown(&'static str),
}

impl Expr {
    pub fn konst(v: i64) -> Self {
        Expr::Const(v)
    }
    pub fn var(v: Var) -> Self {
        Expr::Var(v)
    }
    pub fn bin(op: BinOp, l: Expr, r: Expr) -> Self {
        Expr::Bin(op, Box::new(l), Box::new(r))
    }
}

impl Expr {
    /// Visit every variable used by the expression.
    pub fn for_each_var(&self, f: &mut impl FnMut(&Var)) {
        match self {
            Expr::Var(v) => f(v),
            Expr::Bin(_, a, b) => {
                a.for_each_var(f);
                b.for_each_var(f);
            }
            Expr::Un(_, a) | Expr::Load(a, _) => a.for_each_var(f),
            Expr::Const(_) | Expr::AddrOf(_) | Expr::Unknown(_) => {}
        }
    }

    /// Replace variables in-place using `f`; returns `true` if anything changed.
    pub fn substitute(&mut self, f: &mut impl FnMut(&Var) -> Option<Expr>) -> bool {
        match self {
            Expr::Var(v) => match f(v) {
                Some(e) => {
                    *self = e;
                    true
                }
                None => false,
            },
            Expr::Bin(_, a, b) => {
                let x = a.substitute(f);
                b.substitute(f) | x
            }
            Expr::Un(_, a) | Expr::Load(a, _) => a.substitute(f),
            _ => false,
        }
    }

    /// Expression tree size (used to stop copy propagation from exploding).
    pub fn weight(&self) -> usize {
        match self {
            Expr::Bin(_, a, b) => 1 + a.weight() + b.weight(),
            Expr::Un(_, a) | Expr::Load(a, _) => 1 + a.weight(),
            _ => 1,
        }
    }
}

/// Call target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Callee {
    Direct(u64),
    Indirect(Expr),
}

/// An IR statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    Assign(Var, Expr),
    Store {
        addr: Expr,
        value: Expr,
        width: u8,
    },
    Call {
        target: Callee,
        args: Vec<Expr>,
        ret: Option<Var>,
    },
    /// SSA φ-node: `dst = φ(src from pred_block, ...)`.
    Phi(Var, Vec<(usize, Var)>),
    /// Unmodelled instruction kept verbatim.
    Asm(String),
}

impl Stmt {
    pub fn def(&self) -> Option<&Var> {
        match self {
            Stmt::Assign(v, _) | Stmt::Phi(v, _) => Some(v),
            Stmt::Call { ret, .. } => ret.as_ref(),
            _ => None,
        }
    }

    pub fn def_mut(&mut self) -> Option<&mut Var> {
        match self {
            Stmt::Assign(v, _) | Stmt::Phi(v, _) => Some(v),
            Stmt::Call { ret, .. } => ret.as_mut(),
            _ => None,
        }
    }

    /// Statements that must not be removed even if their result is unused.
    pub fn has_side_effects(&self) -> bool {
        matches!(self, Stmt::Store { .. } | Stmt::Call { .. } | Stmt::Asm(_))
    }

    /// Visit every non-φ variable use.
    pub fn for_each_use(&self, f: &mut impl FnMut(&Var)) {
        match self {
            Stmt::Assign(_, e) => e.for_each_var(f),
            Stmt::Store { addr, value, .. } => {
                addr.for_each_var(f);
                value.for_each_var(f);
            }
            Stmt::Call { target, args, .. } => {
                if let Callee::Indirect(e) = target {
                    e.for_each_var(f);
                }
                args.iter().for_each(|a| a.for_each_var(f));
            }
            Stmt::Phi(_, srcs) => srcs.iter().for_each(|(_, v)| f(v)),
            Stmt::Asm(_) => {}
        }
    }

    /// Substitute variable uses (φ sources are left untouched).
    pub fn substitute_uses(&mut self, f: &mut impl FnMut(&Var) -> Option<Expr>) -> bool {
        match self {
            Stmt::Assign(_, e) => e.substitute(f),
            Stmt::Store { addr, value, .. } => {
                let a = addr.substitute(f);
                value.substitute(f) | a
            }
            Stmt::Call { target, args, .. } => {
                let mut c = false;
                if let Callee::Indirect(e) = target {
                    c |= e.substitute(f);
                }
                for a in args {
                    c |= a.substitute(f);
                }
                c
            }
            _ => false,
        }
    }
}

/// Block terminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    Jump(usize),
    Branch {
        cond: Expr,
        t: usize,
        f: usize,
    },
    Switch {
        value: Expr,
        targets: Vec<usize>,
    },
    Return(Option<Expr>),
    /// Leaves the function without returning (tail call, trap, unresolved jump).
    Exit,
}

impl Terminator {
    pub fn successors(&self) -> Vec<usize> {
        match self {
            Terminator::Jump(b) => vec![*b],
            Terminator::Branch { t, f, .. } => vec![*t, *f],
            Terminator::Switch { targets, .. } => targets.clone(),
            Terminator::Return(_) | Terminator::Exit => vec![],
        }
    }

    pub fn for_each_use(&self, f: &mut impl FnMut(&Var)) {
        match self {
            Terminator::Branch { cond, .. } => cond.for_each_var(f),
            Terminator::Switch { value, .. } => value.for_each_var(f),
            Terminator::Return(Some(e)) => e.for_each_var(f),
            _ => {}
        }
    }

    pub fn substitute_uses(&mut self, f: &mut impl FnMut(&Var) -> Option<Expr>) -> bool {
        match self {
            Terminator::Branch { cond, .. } => cond.substitute(f),
            Terminator::Switch { value, .. } => value.substitute(f),
            Terminator::Return(Some(e)) => e.substitute(f),
            _ => false,
        }
    }
}

/// An IR basic block.
#[derive(Debug, Clone)]
pub struct Block {
    pub addr: u64,
    pub stmts: Vec<Stmt>,
    pub term: Terminator,
    pub preds: Vec<usize>,
}

/// A lifted function.
#[derive(Debug, Clone)]
pub struct IrFunction {
    pub entry_addr: u64,
    pub blocks: Vec<Block>,
    pub entry: usize,
    /// Names of call targets resolved by the lifter (addr → name).
    pub callee_names: BTreeMap<u64, String>,
}

impl IrFunction {
    pub fn successors(&self, b: usize) -> Vec<usize> {
        self.blocks[b].term.successors()
    }

    pub fn recompute_preds(&mut self) {
        for b in &mut self.blocks {
            b.preds.clear();
        }
        for i in 0..self.blocks.len() {
            for s in self.blocks[i].term.successors() {
                if !self.blocks[s].preds.contains(&i) {
                    self.blocks[s].preds.push(i);
                }
            }
        }
    }

    /// Reverse post-order from the entry block.
    pub fn rpo(&self) -> Vec<usize> {
        let n = self.blocks.len();
        let mut seen = vec![false; n];
        let mut post = Vec::with_capacity(n);
        let mut stack = vec![(self.entry, 0usize)];
        seen[self.entry] = true;
        while let Some((b, i)) = stack.pop() {
            let succ = self.successors(b);
            if i < succ.len() {
                stack.push((b, i + 1));
                let s = succ[i];
                if !seen[s] {
                    seen[s] = true;
                    stack.push((s, 0));
                }
            } else {
                post.push(b);
            }
        }
        post.reverse();
        post
    }

    /// Immediate dominators (Cooper–Harvey–Kennedy). `idom[entry] == entry`;
    /// unreachable blocks get `usize::MAX`.
    pub fn idoms(&self) -> Vec<usize> {
        let rpo = self.rpo();
        let mut order = vec![usize::MAX; self.blocks.len()];
        for (i, &b) in rpo.iter().enumerate() {
            order[b] = i;
        }
        let mut idom = vec![usize::MAX; self.blocks.len()];
        idom[self.entry] = self.entry;
        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                let mut new = usize::MAX;
                for &p in &self.blocks[b].preds {
                    if idom[p] == usize::MAX {
                        continue;
                    }
                    new = if new == usize::MAX {
                        p
                    } else {
                        intersect(&idom, &order, p, new)
                    };
                }
                if new != usize::MAX && idom[b] != new {
                    idom[b] = new;
                    changed = true;
                }
            }
        }
        idom
    }

    /// `true` if `a` dominates `b`.
    pub fn dominates(idom: &[usize], a: usize, mut b: usize) -> bool {
        loop {
            if a == b {
                return true;
            }
            let p = idom[b];
            if p == usize::MAX || p == b {
                return false;
            }
            b = p;
        }
    }
}

fn intersect(idom: &[usize], order: &[usize], mut a: usize, mut b: usize) -> usize {
    while a != b {
        while order[a] > order[b] {
            a = idom[a];
        }
        while order[b] > order[a] {
            b = idom[b];
        }
    }
    a
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Const(c) if (-9..=9).contains(c) => write!(f, "{c}"),
            Expr::Const(c) if *c < 0 => write!(f, "-{:#x}", c.unsigned_abs()),
            Expr::Const(c) => write!(f, "{c:#x}"),
            Expr::Var(v) => write!(f, "{v}"),
            Expr::Bin(op, a, b) => write!(f, "({a} {} {b})", op.c_operator()),
            Expr::Un(UnOp::Neg, a) => write!(f, "-{a}"),
            Expr::Un(UnOp::Not, a) => write!(f, "~{a}"),
            Expr::Load(a, w) => write!(f, "*({}*){a}", width_ctype(*w)),
            Expr::AddrOf(l) => write!(f, "&{l}"),
            Expr::Unknown(s) => write!(f, "__{s}()"),
        }
    }
}

/// C integer type name for a byte width.
pub fn width_ctype(w: u8) -> &'static str {
    match w {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        _ => "uint64_t",
    }
}
