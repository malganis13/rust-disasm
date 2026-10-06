//! Lift decoded x86/x64 instructions into the [`crate::ir`] three-address form.
//!
//! This is a pragmatic subset lifter: it models the common integer, memory,
//! stack and control-flow instructions precisely and falls back to an opaque
//! `Asm` / `Unknown` representation for everything else, so the pipeline keeps
//! working on real binaries without pretending to be a full CPU emulator.

use std::collections::BTreeMap;

use disasm_core::{analysis::Function, disasm::Flow};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::context::Context;
use crate::ir::*;
use crate::DecompileError;

/// Canonicalise a register to its 64-bit container name.
fn reg_name(r: Register) -> Option<&'static str> {
    use Register::*;
    Some(match r {
        RAX | EAX | AX | AL | AH => "rax",
        RBX | EBX | BX | BL | BH => "rbx",
        RCX | ECX | CX | CL | CH => "rcx",
        RDX | EDX | DX | DL | DH => "rdx",
        RSI | ESI | SI | SIL => "rsi",
        RDI | EDI | DI | DIL => "rdi",
        RBP | EBP | BP | BPL => "rbp",
        RSP | ESP | SP | SPL => "rsp",
        R8 | R8D | R8W | R8L => "r8",
        R9 | R9D | R9W | R9L => "r9",
        R10 | R10D | R10W | R10L => "r10",
        R11 | R11D | R11W | R11L => "r11",
        R12 | R12D | R12W | R12L => "r12",
        R13 | R13D | R13W | R13L => "r13",
        R14 | R14D | R14W | R14L => "r14",
        R15 | R15D | R15W | R15L => "r15",
        _ => return Option::None,
    })
}

fn reg_width(r: Register) -> u8 {
    (r.size() as u8).clamp(1, 8)
}

struct Lifter {
    bits: u32,
}

impl Lifter {
    fn reg_loc(&self, r: Register) -> Option<Location> {
        reg_name(r).map(Location::Reg)
    }

    /// Model `[base + index*scale + disp]` as an address expression.
    fn mem_addr(&self, insn: &Instruction) -> Expr {
        if insn.is_ip_rel_memory_operand() {
            return Expr::Const(insn.ip_rel_memory_address() as i64);
        }
        let base = insn.memory_base();
        let index = insn.memory_index();
        let disp = insn.memory_displacement64() as i64;

        // Pure stack slot: [rbp - k] or [rsp + k].
        if index == Register::None
            && matches!(
                base,
                Register::RBP | Register::RSP | Register::EBP | Register::ESP
            )
        {
            return Expr::AddrOf(Location::Stack(disp));
        }

        let mut e = match self.reg_loc(base) {
            Some(l) => Expr::var(Var::new(l)),
            None => Expr::Const(0),
        };
        if index != Register::None {
            if let Some(l) = self.reg_loc(index) {
                let idx = Expr::var(Var::new(l));
                let scaled = match insn.memory_index_scale() {
                    1 => idx,
                    s => Expr::bin(BinOp::Mul, idx, Expr::Const(i64::from(s))),
                };
                e = if matches!(e, Expr::Const(0)) {
                    scaled
                } else {
                    Expr::bin(BinOp::Add, e, scaled)
                };
            }
        }
        if disp != 0 || matches!(e, Expr::Const(0)) {
            e = Expr::bin(BinOp::Add, e, Expr::Const(disp));
        }
        e
    }

    /// Read operand `op` as an expression.
    fn read(&self, insn: &Instruction, op: u32) -> Expr {
        match insn.op_kind(op) {
            OpKind::Register => match self.reg_loc(insn.op_register(op)) {
                Some(l) => Expr::var(Var::new(l)),
                None => Expr::Unknown("reg"),
            },
            OpKind::Memory => match self.mem_addr(insn) {
                Expr::AddrOf(slot) => Expr::var(Var::new(slot)),
                a => Expr::Load(Box::new(a), mem_width(insn)),
            },
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => Expr::Const(insn.immediate(op) as i64),
            _ => Expr::Unknown("op"),
        }
    }

    /// Emit a write of `value` into operand `op`.
    fn write(&self, insn: &Instruction, op: u32, value: Expr, out: &mut Vec<Stmt>) {
        match insn.op_kind(op) {
            OpKind::Register => {
                let r = insn.op_register(op);
                if let Some(l) = self.reg_loc(r) {
                    // 32-bit writes zero-extend on x64; 8/16-bit writes merge.
                    let v = match reg_width(r) {
                        1 if matches!(r, Register::AH | Register::BH | Register::CH | Register::DH) => {
                            Expr::Unknown("partial_reg")
                        }
                        4 if self.bits == 64 => Expr::bin(BinOp::And, value, Expr::Const(0xffff_ffff)),
                        _ => value,
                    };
                    out.push(Stmt::Assign(Var::new(l), simplify_mask(v)));
                }
            }
            OpKind::Memory => match self.mem_addr(insn) {
                Expr::AddrOf(slot) => out.push(Stmt::Assign(Var::new(slot), value)),
                addr => out.push(Stmt::Store {
                    addr,
                    value,
                    width: mem_width(insn),
                }),
            },
            _ => out.push(Stmt::Asm(format!("{insn}"))),
        }
    }
}

fn mem_width(insn: &Instruction) -> u8 {
    (insn.memory_size().size() as u8).clamp(1, 8)
}

/// `(x & 0xffffffff)` where `x` is already a 32-bit constant collapses to `x`.
fn simplify_mask(e: Expr) -> Expr {
    if let Expr::Bin(BinOp::And, a, b) = &e {
        if let (Expr::Const(c), Expr::Const(0xffff_ffff)) = (a.as_ref(), b.as_ref()) {
            return Expr::Const(*c & 0xffff_ffff);
        }
    }
    e
}

/// Lift one instruction into zero or more statements plus an optional
/// `(compare_lhs, compare_rhs)` recorded for a following conditional jump.
fn lift_insn(l: &Lifter, insn: &Instruction, stmts: &mut Vec<Stmt>, flags: &mut Option<(Expr, Expr)>) {
    use Mnemonic::*;
    let m = insn.mnemonic();
    let bin = |op: BinOp, l: &Lifter, insn: &Instruction, stmts: &mut Vec<Stmt>| {
        let lhs = l.read(insn, 0);
        let rhs = l.read(insn, 1);
        l.write(insn, 0, Expr::bin(op, lhs, rhs), stmts);
    };
    match m {
        Nop | Endbr64 | Endbr32 | Fnop | Pause => {}
        Mov | Movzx | Movsx | Movsxd | Movaps | Movups | Movdqa | Movdqu | Lea => {
            if m == Lea {
                let addr = l.mem_addr(insn);
                let v = addr;
                l.write(insn, 0, v, stmts);
            } else {
                let v = l.read(insn, 1);
                l.write(insn, 0, v, stmts);
            }
        }
        Add => bin(BinOp::Add, l, insn, stmts),
        Sub => bin(BinOp::Sub, l, insn, stmts),
        Imul if insn.op_count() == 2 => bin(BinOp::Mul, l, insn, stmts),
        And => bin(BinOp::And, l, insn, stmts),
        Or => bin(BinOp::Or, l, insn, stmts),
        Shl | Sal => bin(BinOp::Shl, l, insn, stmts),
        Shr => bin(BinOp::Shr, l, insn, stmts),
        Sar => bin(BinOp::Sar, l, insn, stmts),
        Xor => {
            // xor reg,reg is the idiomatic zero.
            if insn.op0_kind() == OpKind::Register
                && insn.op1_kind() == OpKind::Register
                && insn.op_register(0) == insn.op_register(1)
            {
                l.write(insn, 0, Expr::Const(0), stmts);
            } else {
                bin(BinOp::Xor, l, insn, stmts);
            }
        }
        Inc => l.write(
            insn,
            0,
            Expr::bin(BinOp::Add, l.read(insn, 0), Expr::Const(1)),
            stmts,
        ),
        Dec => l.write(
            insn,
            0,
            Expr::bin(BinOp::Sub, l.read(insn, 0), Expr::Const(1)),
            stmts,
        ),
        Neg => l.write(insn, 0, Expr::Un(UnOp::Neg, Box::new(l.read(insn, 0))), stmts),
        Not => l.write(insn, 0, Expr::Un(UnOp::Not, Box::new(l.read(insn, 0))), stmts),
        Cmp => *flags = Some((l.read(insn, 0), l.read(insn, 1))),
        Test => {
            let a = l.read(insn, 0);
            let b = l.read(insn, 1);
            // test x,x  =>  compare x against 0.
            if a == b {
                *flags = Some((a, Expr::Const(0)));
            } else {
                *flags = Some((Expr::bin(BinOp::And, a, b), Expr::Const(0)));
            }
        }
        // Stack bookkeeping is abstracted away: pushes become invisible and
        // pops produce an opaque value that DCE removes when unused.
        Push => {}
        Pop => l.write(insn, 0, Expr::Unknown("pop"), stmts),
        Call | Ret | Jmp | Leave => {} // handled by terminators
        _ if is_setcc(m) => {
            let cc = cc_binop(m).unwrap_or(BinOp::Ne);
            let (a, b) = flags.clone().unwrap_or((Expr::Unknown("flags"), Expr::Const(0)));
            l.write(insn, 0, Expr::bin(cc, a, b), stmts);
        }
        _ if is_jcc(m) => {} // handled by terminators
        _ => stmts.push(Stmt::Asm(format!("{insn}"))),
    }
}

fn is_jcc(m: Mnemonic) -> bool {
    cc_binop_jcc(m).is_some()
}

fn is_setcc(m: Mnemonic) -> bool {
    cc_binop(m).is_some()
}

fn cc_binop_jcc(m: Mnemonic) -> Option<BinOp> {
    use Mnemonic::*;
    Some(match m {
        Je => BinOp::Eq,
        Jne => BinOp::Ne,
        Jb => BinOp::Ult,
        Jbe => BinOp::Ule,
        Ja => BinOp::Ugt,
        Jae => BinOp::Uge,
        Jl => BinOp::Slt,
        Jle => BinOp::Sle,
        Jg => BinOp::Sgt,
        Jge => BinOp::Sge,
        Js => BinOp::Slt, // sign set  <=> (a - b) < 0 approximated as a < b
        Jns => BinOp::Sge,
        _ => return None,
    })
}

fn cc_binop(m: Mnemonic) -> Option<BinOp> {
    use Mnemonic::*;
    Some(match m {
        Sete => BinOp::Eq,
        Setne => BinOp::Ne,
        Setb => BinOp::Ult,
        Setbe => BinOp::Ule,
        Seta => BinOp::Ugt,
        Setae => BinOp::Uge,
        Setl => BinOp::Slt,
        Setle => BinOp::Sle,
        Setg => BinOp::Sgt,
        Setge => BinOp::Sge,
        _ => return None,
    })
}

/// Lift a whole recovered function into IR.
pub fn lift_function(func: &Function, ctx: &Context) -> Result<IrFunction, DecompileError> {
    let entry_node = func.cfg.entry.ok_or(DecompileError::NoEntry)?;
    let l = Lifter { bits: ctx.bits };
    let arg_regs = ctx.conv.arg_regs();
    // Arguments of a call: callee prototype if known, otherwise the contiguous
    // prefix of argument registers written since the last call in this block.
    let call_args = |target: Option<u64>, written: &[&'static str]| -> Vec<Expr> {
        let n = target
            .and_then(|t| ctx.param_counts.get(&t).copied())
            .unwrap_or_else(|| arg_regs.iter().take_while(|r| written.contains(r)).count());
        arg_regs[..n.min(arg_regs.len())]
            .iter()
            .map(|r| Expr::var(Var::new(Location::Reg(r))))
            .collect()
    };
    let clobber = |stmts: &mut Vec<Stmt>| {
        for r in ctx.conv.volatile_regs() {
            stmts.push(Stmt::Assign(Var::new(Location::Reg(r)), Expr::Unknown("undef")));
        }
    };

    // Stable block numbering by address, entry first.
    let mut nodes: Vec<_> = func.cfg.graph.node_indices().collect();
    nodes.sort_by_key(|&n| (n != entry_node, func.cfg.block(n).start));
    let index: BTreeMap<u64, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, &n)| (func.cfg.block(n).start, i))
        .collect();

    let mut blocks = Vec::with_capacity(nodes.len());
    let callee_names = BTreeMap::new();
    for &n in &nodes {
        let bb = func.cfg.block(n);
        let mut stmts = Vec::new();
        let mut flags: Option<(Expr, Expr)> = None;
        let mut term = None;
        let mut written: Vec<&'static str> = Vec::new();
        for a in &bb.insns {
            let insn = &func.insns[a];
            let raw = &insn.raw;
            let before = stmts.len();
            lift_insn(&l, raw, &mut stmts, &mut flags);
            for st in &stmts[before..] {
                if let Stmt::Assign(
                    Var {
                        loc: Location::Reg(r),
                        ..
                    },
                    _,
                ) = st
                {
                    if !written.contains(r) {
                        written.push(r);
                    }
                }
            }
            match &insn.flow {
                Flow::Call(t) => {
                    stmts.push(Stmt::Call {
                        target: Callee::Direct(*t),
                        args: call_args(Some(*t), &written),
                        ret: Some(Var::new(Location::Reg("rax"))),
                    });
                    clobber(&mut stmts);
                    written.clear();
                }
                Flow::CallNoReturn(t) => {
                    stmts.push(Stmt::Call {
                        target: Callee::Direct(*t),
                        args: call_args(Some(*t), &written),
                        ret: None,
                    });
                    term = Some(Terminator::Exit);
                }
                Flow::IndirectCall => {
                    let slot = insn.mem_refs.first().map(|r| r.addr);
                    stmts.push(Stmt::Call {
                        target: Callee::Indirect(l.read(raw, 0)),
                        args: call_args(slot, &written),
                        ret: Some(Var::new(Location::Reg("rax"))),
                    });
                    clobber(&mut stmts);
                    written.clear();
                }
                Flow::Return => {
                    term = Some(Terminator::Return(Some(Expr::var(Var::new(Location::Reg(
                        "rax",
                    ))))))
                }
                Flow::Halt => term = Some(Terminator::Exit),
                Flow::Jump(t) => {
                    term = Some(match index.get(t) {
                        Some(&b) => Terminator::Jump(b),
                        None => {
                            // Tail call.
                            stmts.push(Stmt::Call {
                                target: Callee::Direct(*t),
                                args: call_args(Some(*t), &written),
                                ret: Some(Var::new(Location::Reg("rax"))),
                            });
                            Terminator::Return(Some(Expr::var(Var::new(Location::Reg("rax")))))
                        }
                    })
                }
                Flow::CondJump(t) => {
                    let op = cc_binop_jcc(raw.mnemonic()).unwrap_or(BinOp::Ne);
                    let (a, b) = flags.clone().unwrap_or((Expr::Unknown("flags"), Expr::Const(0)));
                    let tb = index.get(t).copied();
                    let fb = index.get(&insn.end()).copied();
                    term = Some(match (tb, fb) {
                        (Some(t), Some(f)) => Terminator::Branch {
                            cond: Expr::bin(op, a, b),
                            t,
                            f,
                        },
                        (Some(t), None) => Terminator::Jump(t),
                        (None, Some(f)) => Terminator::Jump(f),
                        (None, None) => Terminator::Exit,
                    });
                }
                Flow::IndirectJump(ts) => {
                    let targets: Vec<usize> = ts.iter().filter_map(|t| index.get(t).copied()).collect();
                    term = Some(if targets.is_empty() {
                        stmts.push(Stmt::Call {
                            target: Callee::Indirect(l.read(raw, 0)),
                            args: call_args(insn.mem_refs.first().map(|r| r.addr), &written),
                            ret: Some(Var::new(Location::Reg("rax"))),
                        });
                        Terminator::Return(Some(Expr::var(Var::new(Location::Reg("rax")))))
                    } else {
                        Terminator::Switch {
                            value: l.read(raw, 0),
                            targets,
                        }
                    });
                }
                Flow::Sequential => {}
            }
        }
        let term = term.unwrap_or_else(|| match index.get(&bb.end) {
            Some(&b) => Terminator::Jump(b),
            None => Terminator::Exit,
        });
        blocks.push(Block {
            addr: bb.start,
            stmts,
            term,
            preds: Vec::new(),
        });
    }

    let mut f = IrFunction {
        entry_addr: func.entry,
        blocks,
        entry: 0,
        callee_names,
    };
    f.recompute_preds();
    Ok(f)
}
