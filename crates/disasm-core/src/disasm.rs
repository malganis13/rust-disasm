//! Instruction decoding: linear sweep and recursive descent powered by `iced-x86`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory, IntelFormatter,
    Mnemonic, OpAccess, OpKind, Register,
};
use serde::Serialize;

use crate::loader::{Binary, MemoryMap};

/// Hard upper bound for jump-table entries we are willing to recover.
const MAX_JUMP_TABLE: usize = 512;
/// Maximum number of instructions explored for a single function.
const MAX_FUNC_INSNS: usize = 200_000;

/// How control leaves an instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Flow {
    /// Falls through to the next instruction.
    Sequential,
    /// Unconditional direct jump.
    Jump(u64),
    /// Conditional direct jump (taken target; fall-through is implicit).
    CondJump(u64),
    /// Direct call (returns to the next instruction).
    Call(u64),
    /// Direct call to a function that never returns (`exit`, `abort`, …).
    CallNoReturn(u64),
    /// Indirect call through register / memory.
    IndirectCall,
    /// Indirect jump with recovered switch targets (may be empty).
    IndirectJump(Vec<u64>),
    /// Function return.
    Return,
    /// Execution stops (`hlt`, `ud2`, `int3`, traps).
    Halt,
}

impl Flow {
    /// `true` if execution may continue at the next instruction.
    pub fn falls_through(&self) -> bool {
        matches!(
            self,
            Flow::Sequential | Flow::CondJump(_) | Flow::Call(_) | Flow::IndirectCall
        )
    }

    /// `true` if this instruction terminates a basic block.
    pub fn ends_block(&self) -> bool {
        !matches!(self, Flow::Sequential | Flow::Call(_) | Flow::IndirectCall)
    }
}

/// Memory access kind of a data reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
    /// Address taken (`lea`, immediate operand) without dereference.
    Address,
}

/// A data reference made by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemRef {
    pub addr: u64,
    pub access: Access,
}

/// A decoded instruction with analysis metadata.
#[derive(Debug, Clone)]
pub struct Insn {
    pub addr: u64,
    pub len: u8,
    pub text: String,
    pub flow: Flow,
    pub mem_refs: Vec<MemRef>,
    /// Raw decoded `iced-x86` instruction (used by the IR lifter).
    pub raw: Instruction,
}

impl Insn {
    #[inline]
    pub fn end(&self) -> u64 {
        self.addr + u64::from(self.len)
    }

    #[inline]
    pub fn mnemonic(&self) -> Mnemonic {
        self.raw.mnemonic()
    }
}

/// Result of recursively exploring one function.
#[derive(Debug, Clone, Default)]
pub struct FunctionCode {
    pub entry: u64,
    /// Instructions keyed by address (sorted).
    pub insns: BTreeMap<u64, Insn>,
    /// Direct call targets discovered inside the function.
    pub call_targets: BTreeSet<u64>,
    /// Direct jumps that leave the function (tail calls to other seeds).
    pub tail_calls: BTreeSet<u64>,
}

/// Stateless x86 / x86-64 disassembler bound to a loaded binary.
#[derive(Debug)]
pub struct Disassembler<'a> {
    memory: &'a MemoryMap,
    bitness: u32,
    ptr_size: usize,
}

impl<'a> Disassembler<'a> {
    /// Create a disassembler. Returns `None` for non-x86 architectures.
    pub fn new(binary: &'a Binary) -> Option<Self> {
        let bitness = binary.arch.bitness()?;
        Some(Self {
            memory: &binary.memory,
            bitness,
            ptr_size: binary.arch.ptr_size(),
        })
    }

    pub fn bitness(&self) -> u32 {
        self.bitness
    }

    /// Decode a single instruction at `addr`.
    pub fn decode_at(&self, addr: u64) -> Option<Insn> {
        if !self.memory.is_executable(addr) {
            return None;
        }
        let bytes = self.memory.slice_from(addr)?;
        let mut dec = Decoder::with_ip(self.bitness, bytes, addr, DecoderOptions::NONE);
        if !dec.can_decode() {
            return None;
        }
        let raw = dec.decode();
        if raw.is_invalid() {
            return None;
        }
        Some(self.annotate(raw, None))
    }

    /// Linear sweep over a byte range. Invalid bytes are skipped one at a time.
    pub fn linear_sweep(&self, start: u64, end: u64) -> Vec<Insn> {
        let Some(bytes) = self.memory.slice_from(start) else {
            return Vec::new();
        };
        let len = usize::try_from(end.saturating_sub(start))
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let mut dec = Decoder::with_ip(self.bitness, &bytes[..len], start, DecoderOptions::NONE);
        let mut fmt = IntelFormatter::new();
        let mut info = InstructionInfoFactory::new();
        let mut out = Vec::with_capacity(len / 4);
        let mut raw = Instruction::default();
        while dec.can_decode() {
            dec.decode_out(&mut raw);
            if raw.is_invalid() {
                continue;
            }
            out.push(self.annotate_with(raw, None, None, &mut fmt, &mut info));
        }
        out
    }

    /// Recursive-descent exploration of a single function starting at `entry`.
    ///
    /// Calls are recorded but not followed; jumps to addresses for which
    /// `is_func_entry` returns `true` are treated as tail calls.
    /// Calls to targets for which `is_noreturn` returns `true` terminate the path.
    pub fn explore_function(
        &self,
        entry: u64,
        is_func_entry: impl Fn(u64) -> bool,
        is_noreturn: impl Fn(u64) -> bool,
    ) -> FunctionCode {
        let mut fc = FunctionCode {
            entry,
            ..Default::default()
        };
        let mut fmt = IntelFormatter::new();
        let mut info = InstructionInfoFactory::new();
        // Per-path state: (address, last rip-relative `lea` target, switch bound).
        let mut work: VecDeque<(u64, Option<u64>, Option<u64>)> = VecDeque::from([(entry, None, None)]);

        while let Some((mut addr, mut last_lea, mut bound)) = work.pop_front() {
            let mut pending_cmp: Option<u64> = None;
            loop {
                if fc.insns.contains_key(&addr) || fc.insns.len() >= MAX_FUNC_INSNS {
                    break;
                }
                let Some(bytes) = self.memory.slice_from(addr) else {
                    break;
                };
                if !self.memory.is_executable(addr) {
                    break;
                }
                let mut dec = Decoder::with_ip(self.bitness, bytes, addr, DecoderOptions::NONE);
                if !dec.can_decode() {
                    break;
                }
                let raw = dec.decode();
                if raw.is_invalid() {
                    break;
                }

                match raw.mnemonic() {
                    Mnemonic::Lea if raw.is_ip_rel_memory_operand() => {
                        last_lea = Some(raw.ip_rel_memory_address());
                    }
                    Mnemonic::Cmp if raw.op_count() == 2 && is_imm(raw.op1_kind()) => {
                        pending_cmp = Some(raw.immediate(1));
                    }
                    // `cmp idx, N` + `ja default` => idx in [0, N]; `jae` => [0, N).
                    Mnemonic::Ja => bound = pending_cmp.take().and_then(|n| n.checked_add(1)),
                    Mnemonic::Jae => bound = pending_cmp.take(),
                    _ => {}
                }
                let mut insn = self.annotate_with(raw, last_lea, bound, &mut fmt, &mut info);
                if let Flow::Call(t) = insn.flow {
                    if is_noreturn(t) {
                        insn.flow = Flow::CallNoReturn(t);
                    }
                }
                let next = insn.end();
                let flow = insn.flow.clone();
                fc.insns.insert(addr, insn);

                match flow {
                    Flow::Sequential => {}
                    Flow::Call(t) => {
                        if self.memory.is_executable(t) {
                            fc.call_targets.insert(t);
                        }
                    }
                    Flow::CallNoReturn(t) => {
                        if self.memory.is_executable(t) {
                            fc.call_targets.insert(t);
                        }
                        break;
                    }
                    Flow::IndirectCall => {}
                    Flow::CondJump(t) => {
                        if is_func_entry(t) && t != entry {
                            fc.tail_calls.insert(t);
                        } else {
                            work.push_back((t, last_lea, bound));
                        }
                    }
                    Flow::Jump(t) => {
                        if is_func_entry(t) && t != entry {
                            fc.tail_calls.insert(t);
                        } else {
                            work.push_back((t, last_lea, bound));
                        }
                        break;
                    }
                    Flow::IndirectJump(targets) => {
                        work.extend(targets.into_iter().map(|t| (t, None, None)));
                        break;
                    }
                    Flow::Return | Flow::Halt => break,
                }
                addr = next;
            }
        }
        fc
    }

    fn annotate(&self, raw: Instruction, last_lea: Option<u64>) -> Insn {
        self.annotate_with(
            raw,
            last_lea,
            None,
            &mut IntelFormatter::new(),
            &mut InstructionInfoFactory::new(),
        )
    }

    fn annotate_with(
        &self,
        raw: Instruction,
        last_lea: Option<u64>,
        bound: Option<u64>,
        fmt: &mut IntelFormatter,
        info: &mut InstructionInfoFactory,
    ) -> Insn {
        let mut text = String::with_capacity(32);
        fmt.format(&raw, &mut text);

        let flow = match raw.flow_control() {
            FlowControl::Next | FlowControl::XbeginXabortXend => Flow::Sequential,
            FlowControl::UnconditionalBranch => match direct_target(&raw) {
                Some(t) => Flow::Jump(t),
                None => Flow::Halt,
            },
            FlowControl::ConditionalBranch => match direct_target(&raw) {
                Some(t) => Flow::CondJump(t),
                None => Flow::Sequential,
            },
            FlowControl::Call => match direct_target(&raw) {
                Some(t) => Flow::Call(t),
                None => Flow::IndirectCall,
            },
            FlowControl::IndirectCall => Flow::IndirectCall,
            FlowControl::IndirectBranch => Flow::IndirectJump(self.recover_jump_table(&raw, last_lea, bound)),
            FlowControl::Return => Flow::Return,
            FlowControl::Interrupt => {
                if raw.mnemonic() == Mnemonic::Int3 {
                    Flow::Halt
                } else {
                    Flow::Sequential
                }
            }
            FlowControl::Exception => Flow::Halt,
        };
        let flow = if raw.mnemonic() == Mnemonic::Hlt {
            Flow::Halt
        } else {
            flow
        };

        let mem_refs = self.mem_refs(&raw, info);
        Insn {
            addr: raw.ip(),
            len: raw.len() as u8,
            text,
            flow,
            mem_refs,
            raw,
        }
    }

    /// Extract statically-known data addresses referenced by an instruction.
    fn mem_refs(&self, raw: &Instruction, info: &mut InstructionInfoFactory) -> Vec<MemRef> {
        let mut refs = Vec::new();
        let ii = info.info(raw);
        for op in 0..raw.op_count() {
            match raw.op_kind(op) {
                OpKind::Memory => {
                    let addr = if raw.is_ip_rel_memory_operand() {
                        Some(raw.ip_rel_memory_address())
                    } else if raw.memory_base() == Register::None && raw.memory_index() == Register::None {
                        Some(raw.memory_displacement64())
                    } else if raw.memory_index() != Register::None && raw.memory_base() == Register::None {
                        // table base: [disp + idx*scale]
                        Some(raw.memory_displacement64())
                    } else {
                        None
                    };
                    if let Some(a) = addr.filter(|a| self.memory.is_mapped(*a)) {
                        let access = if raw.mnemonic() == Mnemonic::Lea {
                            Access::Address
                        } else {
                            match ii.op_access(op) {
                                OpAccess::Write | OpAccess::CondWrite => Access::Write,
                                OpAccess::ReadWrite | OpAccess::ReadCondWrite => Access::ReadWrite,
                                OpAccess::NoMemAccess => Access::Address,
                                _ => Access::Read,
                            }
                        };
                        refs.push(MemRef { addr: a, access });
                    }
                }
                OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64
                    if raw.flow_control() == FlowControl::Next =>
                {
                    let imm = raw.immediate(op);
                    // Heuristic: small immediates are not addresses.
                    if imm > 0x10000 && self.memory.is_mapped(imm) {
                        refs.push(MemRef {
                            addr: imm,
                            access: Access::Address,
                        });
                    }
                }
                _ => {}
            }
        }
        refs
    }

    /// Best-effort switch / jump-table recovery for an indirect `jmp`.
    ///
    /// Handles absolute tables (`jmp [table + idx*ptr]`) and the
    /// GCC/Clang x86-64 relative form (`lea rT,[rip+table]; movsxd; add; jmp reg`).
    ///
    /// The table length comes from the dominating bounds check
    /// (`cmp idx, N; ja default`). Without a bound no targets are guessed,
    /// which avoids bleeding into adjacent tables / functions.
    fn recover_jump_table(&self, raw: &Instruction, last_lea: Option<u64>, bound: Option<u64>) -> Vec<u64> {
        let mut targets = Vec::new();
        let Some(count) = bound.filter(|&n| n > 0 && n as usize <= MAX_JUMP_TABLE) else {
            return targets;
        };
        if raw.op0_kind() == OpKind::Memory {
            // jmp [rip+X] => import thunk, no intra-procedural targets.
            if raw.is_ip_rel_memory_operand() || raw.memory_index() == Register::None {
                return targets;
            }
            if raw.memory_base() == Register::None && raw.memory_index_scale() as usize == self.ptr_size {
                let table = raw.memory_displacement64();
                for i in 0..count as usize {
                    let slot = table + (i * self.ptr_size) as u64;
                    match self.memory.read_ptr(slot, self.ptr_size) {
                        Some(t) if self.memory.is_executable(t) => targets.push(t),
                        _ => break,
                    }
                }
            }
        } else if raw.op0_kind() == OpKind::Register {
            if let Some(table) = last_lea.filter(|t| self.memory.is_mapped(*t)) {
                for i in 0..count {
                    let Ok(b) = self.memory.read(table + i * 4, 4) else {
                        break;
                    };
                    let rel = i64::from(i32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                    let t = table.wrapping_add_signed(rel);
                    if rel.unsigned_abs() > 0x0100_0000 || !self.memory.is_executable(t) {
                        break;
                    }
                    targets.push(t);
                }
            }
        }
        targets.sort_unstable();
        targets.dedup();
        targets
    }
}

fn is_imm(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn direct_target(raw: &Instruction) -> Option<u64> {
    match raw.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => Some(raw.near_branch_target()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::Arch;

    /// push rbp; mov rbp,rsp; cmp edi,0; je L1; mov eax,1; pop rbp; ret;
    /// L1: call f2; pop rbp; ret; f2: xor eax,eax; ret
    pub(crate) const SAMPLE: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x83, 0xff, 0x00, 0x74, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0xe8,
        0x02, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0x31, 0xc0, 0xc3,
    ];

    #[test]
    fn recursive_descent_finds_all_paths() {
        let bin = Binary::raw(SAMPLE, 0x1000, Arch::X86_64);
        let d = Disassembler::new(&bin).unwrap();
        let f = d.explore_function(0x1000, |_| false, |_| false);
        assert_eq!(f.insns.len(), 10);
        assert!(f.call_targets.contains(&0x1017));
        assert_eq!(f.insns[&0x1007].flow, Flow::CondJump(0x1010));
        assert_eq!(f.insns[&0x100f].flow, Flow::Return);
        assert!(!f.insns.contains_key(&0x1017), "callee must not be inlined");
    }

    #[test]
    fn linear_sweep_decodes_everything() {
        let bin = Binary::raw(SAMPLE, 0x1000, Arch::X86_64);
        let d = Disassembler::new(&bin).unwrap();
        let v = d.linear_sweep(0x1000, 0x1000 + SAMPLE.len() as u64);
        assert_eq!(v.len(), 12);
        assert_eq!(v[0].text, "push rbp");
    }
}
