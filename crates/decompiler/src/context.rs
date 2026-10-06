//! Whole-program decompilation context (IDA "type library" / name database
//! analogue): calling convention, callee names and prototypes, string
//! literals and global data, shared by every function decompiled from one
//! binary. Build it once with [`Context::new`] and reuse it.

use std::collections::HashMap;

use disasm_core::{
    analysis::{Analysis, Function},
    loader::{Arch, Binary, Format, SymbolKind},
};
use iced_x86::{InstructionInfoFactory, OpAccess, Register};
use rayon::prelude::*;

/// Calling convention used to recover parameters and call arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConv {
    /// System V AMD64 (Linux, macOS, BSD).
    SysV,
    /// Microsoft x64 (`__fastcall`).
    Win64,
    /// 32-bit stack-based (`__cdecl` / `__stdcall`); register args are not modelled.
    Stack32,
}

impl CallConv {
    pub fn for_binary(format: Format, arch: Arch) -> Self {
        match (arch, format) {
            (Arch::X86, _) => CallConv::Stack32,
            (_, Format::Pe) => CallConv::Win64,
            _ => CallConv::SysV,
        }
    }

    /// Integer argument registers in order (canonical 64-bit names).
    pub fn arg_regs(self) -> &'static [&'static str] {
        match self {
            CallConv::SysV => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            CallConv::Win64 => &["rcx", "rdx", "r8", "r9"],
            CallConv::Stack32 => &[],
        }
    }

    /// Caller-saved registers (other than `rax`) clobbered by a call.
    pub fn volatile_regs(self) -> &'static [&'static str] {
        match self {
            CallConv::SysV => &["rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"],
            CallConv::Win64 => &["rcx", "rdx", "r8", "r9", "r10", "r11"],
            CallConv::Stack32 => &["rcx", "rdx"],
        }
    }

    fn arg_iced(self) -> &'static [Register] {
        match self {
            CallConv::SysV => &[
                Register::RDI,
                Register::RSI,
                Register::RDX,
                Register::RCX,
                Register::R8,
                Register::R9,
            ],
            CallConv::Win64 => &[Register::RCX, Register::RDX, Register::R8, Register::R9],
            CallConv::Stack32 => &[],
        }
    }

    pub fn keyword(self) -> &'static str {
        match self {
            CallConv::Stack32 => "__cdecl",
            _ => "__fastcall",
        }
    }
}

/// Shared decompilation context.
#[derive(Debug, Clone)]
pub struct Context {
    pub conv: CallConv,
    pub bits: u32,
    /// Display names: function entries and import slots (IAT / GOT).
    pub names: HashMap<u64, String>,
    /// Number of register parameters of each recovered function.
    pub param_counts: HashMap<u64, usize>,
    /// String literals by address.
    pub strings: HashMap<u64, String>,
    /// Mapped non-executable ranges (globals).
    data_ranges: Vec<(u64, u64)>,
    /// Mapped executable ranges.
    code_ranges: Vec<(u64, u64)>,
}

/// Strip thunk / DLL / version decorations: `j_KERNEL32.dll!Sleep` → `Sleep`.
pub fn clean_name(n: &str) -> String {
    let n = n.strip_prefix("j_").unwrap_or(n);
    let n = n.rsplit('!').next().unwrap_or(n);
    let n = n.split("@plt").next().unwrap_or(n);
    let n = n.split("@got").next().unwrap_or(n);
    let n = n.split("@@").next().unwrap_or(n);
    n.to_owned()
}

impl Context {
    /// Minimal context with no program knowledge (used by [`crate::decompile`]).
    pub fn bare(format: Format, arch: Arch) -> Self {
        Self {
            conv: CallConv::for_binary(format, arch),
            bits: arch.bitness().unwrap_or(64),
            names: HashMap::new(),
            param_counts: HashMap::new(),
            strings: HashMap::new(),
            data_ranges: Vec::new(),
            code_ranges: Vec::new(),
        }
    }

    /// Build the context for a whole binary (parallel prototype scan).
    pub fn new(bin: &Binary, a: &Analysis) -> Self {
        let mut ctx = Self::bare(bin.format, bin.arch);
        for s in &bin.symbols {
            if s.kind == SymbolKind::Import {
                ctx.names.insert(s.addr, clean_name(&s.name));
            }
        }
        for f in a.functions() {
            let n = if f.name.starts_with("j_") || f.name.ends_with("@plt") {
                clean_name(&f.name)
            } else {
                f.name.clone()
            };
            ctx.names.insert(f.entry, n);
        }
        let funcs: Vec<&Function> = a.functions().collect();
        ctx.param_counts = funcs
            .par_iter()
            .map(|f| (f.entry, param_count(f, ctx.conv)))
            .collect();
        // Thunks inherit nothing; imports fall back to call-site inference.
        for f in &funcs {
            if f.name.starts_with("j_") || f.name.ends_with("@plt") {
                ctx.param_counts.remove(&f.entry);
            }
        }
        ctx.strings = a.strings.iter().map(|s| (s.addr, s.value.clone())).collect();
        for s in bin.memory.sections() {
            if s.perms.exec {
                ctx.code_ranges.push((s.vaddr, s.end()));
            } else {
                ctx.data_ranges.push((s.vaddr, s.end()));
            }
        }
        ctx
    }

    pub fn is_data(&self, a: u64) -> bool {
        a >= 0x1000 && self.data_ranges.iter().any(|&(s, e)| a >= s && a < e)
    }

    pub fn is_code(&self, a: u64) -> bool {
        a >= 0x1000 && self.code_ranges.iter().any(|&(s, e)| a >= s && a < e)
    }

    pub fn name_of(&self, a: u64) -> Option<&str> {
        self.names.get(&a).map(String::as_str)
    }
}

/// Count register parameters: argument registers read before written,
/// scanning in address order up to the first call (IDA-style quick prototype).
pub fn param_count(f: &Function, conv: CallConv) -> usize {
    let regs = conv.arg_iced();
    if regs.is_empty() {
        return 0;
    }
    let mut info = InstructionInfoFactory::new();
    let mut written = [false; 6];
    let mut used = [false; 6];
    for insn in f.insns.values().take(96) {
        let raw = &insn.raw;
        let ii = info.info(raw);
        // `xor r, r` only writes.
        let zero_idiom = matches!(raw.mnemonic(), iced_x86::Mnemonic::Xor | iced_x86::Mnemonic::Sub)
            && raw.op_count() == 2
            && raw.op0_kind() == iced_x86::OpKind::Register
            && raw.op1_kind() == iced_x86::OpKind::Register
            && raw.op0_register() == raw.op1_register();
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for ur in ii.used_registers() {
            let full = ur.register().full_register();
            let Some(i) = regs.iter().position(|r| *r == full) else {
                continue;
            };
            match ur.access() {
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
                    if !zero_idiom =>
                {
                    reads.push(i);
                    if matches!(ur.access(), OpAccess::ReadWrite | OpAccess::ReadCondWrite) {
                        writes.push(i);
                    }
                }
                OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    writes.push(i)
                }
                _ => {}
            }
        }
        for i in reads {
            if !written[i] {
                used[i] = true;
            }
        }
        for i in writes {
            written[i] = true;
        }
        if insn.flow.ends_block()
            || matches!(
                insn.flow,
                disasm_core::disasm::Flow::Call(_) | disasm_core::disasm::Flow::IndirectCall
            )
        {
            // Keep scanning straight-line code through conditional branches,
            // stop at calls / returns / jumps (approximation of the entry region).
            if !matches!(insn.flow, disasm_core::disasm::Flow::CondJump(_)) {
                break;
            }
        }
    }
    used.iter().rposition(|&u| u).map_or(0, |i| i + 1)
}
