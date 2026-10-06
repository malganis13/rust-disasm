//! Entry-point and `main` discovery.
//!
//! The image entry point is usually CRT start-up code. This module follows
//! the well-known start-up shapes to locate the user's `main` / `WinMain`,
//! as IDA does:
//!
//! * **glibc / musl ELF**: `_start` passes `main` in `rdi` (`lea rdi,[rip+main]`
//!   or `mov rdi, imm`) to `__libc_start_main`.
//! * **MSVC PE**: `mainCRTStartup` → `__scrt_common_main_seh` → … `call main`
//!   right after the CRT argument getters (`__p___argc`, `__p___argv`, …), and
//!   its result flows into `exit` (`mov ebx,eax` … `mov ecx,ebx; call exit`).
//! * **MinGW PE**: `call main; mov ecx,eax; call exit`.
//! * **Mach-O** `LC_MAIN`: the entry point *is* `main`.
//! * **Rust**: the C `main` is a tiny shim that passes the real entry
//!   (`lea rcx/rdi,[rip+X]`) to `std::rt::lang_start`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{Mnemonic, OpKind, Register};
use serde::Serialize;

use crate::{
    analysis::Function,
    disasm::{Flow, Insn},
    loader::{Binary, Format, SymbolKind},
};

/// How `main` was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MainSource {
    /// A symbol named `main` / `WinMain` / `wmain` …
    Symbol,
    /// Mach-O `LC_MAIN` entry.
    LcMain,
    /// `__libc_start_main(main, …)` argument.
    LibcStartMain,
    /// MSVC CRT argument getters followed by the call.
    MsvcCrt,
    /// Return value of the call flows into `exit`.
    ExitDataflow,
}

/// Result of entry-point analysis.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EntryInfo {
    /// Image entry point (first of `Binary::entry_points`).
    pub entry: Option<u64>,
    /// The user's `main` / `WinMain`, if found.
    pub main: Option<u64>,
    pub main_name: Option<String>,
    pub source: Option<MainSource>,
    /// Real Rust `main` passed to `lang_start`, if detected.
    pub rust_main: Option<u64>,
}

const MAIN_NAMES: &[&str] = &["main", "wmain", "WinMain", "wWinMain", "_main", "DllMain"];
const CRT_ARG_GETTERS: &[&str] = &[
    "__p___argc",
    "__p___argv",
    "__p___wargv",
    "_get_initial_narrow_environment",
    "_get_initial_wide_environment",
    "__getmainargs",
    "__wgetmainargs",
    "__p__environ",
    "__p__wenviron",
    "_get_narrow_winmain_command_line",
    "_get_wide_winmain_command_line",
];
const EXIT_NAMES: &[&str] = &["exit", "_exit", "ExitProcess", "_cexit", "_c_exit", "quick_exit"];

/// Name lookup helper over imports and recovered functions.
struct Names<'a> {
    imports: BTreeMap<u64, &'a str>,
    funcs: &'a BTreeMap<u64, Function>,
}

fn base_name(n: &str) -> &str {
    let n = n.trim_start_matches("j_");
    let n = n.split('@').next().unwrap_or(n);
    n.rsplit('!').next().unwrap_or(n).trim_start_matches("__imp_")
}

impl Names<'_> {
    /// Base name of a call's target (import via IAT/GOT, thunk or function).
    fn callee(&self, insn: &Insn) -> Option<&str> {
        match insn.flow {
            Flow::Call(t) | Flow::CallNoReturn(t) => {
                if let Some(f) = self.funcs.get(&t) {
                    return Some(base_name(&f.name));
                }
                self.imports.get(&t).map(|s| base_name(s))
            }
            Flow::IndirectCall => insn
                .mem_refs
                .iter()
                .find_map(|r| self.imports.get(&r.addr))
                .map(|s| base_name(s)),
            _ => None,
        }
    }

    fn is_import_call(&self, insn: &Insn) -> bool {
        match insn.flow {
            Flow::IndirectCall => insn.mem_refs.iter().any(|r| self.imports.contains_key(&r.addr)),
            Flow::Call(t) | Flow::CallNoReturn(t) => {
                self.funcs
                    .get(&t)
                    .is_some_and(|f| f.name.ends_with("@plt") || f.name.starts_with("j_"))
                    || self.imports.contains_key(&t)
            }
            _ => false,
        }
    }
}

fn direct_target(insn: &Insn) -> Option<u64> {
    match insn.flow {
        Flow::Call(t) => Some(t),
        _ => None,
    }
}

fn is_reg(insn: &Insn, op: u32, r: Register) -> bool {
    insn.raw.op_kind(op) == OpKind::Register && insn.raw.op_register(op).full_register() == r
}

/// Detect the entry point and `main` over already-recovered functions.
pub fn detect(bin: &Binary, funcs: &BTreeMap<u64, Function>) -> EntryInfo {
    let entry = bin.entry_points.first().copied();
    let mut info = EntryInfo {
        entry,
        ..Default::default()
    };
    let names = Names {
        imports: bin
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Import)
            .map(|s| (s.addr, s.name.as_str()))
            .collect(),
        funcs,
    };

    // 1. Symbols.
    if let Some(f) = funcs.values().find(|f| MAIN_NAMES.contains(&f.name.as_str())) {
        info.main = Some(f.entry);
        info.main_name = Some(f.name.clone());
        info.source = Some(MainSource::Symbol);
    } else if let Some(s) = bin.symbols.iter().find(|s| {
        s.kind != SymbolKind::Import
            && MAIN_NAMES.contains(&s.name.as_str())
            && bin.memory.is_executable(s.addr)
    }) {
        info.main = Some(s.addr);
        info.main_name = Some(s.name.clone());
        info.source = Some(MainSource::Symbol);
    }
    // 2. Mach-O LC_MAIN.
    else if bin.entry_is_main {
        info.main = entry;
        info.source = Some(MainSource::LcMain);
    }
    // 3. Start-up code patterns.
    else if let Some(e) = entry {
        let chain = crt_chain(e, funcs);
        let found = chain
            .iter()
            .filter_map(|a| funcs.get(a))
            .find_map(|f| {
                libc_start_main(f, &names, bin)
                    .map(|m| (m, MainSource::LibcStartMain))
                    .or_else(|| msvc_getters(f, &names).map(|m| (m, MainSource::MsvcCrt)))
            })
            .or_else(|| {
                chain
                    .iter()
                    .filter_map(|a| funcs.get(a))
                    .find_map(|f| exit_dataflow(f, &names, bin.format).map(|m| (m, MainSource::ExitDataflow)))
            });
        if let Some((m, src)) = found {
            info.main = Some(m);
            info.source = Some(src);
        }
    }

    if let Some(m) = info.main {
        if info.main_name.is_none() {
            info.main_name = Some(guess_main_name(funcs.get(&m), &names));
        }
        if let Some(f) = funcs.get(&m) {
            info.rust_main = rust_lang_start(f, &names, bin);
        }
    }
    info
}

/// Functions reachable from the entry through calls / tail-jumps (CRT start-up chain).
fn crt_chain(entry: u64, funcs: &BTreeMap<u64, Function>) -> Vec<u64> {
    let mut seen = BTreeSet::from([entry]);
    let mut order = Vec::new();
    let mut q = VecDeque::from([(entry, 0u32)]);
    while let Some((a, depth)) = q.pop_front() {
        let Some(f) = funcs.get(&a) else { continue };
        order.push(a);
        if depth >= 3 || order.len() > 48 {
            continue;
        }
        for i in f.insns.values() {
            let t = match i.flow {
                Flow::Call(t) => Some(t),
                Flow::Jump(t) if !f.insns.contains_key(&t) => Some(t),
                _ => None,
            };
            if let Some(t) = t.filter(|t| funcs.contains_key(t)) {
                if seen.insert(t) {
                    q.push_back((t, depth + 1));
                }
            }
        }
    }
    order
}

/// `lea rdi,[rip+main]` / `mov edi, main` before `__libc_start_main`.
fn libc_start_main(f: &Function, names: &Names<'_>, bin: &Binary) -> Option<u64> {
    let insns: Vec<&Insn> = f.insns.values().collect();
    let k = insns
        .iter()
        .position(|i| names.callee(i) == Some("__libc_start_main"))?;
    insns[k.saturating_sub(16)..k].iter().rev().find_map(|i| {
        if !is_reg(i, 0, Register::RDI) {
            return None;
        }
        let v = match i.raw.mnemonic() {
            Mnemonic::Lea if i.raw.is_ip_rel_memory_operand() => i.raw.ip_rel_memory_address(),
            Mnemonic::Mov if i.raw.op1_kind() != OpKind::Register && i.raw.op1_kind() != OpKind::Memory => {
                i.raw.immediate(1)
            }
            _ => return None,
        };
        bin.memory.is_executable(v).then_some(v)
    })
}

/// MSVC: first non-import direct call after the last CRT argument getter.
fn msvc_getters(f: &Function, names: &Names<'_>) -> Option<u64> {
    let insns: Vec<&Insn> = f.insns.values().collect();
    let last = insns
        .iter()
        .rposition(|i| names.callee(i).is_some_and(|n| CRT_ARG_GETTERS.contains(&n)))?;
    insns[last + 1..].iter().take(20).find_map(|i| {
        let t = direct_target(i)?;
        if names.is_import_call(i) || names.callee(i).is_some_and(|n| CRT_ARG_GETTERS.contains(&n)) {
            return None;
        }
        Some(t)
    })
}

/// `call main; mov ebx,eax; … mov ecx,ebx; call exit` (and the MinGW
/// `call main; mov ecx,eax; call exit` form).
fn exit_dataflow(f: &Function, names: &Names<'_>, fmt: Format) -> Option<u64> {
    let arg0 = if fmt == Format::Pe {
        Register::RCX
    } else {
        Register::RDI
    };
    let insns: Vec<&Insn> = f.insns.values().collect();
    for k in 1..insns.len() {
        if !names.callee(insns[k]).is_some_and(|n| EXIT_NAMES.contains(&n)) {
            continue;
        }
        let prev = insns[k - 1];
        if prev.raw.mnemonic() != Mnemonic::Mov
            || !is_reg(prev, 0, arg0)
            || prev.raw.op1_kind() != OpKind::Register
        {
            continue;
        }
        let src = prev.raw.op_register(1).full_register();
        if src == Register::RAX {
            if let Some(t) = insns.get(k.wrapping_sub(2)).and_then(|i| direct_target(i)) {
                return Some(t);
            }
            continue;
        }
        // Find `mov src, eax` right after a direct call, earlier in the function.
        for m in (1..k - 1).rev() {
            let i = insns[m];
            if i.raw.mnemonic() == Mnemonic::Mov && is_reg(i, 0, src) && is_reg(i, 1, Register::RAX) {
                if let Some(t) = direct_target(insns[m - 1]).filter(|_| !names.is_import_call(insns[m - 1])) {
                    return Some(t);
                }
            }
        }
    }
    None
}

/// Rust: `main` shim passes the real entry to `std::rt::lang_start`.
fn rust_lang_start(f: &Function, names: &Names<'_>, bin: &Binary) -> Option<u64> {
    if f.insns.len() > 24 {
        return None;
    }
    let insns: Vec<&Insn> = f.insns.values().collect();
    let call = insns
        .iter()
        .position(|i| direct_target(i).is_some() && !names.is_import_call(i))?;
    insns[..call].iter().rev().find_map(|i| {
        // `lea rcx/rdi,[rip+main]` (old) or `lea rax,[rip+main]; mov [rsp+x],rax` (new).
        let ok = i.raw.mnemonic() == Mnemonic::Lea && i.raw.is_ip_rel_memory_operand();
        let t = i.raw.ip_rel_memory_address();
        (ok && bin.memory.is_executable(t) && t != f.entry).then_some(t)
    })
}

fn guess_main_name(f: Option<&Function>, names: &Names<'_>) -> String {
    match f {
        Some(f) if !f.name.starts_with("sub_") => f.name.clone(),
        // GUI apps import user32 and receive (hInstance, …) — call it WinMain.
        _ if names
            .imports
            .values()
            .any(|n| n.to_ascii_lowercase().starts_with("user32")) =>
        {
            "WinMain".into()
        }
        _ => "main".into(),
    }
}
