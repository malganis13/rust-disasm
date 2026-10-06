//! Whole-program analysis driver: parallel function discovery, CFGs, xrefs,
//! strings and code/data separation.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use dashmap::DashSet;
use rayon::prelude::*;
use tracing::{info, info_span};

use crate::{
    cfg::Cfg,
    disasm::{Disassembler, Flow, Insn},
    loader::{Binary, SymbolKind},
    strings::{self, FoundString},
    xref::{XrefDb, XrefKind},
};

/// Imports known never to return.
const NORETURN_IMPORTS: &[&str] = &[
    "exit",
    "_exit",
    "_Exit",
    "abort",
    "__stack_chk_fail",
    "__assert_fail",
    "__assert_rtn",
    "__fortify_fail",
    "__chk_fail",
    "err",
    "errx",
    "verr",
    "verrx",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "_Unwind_Resume",
    "pthread_exit",
    "quick_exit",
    "__libc_start_main",
    "ExitProcess",
    "ExitThread",
    "TerminateProcess",
    "RaiseFailFastException",
    "_invalid_parameter_noinfo_noreturn",
    "__report_rangecheckfailure",
    "_CxxThrowException",
    "__std_terminate",
    "terminate",
];

/// A recovered function.
#[derive(Debug, Clone)]
pub struct Function {
    pub entry: u64,
    pub name: String,
    pub insns: BTreeMap<u64, Insn>,
    pub cfg: Cfg,
    pub calls: BTreeSet<u64>,
    /// Sum of instruction lengths.
    pub size: u64,
}

impl Function {
    pub fn insn_count(&self) -> usize {
        self.insns.len()
    }
}

/// Region inside an executable section not covered by any decoded instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataRegion {
    pub start: u64,
    pub end: u64,
}

/// Tunables for [`Analysis::run_with`].
#[derive(Debug, Clone)]
pub struct Options {
    /// Scan gaps for common function prologues.
    pub prologue_scan: bool,
    /// Minimum string length.
    pub min_string_len: usize,
    /// Scan non-executable sections for code pointers.
    pub data_pointer_scan: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            prologue_scan: true,
            min_string_len: 4,
            data_pointer_scan: true,
        }
    }
}

/// Complete analysis result for a binary.
#[derive(Debug)]
pub struct Analysis {
    functions: BTreeMap<u64, Function>,
    pub xrefs: XrefDb,
    pub strings: Vec<FoundString>,
    pub data_regions: Vec<DataRegion>,
}

impl Analysis {
    /// Run with default [`Options`].
    pub fn run(binary: &Binary) -> Self {
        Self::run_with(binary, &Options::default())
    }

    pub fn run_with(binary: &Binary, opts: &Options) -> Self {
        let _span = info_span!("analysis").entered();
        let xrefs = XrefDb::new();
        let strings = strings::scan(&binary.memory, opts.min_string_len);

        let Some(dis) = Disassembler::new(binary) else {
            info!(arch = ?binary.arch, "architecture not supported by x86 engine; loader-only analysis");
            return Self {
                functions: BTreeMap::new(),
                xrefs,
                strings,
                data_regions: Vec::new(),
            };
        };

        // Seeds: entry points + symbol functions/exports in executable memory.
        let mut seeds: BTreeSet<u64> = binary.entry_points.iter().copied().collect();
        seeds.extend(
            binary
                .symbols
                .iter()
                .filter(|s| matches!(s.kind, SymbolKind::Function | SymbolKind::Export))
                .map(|s| s.addr),
        );
        seeds.retain(|&a| binary.memory.is_executable(a));

        let mut functions = Self::discover(&dis, binary, seeds);

        if opts.prologue_scan {
            let extra = Self::prologue_seeds(binary, &functions);
            if !extra.is_empty() {
                info!(count = extra.len(), "prologue scan found extra functions");
                let more = Self::discover_from(&dis, binary, extra, &functions);
                functions.extend(more);
            }
        }
        info!(functions = functions.len(), "function discovery complete");

        // Code xrefs (parallel, lock-free inserts).
        functions.par_iter().for_each(|(_, f)| {
            for insn in f.insns.values() {
                match &insn.flow {
                    Flow::Call(t) | Flow::CallNoReturn(t) => xrefs.add(insn.addr, *t, XrefKind::Call),
                    Flow::Jump(t) | Flow::CondJump(t) => xrefs.add(insn.addr, *t, XrefKind::Jump),
                    Flow::IndirectJump(ts) => {
                        for t in ts {
                            xrefs.add(insn.addr, *t, XrefKind::Jump);
                        }
                    }
                    _ => {}
                }
                for r in &insn.mem_refs {
                    xrefs.add(insn.addr, r.addr, XrefKind::from_access(r.access));
                }
            }
        });

        // Data -> code pointers.
        if opts.data_pointer_scan {
            let ps = binary.arch.ptr_size();
            let entries: HashSet<u64> = functions.keys().copied().collect();
            let secs: Vec<_> = binary.memory.sections().filter(|s| !s.perms.exec).collect();
            secs.par_iter().for_each(|s| {
                for (i, chunk) in s.data.chunks_exact(ps).enumerate() {
                    let v = match ps {
                        4 => u64::from(u32::from_le_bytes(chunk.try_into().expect("4 bytes"))),
                        _ => u64::from_le_bytes(chunk.try_into().expect("8 bytes")),
                    };
                    if entries.contains(&v) {
                        xrefs.add(s.vaddr + (i * ps) as u64, v, XrefKind::DataToCode);
                    }
                }
            });
        }

        let data_regions = Self::data_regions(binary, &functions);
        info!(xrefs = xrefs.len(), strings = strings.len(), "analysis complete");
        Self {
            functions,
            xrefs,
            strings,
            data_regions,
        }
    }

    fn discover(dis: &Disassembler<'_>, bin: &Binary, seeds: BTreeSet<u64>) -> BTreeMap<u64, Function> {
        Self::discover_from(dis, bin, seeds, &BTreeMap::new())
    }

    /// Iterative, data-parallel discovery: every round explores the frontier
    /// concurrently and feeds newly found call targets into the next round.
    fn discover_from(
        dis: &Disassembler<'_>,
        bin: &Binary,
        seeds: BTreeSet<u64>,
        existing: &BTreeMap<u64, Function>,
    ) -> BTreeMap<u64, Function> {
        let known: DashSet<u64> = existing.keys().copied().collect();
        let mut frontier: Vec<u64> = seeds.into_iter().filter(|s| known.insert(*s)).collect();
        let mut out = BTreeMap::new();
        let names: BTreeMap<u64, &str> = bin
            .symbols
            .iter()
            .filter(|s| s.kind != SymbolKind::Import)
            .map(|s| (s.addr, s.name.as_str()))
            .collect();

        let mut round = 0;
        while !frontier.is_empty() {
            round += 1;
            let snapshot: HashSet<u64> = known.iter().map(|k| *k).collect();
            let explored: Vec<_> = frontier
                .par_iter()
                .map(|&e| dis.explore_function(e, |a| snapshot.contains(&a), |_| false))
                .collect();
            let mut next = Vec::new();
            for fc in &explored {
                for &t in fc.call_targets.iter().chain(&fc.tail_calls) {
                    if known.insert(t) {
                        next.push(t);
                    }
                }
            }
            let built: Vec<Function> = explored
                .into_par_iter()
                .map(|fc| {
                    let cfg = Cfg::build(fc.entry, &fc.insns);
                    let size = fc.insns.values().map(|i| u64::from(i.len)).sum();
                    let name = names
                        .get(&fc.entry)
                        .map(|s| (*s).to_owned())
                        .unwrap_or_else(|| format!("sub_{:x}", fc.entry));
                    Function {
                        entry: fc.entry,
                        name,
                        insns: fc.insns,
                        cfg,
                        calls: fc.call_targets,
                        size,
                    }
                })
                .collect();
            tracing::debug!(
                round,
                explored = built.len(),
                next = next.len(),
                "discovery round"
            );
            out.extend(built.into_iter().map(|f| (f.entry, f)));
            next.sort_unstable();
            frontier = next;
        }
        Self::name_import_stubs(bin, &mut out);
        for e in &bin.entry_points {
            if let Some(f) = out.get_mut(e) {
                if f.name.starts_with("sub_") {
                    f.name = "start".into();
                }
            }
        }
        Self::noreturn_fixpoint(dis, bin, &mut out, existing);
        out
    }

    /// Rename PLT / IAT thunks (`jmp [rip+slot]`) after the imported symbol.
    fn name_import_stubs(bin: &Binary, funcs: &mut BTreeMap<u64, Function>) {
        let imports: BTreeMap<u64, &str> = bin
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Import)
            .map(|s| (s.addr, s.name.as_str()))
            .collect();
        for f in funcs.values_mut() {
            if f.insns.len() > 3 || !f.name.starts_with("sub_") {
                continue;
            }
            let Some(last) = f.insns.values().last() else {
                continue;
            };
            if !matches!(last.flow, Flow::IndirectJump(ref t) if t.is_empty()) {
                continue;
            }
            if let Some(name) = last.mem_refs.iter().find_map(|r| imports.get(&r.addr)) {
                let base = name.trim_end_matches("@got");
                f.name = match bin.format {
                    crate::loader::Format::Elf => format!("{base}@plt"),
                    _ => format!("j_{base}"),
                };
            }
        }
    }

    /// Detect non-returning functions and re-explore their callers so code
    /// after `call exit` is not merged into the caller (fixed point).
    fn noreturn_fixpoint(
        dis: &Disassembler<'_>,
        bin: &Binary,
        funcs: &mut BTreeMap<u64, Function>,
        existing: &BTreeMap<u64, Function>,
    ) {
        let entries: HashSet<u64> = funcs.keys().chain(existing.keys()).copied().collect();
        let mut noreturn: HashSet<u64> = HashSet::new();
        for _ in 0..6 {
            let before = noreturn.len();
            for f in funcs.values().chain(existing.values()) {
                if noreturn.contains(&f.entry) {
                    continue;
                }
                let base = f.name.split('@').next().unwrap_or("").trim_start_matches("j_");
                let base = base.rsplit('!').next().unwrap_or(base);
                let known = NORETURN_IMPORTS.contains(&base);
                // No reachable return and no way to leave except traps / noreturn calls.
                let derived = !f.name.ends_with("@plt")
                    && !f.insns.is_empty()
                    && f.insns.values().all(|i| match &i.flow {
                        Flow::Return | Flow::IndirectJump(_) => false,
                        Flow::Jump(t) | Flow::CondJump(t) => !entries.contains(t) || f.insns.contains_key(t),
                        _ => true,
                    })
                    && f.insns
                        .values()
                        .any(|i| matches!(i.flow, Flow::Halt | Flow::CallNoReturn(_)));
                if known || derived {
                    noreturn.insert(f.entry);
                }
            }
            // Re-explore callers of any noreturn function.
            let callers: Vec<u64> = funcs
                .values()
                .filter(|f| {
                    f.insns
                        .values()
                        .any(|i| matches!(i.flow, Flow::Call(t) if noreturn.contains(&t)))
                })
                .map(|f| f.entry)
                .collect();
            if callers.is_empty() && noreturn.len() == before {
                break;
            }
            let rebuilt: Vec<Function> = callers
                .par_iter()
                .map(|&e| {
                    let fc = dis.explore_function(e, |a| entries.contains(&a), |t| noreturn.contains(&t));
                    let old = &funcs[&e];
                    let cfg = Cfg::build(fc.entry, &fc.insns);
                    let size = fc.insns.values().map(|i| u64::from(i.len)).sum();
                    Function {
                        entry: e,
                        name: old.name.clone(),
                        insns: fc.insns,
                        cfg,
                        calls: fc.call_targets,
                        size,
                    }
                })
                .collect();
            for f in rebuilt {
                funcs.insert(f.entry, f);
            }
            let _ = bin;
        }
    }

    fn covered(functions: &BTreeMap<u64, Function>) -> Vec<(u64, u64)> {
        let mut iv: Vec<(u64, u64)> = functions
            .values()
            .flat_map(|f| f.insns.values().map(|i| (i.addr, i.end())))
            .collect();
        iv.par_sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(iv.len() / 4);
        for (s, e) in iv {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        merged
    }

    fn gaps(binary: &Binary, functions: &BTreeMap<u64, Function>) -> Vec<DataRegion> {
        let covered = Self::covered(functions);
        let mut out = Vec::new();
        for s in binary.memory.exec_sections() {
            let mut cur = s.vaddr;
            let lo = covered.partition_point(|&(_, e)| e <= s.vaddr);
            for &(cs, ce) in &covered[lo..] {
                if cs >= s.end() {
                    break;
                }
                if cs > cur {
                    out.push(DataRegion { start: cur, end: cs });
                }
                cur = cur.max(ce);
            }
            if cur < s.end() {
                out.push(DataRegion {
                    start: cur,
                    end: s.end(),
                });
            }
        }
        out
    }

    /// Exec-section bytes not reached by recursive descent, excluding
    /// pure alignment padding (`int3` / `nop` / zero runs).
    fn data_regions(binary: &Binary, functions: &BTreeMap<u64, Function>) -> Vec<DataRegion> {
        Self::gaps(binary, functions)
            .into_iter()
            .filter(|g| {
                let len = (g.end - g.start) as usize;
                binary
                    .memory
                    .read(g.start, len)
                    .map(|b| !b.iter().all(|&x| matches!(x, 0x00 | 0x90 | 0xcc)))
                    .unwrap_or(false)
            })
            .collect()
    }

    fn prologue_seeds(binary: &Binary, functions: &BTreeMap<u64, Function>) -> BTreeSet<u64> {
        const PATTERNS: &[&[u8]] = &[
            &[0xf3, 0x0f, 0x1e, 0xfa], // endbr64
            &[0x55, 0x48, 0x89, 0xe5], // push rbp; mov rbp,rsp
            &[0x55, 0x89, 0xe5],       // push ebp; mov ebp,esp (x86)
            &[0x48, 0x89, 0x5c, 0x24], // mov [rsp+x],rbx (MSVC x64)
            &[0x48, 0x83, 0xec],       // sub rsp, imm8   (MSVC x64)
        ];
        let gaps = Self::gaps(binary, functions);
        gaps.par_iter()
            .flat_map_iter(|g| {
                let mut found = Vec::new();
                let mut a = (g.start + 15) & !15;
                while a + 4 <= g.end {
                    if let Ok(b) = binary.memory.read(a, 4) {
                        if PATTERNS.iter().any(|p| b.starts_with(p)) {
                            found.push(a);
                        }
                    }
                    a += 16;
                }
                found
            })
            .collect()
    }

    // ------------------------------------------------------------ accessors

    pub fn functions(&self) -> impl Iterator<Item = &Function> {
        self.functions.values()
    }

    pub fn function(&self, entry: u64) -> Option<&Function> {
        self.functions.get(&entry)
    }

    /// Function whose body contains `addr`.
    pub fn function_containing(&self, addr: u64) -> Option<&Function> {
        if let Some(f) = self.functions.get(&addr) {
            return Some(f);
        }
        self.functions.values().find(|f| f.insns.contains_key(&addr))
    }

    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Total number of decoded instructions across all functions.
    pub fn insn_count(&self) -> usize {
        self.functions.values().map(Function::insn_count).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::Arch;

    const SAMPLE: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x83, 0xff, 0x00, 0x74, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0xe8,
        0x02, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0x31, 0xc0, 0xc3,
    ];

    #[test]
    fn end_to_end_raw() {
        let bin = Binary::raw(SAMPLE, 0x1000, Arch::X86_64);
        let a = Analysis::run(&bin);
        assert_eq!(a.function_count(), 2);
        let main = a.function(0x1000).unwrap();
        assert_eq!(main.cfg.block_count(), 3);
        assert_eq!(main.cfg.edge_count(), 2);
        let callers = a.xrefs.refs_to(0x1017);
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].from, 0x1010);
        assert!(a.data_regions.is_empty());
    }

    #[test]
    fn end_to_end_self() {
        let exe = std::env::current_exe().unwrap();
        let bin = Binary::from_path(exe).unwrap();
        let a = Analysis::run(&bin);
        assert!(a.function_count() > 10);
        assert!(a.xrefs.len() > 10);
    }
}
