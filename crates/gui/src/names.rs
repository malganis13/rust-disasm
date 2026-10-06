//! IDA-style name database used to symbolise operands:
//! `sub_140001000`, `loc_1400016A0`, `__imp_Sleep`, `aHelloWorld`, `qword_140003000`.

use std::{collections::HashMap, sync::Arc};

use disasm_core::{
    analysis::Analysis,
    disasm::Insn,
    loader::{Binary, SymbolKind},
};
use iced_x86::{Formatter, FormatterOptions, Instruction, IntelFormatter, SymbolResolver, SymbolResult};

#[derive(Debug, Default)]
pub struct NameDb {
    pub funcs: HashMap<u64, String>,
    pub imports: HashMap<u64, String>,
    pub strings: HashMap<u64, String>,
    code: Vec<(u64, u64)>,
    data: Vec<(u64, u64)>,
}

/// IDA string label: `"Hello, world!\n"` → `aHelloWorld`.
pub fn string_label(s: &str) -> String {
    let mut out = String::from("a");
    let mut up = true;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            if up {
                out.extend(c.to_uppercase());
            } else {
                out.push(c);
            }
            up = false;
        } else {
            up = true;
        }
        if out.len() >= 24 {
            break;
        }
    }
    if out.len() == 1 {
        out.push_str("Str");
    }
    out
}

impl NameDb {
    pub fn new(bin: &Binary, a: &Analysis, user: &HashMap<u64, String>) -> Self {
        let mut db = NameDb::default();
        for f in a.functions() {
            db.funcs.insert(f.entry, f.name.clone());
        }
        for (k, v) in user {
            db.funcs.insert(*k, v.clone());
        }
        for s in &bin.symbols {
            if s.kind == SymbolKind::Import {
                db.imports
                    .insert(s.addr, decompiler::context::clean_name(&s.name));
            }
        }
        for s in &a.strings {
            db.strings.insert(s.addr, s.value.clone());
        }
        for s in bin.memory.sections() {
            if s.perms.exec {
                db.code.push((s.vaddr, s.end()));
            } else {
                db.data.push((s.vaddr, s.end()));
            }
        }
        db
    }

    fn in_ranges(r: &[(u64, u64)], a: u64) -> bool {
        r.iter().any(|&(s, e)| a >= s && a < e)
    }

    pub fn is_code(&self, a: u64) -> bool {
        Self::in_ranges(&self.code, a)
    }

    /// Symbolic label for an address (None for plain numbers).
    pub fn label(&self, a: u64, width: u8) -> Option<String> {
        if let Some(n) = self.funcs.get(&a) {
            return Some(n.clone());
        }
        if let Some(n) = self.imports.get(&a) {
            return Some(format!("__imp_{n}"));
        }
        if let Some(s) = self.strings.get(&a) {
            return Some(string_label(s));
        }
        if a < 0x1000 {
            return None;
        }
        if Self::in_ranges(&self.code, a) {
            return Some(format!("loc_{a:X}"));
        }
        if Self::in_ranges(&self.data, a) {
            let p = match width {
                1 => "byte",
                2 => "word",
                4 => "dword",
                8 => "qword",
                _ => "unk",
            };
            return Some(format!("{p}_{a:X}"));
        }
        None
    }

    /// Auto comment (string literal) for an instruction.
    pub fn auto_comment(&self, insn: &Insn) -> Option<String> {
        insn.mem_refs
            .iter()
            .find_map(|r| self.strings.get(&r.addr))
            .map(|s| {
                let mut t: String = s.chars().take(60).collect();
                t = t.replace('\n', "\\n").replace('\r', "\\r");
                format!("\"{t}\"")
            })
    }
}

struct Resolver(Arc<NameDb>);

impl SymbolResolver for Resolver {
    fn symbol(
        &mut self,
        instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        // Only symbolise branch targets and memory operands / large immediates.
        let _ = address_size;
        let width = instruction.memory_size().size() as u8;
        let name = self.0.label(address, width)?;
        let name = if self.0.imports.contains_key(&address) {
            format!("cs:{name}")
        } else {
            name
        };
        Some(SymbolResult::with_string(address, name))
    }
}

/// Instruction formatter bound to a name database.
pub struct InsnFormatter {
    fmt: IntelFormatter,
}

impl InsnFormatter {
    pub fn new(db: Arc<NameDb>) -> Self {
        let mut fmt = IntelFormatter::with_options(Some(Box::new(Resolver(db))), None);
        let o: &mut FormatterOptions = fmt.options_mut();
        o.set_space_after_operand_separator(true);
        o.set_hex_prefix("");
        o.set_hex_suffix("h");
        o.set_uppercase_hex(true);
        o.set_first_operand_char_index(8);
        o.set_show_branch_size(false);
        o.set_rip_relative_addresses(false);
        o.set_memory_size_options(iced_x86::MemorySizeOptions::Minimal);
        Self { fmt }
    }

    pub fn format(&mut self, insn: &Insn) -> String {
        let mut s = String::with_capacity(48);
        self.fmt.format(&insn.raw, &mut s);
        s
    }
}
