//! Rhai plugin / scripting API.
//!
//! Scripts get a global `bin` object exposing the loaded binary and its
//! analysis. Example:
//!
//! ```rhai
//! for f in bin.functions() {
//!     if f.blocks > 10 { print(`${hex(f.entry)} ${f.name} blocks=${f.blocks}`); }
//! }
//! let callers = bin.xrefs_to(bin.entry);
//! print(bin.decompile(bin.entry));
//! ```

use std::sync::Arc;

use anyhow::{anyhow, Result};
use disasm_core::{analysis::Analysis, loader::Binary};
use rhai::{Array, Dynamic, Engine, Map, Scope, INT};

/// Shared, immutable project handle given to scripts.
#[derive(Clone)]
pub struct Project {
    pub binary: Arc<Binary>,
    pub analysis: Arc<Analysis>,
}

fn addr(i: INT) -> u64 {
    i as u64
}

impl Project {
    fn functions(&mut self) -> Array {
        self.analysis
            .functions()
            .map(|f| {
                let mut m = Map::new();
                m.insert("entry".into(), Dynamic::from_int(f.entry as INT));
                m.insert("name".into(), f.name.clone().into());
                m.insert("blocks".into(), Dynamic::from_int(f.cfg.block_count() as INT));
                m.insert("edges".into(), Dynamic::from_int(f.cfg.edge_count() as INT));
                m.insert("insns".into(), Dynamic::from_int(f.insn_count() as INT));
                m.insert("size".into(), Dynamic::from_int(f.size as INT));
                m.insert(
                    "complexity".into(),
                    Dynamic::from_int(f.cfg.cyclomatic_complexity() as INT),
                );
                m.insert(
                    "calls".into(),
                    f.calls
                        .iter()
                        .map(|c| Dynamic::from_int(*c as INT))
                        .collect::<Array>()
                        .into(),
                );
                Dynamic::from_map(m)
            })
            .collect()
    }

    fn strings(&mut self) -> Array {
        self.analysis
            .strings
            .iter()
            .map(|s| {
                let mut m = Map::new();
                m.insert("addr".into(), Dynamic::from_int(s.addr as INT));
                m.insert("value".into(), s.value.clone().into());
                Dynamic::from_map(m)
            })
            .collect()
    }

    fn xrefs(list: Vec<disasm_core::xref::Xref>) -> Array {
        list.into_iter()
            .map(|x| {
                let mut m = Map::new();
                m.insert("from".into(), Dynamic::from_int(x.from as INT));
                m.insert("to".into(), Dynamic::from_int(x.to as INT));
                m.insert("kind".into(), format!("{:?}", x.kind).into());
                Dynamic::from_map(m)
            })
            .collect()
    }

    fn disasm(&mut self, a: INT) -> Array {
        match self.analysis.function_containing(addr(a)) {
            Some(f) => f
                .insns
                .values()
                .map(|i| format!("{:x}  {}", i.addr, i.text).into())
                .collect(),
            None => Array::new(),
        }
    }

    fn decompile(&mut self, a: INT) -> String {
        match self.analysis.function_containing(addr(a)) {
            Some(f) => decompiler::decompile(f, self.binary.arch).unwrap_or_else(|e| format!("// {e}")),
            None => format!("// no function at {:#x}", a),
        }
    }

    fn read_bytes(&mut self, a: INT, len: INT) -> rhai::Blob {
        self.binary
            .memory
            .read(addr(a), len.max(0) as usize)
            .unwrap_or_default()
    }
}

/// Build a sandboxed Rhai engine with the analysis API registered.
pub fn engine() -> Engine {
    let mut e = Engine::new();
    e.set_max_operations(50_000_000);
    e.set_max_call_levels(64);
    e.register_type_with_name::<Project>("Binary")
        .register_get("entry", |p: &mut Project| {
            p.binary.entry_points.first().copied().unwrap_or(0) as INT
        })
        .register_get("format", |p: &mut Project| format!("{:?}", p.binary.format))
        .register_get("arch", |p: &mut Project| format!("{:?}", p.binary.arch))
        .register_get("image_base", |p: &mut Project| p.binary.image_base as INT)
        .register_fn("functions", Project::functions)
        .register_fn("strings", Project::strings)
        .register_fn("xrefs_to", |p: &mut Project, a: INT| {
            Project::xrefs(p.analysis.xrefs.refs_to(addr(a)))
        })
        .register_fn("xrefs_from", |p: &mut Project, a: INT| {
            Project::xrefs(p.analysis.xrefs.refs_from(addr(a)))
        })
        .register_fn("disasm", Project::disasm)
        .register_fn("decompile", Project::decompile)
        .register_fn("read_bytes", Project::read_bytes)
        .register_fn("symbol", |p: &mut Project, a: INT| {
            p.binary
                .symbol_at(addr(a))
                .map_or(Dynamic::UNIT, |s| s.name.clone().into())
        });
    e.on_print(|s| {
        use std::io::Write as _;
        if writeln!(std::io::stdout().lock(), "{s}").is_err() {
            std::process::exit(0);
        }
    });
    e.register_fn("hex", |v: INT| format!("{:#x}", v as u64));
    e
}

/// Run a script file against a project. The script's final value is returned
/// as a string (or `()` if it evaluated to unit).
pub fn run(script: &str, project: Project) -> Result<String> {
    let engine = engine();
    let mut scope = Scope::new();
    scope.push_constant("bin", project);
    let out: Dynamic = engine
        .eval_with_scope(&mut scope, script)
        .map_err(|e| anyhow!("script error: {e}"))?;
    Ok(if out.is_unit() {
        String::new()
    } else {
        out.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use disasm_core::loader::Arch;

    #[test]
    fn script_sees_functions() {
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0x83, 0xff, 0x00, 0x74, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x5d, 0xc3,
            0xe8, 0x02, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0x31, 0xc0, 0xc3,
        ];
        let bin = Binary::raw(&code, 0x1000, Arch::X86_64);
        let analysis = Analysis::run(&bin);
        let p = Project {
            binary: Arc::new(bin),
            analysis: Arc::new(analysis),
        };
        let out = run(
            r#"let n = 0; for f in bin.functions() { n += f.blocks; } `${bin.functions().len()}:${n}:${bin.xrefs_to(0x1017).len()}`"#,
            p,
        )
        .unwrap();
        assert_eq!(out, "2:4:1");
    }
}
