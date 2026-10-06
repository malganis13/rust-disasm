//! `rdisasm` — headless batch analysis, export and scripting CLI.

#![forbid(unsafe_code)]

/// `print!` that exits quietly on a closed pipe (`rdisasm … | head`).
macro_rules! out {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        if write!(std::io::stdout().lock(), $($t)*).is_err() { std::process::exit(0); }
    }};
}
macro_rules! outln {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        if writeln!(std::io::stdout().lock(), $($t)*).is_err() { std::process::exit(0); }
    }};
}

mod export;
mod plugin;

use std::{path::PathBuf, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use disasm_core::{analysis::Analysis, loader::Binary};

#[derive(Parser)]
#[command(
    name = "rdisasm",
    version,
    about = "Ultra-fast Rust disassembler & decompiler"
)]
struct Cli {
    /// Verbose logging (-v, -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print headers, sections, entry points and analysis statistics.
    Info { file: PathBuf },
    /// List discovered functions.
    Functions {
        file: PathBuf,
        /// Only functions whose name contains this string.
        #[arg(short, long)]
        filter: Option<String>,
    },
    /// Disassemble a function (address or name; default: entry point).
    Disasm { file: PathBuf, target: Option<String> },
    /// Decompile a function (or all with --all) to C pseudocode.
    Decompile {
        file: PathBuf,
        target: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Export a function's CFG as Graphviz DOT.
    Cfg { file: PathBuf, target: Option<String> },
    /// List cross-references to an address / name.
    Xrefs { file: PathBuf, target: String },
    /// Dump strings.
    Strings {
        file: PathBuf,
        #[arg(short = 'n', long, default_value_t = 4)]
        min_len: usize,
    },
    /// Export the full analysis database.
    Export {
        file: PathBuf,
        #[arg(short, long, value_enum, default_value_t = Format::Json)]
        format: Format,
        /// Output file (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run a Rhai plugin script against the binary.
    Script { file: PathBuf, script: PathBuf },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Json,
    Csv,
    C,
}

fn load(file: &PathBuf) -> Result<(Binary, Analysis)> {
    let t = Instant::now();
    let bin = Binary::from_path(file).with_context(|| format!("loading {}", file.display()))?;
    let analysis = Analysis::run(&bin);
    tracing::info!(elapsed = ?t.elapsed(), "analysis finished");
    Ok((bin, analysis))
}

/// Resolve `0x…`, bare hex or a function / symbol name.
fn resolve(bin: &Binary, a: &Analysis, target: Option<&str>) -> Result<u64> {
    let Some(t) = target else {
        return bin
            .entry_points
            .first()
            .copied()
            .context("binary has no entry point");
    };
    if let Some(f) = a.functions().find(|f| f.name == t) {
        return Ok(f.entry);
    }
    if let Some(s) = bin.symbols.iter().find(|s| s.name == t) {
        return Ok(s.addr);
    }
    let hex = t.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(hex, 16).with_context(|| format!("cannot resolve `{t}`"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| level.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli.cmd {
        Cmd::Info { file } => {
            let t = Instant::now();
            let (bin, a) = load(&file)?;
            let elapsed = t.elapsed();
            outln!("file        : {}", file.display());
            outln!("format      : {:?}", bin.format);
            outln!("arch        : {:?}", bin.arch);
            outln!("image base  : {:#x}", bin.image_base);
            for e in &bin.entry_points {
                outln!("entry       : {e:#x}");
            }
            if let Some(p) = &bin.debug.pdb_path {
                outln!("pdb         : {p}");
            }
            outln!("dwarf       : {}", bin.debug.has_dwarf);
            outln!("\nsections:");
            for s in bin.memory.sections() {
                outln!(
                    "  {:<24} {:016x} - {:016x}  {}  {:>10} bytes",
                    s.name,
                    s.vaddr,
                    s.end(),
                    s.perms,
                    s.vsize
                );
            }
            outln!("\nanalysis ({elapsed:.2?}):");
            outln!("  symbols      {}", bin.symbols.len());
            outln!("  functions    {}", a.function_count());
            outln!("  instructions {}", a.insn_count());
            outln!("  xrefs        {}", a.xrefs.len());
            outln!("  strings      {}", a.strings.len());
            outln!("  data-in-code {} regions", a.data_regions.len());
        }
        Cmd::Functions { file, filter } => {
            let (_, a) = load(&file)?;
            outln!(
                "{:<18} {:>7} {:>7} {:>6} {:>4}  name",
                "address",
                "size",
                "insns",
                "blocks",
                "cc"
            );
            for f in a
                .functions()
                .filter(|f| filter.as_ref().is_none_or(|s| f.name.contains(s.as_str())))
            {
                outln!(
                    "{:#018x} {:>7} {:>7} {:>6} {:>4}  {}",
                    f.entry,
                    f.size,
                    f.insn_count(),
                    f.cfg.block_count(),
                    f.cfg.cyclomatic_complexity(),
                    f.name
                );
            }
        }
        Cmd::Disasm { file, target } => {
            let (bin, a) = load(&file)?;
            let addr = resolve(&bin, &a, target.as_deref())?;
            let f = a
                .function_containing(addr)
                .with_context(|| format!("no function at {addr:#x}"))?;
            outln!("; function {} @ {:#x}", f.name, f.entry);
            for insn in f.insns.values() {
                if f.cfg.node_at(insn.addr).is_some() {
                    outln!("\nloc_{:x}:", insn.addr);
                }
                let note = insn
                    .mem_refs
                    .iter()
                    .find_map(|r| a.strings.iter().find(|s| s.addr == r.addr))
                    .map(|s| format!("   ; {:?}", s.value))
                    .unwrap_or_default();
                outln!("    {:016x}  {}{}", insn.addr, insn.text, note);
            }
        }
        Cmd::Decompile { file, target, all } => {
            let (bin, a) = load(&file)?;
            if all {
                out!("{}", export::c_all(&bin, &a));
            } else {
                let addr = resolve(&bin, &a, target.as_deref())?;
                let f = a
                    .function_containing(addr)
                    .with_context(|| format!("no function at {addr:#x}"))?;
                outln!("{}", export::c_one(&decompiler::Context::new(&bin, &a), f));
            }
        }
        Cmd::Cfg { file, target } => {
            let (bin, a) = load(&file)?;
            let addr = resolve(&bin, &a, target.as_deref())?;
            let f = a
                .function_containing(addr)
                .with_context(|| format!("no function at {addr:#x}"))?;
            out!("{}", f.cfg.to_dot(&f.insns));
        }
        Cmd::Xrefs { file, target } => {
            let (bin, a) = load(&file)?;
            let addr = resolve(&bin, &a, Some(&target))?;
            for x in a.xrefs.refs_to(addr) {
                let owner = a.function_containing(x.from).map_or("-", |f| f.name.as_str());
                outln!("{:#018x}  {:<10?}  {}", x.from, x.kind, owner);
            }
        }
        Cmd::Strings { file, min_len } => {
            let bin = Binary::from_path(&file)?;
            for s in disasm_core::strings::scan(&bin.memory, min_len) {
                outln!("{:#018x}  {:?}  {:?}", s.addr, s.encoding, s.value);
            }
        }
        Cmd::Export { file, format, output } => {
            let (bin, a) = load(&file)?;
            let text = match format {
                Format::Json => export::json(&bin, &a)?,
                Format::Csv => export::csv(&a),
                Format::C => export::c_all(&bin, &a),
            };
            match output {
                Some(p) => std::fs::write(&p, text).with_context(|| format!("writing {}", p.display()))?,
                None => out!("{text}"),
            }
        }
        Cmd::Script { file, script } => {
            let (bin, a) = load(&file)?;
            let src =
                std::fs::read_to_string(&script).with_context(|| format!("reading {}", script.display()))?;
            let out = plugin::run(
                &src,
                plugin::Project {
                    binary: Arc::new(bin),
                    analysis: Arc::new(a),
                },
            )?;
            if !out.is_empty() {
                outln!("{out}");
            }
        }
    }
    Ok(())
}
