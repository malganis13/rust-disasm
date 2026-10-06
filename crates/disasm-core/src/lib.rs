//! # disasm-core
//!
//! Core analysis engine: loads PE / ELF / Mach-O binaries into a unified
//! [`MemoryMap`](loader::MemoryMap), performs recursive-descent disassembly
//! with `iced-x86`, builds per-function control-flow graphs with `petgraph`
//! and indexes cross-references in a lock-free `DashMap`.
//!
//! ```no_run
//! use disasm_core::{loader::Binary, analysis::Analysis};
//! let bin = Binary::from_path("a.out")?;
//! let analysis = Analysis::run(&bin);
//! for f in analysis.functions() {
//!     println!("{:#x} {} ({} blocks)", f.entry, f.name, f.cfg.block_count());
//! }
//! # Ok::<(), disasm_core::CoreError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

pub mod analysis;
pub mod cfg;
pub mod disasm;
pub mod error;
pub mod loader;
pub mod strings;
pub mod xref;

pub use error::{CoreError, Result};
