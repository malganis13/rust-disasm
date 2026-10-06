//! # decompiler
//!
//! Pipeline: x86/x64 [`Insn`](disasm_core::disasm::Insn) →
//! [`ir`] (target-agnostic three-address code) → [`ssa`] construction →
//! [`passes`] (constant folding, copy propagation, DCE) →
//! [`structure`] (if/else, while, do-while recovery) → [`types`] inference →
//! [`emit`] C pseudocode.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod context;
pub mod emit;
pub mod ir;
pub mod lift;
pub mod passes;
pub mod ssa;
pub mod structure;
pub mod types;

use disasm_core::{analysis::Function, loader::Arch};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecompileError {
    #[error("function has no entry block")]
    NoEntry,
    #[error("unsupported architecture {0:?}")]
    Arch(Arch),
}

pub use context::{CallConv, Context};

/// Decompile one function with no whole-program knowledge.
/// Prefer [`decompile_with`] with a shared [`Context`] for named calls,
/// call arguments, strings and globals.
pub fn decompile(func: &Function, arch: Arch) -> Result<String, DecompileError> {
    arch.bitness().ok_or(DecompileError::Arch(arch))?;
    let fmt = disasm_core::loader::Format::Raw;
    decompile_with(func, &Context::bare(fmt, arch))
}

/// Decompile one function into Hex-Rays–style C pseudocode.
pub fn decompile_with(func: &Function, ctx: &Context) -> Result<String, DecompileError> {
    let mut irf = lift::lift_function(func, ctx)?;
    ssa::construct(&mut irf);
    passes::optimize(&mut irf);
    ssa::destruct(&mut irf);
    passes::post_destruct(&mut irf);
    let sig = types::infer(&irf, ctx);
    let ast = structure::structure(&irf);
    Ok(emit::emit_function(&func.name, &irf, &sig, &ast, ctx))
}
