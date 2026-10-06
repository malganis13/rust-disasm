//! # decompiler
//!
//! Pipeline: x86/x64 [`Insn`](disasm_core::disasm::Insn) →
//! [`ir`] (target-agnostic three-address code) → [`ssa`] construction →
//! [`passes`] (constant folding, copy propagation, DCE) →
//! [`structure`] (if/else, while, do-while recovery) → [`types`] inference →
//! [`emit`] C pseudocode.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

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

/// Decompile one function into C pseudocode.
pub fn decompile(func: &Function, arch: Arch) -> Result<String, DecompileError> {
    let bits = arch.bitness().ok_or(DecompileError::Arch(arch))?;
    let mut irf = lift::lift_function(func, bits)?;
    ssa::construct(&mut irf);
    passes::optimize(&mut irf);
    ssa::destruct(&mut irf);
    passes::post_destruct(&mut irf);
    let sig = types::infer(&irf, bits);
    let ast = structure::structure(&irf);
    Ok(emit::emit_function(&func.name, &irf, &sig, &ast))
}
