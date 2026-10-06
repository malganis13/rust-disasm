//! Error types for `disasm-core`.

use thiserror::Error;

/// Result alias used across the crate.
pub type Result<T> = std::result::Result<T, CoreError>;

/// All errors produced by the core engine.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse binary: {0}")]
    Parse(#[from] goblin::error::Error),

    #[error("unsupported binary format: {0}")]
    UnsupportedFormat(String),

    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),

    #[error("address {0:#x} is not mapped")]
    Unmapped(u64),

    #[error("section `{name}` has invalid bounds (offset {offset:#x}, size {size:#x})")]
    BadSection { name: String, offset: u64, size: u64 },
}
