//! Lock-free cross-reference index backed by `DashMap`.

use dashmap::DashMap;
use serde::Serialize;

use crate::disasm::Access;

/// Kind of a cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum XrefKind {
    /// Code → code: direct call.
    Call,
    /// Code → code: unconditional / conditional / switch jump.
    Jump,
    /// Code → data read.
    DataRead,
    /// Code → data write.
    DataWrite,
    /// Code → data address taken (`lea`, immediate).
    DataOffset,
    /// Data → code pointer (vtables, callbacks, jump tables).
    DataToCode,
}

impl XrefKind {
    pub fn from_access(a: Access) -> Self {
        match a {
            Access::Read => XrefKind::DataRead,
            Access::Write | Access::ReadWrite => XrefKind::DataWrite,
            Access::Address => XrefKind::DataOffset,
        }
    }

    pub fn is_code(self) -> bool {
        matches!(self, XrefKind::Call | XrefKind::Jump)
    }
}

/// A single cross-reference edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
}

/// Concurrent bidirectional xref database. Safe to populate from many
/// `rayon` workers simultaneously.
#[derive(Debug, Default)]
pub struct XrefDb {
    to: DashMap<u64, Vec<Xref>>,
    from: DashMap<u64, Vec<Xref>>,
}

impl XrefDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, from: u64, to: u64, kind: XrefKind) {
        let x = Xref { from, to, kind };
        self.to.entry(to).or_default().push(x);
        self.from.entry(from).or_default().push(x);
    }

    /// All references *to* `addr`, sorted by source.
    pub fn refs_to(&self, addr: u64) -> Vec<Xref> {
        let mut v = self.to.get(&addr).map(|r| r.clone()).unwrap_or_default();
        v.sort_unstable_by_key(|x| (x.from, x.kind as u8));
        v.dedup();
        v
    }

    /// All references *from* `addr`.
    pub fn refs_from(&self, addr: u64) -> Vec<Xref> {
        let mut v = self.from.get(&addr).map(|r| r.clone()).unwrap_or_default();
        v.sort_unstable_by_key(|x| (x.to, x.kind as u8));
        v.dedup();
        v
    }

    /// Number of distinct target addresses.
    pub fn target_count(&self) -> usize {
        self.to.len()
    }

    /// Total number of xref edges.
    pub fn len(&self) -> usize {
        self.to.iter().map(|e| e.value().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.to.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::prelude::*;

    #[test]
    fn concurrent_insert() {
        let db = XrefDb::new();
        (0..10_000u64)
            .into_par_iter()
            .for_each(|i| db.add(i, i % 7, XrefKind::Call));
        assert_eq!(db.len(), 10_000);
        assert_eq!(db.target_count(), 7);
        assert_eq!(db.refs_from(42)[0].to, 0);
    }
}
