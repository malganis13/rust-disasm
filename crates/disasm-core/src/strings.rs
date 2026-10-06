//! ASCII and UTF-16LE string discovery.

use rayon::prelude::*;
use serde::Serialize;

use crate::loader::MemoryMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Encoding {
    Ascii,
    Utf16Le,
}

/// A string literal found in mapped memory.
#[derive(Debug, Clone, Serialize)]
pub struct FoundString {
    pub addr: u64,
    pub value: String,
    pub encoding: Encoding,
}

#[inline]
fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Scan every mapped section in parallel for strings of at least `min_len` chars.
pub fn scan(memory: &MemoryMap, min_len: usize) -> Vec<FoundString> {
    // Like IDA's default: only data sections (fall back to everything for raw blobs).
    // Mach-O keeps `__cstring` / `__const` inside the executable `__TEXT` segment.
    let mut sections: Vec<_> = memory
        .sections()
        .filter(|s| {
            let n = s.name.to_ascii_lowercase();
            !s.perms.exec || n.contains("cstring") || n.contains("const") || n.contains("rodata")
        })
        .collect();
    if sections.is_empty() {
        sections = memory.sections().collect();
    }
    let mut out: Vec<FoundString> = sections
        .par_iter()
        .flat_map_iter(|s| {
            let mut v = scan_ascii(&s.data, s.vaddr, min_len);
            v.extend(scan_utf16(&s.data, s.vaddr, min_len));
            v
        })
        .collect();
    out.sort_unstable_by_key(|s| s.addr);
    out
}

fn scan_ascii(data: &[u8], base: u64, min_len: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        match (printable(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min_len {
                    out.push(FoundString {
                        addr: base + s as u64,
                        value: String::from_utf8_lossy(&data[s..i]).into_owned(),
                        encoding: Encoding::Ascii,
                    });
                }
                start = None;
            }
            _ => {}
        }
    }
    out
}

fn scan_utf16(data: &[u8], base: u64, min_len: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let s = i;
        let mut units = Vec::new();
        while i + 1 < data.len() && data[i + 1] == 0 && printable(data[i]) {
            units.push(u16::from(data[i]));
            i += 2;
        }
        if units.len() >= min_len {
            out.push(FoundString {
                addr: base + s as u64,
                value: String::from_utf16_lossy(&units),
                encoding: Encoding::Utf16Le,
            });
        } else {
            i = s + 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_and_utf16() {
        let mut data = b"\x00\x01hello world\x00".to_vec();
        data.extend("WIDE".encode_utf16().flat_map(u16::to_le_bytes));
        data.push(0xff);
        let a = scan_ascii(&data, 0x100, 4);
        assert_eq!(a[0].value, "hello world");
        assert_eq!(a[0].addr, 0x102);
        let w = scan_utf16(&data, 0, 4);
        assert!(w.iter().any(|s| s.value.contains("WIDE")));
    }
}
