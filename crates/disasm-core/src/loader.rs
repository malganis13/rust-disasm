//! File loader & section mapper.
//!
//! Parses PE, ELF and Mach-O images into a format-agnostic [`Binary`] that
//! exposes a virtual [`MemoryMap`], symbols and entry points.

use std::{collections::BTreeMap, fmt, path::Path};

use goblin::{elf, mach, pe, Object};
use serde::Serialize;
use tracing::{debug, warn};

use crate::error::{CoreError, Result};

/// Container format of the loaded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Format {
    Pe,
    Elf,
    MachO,
    Raw,
}

/// CPU architecture of the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Arch {
    X86,
    X86_64,
    Arm64,
    Unknown,
}

impl Arch {
    /// Decoder bitness for the x86 family, `None` otherwise.
    pub fn bitness(self) -> Option<u32> {
        match self {
            Arch::X86 => Some(32),
            Arch::X86_64 => Some(64),
            _ => None,
        }
    }

    /// Pointer size in bytes.
    pub fn ptr_size(self) -> usize {
        match self {
            Arch::X86 => 4,
            _ => 8,
        }
    }
}

/// Memory protection flags of a mapped region.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Perms {
    pub const RX: Perms = Perms {
        read: true,
        write: false,
        exec: true,
    };
    pub const RW: Perms = Perms {
        read: true,
        write: true,
        exec: false,
    };
    pub const R: Perms = Perms {
        read: true,
        write: false,
        exec: false,
    };
}

impl fmt::Display for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.exec { 'x' } else { '-' }
        )
    }
}

/// A contiguous mapped section of virtual memory.
#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    /// Virtual size (may exceed `data.len()`; the tail is zero-filled / BSS).
    pub vsize: u64,
    pub file_offset: u64,
    pub perms: Perms,
    #[serde(skip)]
    pub data: Vec<u8>,
}

impl Section {
    #[inline]
    pub fn end(&self) -> u64 {
        self.vaddr.saturating_add(self.vsize)
    }

    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.vaddr && addr < self.end()
    }
}

/// Unified virtual memory representation, sorted by start address.
#[derive(Debug, Default, Clone)]
pub struct MemoryMap {
    sections: BTreeMap<u64, Section>,
}

impl MemoryMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a section. Zero-sized sections are ignored.
    pub fn map(&mut self, section: Section) {
        if section.vsize == 0 {
            return;
        }
        self.sections.insert(section.vaddr, section);
    }

    /// Section containing `addr`, if any. `O(log n)`.
    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        self.sections
            .range(..=addr)
            .next_back()
            .map(|(_, s)| s)
            .filter(|s| s.contains(addr))
    }

    pub fn is_mapped(&self, addr: u64) -> bool {
        self.section_at(addr).is_some()
    }

    pub fn is_executable(&self, addr: u64) -> bool {
        self.section_at(addr).is_some_and(|s| s.perms.exec)
    }

    /// Borrow file-backed bytes from `addr` to the end of its section.
    pub fn slice_from(&self, addr: u64) -> Option<&[u8]> {
        let s = self.section_at(addr)?;
        let off = usize::try_from(addr - s.vaddr).ok()?;
        s.data.get(off..)
    }

    /// Read exactly `len` bytes at `addr` (zero-fills BSS within one section).
    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let s = self.section_at(addr).ok_or(CoreError::Unmapped(addr))?;
        let end = addr.checked_add(len as u64).ok_or(CoreError::Unmapped(addr))?;
        if end > s.end() {
            return Err(CoreError::Unmapped(s.end()));
        }
        let off = (addr - s.vaddr) as usize;
        let mut out = vec![0u8; len];
        if off < s.data.len() {
            let avail = (s.data.len() - off).min(len);
            out[..avail].copy_from_slice(&s.data[off..off + avail]);
        }
        Ok(out)
    }

    /// Read a little-endian pointer of `size` (4 or 8) bytes.
    pub fn read_ptr(&self, addr: u64, size: usize) -> Option<u64> {
        let b = self.read(addr, size).ok()?;
        Some(match size {
            4 => u32::from_le_bytes(b.try_into().ok()?) as u64,
            8 => u64::from_le_bytes(b.try_into().ok()?),
            _ => return None,
        })
    }

    pub fn sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.values()
    }

    pub fn exec_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.values().filter(|s| s.perms.exec)
    }

    pub fn len(&self) -> usize {
        self.sections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }
}

/// Kind of a discovered symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SymbolKind {
    Function,
    Data,
    Import,
    Export,
}

/// A named address.
#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: SymbolKind,
}

/// Debug-info availability (PDB / DWARF are detected; full parsing is stubbed).
#[derive(Debug, Clone, Default, Serialize)]
pub struct DebugInfo {
    pub pdb_path: Option<String>,
    pub has_dwarf: bool,
}

/// A fully-loaded binary image.
#[derive(Debug, Clone)]
pub struct Binary {
    pub format: Format,
    pub arch: Arch,
    pub image_base: u64,
    pub entry_points: Vec<u64>,
    pub symbols: Vec<Symbol>,
    pub memory: MemoryMap,
    pub debug: DebugInfo,
}

impl Binary {
    /// Load and parse a binary from disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref())?;
        Self::from_bytes(&bytes)
    }

    /// Parse a binary from an in-memory buffer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match Object::parse(bytes)? {
            Object::Elf(e) => load_elf(&e, bytes),
            Object::PE(p) => load_pe(&p, bytes),
            Object::Mach(mach::Mach::Binary(m)) => load_macho(&m, bytes),
            Object::Mach(mach::Mach::Fat(fat)) => {
                for arch in fat.iter_arches().flatten() {
                    let start = arch.offset as usize;
                    let end = start.saturating_add(arch.size as usize);
                    if let Some(slice) = bytes.get(start..end) {
                        if let Ok(m) = mach::MachO::parse(slice, 0) {
                            return load_macho(&m, slice);
                        }
                    }
                }
                Err(CoreError::UnsupportedFormat("empty fat Mach-O".into()))
            }
            Object::Archive(_) => Err(CoreError::UnsupportedFormat("ar archive".into())),
            _ => Err(CoreError::UnsupportedFormat("unknown magic".into())),
        }
    }

    /// Treat an arbitrary buffer as raw code mapped at `base`.
    pub fn raw(bytes: &[u8], base: u64, arch: Arch) -> Self {
        let mut memory = MemoryMap::new();
        memory.map(Section {
            name: ".raw".into(),
            vaddr: base,
            vsize: bytes.len() as u64,
            file_offset: 0,
            perms: Perms::RX,
            data: bytes.to_vec(),
        });
        Binary {
            format: Format::Raw,
            arch,
            image_base: base,
            entry_points: vec![base],
            symbols: Vec::new(),
            memory,
            debug: DebugInfo::default(),
        }
    }

    /// Look up a symbol at an exact address.
    pub fn symbol_at(&self, addr: u64) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.addr == addr)
    }
}

fn file_slice(bytes: &[u8], name: &str, offset: u64, size: u64) -> Result<Vec<u8>> {
    let start = usize::try_from(offset).ok();
    let end = offset.checked_add(size).and_then(|e| usize::try_from(e).ok());
    match (start, end) {
        (Some(s), Some(e)) if e <= bytes.len() => Ok(bytes[s..e].to_vec()),
        _ => Err(CoreError::BadSection {
            name: name.to_owned(),
            offset,
            size,
        }),
    }
}

fn dedup_symbols(symbols: &mut Vec<Symbol>) {
    symbols.sort_by(|a, b| a.addr.cmp(&b.addr).then_with(|| a.name.cmp(&b.name)));
    symbols.dedup_by(|a, b| a.addr == b.addr && a.name == b.name);
}

// ---------------------------------------------------------------- ELF ----

fn load_elf(e: &elf::Elf<'_>, bytes: &[u8]) -> Result<Binary> {
    use elf::header::{EM_386, EM_AARCH64, EM_X86_64};
    use elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};

    let arch = match e.header.e_machine {
        EM_386 => Arch::X86,
        EM_X86_64 => Arch::X86_64,
        EM_AARCH64 => Arch::Arm64,
        m => {
            warn!(machine = m, "unknown ELF machine");
            Arch::Unknown
        }
    };

    let mut memory = MemoryMap::new();
    let mut has_dwarf = false;
    for sh in &e.section_headers {
        let name = e.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_owned();
        if name.starts_with(".debug_") {
            has_dwarf = true;
        }
        if sh.sh_flags & u64::from(SHF_ALLOC) == 0 || sh.sh_addr == 0 {
            continue;
        }
        let perms = Perms {
            read: true,
            write: sh.sh_flags & u64::from(SHF_WRITE) != 0,
            exec: sh.sh_flags & u64::from(SHF_EXECINSTR) != 0,
        };
        let data = if sh.sh_type == SHT_NOBITS {
            Vec::new()
        } else {
            file_slice(bytes, &name, sh.sh_offset, sh.sh_size)?
        };
        debug!(%name, vaddr = sh.sh_addr, size = sh.sh_size, "map ELF section");
        memory.map(Section {
            name,
            vaddr: sh.sh_addr,
            vsize: sh.sh_size,
            file_offset: sh.sh_offset,
            perms,
            data,
        });
    }

    // Section-less ELF: fall back to PT_LOAD segments.
    if memory.is_empty() {
        let loads = e
            .program_headers
            .iter()
            .filter(|p| p.p_type == elf::program_header::PT_LOAD);
        for (i, ph) in loads.enumerate() {
            let name = format!("LOAD{i}");
            let data = file_slice(bytes, &name, ph.p_offset, ph.p_filesz)?;
            memory.map(Section {
                name,
                vaddr: ph.p_vaddr,
                vsize: ph.p_memsz,
                file_offset: ph.p_offset,
                perms: Perms {
                    read: ph.is_read(),
                    write: ph.is_write(),
                    exec: ph.is_executable(),
                },
                data,
            });
        }
    }

    let mut symbols = Vec::new();
    for (strtab, syms) in [(&e.strtab, &e.syms), (&e.dynstrtab, &e.dynsyms)] {
        for s in syms.iter() {
            let Some(name) = strtab.get_at(s.st_name).filter(|n| !n.is_empty()) else {
                continue;
            };
            let kind = match s.st_type() {
                elf::sym::STT_FUNC if s.st_value != 0 => SymbolKind::Function,
                elf::sym::STT_FUNC => continue,
                elf::sym::STT_OBJECT => SymbolKind::Data,
                _ => continue,
            };
            symbols.push(Symbol {
                name: name.to_owned(),
                addr: s.st_value,
                size: s.st_size,
                kind,
            });
        }
    }

    // GOT import slots from PLT relocations.
    for rel in e.pltrelocs.iter() {
        let Some(sym) = e.dynsyms.get(rel.r_sym) else {
            continue;
        };
        let Some(name) = e.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        symbols.push(Symbol {
            name: format!("{name}@got"),
            addr: rel.r_offset,
            size: arch.ptr_size() as u64,
            kind: SymbolKind::Import,
        });
    }
    dedup_symbols(&mut symbols);

    let image_base = e
        .program_headers
        .iter()
        .filter(|p| p.p_type == elf::program_header::PT_LOAD)
        .map(|p| p.p_vaddr)
        .min()
        .unwrap_or(0);

    let entry_points = if e.entry != 0 { vec![e.entry] } else { vec![] };

    Ok(Binary {
        format: Format::Elf,
        arch,
        image_base,
        entry_points,
        symbols,
        memory,
        debug: DebugInfo {
            pdb_path: None,
            has_dwarf,
        },
    })
}

// ----------------------------------------------------------------- PE ----

fn load_pe(p: &pe::PE<'_>, bytes: &[u8]) -> Result<Binary> {
    use pe::header::{COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64};
    use pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};

    let arch = match p.header.coff_header.machine {
        COFF_MACHINE_X86 => Arch::X86,
        COFF_MACHINE_X86_64 => Arch::X86_64,
        COFF_MACHINE_ARM64 => Arch::Arm64,
        _ => Arch::Unknown,
    };
    let base = p.image_base as u64;

    let mut memory = MemoryMap::new();
    for s in &p.sections {
        let name = s.name().unwrap_or("?").to_owned();
        let raw_off = u64::from(s.pointer_to_raw_data);
        let raw_size = u64::from(s.size_of_raw_data).min((bytes.len() as u64).saturating_sub(raw_off));
        let vsize = u64::from(s.virtual_size).max(raw_size);
        let data = if raw_size == 0 {
            Vec::new()
        } else {
            file_slice(bytes, &name, raw_off, raw_size)?
        };
        memory.map(Section {
            name,
            vaddr: base + u64::from(s.virtual_address),
            vsize,
            file_offset: raw_off,
            perms: Perms {
                read: s.characteristics & IMAGE_SCN_MEM_READ != 0,
                write: s.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                exec: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            },
            data,
        });
    }

    let mut symbols = Vec::new();
    for ex in &p.exports {
        if let Some(name) = ex.name {
            symbols.push(Symbol {
                name: name.to_owned(),
                addr: base + ex.rva as u64,
                size: ex.size as u64,
                kind: SymbolKind::Export,
            });
        }
    }
    for im in &p.imports {
        symbols.push(Symbol {
            name: format!("{}!{}", im.dll, im.name),
            addr: base + im.rva as u64,
            size: im.size as u64,
            kind: SymbolKind::Import,
        });
    }
    dedup_symbols(&mut symbols);

    let mut entry_points = Vec::new();
    if p.entry != 0 {
        entry_points.push(base + p.entry as u64);
    }
    entry_points.extend(
        symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Export && memory.is_executable(s.addr))
            .map(|s| s.addr),
    );

    let pdb_path = p
        .debug_data
        .as_ref()
        .and_then(|d| d.codeview_pdb70_debug_info.as_ref())
        .map(|cv| {
            String::from_utf8_lossy(cv.filename)
                .trim_end_matches('\0')
                .to_owned()
        });

    Ok(Binary {
        format: Format::Pe,
        arch,
        image_base: base,
        entry_points,
        symbols,
        memory,
        debug: DebugInfo {
            pdb_path,
            has_dwarf: false,
        },
    })
}

// ------------------------------------------------------------- Mach-O ----

fn load_macho(m: &mach::MachO<'_>, bytes: &[u8]) -> Result<Binary> {
    use mach::constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86, CPU_TYPE_X86_64};

    let arch = match m.header.cputype() {
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_X86_64 => Arch::X86_64,
        CPU_TYPE_ARM64 => Arch::Arm64,
        _ => Arch::Unknown,
    };

    let mut memory = MemoryMap::new();
    let mut image_base = u64::MAX;
    let mut has_dwarf = false;
    for seg in m.segments.iter() {
        let segname = seg.name().unwrap_or("?").to_owned();
        if segname == "__TEXT" {
            image_base = image_base.min(seg.vmaddr);
        }
        if segname == "__DWARF" {
            has_dwarf = true;
        }
        let prot = seg.initprot;
        let Ok(sections) = seg.sections() else { continue };
        for (sect, _) in sections {
            if sect.addr == 0 || sect.size == 0 {
                continue;
            }
            let name = format!("{},{}", segname, sect.name().unwrap_or("?"));
            let zerofill = sect.flags & 0xff == mach::constants::S_ZEROFILL;
            let data = if zerofill || sect.offset == 0 {
                Vec::new()
            } else {
                file_slice(bytes, &name, u64::from(sect.offset), sect.size)?
            };
            memory.map(Section {
                name,
                vaddr: sect.addr,
                vsize: sect.size,
                file_offset: u64::from(sect.offset),
                perms: Perms {
                    read: prot & 1 != 0,
                    write: prot & 2 != 0,
                    exec: prot & 4 != 0,
                },
                data,
            });
        }
    }
    if image_base == u64::MAX {
        image_base = 0;
    }

    let mut symbols = Vec::new();
    if let Some(syms) = &m.symbols {
        for (name, nlist) in syms.iter().flatten() {
            if name.is_empty() || nlist.is_stab() || nlist.is_undefined() || nlist.n_value == 0 {
                continue;
            }
            let kind = if memory.is_executable(nlist.n_value) {
                SymbolKind::Function
            } else {
                SymbolKind::Data
            };
            symbols.push(Symbol {
                name: name.trim_start_matches('_').to_owned(),
                addr: nlist.n_value,
                size: 0,
                kind,
            });
        }
    }
    if let Ok(exports) = m.exports() {
        for ex in exports {
            symbols.push(Symbol {
                name: ex.name.trim_start_matches('_').to_owned(),
                addr: image_base + ex.offset,
                size: ex.size as u64,
                kind: SymbolKind::Export,
            });
        }
    }
    dedup_symbols(&mut symbols);

    let mut entry_points = Vec::new();
    if m.entry != 0 {
        // LC_MAIN gives a file offset relative to __TEXT; LC_UNIXTHREAD gives a vaddr.
        let e = if memory.is_mapped(m.entry) {
            m.entry
        } else {
            image_base + m.entry
        };
        entry_points.push(e);
    }

    Ok(Binary {
        format: Format::MachO,
        arch,
        image_base,
        entry_points,
        symbols,
        memory,
        debug: DebugInfo {
            pdb_path: None,
            has_dwarf,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_map_lookup_and_read() {
        let bin = Binary::raw(&[0x90, 0x90, 0xc3], 0x1000, Arch::X86_64);
        assert!(bin.memory.is_executable(0x1002));
        assert!(!bin.memory.is_mapped(0x1003));
        assert_eq!(bin.memory.read(0x1001, 2).unwrap(), vec![0x90, 0xc3]);
        assert!(bin.memory.read(0x1002, 2).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Binary::from_bytes(b"definitely not a binary").is_err());
    }

    #[test]
    fn loads_self() {
        // The test executable itself is a valid native binary.
        let exe = std::env::current_exe().unwrap();
        let bin = Binary::from_path(exe).unwrap();
        assert!(!bin.memory.is_empty());
        assert!(!bin.entry_points.is_empty());
    }
}
