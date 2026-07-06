//! Minimal, bounds-checked ELF64 parsing for the warden-rich loader.
//!
//! An ELF kernel is a boot module and therefore hostile (GC-03): every field is
//! range-checked against the buffer, and any malformed structure is an `Err`,
//! never a panic. We only parse what the loader needs — the entry point and the
//! `PT_LOAD` segments.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

const PT_LOAD: u32 = 1;
const ET_EXEC: u16 = 2;
/// Expected `e_machine`: the kernel must be built for the arch Warden runs on.
#[cfg(target_arch = "x86_64")]
const EXPECTED_MACHINE: u16 = 0x3E; // EM_X86_64
#[cfg(target_arch = "aarch64")]
const EXPECTED_MACHINE: u16 = 0xB7; // EM_AARCH64

/// One loadable segment. The BSS tail (`mem_size > file_size`) needs no field:
/// the loader zeroes the whole kernel region before copying `file_size` bytes.
pub struct Segment {
    pub file_offset: usize,
    pub file_size: usize,
    pub virt_addr: u64,
}

/// What the loader needs from an ELF image.
pub struct Image {
    pub entry: u64,
    pub min_vaddr: u64,
    pub max_vaddr: u64,
    pub segments: Vec<Segment>,
}

/// Parse an ELF64 executable, returning its entry point and loadable segments.
pub fn parse(elf: &[u8]) -> Result<Image, String> {
    // ELF64 header is 64 bytes.
    let hdr = elf.get(..64).ok_or_else(|| String::from("ELF too small for a header"))?;
    if &hdr[0..4] != b"\x7fELF" {
        return Err(String::from("not an ELF (bad magic)"));
    }
    if hdr[4] != 2 {
        return Err(String::from("not a 64-bit ELF"));
    }
    if hdr[5] != 1 {
        return Err(String::from("not a little-endian ELF"));
    }
    // Only ET_EXEC: we do not apply relocations, so a PIE (ET_DYN) kernel would
    // be mapped at the wrong addresses.
    let e_type = u16(hdr, 16);
    if e_type != ET_EXEC {
        return Err(format!("unsupported ELF type {e_type} (want EXEC)"));
    }
    let e_machine = u16(hdr, 18);
    if e_machine != EXPECTED_MACHINE {
        return Err(format!("ELF machine {e_machine:#x} does not match this build ({EXPECTED_MACHINE:#x})"));
    }

    let entry = u64f(hdr, 24);
    let e_phoff = u64f(hdr, 32) as usize;
    let e_phentsize = u16(hdr, 54) as usize;
    let e_phnum = u16(hdr, 56) as usize;

    if e_phentsize < 56 {
        return Err(format!("program header entry size {e_phentsize} too small"));
    }

    let mut segments = Vec::new();
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;

    for i in 0..e_phnum {
        let off = e_phoff
            .checked_add(i.checked_mul(e_phentsize).ok_or_else(|| String::from("phdr index overflow"))?)
            .ok_or_else(|| String::from("phdr offset overflow"))?;
        let ph = elf
            .get(off..off.checked_add(56).ok_or_else(|| String::from("phdr end overflow"))?)
            .ok_or_else(|| String::from("program header out of range"))?;

        if u32(ph, 0) != PT_LOAD {
            continue;
        }
        let p_offset = u64f(ph, 8) as usize;
        let p_vaddr = u64f(ph, 16);
        let p_filesz = u64f(ph, 32) as usize;
        let p_memsz = u64f(ph, 40);

        if p_memsz < p_filesz as u64 {
            return Err(String::from("segment mem_size < file_size"));
        }
        // File content must be within the buffer.
        let end = p_offset.checked_add(p_filesz).ok_or_else(|| String::from("segment file range overflow"))?;
        if end > elf.len() {
            return Err(String::from("segment file content out of range"));
        }
        let vend = p_vaddr.checked_add(p_memsz).ok_or_else(|| String::from("segment vaddr range overflow"))?;

        min_vaddr = min_vaddr.min(p_vaddr);
        max_vaddr = max_vaddr.max(vend);
        let _ = p_memsz; // consumed above for max_vaddr; BSS is pre-zeroed by the loader
        segments.push(Segment { file_offset: p_offset, file_size: p_filesz, virt_addr: p_vaddr });
    }

    if segments.is_empty() {
        return Err(String::from("ELF has no PT_LOAD segments"));
    }
    if entry < min_vaddr || entry >= max_vaddr {
        return Err(format!("entry {entry:#x} outside loadable range"));
    }

    Ok(Image { entry, min_vaddr, max_vaddr, segments })
}

fn u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u64f(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}
