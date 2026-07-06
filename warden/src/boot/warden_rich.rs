//! The custom "warden-rich" handoff (DEC-007 / IMP-004).
//!
//! Unlike the Linux path (where the kernel stub owns ExitBootServices), here
//! **Warden owns the whole transition**: it loads an ELF kernel higher-half,
//! builds a fresh page-table hierarchy (identity map for the trampoline + a
//! higher-half direct map + the kernel mapping), populates a [`WardenBootInfo`],
//! performs the ExitBootServices memory-map-key dance (via the `uefi` crate),
//! and jumps to the kernel entry with `WardenBootInfo*` in `rdi`.
//!
//! Memory model handed to the kernel:
//!   * identity map of the low [`IDENTITY_GIB`] GiB (also what the trampoline runs in),
//!   * HHDM: the same physical range mapped at [`HHDM_OFFSET`] (the kernel reads
//!     the physical pointers in `WardenBootInfo` by adding this offset),
//!   * the kernel image at its link address ([`vbase`], 4 KiB pages).

use alloc::format;
use alloc::string::String;
use core::ptr;

use uefi::boot::{self, AllocateType};
use uefi::mem::memory_map::{MemoryMap, MemoryType};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::table::cfg::ConfigTableEntry;
use warden_abi::{
    MemMap, MemRegion, MemoryKind, ModuleList, OptFb, OptRange, PhysStr, PixelFormat as AbiPixelFormat,
    WardenBootInfo, WARDEN_ABI_VERSION, WARDEN_MAGIC,
};
use warden_config::Entry;

use super::elf;
use crate::{arch, fs, measure, trust};

const PAGE: u64 = 4096;
/// Higher-half direct map base (canonical, negative-address half).
const HHDM_OFFSET: u64 = 0xffff_8000_0000_0000;
/// How much low physical memory the identity map and HHDM cover (1 GiB pages).
const IDENTITY_GIB: u64 = 4;

// x86_64 page-table entry flags.
#[cfg(target_arch = "x86_64")]
const PRESENT: u64 = 1 << 0;
#[cfg(target_arch = "x86_64")]
const WRITABLE: u64 = 1 << 1;
#[cfg(target_arch = "x86_64")]
const HUGE: u64 = 1 << 7;

/// Load and launch a warden-rich ELF kernel. Returns only on failure.
pub fn boot_warden_rich(entry: &Entry, config_bytes: &[u8]) -> Result<(), String> {
    // --- verify + measure (same discipline as the Linux path) ---
    let kernel = fs::read_path(&entry.kernel, fs::MAX_KERNEL_BYTES)?;
    log::info!("rich kernel '{}': {} bytes", entry.kernel, kernel.len());
    match entry.signature.as_deref() {
        Some(sig_path) => {
            let sig = fs::read_path(sig_path, fs::MAX_SIG_BYTES)?;
            trust::verify(&kernel, &sig).map_err(|e| format!("REFUSING to boot: kernel signature INVALID — {e}"))?;
            log::info!("signature OK: '{}' verified against the embedded key", entry.kernel);
        }
        None => {
            if trust::secure_boot_enabled() {
                return Err(format!("REFUSING to boot unsigned entry '{}': Secure Boot is enabled", entry.id));
            }
            log::warn!("entry '{}' is unsigned and Secure Boot is off — booting unverified", entry.id);
        }
    }
    let cmdline = entry.cmdline.as_deref().unwrap_or("");
    let outcome = measure::measure_and_gate(&measure::Inputs {
        config: config_bytes,
        entry_id: &entry.id,
        cmdline,
        kernel: &kernel,
        initrd: None,
    });
    log::info!("measured boot: {outcome:?}");

    // --- parse + load the ELF (every ELF-derived value is hostile; GC-03) ---
    let image = elf::parse(&kernel)?;
    let vbase = image.min_vaddr & !(PAGE - 1);
    // Checked round-up: a crafted max_vaddr near u64::MAX must not wrap `vend` to
    // 0 (which would collapse kernel_pages and bypass the layout guard below).
    let vend = image
        .max_vaddr
        .checked_add(PAGE - 1)
        .ok_or_else(|| String::from("kernel vaddr range overflows"))?
        & !(PAGE - 1);
    let kernel_pages = (vend - vbase) / PAGE;
    let pml4_idx = (vbase >> 39) & 0x1ff;
    let hhdm_idx = (HHDM_OFFSET >> 39) & 0x1ff;
    // The P4 loader maps a single 2 MiB window at a canonical higher-half base
    // whose PML4 slot is disjoint from the identity (0) and HHDM slots — else the
    // kernel mapping would clobber one of those and triple-fault after `mov cr3`.
    if kernel_pages == 0
        || kernel_pages > 512
        || vbase & 0x1f_ffff != 0
        || vbase < 0xffff_8000_0000_0000
        || pml4_idx == 0
        || pml4_idx == hhdm_idx
    {
        return Err(format!(
            "unsupported kernel layout (base {vbase:#x}, {kernel_pages} pages): P4 requires a higher-half base, 2 MiB-aligned, ≤2 MiB, PML4 slot disjoint from identity/HHDM"
        ));
    }
    log::info!("kernel vaddr {vbase:#x}..{vend:#x} ({kernel_pages} pages), entry {:#x}", image.entry);

    let kphys = alloc_pages(kernel_pages)?;
    let region_len = kernel_pages * PAGE;
    // SAFETY: `kphys` is a freshly-allocated, identity-mapped region of exactly
    // `kernel_pages` pages we own; zero it before copying (also zeroes BSS tails).
    unsafe { ptr::write_bytes(kphys as *mut u8, 0, region_len as usize) };
    for seg in &image.segments {
        // Explicitly enforce that the destination stays inside the kernel region,
        // so the unsafe copy's bounds claim is checked, not assumed.
        let off = seg.virt_addr.checked_sub(vbase).ok_or_else(|| String::from("segment below kernel base"))?;
        let end = off.checked_add(seg.file_size as u64).ok_or_else(|| String::from("segment size overflows"))?;
        if end > region_len {
            return Err(String::from("segment extends past the kernel region"));
        }
        let src = &kernel[seg.file_offset..seg.file_offset + seg.file_size];
        // SAFETY: bounds checked above — `kphys+off .. +file_size` ⊆ the kernel
        // region; `src` is an in-bounds slice of the ELF buffer.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), (kphys + off) as *mut u8, seg.file_size) };
    }
    // aarch64's I/D caches are not coherent: the kernel image was just written via
    // data stores, so sync it to the Point of Unification before it is executed.
    #[cfg(target_arch = "aarch64")]
    arch::sync_instruction_cache(kphys, region_len);

    // --- allocate handoff structures + page tables BEFORE ExitBootServices ---
    // Size the region array from the live map plus slack for the growth our own
    // pre-EBS allocations add (the array must be allocated before EBS).
    let live_regions = boot::memory_map(MemoryType::LOADER_DATA).map(|m| m.len()).unwrap_or(256);
    let max_regions = live_regions + 64;
    let memmap_phys = alloc_pages(((max_regions * core::mem::size_of::<MemRegion>()) as u64).div_ceil(PAGE))?;
    let bootinfo_phys = alloc_pages(1)?;
    let fb = framebuffer();
    let rsdp = rsdp();
    // The page-table format is the only arch-specific part of the build: x86_64
    // returns one CR3 root; aarch64 returns (TTBR0 identity, TTBR1 HHDM+kernel).
    #[cfg(target_arch = "x86_64")]
    let root = build_page_tables(kphys, vbase, kernel_pages)?;
    #[cfg(target_arch = "aarch64")]
    let root = build_page_tables_aarch64(kphys, vbase, kernel_pages)?;

    // --- point of no return: exit boot services, then finish the handoff with
    //     NO allocation (only pointer writes + the returned map). ---
    log::info!("exiting boot services; Warden owns the handoff from here");
    // SAFETY: all needed memory is already allocated; we make no boot-services
    // calls after this. The `uefi` crate performs the memory-map-key retry dance.
    let memmap = unsafe { boot::exit_boot_services(None) };

    // Fill the MemRegion array from the final post-EBS memory map. (Logging over
    // serial is fine post-EBS; no allocation happens here.)
    let regions = memmap_phys as *mut MemRegion;
    let mut count = 0usize;
    for d in memmap.entries() {
        if count >= max_regions {
            log::warn!("post-EBS memory map exceeds {max_regions} regions — truncated");
            break;
        }
        // SAFETY: `regions[count]` is within the allocated array (count < max).
        unsafe {
            regions.add(count).write(MemRegion {
                base: d.phys_start,
                pages: d.page_count,
                kind: classify(d.ty),
                _pad: 0,
            });
        }
        count += 1;
    }

    // Re-tag the region holding the loaded kernel image as non-reclaimable, so a
    // kernel that reclaims BOOTLOADER_RECLAIMABLE RAM cannot free its own live
    // code/data. (The kernel was allocated LOADER_DATA, classified as
    // reclaimable; over-tagging an adjacent coalesced descriptor is conservative.)
    for i in 0..count {
        // SAFETY: `i < count <= max_regions`, within the allocated array.
        let r = unsafe { &mut *regions.add(i) };
        let end = r.base.saturating_add(r.pages.saturating_mul(PAGE));
        if r.base <= kphys && kphys < end {
            r.kind = MemoryKind::KERNEL_AND_MODULES;
        }
    }

    // SAFETY: `bootinfo_phys` is our allocated, page-aligned WardenBootInfo slot.
    unsafe {
        (bootinfo_phys as *mut WardenBootInfo).write(WardenBootInfo {
            magic: WARDEN_MAGIC,
            abi_version: WARDEN_ABI_VERSION,
            _pad: 0,
            memmap: MemMap { regions: memmap_phys, count: count as u64 },
            framebuffer: fb,
            modules: ModuleList::EMPTY,
            hhdm_offset: HHDM_OFFSET,
            rsdp,
            tpm_event_log: OptRange::NONE,
            cmdline: PhysStr::EMPTY,
        });
    }

    log::info!("jumping to warden-rich kernel: entry={:#x} regions={count}", image.entry);
    // Pass the boot info as an HHDM-virtual pointer (kernel reads it via HHDM).
    let bootinfo_virt = bootinfo_phys + HHDM_OFFSET;
    // SAFETY: the page tables map the current PC (identity), the boot info
    // (HHDM), and the kernel (its link address). Boot services are exited.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        arch::enter_kernel(root, image.entry, bootinfo_virt)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        arch::enter_kernel(root.0, root.1, image.entry, bootinfo_virt)
    }
}

/// Allocate `n` zeroable pages, returning the (identity-mapped) physical base.
fn alloc_pages(n: u64) -> Result<u64, String> {
    let ptr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, n as usize)
        .map_err(|e| format!("allocate_pages({n}) failed: {e:?}"))?;
    Ok(ptr.as_ptr() as u64)
}

/// Allocate one page table, zeroed; return its physical address.
fn alloc_table() -> Result<u64, String> {
    let addr = alloc_pages(1)?;
    // SAFETY: freshly-allocated, identity-mapped 4 KiB page we own.
    unsafe { ptr::write_bytes(addr as *mut u8, 0, PAGE as usize) };
    Ok(addr)
}

/// Write `value` into `table[idx]` (both physical/identity-mapped).
fn set_entry(table: u64, idx: u64, value: u64) {
    // SAFETY: `table` is one of our page-table pages and `idx < 512`.
    unsafe { (table as *mut u64).add(idx as usize).write(value) };
}

/// Build a 4-level page-table hierarchy: identity + HHDM (2 MiB pages) + kernel
/// (4 KiB pages). Returns the PML4 physical address.
///
/// 2 MiB pages (PS at the PD level) are used rather than 1 GiB pages because
/// every long-mode CPU supports them, whereas 1 GiB pages require the CPUID
/// `PDPE1GB` feature — the identity map underpins the trampoline itself, so it
/// must never fault.
#[cfg(target_arch = "x86_64")]
fn build_page_tables(kphys: u64, vbase: u64, kernel_pages: u64) -> Result<u64, String> {
    let pml4 = alloc_table()?;

    // Identity map + HHDM of the low IDENTITY_GIB GiB, both via 2 MiB pages.
    map_low_2mib(pml4, 0)?;
    map_low_2mib(pml4, (HHDM_OFFSET >> 39) & 0x1ff)?;

    // Kernel: vbase..+kernel_pages*4K -> kphys (4 KiB pages). vbase is 2 MiB
    // aligned (checked by the caller), so it starts at PT index 0, and its PML4
    // slot is disjoint from identity/HHDM (also checked by the caller).
    let pdpt_k = alloc_table()?;
    let pd_k = alloc_table()?;
    let pt_k = alloc_table()?;
    for i in 0..kernel_pages {
        set_entry(pt_k, i, (kphys + i * PAGE) | PRESENT | WRITABLE);
    }
    set_entry(pd_k, (vbase >> 21) & 0x1ff, pt_k | PRESENT | WRITABLE);
    set_entry(pdpt_k, (vbase >> 30) & 0x1ff, pd_k | PRESENT | WRITABLE);
    set_entry(pml4, (vbase >> 39) & 0x1ff, pdpt_k | PRESENT | WRITABLE);

    Ok(pml4)
}

/// Map the low `IDENTITY_GIB` GiB of physical memory into `pml4[pml4_idx]` using
/// 2 MiB pages (one PDPT + one PD per GiB).
#[cfg(target_arch = "x86_64")]
fn map_low_2mib(pml4: u64, pml4_idx: u64) -> Result<(), String> {
    let pdpt = alloc_table()?;
    for gib in 0..IDENTITY_GIB {
        let pd = alloc_table()?;
        for j in 0..512u64 {
            let phys = (gib << 30) | (j << 21);
            set_entry(pd, j, phys | PRESENT | WRITABLE | HUGE);
        }
        set_entry(pdpt, gib, pd | PRESENT | WRITABLE);
    }
    set_entry(pml4, pml4_idx, pdpt | PRESENT | WRITABLE);
    Ok(())
}

// aarch64 (VMSAv8-64, 4 KiB granule) page-table descriptor bits. Table/page
// descriptors are `0b11`, block descriptors `0b01` (both set the valid bit).
#[cfg(target_arch = "aarch64")]
const A64_TABLE: u64 = 0b11;
#[cfg(target_arch = "aarch64")]
const A64_BLOCK: u64 = 0b01;
#[cfg(target_arch = "aarch64")]
const A64_AF: u64 = 1 << 10; // access flag (must be set or the access faults)
#[cfg(target_arch = "aarch64")]
const A64_SH_INNER: u64 = 0b11 << 8; // inner shareable
#[cfg(target_arch = "aarch64")]
const A64_ATTR_NORMAL: u64 = 0 << 2; // AttrIndx -> MAIR attr0 (Normal WB)
#[cfg(target_arch = "aarch64")]
const A64_ATTR_DEVICE: u64 = 1 << 2; // AttrIndx -> MAIR attr1 (Device nGnRnE)
/// On the QEMU `virt` machine RAM begins at 1 GiB; everything below is MMIO
/// (PL011, GIC, RTC, flash, ...) and must be mapped as Device memory.
#[cfg(target_arch = "aarch64")]
const A64_RAM_BASE: u64 = 0x4000_0000;

#[cfg(target_arch = "aarch64")]
fn a64_normal_block(pa: u64) -> u64 {
    pa | A64_AF | A64_SH_INNER | A64_ATTR_NORMAL | A64_BLOCK
}
#[cfg(target_arch = "aarch64")]
fn a64_device_block(pa: u64) -> u64 {
    pa | A64_AF | A64_ATTR_DEVICE | A64_BLOCK
}
#[cfg(target_arch = "aarch64")]
fn a64_normal_page(pa: u64) -> u64 {
    pa | A64_AF | A64_SH_INNER | A64_ATTR_NORMAL | A64_TABLE
}

/// Build the aarch64 translation tables and return `(ttbr0, ttbr1)`.
///
/// * TTBR0 (low half): identity map of the low `IDENTITY_GIB` GiB via 2 MiB
///   blocks — sub-`A64_RAM_BASE` as Device (so the kernel's PL011 MMIO works),
///   RAM as Normal (the trampoline, page tables, and kernel image live here).
/// * TTBR1 (high half): the HHDM at [`HHDM_OFFSET`] (Normal) plus the higher-half
///   kernel mapped with 4 KiB pages. The two share a single L0 table at disjoint
///   slots (256 for the HHDM, 511 for the kernel).
#[cfg(target_arch = "aarch64")]
fn build_page_tables_aarch64(kphys: u64, vbase: u64, kernel_pages: u64) -> Result<(u64, u64), String> {
    // --- TTBR0: identity ---
    let ttbr0 = alloc_table()?;
    let l1_id = alloc_table()?;
    set_entry(ttbr0, 0, l1_id | A64_TABLE);
    for gib in 0..IDENTITY_GIB {
        let l2 = alloc_table()?;
        for j in 0..512u64 {
            let pa = (gib << 30) | (j << 21);
            let desc = if pa < A64_RAM_BASE { a64_device_block(pa) } else { a64_normal_block(pa) };
            set_entry(l2, j, desc);
        }
        set_entry(l1_id, gib, l2 | A64_TABLE);
    }

    // --- TTBR1: HHDM (view of physical memory) ---
    // Use the SAME Device/Normal split as the identity map: the sub-A64_RAM_BASE
    // MMIO hole must stay Device here too, so we don't create a second, Normal-
    // cacheable alias of device registers (which speculation could disturb).
    let ttbr1 = alloc_table()?;
    let l1_h = alloc_table()?;
    set_entry(ttbr1, (HHDM_OFFSET >> 39) & 0x1ff, l1_h | A64_TABLE);
    for gib in 0..IDENTITY_GIB {
        let l2 = alloc_table()?;
        for j in 0..512u64 {
            let pa = (gib << 30) | (j << 21);
            let desc = if pa < A64_RAM_BASE { a64_device_block(pa) } else { a64_normal_block(pa) };
            set_entry(l2, j, desc);
        }
        set_entry(l1_h, gib, l2 | A64_TABLE);
    }

    // --- TTBR1: the higher-half kernel (4 KiB pages) ---
    let l1_k = alloc_table()?;
    let l2_k = alloc_table()?;
    let l3_k = alloc_table()?;
    for i in 0..kernel_pages {
        set_entry(l3_k, i, a64_normal_page(kphys + i * PAGE));
    }
    set_entry(l2_k, (vbase >> 21) & 0x1ff, l3_k | A64_TABLE);
    set_entry(l1_k, (vbase >> 30) & 0x1ff, l2_k | A64_TABLE);
    set_entry(ttbr1, (vbase >> 39) & 0x1ff, l1_k | A64_TABLE);

    Ok((ttbr0, ttbr1))
}

/// Map a UEFI memory type to the ABI's `MemoryKind`. Boot-services memory is
/// free after ExitBootServices; loader memory holds the live handoff structures
/// + page tables, so it is reclaimable-but-not-yet.
fn classify(ty: MemoryType) -> MemoryKind {
    match ty {
        MemoryType::CONVENTIONAL | MemoryType::BOOT_SERVICES_CODE | MemoryType::BOOT_SERVICES_DATA => {
            MemoryKind::USABLE
        }
        MemoryType::LOADER_CODE | MemoryType::LOADER_DATA => MemoryKind::BOOTLOADER_RECLAIMABLE,
        MemoryType::ACPI_RECLAIM => MemoryKind::ACPI_RECLAIMABLE,
        MemoryType::ACPI_NON_VOLATILE => MemoryKind::ACPI_NVS,
        MemoryType::MMIO | MemoryType::MMIO_PORT_SPACE => MemoryKind::MMIO,
        MemoryType::UNUSABLE => MemoryKind::BAD_MEMORY,
        _ => MemoryKind::RESERVED,
    }
}

/// Read the linear framebuffer from GOP, or `OptFb::NONE` if none is present.
fn framebuffer() -> OptFb {
    let Ok(handle) = boot::get_handle_for_protocol::<GraphicsOutput>() else {
        return OptFb::NONE;
    };
    let Ok(mut gop) = boot::open_protocol_exclusive::<GraphicsOutput>(handle) else {
        return OptFb::NONE;
    };
    let mode = gop.current_mode_info();
    let (width, height) = mode.resolution();
    let format = match mode.pixel_format() {
        PixelFormat::Rgb => AbiPixelFormat::RGBX8,
        PixelFormat::Bgr => AbiPixelFormat::BGRX8,
        _ => AbiPixelFormat::OTHER,
    };
    let pitch = (mode.stride() * 4) as u64;
    let base = gop.frame_buffer().as_mut_ptr() as u64;
    OptFb {
        present: 1,
        _pad: [0; 7],
        base,
        pitch,
        width: width as u32,
        height: height as u32,
        bpp: 32,
        format,
    }
}

/// Physical address of the ACPI RSDP (prefer ACPI 2.0), or 0 if not found.
fn rsdp() -> u64 {
    uefi::system::with_config_table(|entries| {
        let mut acpi1 = 0u64;
        for e in entries {
            if e.guid == ConfigTableEntry::ACPI2_GUID {
                return e.address as u64;
            }
            if e.guid == ConfigTableEntry::ACPI_GUID {
                acpi1 = e.address as u64;
            }
        }
        acpi1
    })
}
