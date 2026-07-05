//! UEFI firmware glue.
//!
//! P0 exercises exactly one firmware service: fetching and dumping the physical
//! memory map (T0.4). Later phases grow this module with GOP, the Simple File
//! System, and the `ExitBootServices` dance.

use log::{error, info};
use uefi::mem::memory_map::{MemoryMap, MemoryType};

/// UEFI page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Fetch the UEFI memory map and pretty-print it to the log (serial-first).
///
/// Returns the number of descriptors printed, or `0` if the map could not be
/// obtained (the error is logged). Every arithmetic step is saturating: the
/// firmware map is trusted less than our own state (GC-03), and a bogus
/// `page_count` must never overflow into a panic.
pub fn dump_memory_map() -> usize {
    let map = match uefi::boot::memory_map(MemoryType::LOADER_DATA) {
        Ok(map) => map,
        Err(e) => {
            error!("could not obtain UEFI memory map: {e:?}");
            return 0;
        }
    };

    let meta = map.meta();
    let count = map.len();
    info!(
        "UEFI memory map: {count} descriptors (map_size={} B, desc_size={} B, desc_ver={})",
        meta.map_size, meta.desc_size, meta.desc_version
    );

    let mut total_pages: u64 = 0;
    let mut usable_pages: u64 = 0;
    for (i, d) in map.entries().enumerate() {
        let bytes = d.page_count.saturating_mul(PAGE_SIZE);
        let end = d.phys_start.saturating_add(bytes);
        info!(
            "  [{i:>3}] {:<22?} {:#013x}..{:#013x} {:>9} pages {:>8} KiB  att={:#x}",
            d.ty,
            d.phys_start,
            end,
            d.page_count,
            bytes / 1024,
            d.att.bits(),
        );
        total_pages = total_pages.saturating_add(d.page_count);
        if d.ty == MemoryType::CONVENTIONAL {
            usable_pages = usable_pages.saturating_add(d.page_count);
        }
    }

    info!(
        "memory summary: {} MiB mapped, {} MiB usable (CONVENTIONAL) across {count} regions",
        total_pages.saturating_mul(PAGE_SIZE) / (1024 * 1024),
        usable_pages.saturating_mul(PAGE_SIZE) / (1024 * 1024),
    );
    count
}
