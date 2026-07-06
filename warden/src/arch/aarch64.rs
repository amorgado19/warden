//! aarch64 low-level primitives: the PL011 UART (QEMU `virt`) and CPU halt.
//!
//! Mirrors `arch::x86_64`. We talk to the PL011 UART by MMIO rather than through
//! the firmware Serial I/O protocol: it is unconditionally available in
//! `-nographic` QEMU regardless of how the firmware routes its console (GC-02).
//! As on x86 we only ever *transmit* and share the UART with the firmware, so
//! interleaving is benign. The base address is the QEMU `virt` PL011 location.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

/// PL011 UART base on the QEMU `virt` machine.
const PL011_BASE: usize = 0x0900_0000;
const UART_DR: usize = 0x00; // data register
const UART_FR: usize = 0x18; // flag register
const FR_TXFF: u32 = 1 << 5; // transmit FIFO full
const FR_RXFE: u32 = 1 << 4; // receive FIFO empty

/// The firmware already configured the PL011; like the x86 COM1 path we only
/// transmit and share it, so no (re)initialisation is needed. Kept for API parity.
pub fn serial_init() {}

/// Number of TX-full polls to tolerate before dropping a byte — bounds the spin
/// so a wedged/absent UART degrades to lost output instead of hanging (mirrors
/// the x86 `TX_SPIN_CAP`; the panic handler transmits through here before halt).
const TX_SPIN_CAP: u32 = 1_000_000;

/// Transmit one byte over the PL011, bounded-spinning while the TX FIFO is full.
pub fn serial_write_byte(byte: u8) {
    // SAFETY: MMIO to the PL011 register block. Volatile accesses with a bounded
    // spin observing only the TX-full flag; no memory-safety effects.
    unsafe {
        let mut spins: u32 = 0;
        while read_volatile((PL011_BASE + UART_FR) as *const u32) & FR_TXFF != 0 {
            spins += 1;
            if spins >= TX_SPIN_CAP {
                return; // wedged UART: drop the byte rather than hang forever
            }
        }
        write_volatile((PL011_BASE + UART_DR) as *mut u8, byte);
    }
}

/// Non-blocking read of one byte from the PL011. Returns `None` if none pending.
#[allow(dead_code)] // wired up for menu input in P1 (T1.4), same as x86
pub fn serial_read_byte() -> Option<u8> {
    // SAFETY: MMIO reads of the PL011 FR (status) and DR (received byte). Reading
    // DR only consumes a byte the UART already buffered.
    unsafe {
        if read_volatile((PL011_BASE + UART_FR) as *const u32) & FR_RXFE == 0 {
            Some(read_volatile((PL011_BASE + UART_DR) as *const u8))
        } else {
            None
        }
    }
}

/// `MAIR_EL1`: attr0 = Normal, Inner+Outer Write-Back non-transient (`0xFF`);
/// attr1 = Device-nGnRnE (`0x00`). The page-table builder tags RAM with AttrIndx
/// 0 and device MMIO with AttrIndx 1.
pub const MAIR_VALUE: u64 = 0x0000_0000_0000_00FF;

/// `TCR_EL1`: 48-bit VA for both halves (T0SZ=T1SZ=16), 4 KiB granule (TG0=00,
/// TG1=10), inner-shareable Write-Back-WA table walks, IPS = 40-bit PA (covers
/// the QEMU `virt` map, ≤ the Cortex-A72 44-bit PARange).
pub const TCR_VALUE: u64 = 0x0000_0002_B510_3510;

/// Install the rich-handoff translation tables and jump to `entry`, passing `arg`
/// in `x0` (AAPCS64 first argument). `ttbr0` maps the low half (identity — the
/// current instruction stream, the page tables, and device MMIO); `ttbr1` maps
/// the high half (the HHDM and the higher-half kernel). Never returns.
///
/// # Safety
/// Boot services must be exited. The tables must map the current PC (identity, so
/// the fetch after the register writes doesn't fault) and `entry`; `entry` must be
/// executable code expecting a `WardenBootInfo*` in `x0`. Interrupts are masked.
/// The firmware MMU is left enabled (`SCTLR_EL1.M=1`); we only swap the tables and
/// the matching `TCR`/`MAIR`, with the trampoline running identity-mapped across
/// the switch.
pub unsafe fn enter_kernel(ttbr0: u64, ttbr1: u64, entry: u64, arg: u64) -> ! {
    asm!(
        "msr daifset, #0xf",       // mask D/A/I/F interrupts
        "dsb ish",                 // page-table descriptor stores visible to the walker
        "msr mair_el1, {mair}",    // memory attribute indirection
        "msr ttbr0_el1, {ttbr0}",  // low-half (identity) table
        "msr ttbr1_el1, {ttbr1}",  // high-half (HHDM + kernel) table
        "msr tcr_el1, {tcr}",      // 48-bit / 4 KiB regime matching the tables
        "isb",
        "tlbi vmalle1",            // drop stale stage-1 EL1 translations
        "dsb ish",
        "isb",
        "br {entry}",              // jump; x0 already holds arg
        mair = in(reg) MAIR_VALUE,
        tcr = in(reg) TCR_VALUE,
        ttbr0 = in(reg) ttbr0,
        ttbr1 = in(reg) ttbr1,
        entry = in(reg) entry,
        in("x0") arg,
        options(noreturn),
    );
}

/// Make freshly-written code at `[base, base+len)` executable: clean the D-cache
/// to the Point of Unification, then invalidate the I-cache. aarch64 I/D caches
/// are **not** coherent, so a kernel image copied in via data stores must be
/// synced before it is fetched or the CPU may execute stale bytes. (x86_64 needs
/// no equivalent — its caches are architecturally coherent.)
pub fn sync_instruction_cache(base: u64, len: u64) {
    // SAFETY: cache-maintenance ops (`dc cvau` / `ic iallu`) over a range we own;
    // they touch only cache state, never memory contents or safety invariants.
    unsafe {
        // D-cache minimum line size from CTR_EL0.DminLine (log2 of words).
        let ctr: u64;
        asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack));
        let line = 4u64 << ((ctr >> 16) & 0xf);
        let mut addr = base & !(line - 1);
        let end = base + len;
        while addr < end {
            asm!("dc cvau, {}", in(reg) addr, options(nomem, nostack, preserves_flags));
            addr += line;
        }
        asm!("dsb ish", options(nomem, nostack, preserves_flags));
        asm!("ic iallu", options(nomem, nostack, preserves_flags)); // invalidate I-cache to PoU
        asm!("dsb ish", options(nomem, nostack, preserves_flags));
        asm!("isb", options(nomem, nostack, preserves_flags));
    }
}

/// Halt the CPU forever (end-of-life and panic). Never returns.
///
/// Masks all interrupts via `DAIFSet` so the firmware timer/watchdog can no
/// longer wake us (the aarch64 analogue of the x86 `cli`), then parks in `wfi` —
/// together with the explicit watchdog disarm this guarantees AC0.2's clean halt.
pub fn halt() -> ! {
    // SAFETY: masking DAIF interrupts modifies PSTATE only; we never intend to
    // service another interrupt or return to firmware.
    unsafe {
        asm!("msr daifset, #0xf", options(nomem, nostack));
    }
    loop {
        // SAFETY: `wfi` only pauses the CPU until an interrupt/event; with
        // interrupts masked it parks. No memory effects.
        unsafe {
            asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}
