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

/// Install the kernel translation tables and jump to `entry`, passing `arg` in
/// `x0` (AAPCS64 first argument). `ttbr_phys` is loaded into `TTBR0_EL1` (the
/// low-half table that must map both the current instruction stream and the
/// trampoline); the higher-half kernel/HHDM mapping is installed via `TTBR1_EL1`
/// by the rich-handoff builder before this is called. Never returns.
///
/// # Safety
/// Boot services must be exited. The translation tables must map the current PC
/// (so the post-`msr` fetch doesn't fault) and `entry`; `entry` must be
/// executable code expecting a `WardenBootInfo*` in `x0`. Interrupts are masked.
pub unsafe fn enter_kernel(ttbr_phys: u64, entry: u64, arg: u64) -> ! {
    asm!(
        "msr daifset, #0xf",     // mask D/A/I/F interrupts
        "msr ttbr0_el1, {ttbr}", // install the low-half translation table
        "dsb ish",
        "isb",
        "tlbi vmalle1",          // invalidate stage-1 TLB for EL1
        "dsb ish",
        "isb",
        "br {entry}",            // jump; x0 already holds arg
        ttbr = in(reg) ttbr_phys,
        entry = in(reg) entry,
        in("x0") arg,
        options(noreturn),
    );
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
