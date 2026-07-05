//! x86_64 low-level primitives: the COM1 16550 UART and CPU halt.
//!
//! We talk to COM1 (I/O port `0x3F8`) directly rather than going through the
//! firmware Serial I/O protocol: raw port I/O is unconditionally available in
//! `-nographic` QEMU and does not depend on how OVMF happens to route its
//! console, which is exactly the "serial is always available" guarantee GC-02
//! relies on. Under QEMU the emulated UART is shared with the firmware; we only
//! ever *transmit*, so interleaving with firmware output is benign.

use core::arch::asm;

/// Base I/O port of COM1.
const COM1: u16 = 0x3F8;

// 16550 register offsets from the base port.
const REG_IER: u16 = 1; // Interrupt Enable (also divisor-high when DLAB=1)
const REG_FCR: u16 = 2; // FIFO Control
const REG_LCR: u16 = 3; // Line Control
const REG_MCR: u16 = 4; // Modem Control
const REG_LSR: u16 = 5; // Line Status

// Line Status Register bits.
#[allow(dead_code)] // consumed by `serial_read_byte`, first used for input in P1 (T1.4)
const LSR_DATA_READY: u8 = 0x01; // a byte is waiting in the receive buffer
const LSR_THR_EMPTY: u8 = 0x20; // transmit holding register can accept a byte

/// Write one byte to an I/O port.
///
/// # Safety
/// `port` must be a valid I/O port whose write has no memory-safety-relevant
/// side effects. Used here only for the COM1 UART register block.
#[inline]
unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

/// Read one byte from an I/O port.
///
/// # Safety
/// `port` must be a valid I/O port whose read has no memory-safety-relevant
/// side effects. Used here only for the COM1 UART register block.
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    val
}

/// Initialise COM1 to 115200 baud, 8N1, FIFO enabled. Idempotent.
pub fn serial_init() {
    // SAFETY: programming the standard COM1 UART register block (0x3F8..=0x3FD).
    // These writes have no memory-safety effects; re-running them is harmless.
    unsafe {
        outb(COM1 + REG_IER, 0x00); // disable UART interrupts
        outb(COM1 + REG_LCR, 0x80); // DLAB=1: next two writes set the divisor
        outb(COM1 + 0, 0x01); // divisor low  = 1  -> 115200 baud
        outb(COM1 + REG_IER, 0x00); // divisor high = 0
        outb(COM1 + REG_LCR, 0x03); // DLAB=0, 8 bits, no parity, 1 stop bit
        outb(COM1 + REG_FCR, 0xC7); // enable+clear FIFOs, 14-byte trigger level
        outb(COM1 + REG_MCR, 0x0B); // DTR, RTS, OUT2 asserted
    }
}

/// Number of THR-empty polls to tolerate before giving up on a byte. Bounds the
/// transmit spin so a wedged/absent UART degrades to dropped output instead of
/// hanging the CPU. At QEMU speeds this cap is never approached.
const TX_SPIN_CAP: u32 = 1_000_000;

/// Transmit one byte over COM1, spinning until the UART can accept it — but with
/// a bounded number of polls. Serial is the only output channel and the panic
/// handler writes through here *before* halting (GC-01), so an unbounded spin on
/// a UART whose THR-empty bit never asserts would deadlock the machine with
/// neither log nor halt. On cap exhaustion we drop the byte and return.
pub fn serial_write_byte(byte: u8) {
    // SAFETY: polling LSR and writing THR of the standard COM1 UART. No memory
    // effects; the spin loop only observes the transmit-holding-empty bit.
    unsafe {
        let mut spins: u32 = 0;
        while inb(COM1 + REG_LSR) & LSR_THR_EMPTY == 0 {
            spins += 1;
            if spins >= TX_SPIN_CAP {
                return; // wedged UART: drop the byte rather than hang forever
            }
        }
        outb(COM1, byte);
    }
}

/// Non-blocking read of one byte from COM1. Returns `None` if none is pending.
#[allow(dead_code)] // first wired up for menu input in P1 (T1.4)
pub fn serial_read_byte() -> Option<u8> {
    // SAFETY: reading LSR (status) and RBR (received byte) of COM1. No memory
    // effects; reading RBR only consumes a byte the UART already buffered.
    unsafe {
        if inb(COM1 + REG_LSR) & LSR_DATA_READY != 0 {
            Some(inb(COM1))
        } else {
            None
        }
    }
}

/// Halt the CPU forever (used at end-of-life and on panic). Never returns.
///
/// Masks interrupts first: with IF clear, the firmware timer/watchdog IRQ can no
/// longer wake us, so the firmware never dispatches its watchdog-expiry reset —
/// a hardware backstop to the explicit `set_watchdog_timer(0, …)` disarm in
/// `efi_main`, together guaranteeing AC0.2's "halts, no reboot loop". Safe
/// because we never return to firmware or touch boot services again.
pub fn halt() -> ! {
    // SAFETY: `cli` masks maskable interrupts. It modifies RFLAGS.IF (hence no
    // `preserves_flags`). We intend never to service another interrupt.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
    loop {
        // SAFETY: `hlt` only pauses the CPU; with interrupts masked it pauses
        // until an NMI/SMI. No memory effects.
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
