//! Serial-first console + logging (GC-02 / DEC-008).
//!
//! Warden installs a single [`log`] backend — the one mux point for all output.
//! Every record is written to the COM1 serial line, which is always present in a
//! headless `-nographic` boot; that is the "serial is always available"
//! guarantee GC-02 requires.
//!
//! Note on the firmware text console: under OVMF `-nographic`, firmware ConOut
//! is itself routed to COM1, so also writing there would double every line on
//! the one physical wire. Console *routing* (serial / firmware / both) is a
//! per-boot config choice (`console = …`, ADR IMP-005) introduced in P1; until
//! config exists, P0 logs to serial only.

use core::fmt::{self, Write};

use log::{LevelFilter, Metadata, Record};

use crate::arch;

/// A zero-sized writer over the primary serial line (COM1).
///
/// Implements [`core::fmt::Write`], translating `\n` into `\r\n` so output is
/// well-formed on a raw serial terminal. Writes are direct port I/O with no
/// buffered state, so a `Serial` can be created freely wherever output is
/// needed (including the panic handler, before the logger is installed).
pub struct Serial;

impl Serial {
    /// Create a serial writer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for Serial {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                arch::serial_write_byte(b'\r');
            }
            arch::serial_write_byte(byte);
        }
        Ok(())
    }
}

/// The one and only `log` backend.
struct WardenLogger;

static LOGGER: WardenLogger = WardenLogger;

impl log::Log for WardenLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        // Serial first (GC-02): guaranteed available headless.
        let mut serial = Serial::new();
        let _ = writeln!(serial, "[warden {:<5}] {}", record.level(), record.args());
    }

    fn flush(&self) {}
}

/// Bring up the serial UART and install the serial-first logger. Call once,
/// as early as possible in `efi_main`. Safe to call more than once (subsequent
/// `set_logger` calls are ignored).
pub fn init() {
    arch::serial_init();
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(LevelFilter::Trace);
}
