//! Warden — a memory-safe UEFI boot manager.
//!
//! P0 bootstrap: come up under UEFI firmware, install a serial-first logger,
//! print a banner + the firmware memory map, and halt cleanly. This establishes
//! the whole toolchain and run loop that every later phase builds on.

#![no_std]
#![no_main]

mod arch;
mod console;
mod firmware;

use core::panic::PanicInfo;

use uefi::prelude::*;

/// Target architecture name, for the banner.
const TARGET_ARCH: &str = if cfg!(target_arch = "x86_64") {
    "x86_64"
} else if cfg!(target_arch = "aarch64") {
    "aarch64"
} else {
    "unknown"
};

/// Firmware entry point. The `#[entry]` macro records the image handle and
/// system table (used by `uefi::boot`/`uefi::system`) and exports this as
/// `efi_main`. This function never returns — it ends in a halt loop (AC0.2:
/// "the app halts, no reboot loop"), so returning control to the firmware boot
/// manager (which would re-launch us) cannot happen.
#[entry]
fn efi_main() -> Status {
    console::init();

    // Disarm the firmware boot-manager watchdog (UEFI spec §7.5). It is armed to
    // ~5 minutes before our image is launched; because P0 never returns to the
    // boot manager and never calls ExitBootServices, an armed watchdog would fire
    // ResetSystem while we sit halted — the firmware then re-launches BOOTX64.EFI,
    // giving exactly the reboot loop AC0.2 forbids. Timeout 0 disables it.
    // (arch::halt() also masks interrupts as a hardware backstop.)
    if let Err(e) = uefi::boot::set_watchdog_timer(0, 0, None) {
        log::warn!("could not disarm firmware watchdog: {e:?}");
    }

    log::info!(
        "Warden v{} — memory-safe UEFI boot manager [{}]",
        env!("CARGO_PKG_VERSION"),
        TARGET_ARCH
    );
    log::info!("firmware vendor: {}", uefi::system::firmware_vendor());
    log::info!(
        "firmware revision: {:#010x}, UEFI revision: {}",
        uefi::system::firmware_revision(),
        uefi::system::uefi_revision()
    );

    let n = firmware::dump_memory_map();
    if n == 0 {
        log::error!("memory map was empty or unavailable — see above");
    }

    log::info!("P0 bootstrap complete — halting (headless, serial-operable).");
    arch::halt();
}

/// Panic handler (GC-01): report to serial directly — never depend on the
/// logger being installed — then halt forever. No unwinding (`panic = "abort"`).
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use core::fmt::Write;
    // Ensure the UART is up even if we panicked before `console::init`.
    arch::serial_init();
    let mut serial = console::Serial::new();
    let _ = writeln!(serial, "\n*** WARDEN PANIC: {info} ***");
    arch::halt();
}
