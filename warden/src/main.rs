//! Warden — a memory-safe UEFI boot manager.
//!
//! P0 bootstrap: serial-first logger, banner, firmware memory-map dump, clean
//! halt. P1 adds: load `warden.toml` from the ESP, present a numbered text menu
//! with a countdown + serial/console input, and a rescue prompt on bad config.
//! Actually handing control to a kernel is P2.

#![no_std]
#![no_main]

extern crate alloc;

mod arch;
mod console;
mod firmware;
mod fs;

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

/// Config file, at the root of the ESP Warden was loaded from.
const CONFIG_PATH: &uefi::CStr16 = uefi::cstr16!("warden.toml");

/// Firmware entry point. The `#[entry]` macro records the image handle and
/// system table (used by `uefi::boot`/`uefi::system`) and exports this as
/// `efi_main`. This function never returns — it ends in a halt loop (AC0.2).
#[entry]
fn efi_main() -> Status {
    console::init();

    // Disarm the firmware boot-manager watchdog (UEFI spec §7.5). It is armed to
    // ~5 minutes before our image is launched; because P0/P1 never return to the
    // boot manager and never call ExitBootServices, an armed watchdog would fire
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

    boot_menu_phase();

    // Distinct end-of-life marker: appears only here, immediately before the CPU
    // is parked, so a test can prove `arch::halt()` was actually reached (not a
    // mid-tail log that merely contains the word "halt").
    log::info!("warden: reached final halt — parking CPU (headless, serial-operable).");
    arch::halt();
}

/// P1: load + parse the config, then either drive the menu or drop to rescue.
/// Any failure ends in the rescue prompt — never a panic (AC1.3).
fn boot_menu_phase() {
    use alloc::format;

    let bytes = match fs::read_esp_file(CONFIG_PATH) {
        Ok(b) => b,
        Err(e) => {
            log::error!("config load failed: {e}");
            console::rescue::run(None, &e);
            return;
        }
    };

    let text = match core::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(_) => {
            log::error!("config is not valid UTF-8");
            console::rescue::run(None, "warden.toml is not valid UTF-8");
            return;
        }
    };

    let config = match warden_config::parse(text) {
        Ok(c) => c,
        Err(e) => {
            // Readable error + rescue prompt, no crash (AC1.3).
            log::error!("config parse failed: {e}");
            console::rescue::run(None, &format!("{e}"));
            return;
        }
    };

    log::info!(
        "config OK: {} entries, default '{}', console {:?}, timeout {}s",
        config.entries.len(),
        config.global.default,
        config.global.console,
        config.global.timeout
    );

    match console::menu::run(&config) {
        console::menu::Choice::Boot(i) => {
            let e = &config.entries[i];
            log::info!(
                "selected entry: {} — title='{}' protocol={} kernel='{}'",
                e.id,
                e.title,
                e.protocol.as_str(),
                e.kernel
            );
            log::info!("kernel handoff is implemented in P2 — halting after selection");
        }
        console::menu::Choice::Rescue => {
            console::rescue::run(Some(&config), "rescue requested from the menu");
        }
    }
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
