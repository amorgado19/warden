//! Minimal rescue prompt (T1.5).
//!
//! When the config is missing, unreadable, non-UTF-8, or malformed, Warden must
//! **not** panic (GC-01 / AC1.3). It prints a readable reason and an interactive
//! prompt where the operator can reboot (`r`) or halt (any other key). The full
//! interactive rescue *shell* (inspect memmap/PCRs, edit+boot a one-off entry)
//! is P8; this is the safety-net stub that stands in until then.

use core::time::Duration;

use uefi::boot::stall;
use uefi::runtime::{reset, ResetType};
use uefi::Status;
use warden_config::{Config, ConsoleMode};

use crate::console::{self, input::InputReader, input::Key};

/// Show the rescue prompt. `reason` is a human-readable explanation of why we
/// are here. Returns only if the operator chooses to halt (the caller then
/// halts the CPU); choosing reboot never returns.
pub fn run(config: Option<&Config>, reason: &str) {
    // Rescue always speaks on serial (the always-available channel, GC-02). If a
    // parsed config asked for the firmware console too, widen to Both — but never
    // drop serial, or a headless operator could be left staring at a blank line.
    let mode = match config.map(|c| c.global.console) {
        Some(ConsoleMode::Firmware | ConsoleMode::Both) => ConsoleMode::Both,
        _ => ConsoleMode::Serial,
    };

    console::emit(mode, "\n=== WARDEN RESCUE ===\n");
    console::emit(mode, "the boot configuration is unavailable or invalid; no entry was booted.\n");
    console::emit(mode, "reason: ");
    console::emit(mode, reason);
    console::emit(mode, "\nkeys: [r] reboot, any other key halts\nrescue> ");

    let mut reader = InputReader::new();
    loop {
        if let Some(key) = reader.poll() {
            match key {
                Key::Rescue => {
                    console::emit(mode, "\nrebooting...\n");
                    // Never returns.
                    reset(ResetType::COLD, Status::SUCCESS, None);
                }
                _ => {
                    console::emit(mode, "\nhalting.\n");
                    return;
                }
            }
        }
        stall(Duration::from_millis(TICK_MS));
    }
}

const TICK_MS: u64 = 50;
