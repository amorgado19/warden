//! Interactive rescue shell (T8.1).
//!
//! Reached when the config is missing/invalid or a boot fails. Speaks serial
//! first (GC-02) so it is fully operable headless. The operator can inspect
//! state — list entries, summarise the memory map, read the measured-boot PCRs —
//! and boot a one-off entry by number, reboot, or halt. Inspecting and halting
//! need no config; listing/booting need a parsed config and its bytes.

use core::fmt::Write;
use core::time::Duration;

use alloc::string::String;
use uefi::boot::{memory_map, stall, MemoryType};
use uefi::mem::memory_map::MemoryMap;
use uefi::runtime::{reset, ResetType};
use uefi::Status;
use warden_config::{Config, ConsoleMode};

use crate::console::{self, input::InputReader, input::Key};
use crate::measure;

const TICK_MS: u64 = 50;

/// Run the rescue shell. `reason` explains why we are here. Returns only if the
/// operator halts (the caller then halts the CPU); reboot/boot never return here.
pub fn run(config: Option<&Config>, config_bytes: Option<&[u8]>, reason: &str) {
    // Rescue always speaks serial (GC-02); widen to the firmware console too if a
    // parsed config asked for it, but never drop serial.
    let mode = match config.map(|c| c.global.console) {
        Some(ConsoleMode::Firmware | ConsoleMode::Both) => ConsoleMode::Both,
        _ => ConsoleMode::Serial,
    };

    console::emit(mode, "\n=== WARDEN RESCUE ===\n");
    console::emit(mode, "reason: ");
    console::emit(mode, reason);
    console::emit(mode, "\n");
    help(mode);

    let mut reader = InputReader::new();
    prompt(mode);
    loop {
        if let Some(key) = reader.poll() {
            match key {
                Key::Rescue => {
                    console::emit(mode, "\nrebooting...\n");
                    reset(ResetType::COLD, Status::SUCCESS, None); // never returns
                }
                Key::Char(b'q') | Key::Char(b'Q') => {
                    console::emit(mode, "\nhalting.\n");
                    return;
                }
                Key::Char(b'l') | Key::Char(b'L') => list_entries(mode, config),
                Key::Char(b'm') | Key::Char(b'M') => show_memmap(mode),
                Key::Char(b'p') | Key::Char(b'P') => {
                    console::emit(mode, "\nmeasured-boot state:\n");
                    measure::show_measured_state();
                }
                Key::Char(b'h') | Key::Char(b'H') | Key::Char(b'?') => help(mode),
                Key::Digit(n) => boot_one_off(mode, config, config_bytes, n),
                _ => {}
            }
            prompt(mode);
        }
        stall(Duration::from_millis(TICK_MS));
    }
}

fn prompt(mode: ConsoleMode) {
    console::emit(mode, "rescue> ");
}

fn help(mode: ConsoleMode) {
    console::emit(
        mode,
        "\ncommands: [l]ist entries  [m]emory map  [p]cr/measured state  \
         [1-9] boot entry N  [r]eboot  [q]uit(halt)  [h]elp\n",
    );
}

fn list_entries(mode: ConsoleMode, config: Option<&Config>) {
    let mut s = String::new();
    match config {
        Some(c) => {
            s.push_str("\nentries:\n");
            for (i, e) in c.entries.iter().enumerate() {
                let _ = write!(s, "  {}) {} — {} [{}]\n", i + 1, e.id, e.title, e.protocol.as_str());
            }
        }
        None => s.push_str("\n(no valid config loaded — nothing to list)\n"),
    }
    console::emit(mode, &s);
}

fn show_memmap(mode: ConsoleMode) {
    let map = match memory_map(MemoryType::LOADER_DATA) {
        Ok(m) => m,
        Err(e) => {
            let mut s = String::new();
            let _ = write!(s, "\nmemory map unavailable: {e:?}\n");
            console::emit(mode, &s);
            return;
        }
    };
    let (mut total, mut usable, mut regions) = (0u64, 0u64, 0u64);
    for d in map.entries() {
        total += d.page_count;
        regions += 1;
        if d.ty == MemoryType::CONVENTIONAL {
            usable += d.page_count;
        }
    }
    let mut s = String::new();
    let _ = write!(
        s,
        "\nmemory: {regions} regions, {} MiB total, {} MiB usable (CONVENTIONAL)\n",
        total * 4 / 1024,
        usable * 4 / 1024,
    );
    console::emit(mode, &s);
}

fn boot_one_off(mode: ConsoleMode, config: Option<&Config>, config_bytes: Option<&[u8]>, n: u8) {
    let (Some(cfg), Some(bytes)) = (config, config_bytes) else {
        console::emit(mode, "\n(no config loaded — cannot boot an entry)\n");
        return;
    };
    let idx = n as usize;
    let Some(entry) = cfg.entries.get(idx.wrapping_sub(1)) else {
        console::emit(mode, "\nno such entry\n");
        return;
    };
    log::info!("rescue: booting one-off entry {n}: '{}'", entry.id);
    // Control returns here if a kernel boot failed, or if a chainloaded app ran
    // and exited cleanly (both leave us in the shell). boot_entry logs the
    // specific outcome; keep the shell message neutral.
    crate::boot::boot_entry(cfg, bytes, entry);
    console::emit(mode, "\nentry returned control to rescue\n");
}
