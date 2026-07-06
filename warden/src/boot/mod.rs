//! Kernel boot protocols.
//!
//! P2 implements the Linux path via the EFI stub ([`linux`]). The custom
//! "warden-rich" handoff lands in P4.

pub mod chainload;
mod elf;
pub mod linux;
pub mod warden_rich;

use warden_config::{Config, Entry, Protocol};

/// Boot the selected entry. Returns **only if the boot failed** (on success the
/// kernel takes over the machine and never returns to us); the caller then drops
/// to the rescue prompt.
pub fn boot_entry(_config: &Config, config_bytes: &[u8], entry: &Entry) {
    match entry.protocol {
        Protocol::LinuxEfi => {
            if let Err(e) = linux::boot_linux(entry, config_bytes) {
                log::error!("linux boot of '{}' failed: {e}", entry.id);
            }
        }
        Protocol::WardenRich => {
            if let Err(e) = warden_rich::boot_warden_rich(entry, config_bytes) {
                log::error!("warden-rich boot of '{}' failed: {e}", entry.id);
            }
        }
        Protocol::Chainload => {
            if let Err(e) = chainload::boot_chainload(entry, config_bytes) {
                log::error!("chainload of '{}' failed: {e}", entry.id);
            }
        }
    }
}
