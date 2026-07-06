//! Explicit UEFI chainloading (T8.2 / DEC-011).
//!
//! Loads and starts another UEFI application via `LoadImage`/`StartImage` — but
//! **only** when a config entry explicitly declares `protocol = "chainload"`.
//! Warden never auto-discovers or chainloads anything by default. The chainloaded
//! image is subject to the same verify → measure → execute discipline as a
//! kernel: a bad signature is refused, an unsigned image is refused under Secure
//! Boot, and the exact bytes are measured before they run.
//!
//! Unlike a kernel handoff, a chainloaded application may *return* (e.g. a UEFI
//! shell that exits); control then comes back to Warden.

use alloc::format;
use alloc::string::String;

use uefi::boot;
use warden_config::Entry;

use crate::{fs, measure, trust};

/// Chainload the UEFI application named by `entry.kernel`. Returns `Ok(())` if the
/// application ran and returned; `Err` if it could not be loaded/verified/started.
pub fn boot_chainload(entry: &Entry, config_bytes: &[u8]) -> Result<(), String> {
    // Read the exact bytes we will verify, measure, and execute (no TOCTOU).
    let image_bytes = fs::read_path(&entry.kernel, fs::MAX_KERNEL_BYTES)?;
    log::info!("chainload '{}': {} bytes", entry.kernel, image_bytes.len());

    // verify → measure → execute (IMP-006), same as the kernel paths.
    match entry.signature.as_deref() {
        Some(sig_path) => {
            let sig = fs::read_path(sig_path, fs::MAX_SIG_BYTES)?;
            trust::verify(&image_bytes, &sig)
                .map_err(|e| format!("REFUSING to chainload '{}': signature INVALID — {e}", entry.id))?;
            log::info!("signature OK: '{}' verified against the embedded key", entry.kernel);
        }
        None => {
            if trust::secure_boot_enabled() {
                return Err(format!(
                    "REFUSING to chainload unsigned entry '{}': Secure Boot is enabled",
                    entry.id
                ));
            }
            log::warn!("chainload entry '{}' is unsigned and Secure Boot is off — loading unverified", entry.id);
        }
    }

    let cmdline = entry.cmdline.as_deref().unwrap_or("");
    let outcome = measure::measure_and_gate(&measure::Inputs {
        config: config_bytes,
        entry_id: &entry.id,
        cmdline,
        kernel: &image_bytes,
        initrd: None,
    });
    log::info!("measured boot: {outcome:?}");

    let image = super::load_image_from_buffer(&image_bytes)?;

    log::info!("chainloading '{}' via StartImage…", entry.id);
    let result = boot::start_image(image).map_err(|e| format!("StartImage failed: {e:?}"));
    // The chainloaded app returned (it may legitimately exit); reclaim it.
    let _ = boot::unload_image(image);
    result?;
    log::info!("chainloaded '{}' returned control to Warden", entry.id);
    Ok(())
}
