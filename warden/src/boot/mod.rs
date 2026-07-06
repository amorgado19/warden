//! Kernel boot protocols.
//!
//! P2 implements the Linux path via the EFI stub ([`linux`]). The custom
//! "warden-rich" handoff lands in P4.

pub mod chainload;
mod elf;
pub mod linux;
pub mod warden_rich;

use alloc::format;
use alloc::string::String;

use uefi::boot::{self, LoadImageSource};
use uefi::proto::loaded_image::LoadedImage;
use uefi::Handle;
use warden_config::{Config, Entry, Protocol};

/// `LoadImage` an EFI image from an in-memory buffer (the exact verified bytes).
///
/// We pass Warden's own image device path (from our `LoadedImage`) as the
/// `file_path`: AAVMF (ArmVirtQemu) returns `INVALID_PARAMETER` for a `FromBuffer`
/// load with a NULL device path (it needs one to set the loaded image's
/// `FilePath`), whereas OVMF tolerates NULL. Reusing our own path is a valid
/// device path on both arches; the `SourceBuffer` still determines the actual
/// bytes loaded, so this does not weaken the verify-then-execute guarantee.
pub fn load_image_from_buffer(buffer: &[u8]) -> Result<Handle, String> {
    // Keep the protocol wrapper alive across `load_image` (it borrows the path).
    let self_li = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()).ok();
    let file_path = self_li.as_ref().and_then(|li| li.file_path());
    if file_path.is_none() {
        // We could not obtain our own device path, so the load falls back to a
        // NULL path — which AAVMF (arm64) rejects with INVALID_PARAMETER. Surface
        // the root cause so that failure isn't misread as a bad image. OVMF
        // tolerates a NULL path, so we still proceed rather than refuse the boot.
        log::warn!("LoadImage: no self device path available — arm64 firmware may reject this load");
    }
    boot::load_image(boot::image_handle(), LoadImageSource::FromBuffer { buffer, file_path })
        .map_err(|e| format!("LoadImage failed: {e:?}"))
}

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
