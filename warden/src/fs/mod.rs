//! Filesystem access.
//!
//! P1 reads a single file — `warden.toml` — from the ESP via the firmware's
//! Simple File System protocol (the volume Warden itself was loaded from). The
//! dedicated read-only ext4/btrfs readers arrive in P5 as sibling modules here.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use uefi::CStr16;

/// Hard cap on a config file we will allocate for. The firmware-reported file
/// size is untrusted (GC-03): a corrupt/hostile FAT directory entry claiming a
/// multi-gigabyte size would otherwise make `FileSystem::read` allocate that
/// much and abort on OOM instead of failing gracefully to rescue. `warden.toml`
/// is tiny; 1 MiB is a generous ceiling.
const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// Read a file from the ESP root (the volume this image was loaded from), after
/// bounds-checking its firmware-reported size.
///
/// Returns the file bytes, or a human-readable error message on any failure
/// (missing volume, missing file, oversized file, I/O error). Callers treat
/// failure as "no usable config" and drop to the rescue prompt — never a panic
/// (GC-03 / AC1.3).
pub fn read_esp_file(path: &CStr16) -> Result<Vec<u8>, String> {
    let sfs = uefi::boot::get_image_file_system(uefi::boot::image_handle())
        .map_err(|e| format!("cannot open the ESP filesystem: {e:?}"))?;
    let mut fs = uefi::fs::FileSystem::new(sfs);

    // Validate the declared length *before* allocating for it (GC-03).
    let info = fs
        .metadata(path)
        .map_err(|e| format!("cannot stat {path}: {e:?}"))?;
    let size = info.file_size();
    if size > MAX_CONFIG_BYTES {
        return Err(format!(
            "{path} is {size} bytes, over the {MAX_CONFIG_BYTES}-byte limit — refusing to load"
        ));
    }

    fs.read(path).map_err(|e| format!("cannot read {path}: {e:?}"))
}
