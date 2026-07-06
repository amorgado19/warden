//! Filesystem access.
//!
//! P1 read `warden.toml` from the ESP; P2 generalises this to read kernels and
//! initrds named by a config path scheme. Only the `esp:` scheme (the FAT ESP,
//! via the firmware Simple File System) is supported here — the read-only
//! `ext4:`/`btrfs:` readers arrive in P5 as sibling modules.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use uefi::{CStr16, CString16};

/// Config file, at the root of the ESP Warden was loaded from.
pub const CONFIG_PATH: &CStr16 = uefi::cstr16!("warden.toml");

/// Size ceilings. The firmware-reported file size is untrusted (GC-03): we
/// reject anything over the cap *before* allocating, so a corrupt directory
/// entry claiming a multi-gigabyte size fails to rescue instead of attempting a
/// huge allocation. NOTE: the firmware's `FileSystem::read` then allocates the
/// full (under-cap) size infallibly, so these caps must stay comfortably below
/// the target's free heap — they bound, but do not make fallible, the read.
pub const MAX_CONFIG_BYTES: u64 = 1 << 20; //   1 MiB — warden.toml is tiny
pub const MAX_KERNEL_BYTES: u64 = 64 << 20; //  64 MiB — a bzImage
pub const MAX_INITRD_BYTES: u64 = 128 << 20; // 128 MiB — an initramfs
pub const MAX_SIG_BYTES: u64 = 4096; //         4 KiB — a detached signature

/// Read `warden.toml` from the ESP root.
pub fn read_config() -> Result<Vec<u8>, String> {
    read_esp_file(CONFIG_PATH, MAX_CONFIG_BYTES)
}

/// Read a file named by a config path scheme (e.g. `esp:/boot/vmlinuz`).
///
/// Only the `esp:` scheme is understood in P2; anything else is a clear error
/// (ext4/btrfs land in P5). `max_bytes` bounds the allocation.
pub fn read_path(scheme_path: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let rel = scheme_path
        .strip_prefix("esp:")
        .ok_or_else(|| format!("unsupported path scheme in '{scheme_path}' (only esp: is supported until P5)"))?;

    // Normalise to a UEFI relative path: drop the leading slash, and use `\`
    // separators, which the firmware file system expects.
    let rel = rel.trim_start_matches('/');
    let mut winpath = String::with_capacity(rel.len());
    for c in rel.chars() {
        winpath.push(if c == '/' { '\\' } else { c });
    }
    if winpath.is_empty() {
        return Err(format!("empty path in '{scheme_path}'"));
    }

    let cpath =
        CString16::try_from(winpath.as_str()).map_err(|_| format!("invalid characters in path '{scheme_path}'"))?;
    read_esp_file(&cpath, max_bytes)
}

/// Read a file from the ESP root (the volume this image was loaded from), after
/// bounds-checking its firmware-reported size against `max_bytes`.
///
/// Returns the file bytes, or a human-readable error message on any failure.
/// Callers treat failure as recoverable (rescue / next entry) — never a panic
/// (GC-03 / AC1.3).
pub fn read_esp_file(path: &CStr16, max_bytes: u64) -> Result<Vec<u8>, String> {
    let sfs = uefi::boot::get_image_file_system(uefi::boot::image_handle())
        .map_err(|e| format!("cannot open the ESP filesystem: {e:?}"))?;
    let mut fs = uefi::fs::FileSystem::new(sfs);

    // Validate the declared length *before* allocating for it (GC-03).
    let info = fs
        .metadata(path)
        .map_err(|e| format!("cannot stat {path}: {e:?}"))?;
    let size = info.file_size();
    if size > max_bytes {
        return Err(format!(
            "{path} is {size} bytes, over the {max_bytes}-byte limit — refusing to load"
        ));
    }

    fs.read(path).map_err(|e| format!("cannot read {path}: {e:?}"))
}
