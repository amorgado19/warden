//! Boot a Linux kernel via its EFI stub (DEC-005).
//!
//! Modern `x86_64` `vmlinuz` images are themselves PE/COFF EFI applications
//! (`CONFIG_EFI_STUB`). Warden reads the kernel bytes from the ESP, hands them to
//! the firmware with `LoadImage`, sets the kernel command line in the loaded
//! image's `LoadOptions`, attaches an initrd via the Linux initrd-media
//! `LOAD_FILE2` protocol, and calls `StartImage`. The kernel's own stub then
//! queries the memory map, calls `ExitBootServices`, and boots the OS.
//!
//! This means **the kernel stub owns `ExitBootServices`**, not Warden — the
//! robust, idiomatic path for chainloading a stock kernel (as systemd-boot /
//! rEFInd do). Warden performs its own `ExitBootServices` in P4, for the custom
//! rich handoff where there is no stub to do it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use uefi::boot::{self, LoadImageSource};
use uefi::proto::loaded_image::LoadedImage;
use uefi::Handle;
use uefi_raw::protocol::loaded_image::LoadedImageProtocol;
use warden_config::Entry;

use crate::{fs, measure, trust};

mod initrd;

/// Load and start the Linux kernel named by `entry`. Returns only on failure —
/// a successful boot transfers control to the kernel and never comes back.
pub fn boot_linux(entry: &Entry, config_bytes: &[u8]) -> Result<(), String> {
    // Read the kernel + initrd from the ESP ONCE, so the exact bytes we measure
    // and verify are the exact bytes we execute (no TOCTOU). `LoadImage` copies
    // the kernel buffer, so it need not outlive the load call.
    let kernel = fs::read_path(&entry.kernel, fs::MAX_KERNEL_BYTES)?;
    log::info!("kernel '{}': {} bytes", entry.kernel, kernel.len());

    let initrd = match entry.initrd.as_deref() {
        Some(path) => {
            let data = fs::read_path(path, fs::MAX_INITRD_BYTES)?;
            log::info!("initrd '{path}': {} bytes", data.len());
            Some(data)
        }
        None => {
            log::info!("no initrd configured for '{}'", entry.id);
            None
        }
    };

    // Verify the kernel signature against Warden's embedded key BEFORE measuring
    // or loading anything (IMP-006: verify → measure → execute). A bad signature
    // is refused here; an unsigned entry is refused only when Secure Boot is on.
    match entry.signature.as_deref() {
        Some(sig_path) => {
            let sig = fs::read_path(sig_path, fs::MAX_SIG_BYTES)?;
            match trust::verify(&kernel, &sig) {
                Ok(()) => log::info!("signature OK: '{}' verified against the embedded key", entry.kernel),
                Err(e) => {
                    return Err(format!("REFUSING to boot: kernel signature INVALID — {e}"));
                }
            }
        }
        None => {
            if trust::secure_boot_enabled() {
                return Err(format!(
                    "REFUSING to boot unsigned entry '{}': Secure Boot is enabled",
                    entry.id
                ));
            }
            log::warn!("entry '{}' is unsigned and Secure Boot is off — booting unverified", entry.id);
        }
    }

    let cmdline = entry.cmdline.as_deref().unwrap_or("");

    // Measure the exact bytes we are about to trust, then self-verify the
    // measured-boot chain (event log replays to the PCR values). Best-effort:
    // absent a TPM this is skipped and the boot proceeds (measured boot is an
    // integrity add-on, not a boot prerequisite in P3).
    let outcome = measure::measure_and_gate(&measure::Inputs {
        config: config_bytes,
        entry_id: &entry.id,
        cmdline,
        kernel: &kernel,
        initrd: initrd.as_deref(),
    });
    log::info!("measured boot: {outcome:?}");

    let image = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromBuffer { buffer: &kernel, file_path: None },
    )
    .map_err(|e| format!("LoadImage failed: {e:?}"))?;

    // `run_loaded` only returns on failure; unload the image on the way out so a
    // failed boot doesn't orphan it in firmware memory.
    let result = run_loaded(image, cmdline, initrd);
    let _ = boot::unload_image(image);
    result
}

/// Set the cmdline + initrd on the already-loaded `image`, then `StartImage`.
/// Returns `Err` only if the boot failed; a successful boot never returns.
fn run_loaded(image: Handle, cmdline: &str, initrd: Option<Vec<u8>>) -> Result<(), String> {
    // Command line via LoadOptions (UCS-2). `cmdline16` MUST stay alive across
    // StartImage — the stub reads it during boot.
    let cmdline16: Vec<u16> = cmdline.encode_utf16().chain(core::iter::once(0)).collect();
    set_load_options(image, &cmdline16)?;
    log::info!("cmdline: {cmdline:?}");

    // Optional initrd, exposed to the stub via the initrd-media LOAD_FILE2
    // protocol. The registration must stay alive across StartImage.
    let _initrd_guard = match initrd {
        Some(data) => Some(initrd::register(data)?),
        None => None,
    };

    log::info!("starting Linux EFI stub — it performs ExitBootServices and takes over the machine");

    // On success this never returns; if it does, the stub failed before taking
    // over the machine.
    let ret = boot::start_image(image);
    Err(format!("kernel returned control to Warden (StartImage -> {ret:?}); boot did not proceed"))
}

/// Point the loaded image's `LoadOptions` at our UCS-2 command line.
fn set_load_options(image: Handle, cmdline16: &[u16]) -> Result<(), String> {
    let mut li = boot::open_protocol_exclusive::<LoadedImage>(image)
        .map_err(|e| format!("open LoadedImage failed: {e:?}"))?;
    // `LoadedImage` is a `repr(transparent)` wrapper over `LoadedImageProtocol`.
    let raw = &mut *li as *mut LoadedImage as *mut LoadedImageProtocol;
    // SAFETY: `raw` is the firmware's LoadedImageProtocol for this freshly loaded,
    // exclusively-opened image. We set the load-options pointer/length to the
    // caller's UCS-2 buffer (kept alive across StartImage). Size is bytes
    // including the trailing NUL.
    unsafe {
        (*raw).load_options = cmdline16.as_ptr() as *const c_void;
        (*raw).load_options_size = (core::mem::size_of_val(cmdline16)) as u32;
    }
    Ok(())
}
