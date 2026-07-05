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

use crate::fs;

mod initrd;

/// Load and start the Linux kernel named by `entry`. Returns only on failure —
/// a successful boot transfers control to the kernel and never comes back.
pub fn boot_linux(entry: &Entry) -> Result<(), String> {
    // Read the kernel image from the ESP. `LoadImage` copies the buffer, so it
    // need not outlive the load call.
    let kernel = fs::read_path(&entry.kernel, fs::MAX_KERNEL_BYTES)?;
    log::info!("kernel '{}': {} bytes", entry.kernel, kernel.len());

    let image = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromBuffer { buffer: &kernel, file_path: None },
    )
    .map_err(|e| format!("LoadImage failed: {e:?}"))?;

    // Everything after this can fail; `run_loaded` only returns on failure, so
    // unload the loaded image on the way out to avoid orphaning it in firmware
    // memory (a successful boot never returns from `run_loaded`).
    let outcome = run_loaded(image, entry);
    let _ = boot::unload_image(image);
    outcome
}

/// Set the cmdline + initrd on the already-loaded `image`, then `StartImage`.
/// Returns `Err` only if the boot failed; a successful boot never returns.
fn run_loaded(image: Handle, entry: &Entry) -> Result<(), String> {
    // Command line via LoadOptions (UCS-2). `cmdline16` MUST stay alive across
    // StartImage — the stub reads it during boot.
    let cmdline = entry.cmdline.as_deref().unwrap_or("");
    let cmdline16: Vec<u16> = cmdline.encode_utf16().chain(core::iter::once(0)).collect();
    set_load_options(image, &cmdline16)?;
    log::info!("cmdline: {cmdline:?}");

    // Optional initrd, exposed to the stub via the initrd-media LOAD_FILE2
    // protocol. The registration must stay alive across StartImage.
    let _initrd_guard = match entry.initrd.as_deref() {
        Some(path) => {
            let data = fs::read_path(path, fs::MAX_INITRD_BYTES)?;
            log::info!("initrd '{path}': {} bytes", data.len());
            Some(initrd::register(data)?)
        }
        None => {
            log::info!("no initrd configured for '{}'", entry.id);
            None
        }
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
