//! Expose an initrd to the Linux EFI stub via the initrd-media `LOAD_FILE2`
//! protocol.
//!
//! Modern kernels (>= 5.8) fetch their initrd by locating an
//! `EFI_LOAD_FILE2_PROTOCOL` on a handle whose device path is the well-known
//! vendor-media node `LINUX_EFI_INITRD_MEDIA_GUID`, then calling its `LoadFile`
//! twice (once to size the buffer, once to fill it). This is the only method
//! that also works under Secure Boot, and it needs no filesystem path handling.
//!
//! We install two interfaces on a fresh handle: the `LOAD_FILE2` protocol (whose
//! callback serves our in-memory initrd) and the device path identifying it. The
//! returned [`Registration`] owns everything the firmware/kernel may dereference;
//! it must outlive `StartImage`, and its `Drop` uninstalls + frees on a failed
//! boot.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use uefi::boot;
use uefi::{guid, Guid, Handle};
use uefi_raw::protocol::device_path::DevicePathProtocol;
use uefi_raw::protocol::media::LoadFile2Protocol;
use uefi_raw::{Boolean, Status};

/// `LINUX_EFI_INITRD_MEDIA_GUID` — the device-path vendor GUID the kernel stub
/// searches for.
const LINUX_EFI_INITRD_MEDIA_GUID: Guid = guid!("5568e427-68fc-4f3d-ac74-ca555231cc68");

/// A `LOAD_FILE2` interface plus the initrd it serves. `proto` MUST be the first
/// field (offset 0): the interface pointer we hand firmware is a *whole-struct*
/// pointer cast to `*LoadFile2Protocol`, so the callback recovering the container
/// reads `data`/`len` within that pointer's provenance.
#[repr(C)]
struct InitrdLoader {
    proto: LoadFile2Protocol,
    data: *const u8,
    len: usize,
}

/// Keeps the installed initrd alive. On drop (a failed boot) it uninstalls the
/// interfaces and frees the loader; on a successful boot it is never dropped.
pub struct Registration {
    handle: Handle,
    /// Owned `InitrdLoader` (leaked from a `Box`); freed in `Drop`.
    loader: *mut InitrdLoader,
    /// Backing storage the firmware/kernel may dereference until boot proceeds.
    _data: Vec<u8>,
    dpath: Vec<u8>,
    dpath_installed: bool,
}

impl Drop for Registration {
    fn drop(&mut self) {
        // SAFETY: we uninstall exactly the interfaces we installed on `handle`,
        // passing back the identical interface pointers, then reclaim the leaked
        // `Box<InitrdLoader>`. Best-effort — uninstall errors are ignored. This
        // only runs on a failed boot (a successful boot never returns here).
        unsafe {
            if self.dpath_installed {
                let _ = boot::uninstall_protocol_interface(
                    self.handle,
                    &DevicePathProtocol::GUID,
                    self.dpath.as_ptr().cast(),
                );
            }
            let _ = boot::uninstall_protocol_interface(
                self.handle,
                &LoadFile2Protocol::GUID,
                self.loader.cast(),
            );
            drop(Box::from_raw(self.loader));
        }
    }
}

/// The `EFI_LOAD_FILE2_PROTOCOL.LoadFile` callback: serves the whole initrd.
///
/// # Safety
/// Invoked by firmware/kernel per the UEFI ABI. `this` is the interface pointer
/// we installed — a whole-`InitrdLoader` pointer (its first field is `proto`).
/// `buffer_size` is valid; `buffer` is either null or points to at least
/// `*buffer_size` writable bytes.
unsafe extern "efiapi" fn load_file(
    this: *mut LoadFile2Protocol,
    _file_path: *const DevicePathProtocol,
    _boot_policy: Boolean,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if this.is_null() || buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: `this` was installed as a whole-`InitrdLoader` pointer (proto at
    // offset 0), so this cast recovers the container with full provenance.
    let loader = unsafe { &*this.cast::<InitrdLoader>() };
    let want = loader.len;

    // SAFETY: `buffer_size` is a valid, caller-owned `usize`.
    let provided = unsafe { *buffer_size };
    // Sizing call, or too-small buffer: report the required size.
    if buffer.is_null() || provided < want {
        unsafe { *buffer_size = want };
        return Status::BUFFER_TOO_SMALL;
    }

    // SAFETY: caller guarantees `buffer` has >= `want` writable bytes (we just
    // told it), and `loader.data`/`len` describe our initrd bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(loader.data, buffer.cast::<u8>(), want);
        *buffer_size = want;
    }
    Status::SUCCESS
}

/// Register `data` as the initrd for the next `StartImage`.
pub fn register(data: Vec<u8>) -> Result<Registration, String> {
    let dpath = build_device_path();

    // Leak the loader to a raw whole-struct pointer (stable heap address; the
    // interface + callback both use *this* provenance).
    let loader = Box::new(InitrdLoader {
        proto: LoadFile2Protocol { load_file },
        data: data.as_ptr(),
        len: data.len(),
    });
    let raw: *mut InitrdLoader = Box::into_raw(loader);

    // Install LOAD_FILE2 on a new handle. The interface pointer is the whole
    // `InitrdLoader` (proto is at offset 0).
    // SAFETY: `raw` is a live, uniquely-owned InitrdLoader; its first field is a
    // valid LoadFile2Protocol. On success ownership passes to the guard below.
    let handle = match unsafe {
        boot::install_protocol_interface(None, &LoadFile2Protocol::GUID, raw.cast())
    } {
        Ok(h) => h,
        Err(e) => {
            // Nothing installed; reclaim the leaked box.
            // SAFETY: `raw` came from `Box::into_raw` and was never installed.
            unsafe { drop(Box::from_raw(raw)) };
            return Err(format!("install LOAD_FILE2 failed: {e:?}"));
        }
    };

    // Build the guard NOW so any later failure uninstalls + frees via Drop
    // (exception safety — no dangling registered interface).
    let mut reg = Registration { handle, loader: raw, _data: data, dpath, dpath_installed: false };

    // SAFETY: `reg.dpath` is a valid VenMedia/End device path whose bytes stay
    // valid and address-stable (owned by `reg`) for as long as the interface is
    // installed. On error, `reg` drops here and uninstalls the LOAD_FILE2 above.
    unsafe {
        boot::install_protocol_interface(Some(handle), &DevicePathProtocol::GUID, reg.dpath.as_ptr().cast())
    }
    .map_err(|e| format!("install initrd device path failed: {e:?}"))?;
    reg.dpath_installed = true;

    log::info!("initrd registered via LOAD_FILE2 (LINUX_EFI_INITRD_MEDIA)");
    Ok(reg)
}

/// Build the raw bytes of `VenMedia(LINUX_EFI_INITRD_MEDIA_GUID)/End` — a 20-byte
/// media/vendor node followed by the 4-byte end node.
fn build_device_path() -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.push(0x04); // MEDIA_DEVICE_PATH
    v.push(0x03); // MEDIA_VENDOR_DP
    v.extend_from_slice(&20u16.to_le_bytes()); // node length
    v.extend_from_slice(&LINUX_EFI_INITRD_MEDIA_GUID.to_bytes());
    v.push(0x7F); // END_DEVICE_PATH_TYPE
    v.push(0xFF); // END_ENTIRE_DEVICE_PATH_SUBTYPE
    v.extend_from_slice(&4u16.to_le_bytes());
    v
}
