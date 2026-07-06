//! Raw block-device access for the on-disk filesystem readers (ext4/btrfs).
//!
//! We read arbitrary byte ranges via the firmware `DiskIo` protocol, and pick
//! the right device by probing its superblock magic — the FAT ESP is skipped
//! because it won't match. Every read is bounds-checked against the device size
//! (GC-03: on-disk data is hostile).

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::disk::DiskIo;
use uefi::Handle;

/// A raw disk supporting byte-granular reads.
pub struct Disk {
    disk_io: ScopedProtocol<DiskIo>,
    media_id: u32,
    size: u64,
}

impl Disk {
    /// Read exactly `buf.len()` bytes starting at byte `offset`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| String::from("disk read range overflow"))?;
        if end > self.size {
            return Err(format!("disk read {offset}+{} exceeds device size {}", buf.len(), self.size));
        }
        self.disk_io
            .read_disk(self.media_id, offset, buf)
            .map_err(|e| format!("DiskIo read at {offset:#x} failed: {e:?}"))
    }

    /// Read `len` bytes at `offset` into a fresh buffer.
    pub fn read_vec(&self, offset: u64, len: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        self.read_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// Return the first block device whose contents satisfy `probe` (e.g. an ext4 or
/// btrfs superblock magic). Returns an error if none match.
pub fn find_disk<F: Fn(&Disk) -> bool>(probe: F) -> Result<Disk, String> {
    let handles =
        boot::find_handles::<BlockIO>().map_err(|e| format!("enumerating block devices: {e:?}"))?;
    for handle in handles {
        if let Some(disk) = open_disk(handle) {
            if probe(&disk) {
                return Ok(disk);
            }
        }
    }
    Err(String::from("no matching filesystem found on any block device"))
}

fn open_disk(handle: Handle) -> Option<Disk> {
    // Open non-destructively (GetProtocol): the firmware already holds BlockIO /
    // DiskIo open on real disks, so an exclusive open would fail.
    let agent = boot::image_handle();

    // Media id + size come from BlockIO; the byte reads go through DiskIo.
    let (media_id, size) = {
        let params = OpenProtocolParams { handle, agent, controller: None };
        // SAFETY: GetProtocol opens the interface read-only without disturbing
        // any existing (firmware) opener; we only read media metadata.
        let bio = unsafe { boot::open_protocol::<BlockIO>(params, OpenProtocolAttributes::GetProtocol) }.ok()?;
        let media = bio.media();
        if !media.is_media_present() {
            return None;
        }
        let block_size = u64::from(media.block_size());
        let size = (media.last_block() + 1).checked_mul(block_size)?;
        (media.media_id(), size)
    };

    let params = OpenProtocolParams { handle, agent, controller: None };
    // SAFETY: as above — non-destructive GetProtocol open for byte reads.
    let disk_io = unsafe { boot::open_protocol::<DiskIo>(params, OpenProtocolAttributes::GetProtocol) }.ok()?;
    Some(Disk { disk_io, media_id, size })
}
