//! P6 — A/B boot assessment + automatic rollback (DEC-012).
//!
//! Policy + record format live in the host-tested [`warden_assess`] crate; this
//! module is the UEFI glue: it finds the dedicated **state disk**, reads the two
//! double-buffered records, consumes the kernel's boot-success signal, runs the
//! decision, persists the new state **before** booting (write-new-then-swap), and
//! reports what to boot.
//!
//! ## Storage
//! A dedicated raw disk, identified by an 8-byte header magic in LBA 0. The two
//! state buffers live in LBA 1 and LBA 2. We only ever rewrite the buffer that
//! does *not* hold the current record, so an interrupted write can never destroy
//! the last good state (AC6.2).
//!
//! ## Boot-success signal (T6.3)
//! The OS, once healthy, sets the UEFI variable **`WardenConfirm`** (Warden
//! vendor GUID) to the booted entry's id. On the next boot Warden reads and
//! *deletes* it, and only then promotes that slot to `last_known_good` — never at
//! menu render. See `docs/warden-boot-success-signal.md`.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::proto::media::block::BlockIO;
use uefi::runtime::{self, VariableVendor};
use uefi::{cstr16, guid, Guid, Handle};
use warden_assess::Action;
use warden_config::Config;

/// Warden's vendor GUID for its UEFI variables.
const WARDEN_VENDOR: Guid = guid!("57415244-454e-5354-4154-450000000001");
/// Header magic (LBA 0) marking a disk as Warden's state store.
const DISK_MAGIC: &[u8; 8] = b"WARDNDSK";

/// The assessment result handed back to the boot flow.
pub struct AssessOutcome {
    /// Entry id to boot (the resulting active slot).
    pub boot_id: String,
    /// What the policy did.
    pub action: Action,
    /// Active slot after the decision.
    pub active: String,
    /// Rollback target after the decision.
    pub last_known_good: String,
    /// Attempts left after the decision.
    pub tries_remaining: u32,
    /// Attempt budget.
    pub max_tries: u32,
}

/// Run A/B assessment if `[assess]` is enabled and a state disk is present.
/// Returns `None` (normal boot) when assessment is off or no state disk exists.
pub fn run(config: &Config) -> Option<AssessOutcome> {
    let assess = config.assess?;
    if !assess.enabled {
        return None;
    }
    let mut disk = match StateDisk::find() {
        Some(d) => d,
        None => {
            log::warn!("assess: [assess] enabled but no Warden state disk found — booting normally");
            return None;
        }
    };

    // A read glitch must not be treated as a blank buffer: that would make
    // select() pick the stale copy and then overwrite the fresh one. On any read
    // error, skip assessment for this boot (fall back to a normal boot).
    let slot0 = match disk.read_slot(0) {
        Ok(b) => b,
        Err(e) => {
            log::error!("assess: state read (slot 0) failed ({e}) — booting normally this cycle");
            return None;
        }
    };
    let slot1 = match disk.read_slot(1) {
        Ok(b) => b,
        Err(e) => {
            log::error!("assess: state read (slot 1) failed ({e}) — booting normally this cycle");
            return None;
        }
    };
    let sel = warden_assess::select(&slot0, &slot1);

    // Consume the kernel→Warden boot-success signal (one-shot).
    let confirm = take_confirm();
    let confirmed_active = match (confirm.as_deref(), sel.current.as_ref()) {
        (Some(v), Some(cur)) => v == cur.active_id(),
        _ => false,
    };
    if let Some(v) = &confirm {
        log::info!("assess: consumed boot-success signal for '{v}' (matches active: {confirmed_active})");
    }

    let outcome = warden_assess::decide(sel.current, confirmed_active, &config.global.default, assess.max_tries);

    // Persist BEFORE booting: a crashing kernel must still consume its try.
    // If the write fails the attempt is NOT durable — do not enter assess mode,
    // or main.rs would reboot on failure without ever decrementing tries or
    // rolling back (an infinite loop). Fall back to the normal menu/rescue path.
    let bytes = outcome.next.encode();
    if let Err(e) = disk.write_slot(sel.write_slot, &bytes) {
        log::error!("assess: FAILED to persist state ({e}); NOT entering A/B mode (avoids an un-recorded reboot loop)");
        return None;
    }
    log::info!(
        "assess: {:?} → boot '{}' (active='{}' lkg='{}' tries={}/{})",
        outcome.action,
        outcome.boot_id(),
        outcome.next.active_id(),
        outcome.next.lkg_id(),
        outcome.next.tries_remaining,
        outcome.next.max_tries
    );

    Some(AssessOutcome {
        boot_id: outcome.boot_id().into(),
        action: outcome.action,
        active: outcome.next.active_id().into(),
        last_known_good: outcome.next.lkg_id().into(),
        tries_remaining: outcome.next.tries_remaining,
        max_tries: outcome.next.max_tries,
    })
}

/// Read and delete the `WardenConfirm` variable, returning the confirmed id.
fn take_confirm() -> Option<String> {
    let vendor = VariableVendor(WARDEN_VENDOR);
    let mut buf = [0u8; 64];
    let val = match runtime::get_variable(cstr16!("WardenConfirm"), &vendor, &mut buf) {
        Ok((data, _)) => core::str::from_utf8(data)
            .ok()
            .map(|s| String::from(s.trim_end_matches('\0'))),
        Err(_) => return None,
    };
    let val = val.filter(|s| !s.is_empty())?;
    // Honour the confirmation ONLY if we can actually consume (delete) it: a
    // variable we cannot clear would otherwise re-confirm the same slot every
    // boot, resetting tries and blocking rollback forever.
    match runtime::delete_variable(cstr16!("WardenConfirm"), &vendor) {
        Ok(()) => Some(val),
        Err(e) => {
            log::error!("assess: could not consume WardenConfirm ({e:?}); ignoring the signal this boot");
            None
        }
    }
}

/// The dedicated raw disk that stores the double-buffered A/B state.
struct StateDisk {
    bio: ScopedProtocol<BlockIO>,
    media_id: u32,
    block_size: usize,
}

impl StateDisk {
    /// Find the disk whose LBA 0 carries the Warden state header magic.
    fn find() -> Option<Self> {
        let handles = boot::find_handles::<BlockIO>().ok()?;
        for handle in handles {
            if let Some(d) = Self::try_open(handle) {
                return Some(d);
            }
        }
        None
    }

    fn try_open(handle: Handle) -> Option<Self> {
        let params = OpenProtocolParams { handle, agent: boot::image_handle(), controller: None };
        // SAFETY: GetProtocol opens the interface non-destructively; the dedicated
        // state disk is raw (no firmware fs driver holds it) so reads/writes are ours.
        let bio = unsafe { boot::open_protocol::<BlockIO>(params, OpenProtocolAttributes::GetProtocol) }.ok()?;
        let media = bio.media();
        // A read-only state disk can't record attempts — never adopt it (else a
        // write-failing disk would loop forever without ever rolling back).
        if !media.is_media_present() || media.is_read_only() {
            return None;
        }
        // Bound block_size on BOTH sides: it is a device-reported length and we
        // allocate a buffer of it (GC-03). Real block devices are 512 or 4096.
        let block_size = media.block_size() as usize;
        if block_size < warden_assess::RECORD_LEN || block_size > 65_536 {
            return None;
        }
        let media_id = media.media_id();
        let mut disk = StateDisk { bio, media_id, block_size };
        let hdr = disk.read_block(0).ok()?;
        (hdr.get(0..8) == Some(DISK_MAGIC.as_slice())).then_some(disk)
    }

    fn read_block(&mut self, lba: u64) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; self.block_size];
        self.bio
            .read_blocks(self.media_id, lba, &mut buf)
            .map_err(|e| format!("read lba {lba}: {e:?}"))?;
        Ok(buf)
    }

    /// State buffers live at LBA 1 (slot 0) and LBA 2 (slot 1); LBA 0 is the header.
    fn read_slot(&mut self, slot: usize) -> Result<Vec<u8>, String> {
        self.read_block(1 + slot as u64)
    }

    fn write_slot(&mut self, slot: usize, rec: &[u8]) -> Result<(), String> {
        let mut buf = vec![0u8; self.block_size];
        buf.get_mut(..rec.len())
            .ok_or_else(|| String::from("record larger than block"))?
            .copy_from_slice(rec);
        self.bio
            .write_blocks(self.media_id, 1 + slot as u64, &buf)
            .map_err(|e| format!("write lba {}: {e:?}", 1 + slot))?;
        self.bio.flush_blocks().map_err(|e| format!("flush: {e:?}"))?;
        Ok(())
    }
}
