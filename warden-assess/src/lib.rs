//! Warden A/B boot assessment (P6, DEC-012): the durable boot-state record and
//! the rollback decision logic, as **pure `no_std` code** so it can be unit-tested
//! on the host (like `warden-config`). The UEFI I/O (which disk, reading the
//! success-signal variable) lives in the `warden` crate; everything policy- and
//! format-related lives here.
//!
//! State record (build-spec §3.3): `{active_slot, tries_remaining, last_known_good}`,
//! stored **double-buffered with a CRC** using write-new-then-swap, so a crash
//! mid-write can never corrupt both copies. The "good" marker is written **only
//! after** the kernel signals boot success — never at menu render.

#![no_std]
#![forbid(unsafe_code)]

/// Fixed-width, null-padded entry-id field (matches config `entry.id`).
pub const ID_LEN: usize = 32;
/// Serialized record length in bytes (fits comfortably in one 512-byte sector).
pub const RECORD_LEN: usize = 92;
const MAGIC: [u8; 8] = *b"WARDNST1";

/// A boot-assessment id (an `entry.id`, null-padded).
pub type Id = [u8; ID_LEN];

/// Encode a config entry id into the fixed-width field. Returns `None` if the id
/// is longer than [`ID_LEN`].
#[must_use]
pub fn id_from_str(s: &str) -> Option<Id> {
    let b = s.as_bytes();
    if b.len() > ID_LEN {
        return None;
    }
    let mut id = [0u8; ID_LEN];
    id[..b.len()].copy_from_slice(b);
    Some(id)
}

/// Decode a fixed-width id field back to a string slice (up to the first NUL).
#[must_use]
pub fn id_str(id: &Id) -> &str {
    let end = id.iter().position(|&c| c == 0).unwrap_or(ID_LEN);
    core::str::from_utf8(&id[..end]).unwrap_or("")
}

/// The durable A/B boot state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StateRecord {
    /// Monotonic sequence number; the higher valid copy wins.
    pub generation: u64,
    /// Slot currently being attempted.
    pub active: Id,
    /// Last slot confirmed healthy — the rollback target.
    pub last_known_good: Id,
    /// Attempts left before rolling back.
    pub tries_remaining: u32,
    /// Attempt budget (from `[assess] max_tries`; self-describing).
    pub max_tries: u32,
}

impl StateRecord {
    /// The active slot id as a string.
    #[must_use]
    pub fn active_id(&self) -> &str {
        id_str(&self.active)
    }
    /// The last-known-good slot id as a string.
    #[must_use]
    pub fn lkg_id(&self) -> &str {
        id_str(&self.last_known_good)
    }

    /// Serialize to a fixed-length, CRC-protected record.
    #[must_use]
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut b = [0u8; RECORD_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..16].copy_from_slice(&self.generation.to_le_bytes());
        b[16..48].copy_from_slice(&self.active);
        b[48..80].copy_from_slice(&self.last_known_good);
        b[80..84].copy_from_slice(&self.tries_remaining.to_le_bytes());
        b[84..88].copy_from_slice(&self.max_tries.to_le_bytes());
        let crc = crc32(&b[0..88]);
        b[88..92].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Parse a record, returning `None` if the magic or CRC does not check out
    /// (a blank, torn, or corrupted buffer — never trusted, GC-03).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < RECORD_LEN || bytes[0..8] != MAGIC {
            return None;
        }
        let stored = u32::from_le_bytes(bytes[88..92].try_into().ok()?);
        if crc32(&bytes[0..88]) != stored {
            return None;
        }
        Some(Self {
            generation: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            active: bytes[16..48].try_into().ok()?,
            last_known_good: bytes[48..80].try_into().ok()?,
            tries_remaining: u32::from_le_bytes(bytes[80..84].try_into().ok()?),
            max_tries: u32::from_le_bytes(bytes[84..88].try_into().ok()?),
        })
    }
}

/// Result of picking the current state from the two on-disk buffers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Selection {
    /// The freshest valid record, if any.
    pub current: Option<StateRecord>,
    /// The buffer index (0 or 1) the next write must target — always the buffer
    /// **not** holding `current`, so an interrupted write can't destroy it.
    pub write_slot: usize,
}

/// Choose the current record from the two double-buffered slots and decide which
/// slot the next write should target (write-new-then-swap).
#[must_use]
pub fn select(slot0: &[u8], slot1: &[u8]) -> Selection {
    match (StateRecord::decode(slot0), StateRecord::decode(slot1)) {
        (Some(a), Some(b)) => {
            if a.generation >= b.generation {
                Selection { current: Some(a), write_slot: 1 }
            } else {
                Selection { current: Some(b), write_slot: 0 }
            }
        }
        (Some(a), None) => Selection { current: Some(a), write_slot: 1 },
        (None, Some(b)) => Selection { current: Some(b), write_slot: 0 },
        (None, None) => Selection { current: None, write_slot: 0 },
    }
}

/// What the decision did (for logging / menu display).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// No prior state — initialized from the config default and attempted it.
    Bootstrap,
    /// The previous boot of `active` was confirmed healthy → marked good.
    Confirm,
    /// Unconfirmed boot with tries left → decremented and attempting `active`.
    Attempt,
    /// Tries exhausted → rolled back to `last_known_good`.
    Rollback,
}

/// The outcome of an assessment: the next state to persist and what to boot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Outcome {
    /// The record to write back (to `Selection::write_slot`) **before** booting.
    pub next: StateRecord,
    /// What happened, for the operator.
    pub action: Action,
}

impl Outcome {
    /// The entry id to boot (always the resulting active slot).
    #[must_use]
    pub fn boot_id(&self) -> &str {
        self.next.active_id()
    }
}

/// The core A/B policy. Pure: all UEFI side effects (persisting `next`, deleting
/// the consumed confirm variable, booting) are performed by the caller.
///
/// * `current` — freshest valid state ([`select`]), or `None` on first boot.
/// * `confirmed_active` — the OS set the success signal for `current.active`.
/// * `default_id` — the config default entry (bootstrap target).
/// * `max_tries` — from `[assess] max_tries`.
#[must_use]
pub fn decide(current: Option<StateRecord>, confirmed_active: bool, default_id: &str, max_tries: u32) -> Outcome {
    let base_gen = current.map_or(0, |s| s.generation);
    let default = id_from_str(default_id).unwrap_or([0u8; ID_LEN]);

    let (mut st, bootstrap) = match current {
        Some(s) => (s, false),
        None => (
            StateRecord { generation: base_gen, active: default, last_known_good: default, tries_remaining: max_tries, max_tries },
            true,
        ),
    };
    // Config is the source of truth for the attempt budget.
    st.max_tries = max_tries;

    let action = if bootstrap {
        // First-ever boot: attempt the default, consuming one try.
        st.tries_remaining = max_tries.saturating_sub(1);
        Action::Bootstrap
    } else if confirmed_active {
        // The OS reported the active slot healthy → it becomes the good one.
        st.last_known_good = st.active;
        st.tries_remaining = max_tries;
        Action::Confirm
    } else if st.tries_remaining > 0 {
        // Another unconfirmed attempt.
        st.tries_remaining -= 1;
        Action::Attempt
    } else {
        // Budget exhausted with no confirmation → revert to the good slot.
        st.active = st.last_known_good;
        st.tries_remaining = max_tries;
        Action::Rollback
    };

    st.generation = base_gen.saturating_add(1);
    Outcome { next: st, action }
}

/// CRC-32 (IEEE 802.3, reflected, init `0xFFFFFFFF`, final invert).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(active: &str, lkg: &str, tries: u32, gen: u64) -> StateRecord {
        StateRecord {
            generation: gen,
            active: id_from_str(active).unwrap(),
            last_known_good: id_from_str(lkg).unwrap(),
            tries_remaining: tries,
            max_tries: 3,
        }
    }

    #[test]
    fn encode_decode_roundtrips() {
        let r = rec("slot-b", "slot-a", 2, 7);
        let bytes = r.encode();
        assert_eq!(bytes.len(), RECORD_LEN);
        assert_eq!(StateRecord::decode(&bytes), Some(r));
        assert_eq!(r.active_id(), "slot-b");
        assert_eq!(r.lkg_id(), "slot-a");
    }

    #[test]
    fn corrupt_or_blank_is_rejected() {
        let mut bytes = rec("a", "b", 1, 1).encode();
        bytes[20] ^= 0xff; // flip a payload byte → CRC fails
        assert_eq!(StateRecord::decode(&bytes), None);
        assert_eq!(StateRecord::decode(&[0u8; RECORD_LEN]), None); // blank
        assert_eq!(StateRecord::decode(&[0u8; 4]), None); // too short
        let mut bad_magic = rec("a", "b", 1, 1).encode();
        bad_magic[0] = b'X';
        assert_eq!(StateRecord::decode(&bad_magic), None);
    }

    #[test]
    fn select_prefers_newest_and_swaps_write_slot() {
        let older = rec("a", "a", 3, 5).encode();
        let newer = rec("b", "a", 2, 6).encode();
        // newest in slot0 → write next to slot1
        let s = select(&newer, &older);
        assert_eq!(s.current.unwrap().generation, 6);
        assert_eq!(s.write_slot, 1);
        // newest in slot1 → write next to slot0
        let s = select(&older, &newer);
        assert_eq!(s.current.unwrap().generation, 6);
        assert_eq!(s.write_slot, 0);
    }

    #[test]
    fn select_survives_one_corrupt_buffer() {
        let good = rec("a", "a", 3, 9).encode();
        let torn = [0u8; RECORD_LEN]; // interrupted write
        let s = select(&good, &torn);
        assert_eq!(s.current.unwrap().generation, 9);
        assert_eq!(s.write_slot, 1); // rewrite the torn one
        let s = select(&torn, &good);
        assert_eq!(s.current.unwrap().generation, 9);
        assert_eq!(s.write_slot, 0);
        // both blank → bootstrap, write slot 0
        let s = select(&torn, &torn);
        assert!(s.current.is_none());
        assert_eq!(s.write_slot, 0);
    }

    #[test]
    fn bootstrap_attempts_default() {
        let o = decide(None, false, "arch", 3);
        assert_eq!(o.action, Action::Bootstrap);
        assert_eq!(o.boot_id(), "arch");
        assert_eq!(o.next.lkg_id(), "arch");
        assert_eq!(o.next.tries_remaining, 2);
        assert_eq!(o.next.generation, 1);
    }

    #[test]
    fn confirm_marks_good_and_resets() {
        let cur = rec("b", "a", 1, 4);
        let o = decide(Some(cur), true, "a", 3);
        assert_eq!(o.action, Action::Confirm);
        assert_eq!(o.boot_id(), "b");
        assert_eq!(o.next.lkg_id(), "b"); // active promoted to good
        assert_eq!(o.next.tries_remaining, 3); // reset
        assert_eq!(o.next.generation, 5);
    }

    #[test]
    fn unconfirmed_attempts_then_rolls_back() {
        // Seeded: active=bad, good=good, tries=2, max=2. Simulate AC6.1 cycles.
        let mut cur = StateRecord {
            generation: 10,
            active: id_from_str("bad").unwrap(),
            last_known_good: id_from_str("good").unwrap(),
            tries_remaining: 2,
            max_tries: 2,
        };
        // cycle 1: attempt bad, tries 2->1
        let o = decide(Some(cur), false, "good", 2);
        assert_eq!(o.action, Action::Attempt);
        assert_eq!(o.boot_id(), "bad");
        assert_eq!(o.next.tries_remaining, 1);
        cur = o.next;
        // cycle 2: attempt bad, tries 1->0
        let o = decide(Some(cur), false, "good", 2);
        assert_eq!(o.action, Action::Attempt);
        assert_eq!(o.boot_id(), "bad");
        assert_eq!(o.next.tries_remaining, 0);
        cur = o.next;
        // cycle 3: tries exhausted -> rollback to good
        let o = decide(Some(cur), false, "good", 2);
        assert_eq!(o.action, Action::Rollback);
        assert_eq!(o.boot_id(), "good");
        assert_eq!(o.next.active_id(), "good");
        assert_eq!(o.next.tries_remaining, 2);
        assert_eq!(o.next.generation, 13);
    }

    #[test]
    fn generation_advances_every_decision() {
        let cur = rec("a", "a", 3, 100);
        assert_eq!(decide(Some(cur), false, "a", 3).next.generation, 101);
    }
}
