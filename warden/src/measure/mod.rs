//! TPM 2.0 measured boot (T3.3/T3.4) + the event-log-replay / PCR gate (AC3.2).
//!
//! Before handing off, Warden extends the components it is about to trust into
//! TPM PCRs via `EFI_TCG2_PROTOCOL.HashLogExtendEvent` (which hashes, extends
//! *and* appends a crypto-agile event-log entry), then **self-verifies**: it
//! replays the firmware event log in software and checks that the replay
//! reproduces the TPM's actual PCR values (read back via `TPM2_PCR_Read`). This
//! is the property downstream sealing/attestation depends on.
//!
//! Documented measurement scheme (order matters — extends are order-sensitive):
//!   PCR 8  (policy):   config bytes → entry id → cmdline
//!   PCR 9  (binaries): kernel → initrd
//!
//! Measured boot is best-effort: with no TPM present Warden still boots (it is an
//! integrity add-on, not a boot prerequisite). The replay+PCR check is the hard
//! gate exercised under swtpm.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use uefi::boot::{self, ScopedProtocol};
use uefi::proto::tcg::v2::{HashLogExtendEventFlags, PcrEventInputs, Tcg};
use uefi::proto::tcg::{AlgorithmId, EventType, PcrIndex};

mod tpm2;

/// PCR that records Warden's policy inputs (config, entry, cmdline).
pub const PCR_POLICY: u32 = 8;
/// PCR that records the executed binaries (kernel, initrd).
pub const PCR_BINARIES: u32 = 9;

const SHA256_LEN: usize = 32;
const NUM_PCRS: usize = 24;

/// Outcome of measuring + gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Measured and the replay/PCR gate passed.
    Pass,
    /// A TPM is present but the gate failed (mismatch or zero PCR).
    Fail,
    /// No TPM present — measured boot skipped (Warden still boots).
    NoTpm,
    /// A TPM error occurred while measuring or reading PCRs.
    Error,
}

/// The components to measure — borrowed so the exact bytes that are executed are
/// the exact bytes measured (no TOCTOU).
pub struct Inputs<'a> {
    pub config: &'a [u8],
    pub entry_id: &'a str,
    pub cmdline: &'a str,
    pub kernel: &'a [u8],
    pub initrd: Option<&'a [u8]>,
}

fn open_tcg() -> Option<ScopedProtocol<Tcg>> {
    let handle = boot::get_handle_for_protocol::<Tcg>().ok()?;
    boot::open_protocol_exclusive::<Tcg>(handle).ok()
}

/// Print the current measured-boot state (PCR8/PCR9 SHA-256) for the rescue
/// shell's inspect command (T8.1). Best-effort and non-fatal.
pub fn show_measured_state() {
    let mut tcg = match open_tcg() {
        Some(t) => t,
        None => {
            log::info!("measured-boot state: no TPM (TCG2 protocol) present");
            return;
        }
    };
    for pcr in [PCR_POLICY, PCR_BINARIES] {
        match tpm2::pcr_read_sha256(&mut tcg, pcr) {
            Ok(v) => log::info!("PCR{pcr} (SHA-256) = {}", hex(&v)),
            Err(e) => log::warn!("PCR{pcr} read failed: {e}"),
        }
    }
}

/// Lowercase hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    s
}

/// Measure all components into PCRs, then run the replay+PCR gate.
pub fn measure_and_gate(inp: &Inputs) -> Outcome {
    let mut tcg = match open_tcg() {
        Some(t) => t,
        None => {
            log::warn!("no TPM (TCG2 protocol) present — skipping measured boot");
            return Outcome::NoTpm;
        }
    };

    // Extend in the documented order. Each entry: (pcr, label, bytes).
    let mut steps: Vec<(u32, &str, &[u8])> = Vec::with_capacity(5);
    steps.push((PCR_POLICY, "warden.config", inp.config));
    steps.push((PCR_POLICY, "warden.entry-id", inp.entry_id.as_bytes()));
    steps.push((PCR_POLICY, "warden.cmdline", inp.cmdline.as_bytes()));
    steps.push((PCR_BINARIES, "warden.kernel", inp.kernel));
    if let Some(initrd) = inp.initrd {
        steps.push((PCR_BINARIES, "warden.initrd", initrd));
    }

    for (pcr, label, data) in &steps {
        if let Err(e) = extend(&mut tcg, *pcr, label, data) {
            log::error!("measured boot: {e}");
            return Outcome::Error;
        }
        log::info!("MEASURE: PCR{pcr} <- {label} ({} bytes)", data.len());
    }

    gate(&mut tcg)
}

/// Extend one component into `pcr` and log a TCG event describing it.
fn extend(tcg: &mut Tcg, pcr: u32, label: &str, data: &[u8]) -> Result<(), String> {
    let event = PcrEventInputs::new_in_box(PcrIndex(pcr), EventType::IPL, label.as_bytes())
        .map_err(|e| format!("event alloc failed: {e:?}"))?;
    tcg.hash_log_extend_event(HashLogExtendEventFlags::empty(), data, &event)
        .map_err(|e| format!("HashLogExtendEvent(PCR{pcr}, {label}) failed: {e:?}"))
}

/// Replay the event log and confirm it reproduces the TPM's actual PCR values.
fn gate(tcg: &mut Tcg) -> Outcome {
    // 1. Replay: fold every logged SHA-256 digest into a synthetic PCR bank.
    let replayed = match replay_event_log(tcg) {
        Ok(r) => r,
        Err(e) => {
            log::error!("measured boot: event-log replay failed: {e}");
            return Outcome::Error;
        }
    };

    // 2. Compare the replay against the real TPM PCRs for the ones Warden owns.
    let mut all_ok = true;
    for pcr in [PCR_POLICY, PCR_BINARIES] {
        let actual = match tpm2::pcr_read_sha256(tcg, pcr) {
            Ok(a) => a,
            Err(e) => {
                log::error!("measured boot: {e}");
                return Outcome::Error;
            }
        };
        let expected = replayed[pcr as usize];
        let matches = expected == actual;
        let nonzero = actual != [0u8; SHA256_LEN];
        log::info!(
            "REPLAY PCR{pcr}: {} (nonzero={nonzero}) tpm={} replay={}",
            if matches { "MATCH" } else { "MISMATCH" },
            hex8(&actual),
            hex8(&expected),
        );
        all_ok &= matches && nonzero;
    }

    if all_ok {
        log::info!("MEASURED-BOOT GATE: PASS");
        Outcome::Pass
    } else {
        log::error!("MEASURED-BOOT GATE: FAIL");
        Outcome::Fail
    }
}

/// Replay the crypto-agile event log into a synthetic SHA-256 PCR bank.
/// `EV_NO_ACTION` events are logged but never extended, so they are skipped.
fn replay_event_log(tcg: &mut Tcg) -> Result<[[u8; SHA256_LEN]; NUM_PCRS], String> {
    let log = tcg
        .get_event_log_v2()
        .map_err(|e| format!("GetEventLog failed: {e:?}"))?;

    let mut bank = [[0u8; SHA256_LEN]; NUM_PCRS];
    for event in log.iter() {
        if event.event_type() == EventType::NO_ACTION {
            continue;
        }
        let pcr = event.pcr_index().0 as usize;
        if pcr >= NUM_PCRS {
            continue; // ignore events for PCRs outside the standard range
        }
        // Extract the SHA-256 digest for this event.
        let sha256 = event.digests().into_iter().find_map(|(alg, digest)| {
            (alg == AlgorithmId::SHA256 && digest.len() == SHA256_LEN).then_some(digest)
        });
        let Some(digest) = sha256 else {
            continue; // no SHA-256 bank in this event
        };

        // PCR extend: new = SHA256(old || digest).
        let mut h = Sha256::new();
        h.update(bank[pcr]);
        h.update(digest);
        bank[pcr].copy_from_slice(&h.finalize());
    }
    Ok(bank)
}

/// First 8 bytes of a digest as hex, for compact logging.
fn hex8(d: &[u8; SHA256_LEN]) -> String {
    let mut s = String::with_capacity(18);
    for b in &d[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s.push_str("..");
    s
}
