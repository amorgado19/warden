//! Minimal raw TPM 2.0 commands sent via `EFI_TCG2_PROTOCOL.SubmitCommand`.
//!
//! The TCG2 protocol hashes+extends+logs for us, but exposes no way to *read* a
//! PCR back — which the event-log replay gate needs. So we hand-encode a single
//! command, `TPM2_PCR_Read`, and parse its response. All TPM structures are
//! big-endian. The response is parsed defensively (bounds-checked at every step,
//! GC-03): a malformed reply yields an error, never a panic.

use alloc::format;
use alloc::string::String;

use uefi::proto::tcg::v2::Tcg;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_PCR_READ: u32 = 0x0000_017E;
const TPM_ALG_SHA256: u16 = 0x000B;
const SHA256_LEN: usize = 32;

/// Read the SHA-256 bank value of a single PCR (`0..=23`).
pub fn pcr_read_sha256(tcg: &mut Tcg, pcr: u32) -> Result<[u8; SHA256_LEN], String> {
    if pcr >= 24 {
        return Err(format!("PCR index {pcr} out of range"));
    }

    // TPML_PCR_SELECTION with one TPMS_PCR_SELECTION selecting `pcr` in SHA-256.
    let mut select = [0u8; 3];
    select[(pcr / 8) as usize] = 1u8 << (pcr % 8);

    // Command: header (tag,size,code) + count + {hash, sizeofSelect, select[3]}.
    let cmd: [u8; 20] = [
        (TPM_ST_NO_SESSIONS >> 8) as u8,
        TPM_ST_NO_SESSIONS as u8,
        0x00,
        0x00,
        0x00,
        0x14, // commandSize = 20
        (TPM_CC_PCR_READ >> 24) as u8,
        (TPM_CC_PCR_READ >> 16) as u8,
        (TPM_CC_PCR_READ >> 8) as u8,
        TPM_CC_PCR_READ as u8,
        0x00,
        0x00,
        0x00,
        0x01, // pcrSelectionIn.count = 1
        (TPM_ALG_SHA256 >> 8) as u8,
        TPM_ALG_SHA256 as u8,
        0x03, // sizeofSelect
        select[0],
        select[1],
        select[2],
    ];

    let mut out = [0u8; 256];
    tcg.submit_command(&cmd, &mut out)
        .map_err(|e| format!("PCR_Read SubmitCommand failed: {e:?}"))?;

    parse_pcr_read_response(&out)
}

/// Parse a `TPM2_PCR_Read` response, returning the single SHA-256 PCR value.
///
/// Layout: tag(2) responseSize(4) responseCode(4) pcrUpdateCounter(4)
/// pcrSelectionOut(TPML_PCR_SELECTION) pcrValues(TPML_DIGEST). Every field is
/// bounds-checked.
fn parse_pcr_read_response(out: &[u8]) -> Result<[u8; SHA256_LEN], String> {
    let mut c = Cursor { buf: out, off: 0 };

    let _tag = c.u16()?;
    let _size = c.u32()?;
    let rc = c.u32()?;
    if rc != 0 {
        return Err(format!("TPM2_PCR_Read returned responseCode {rc:#010x}"));
    }
    let _pcr_update_counter = c.u32()?;

    // pcrSelectionOut: count, then `count` * {hash(2), sizeofSelect(1), select}.
    let sel_count = c.u32()?;
    for _ in 0..sel_count {
        let _hash = c.u16()?;
        let sizeof_select = c.u8()? as usize;
        c.skip(sizeof_select)?;
    }

    // pcrValues: TPML_DIGEST = count, then `count` * TPM2B_DIGEST{size, buffer}.
    let dig_count = c.u32()?;
    if dig_count < 1 {
        return Err("TPM2_PCR_Read returned no PCR value".into());
    }
    let size = c.u16()? as usize;
    if size != SHA256_LEN {
        return Err(format!("unexpected PCR digest size {size} (want {SHA256_LEN})"));
    }
    let digest = c.take(SHA256_LEN)?;
    let mut pcr = [0u8; SHA256_LEN];
    pcr.copy_from_slice(digest);
    Ok(pcr)
}

/// Big-endian, bounds-checked cursor over a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.off.checked_add(n).ok_or_else(|| String::from("TPM response length overflow"))?;
        let slice = self.buf.get(self.off..end).ok_or_else(|| String::from("truncated TPM response"))?;
        self.off = end;
        Ok(slice)
    }
    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}
