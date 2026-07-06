//! Trust: verify detached component signatures against Warden's embedded key,
//! and read the firmware Secure Boot state (T3.1/T3.2).
//!
//! Warden is the root of the runtime trust chain: firmware Secure Boot verifies
//! *Warden's* PE signature, and Warden in turn verifies the kernel/modules it is
//! about to execute against its own embedded public key — an ed25519 detached
//! signature over the raw file bytes. A bad signature is refused before anything
//! is measured or loaded (AC3.1).

use alloc::format;
use alloc::string::String;

use ed25519_dalek::{Signature, VerifyingKey};

/// Warden's embedded signing public key (ed25519).
///
/// **Test key** derived from a fixed seed by `cargo xtask pubkey`; replace with
/// your own for production. The corresponding private key never lives in Warden.
pub const SIGNING_PUBKEY: [u8; 32] = [
    0x3e, 0x13, 0x94, 0x0d, 0x57, 0x0b, 0x24, 0xb7, //
    0x29, 0x5c, 0x1c, 0x98, 0xbf, 0x82, 0xcc, 0x0b, //
    0x3a, 0x15, 0xd3, 0x6e, 0x8a, 0x41, 0xde, 0x12, //
    0x48, 0x1f, 0x96, 0xf2, 0x19, 0x92, 0x95, 0xdd, //
];

/// Length of an ed25519 detached signature.
pub const SIGNATURE_LEN: usize = 64;

/// Verify a detached ed25519 signature of `message` against [`SIGNING_PUBKEY`].
///
/// Returns `Ok(())` only on a cryptographically valid signature; every other
/// case (wrong length, malformed key, non-matching signature) is an `Err` with a
/// readable message — never a panic (GC-03).
pub fn verify(message: &[u8], signature: &[u8]) -> Result<(), String> {
    let sig_bytes: [u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| format!("signature is {} bytes, expected {SIGNATURE_LEN}", signature.len()))?;
    let key = VerifyingKey::from_bytes(&SIGNING_PUBKEY)
        .map_err(|e| format!("invalid embedded signing key: {e}"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify_strict(message, &signature)
        .map_err(|_| String::from("signature does not match the embedded key"))
}

/// Returns `true` iff firmware Secure Boot is enforcing.
///
/// The `SecureBoot` global variable is `1` when enforcing, `0` in setup mode, and
/// absent (`NOT_FOUND`) when the platform has no Secure Boot at all. For a
/// root-of-trust decision we **fail closed**: only a definitive `0`/`NOT_FOUND`
/// means "not enforcing"; any *unexpected* read error is treated as enforcing so
/// a transient fault cannot silently admit unsigned kernels.
pub fn secure_boot_enabled() -> bool {
    let mut buf = [0u8; 1];
    match uefi::runtime::get_variable(
        uefi::cstr16!("SecureBoot"),
        &uefi::runtime::VariableVendor::GLOBAL_VARIABLE,
        &mut buf,
    ) {
        Ok((data, _attrs)) => data.first().copied() == Some(1),
        // No Secure Boot on this platform → genuinely not enforcing.
        Err(e) if e.status() == uefi::Status::NOT_FOUND => false,
        // Any other error reading the root-of-trust state → fail closed.
        Err(_) => true,
    }
}
