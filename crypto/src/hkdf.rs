//! HKDF (RFC 5869): the extract-then-expand key-derivation function, over
//! HMAC-SHA-256 and HMAC-SHA-512.
//!
//! HKDF turns one shared secret (such as a Diffie-Hellman output) into as
//! many independent keys as a protocol needs. `extract` concentrates the
//! input into a pseudorandom key; `expand` stretches that key into output
//! keyed by a short `info` label, so a different label gives an unrelated
//! key. Drawbridge uses the SHA-512 variant for its key schedule.

use crate::hmac::{Hmac256, Hmac512, hmac_sha256, hmac_sha512};

/// HKDF-Extract with SHA-256: PRK = HMAC(salt, ikm). An empty salt means
/// the RFC's default of HashLen zero bytes (HMAC pads a short key with
/// zeros, so the two are identical).
pub fn extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Extract with SHA-512.
pub fn extract_sha512(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
    hmac_sha512(salt, ikm)
}

/// HKDF-Expand with SHA-256: fill `out` with output keyed by `info`.
/// `out` may be up to 255·32 bytes; a longer slice is a programming error
/// and leaves the tail unwritten (callers here ask for 32).
pub fn expand_sha256(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    let mut t = [0u8; 32];
    let mut t_len = 0usize; // 0 for T(0) = empty, 32 afterwards
    let mut counter: u8 = 1;
    let mut filled = 0;
    while filled < out.len() {
        // T(n) = HMAC(prk, T(n-1) || info || n).
        let mut mac = Hmac256::new(prk);
        mac.update(&t[..t_len]);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize();
        t_len = 32;
        let take = core::cmp::min(32, out.len() - filled);
        out[filled..filled + take].copy_from_slice(&t[..take]);
        filled += take;
        if counter == 255 {
            break;
        }
        counter += 1;
    }
}

/// HKDF-Expand with SHA-512: fill `out` with output keyed by `info`.
/// `out` may be up to 255·64 bytes.
pub fn expand_sha512(prk: &[u8; 64], info: &[u8], out: &mut [u8]) {
    let mut t = [0u8; 64];
    let mut t_len = 0usize;
    let mut counter: u8 = 1;
    let mut filled = 0;
    while filled < out.len() {
        let mut mac = Hmac512::new(prk);
        mac.update(&t[..t_len]);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize();
        t_len = 64;
        let take = core::cmp::min(64, out.len() - filled);
        out[filled..filled + take].copy_from_slice(&t[..take]);
        filled += take;
        if counter == 255 {
            break;
        }
        counter += 1;
    }
}

/// Derive a 32-byte key from `ikm` in one call, the common case: extract
/// under `salt`, then expand under `info`. SHA-512 variant.
pub fn derive_key_sha512(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = extract_sha512(salt, ikm);
    let mut out = [0u8; 32];
    expand_sha512(&prk, info, &mut out);
    out
}
