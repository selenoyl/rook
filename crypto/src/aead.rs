//! ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
//!
//! Seal encrypts in place and returns the tag; open checks the tag in
//! constant time and only then decrypts, so a forgery is never handed
//! back as plaintext.

use crate::chacha;
use crate::poly1305::Poly1305;

/// Compare two tags without letting the time taken reveal where they
/// first differ.
pub fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha::block(key, 0, nonce);
    let mut poly = [0u8; 32];
    poly.copy_from_slice(&block[..32]);
    poly
}

fn mac_padded(mac: &mut Poly1305, data: &[u8]) {
    mac.update(data);
    let rem = data.len() % 16;
    if rem != 0 {
        let zeros = [0u8; 16];
        mac.update(&zeros[..16 - rem]);
    }
}

fn tag(poly: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(poly);
    mac_padded(&mut mac, aad);
    mac_padded(&mut mac, ciphertext);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac.update(&lengths);
    mac.finalize()
}

/// Encrypt `buf` in place under `key` and `nonce`, authenticating `aad`
/// too, and return the tag.
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    let poly = poly_key(key, nonce);
    chacha::chacha20_xor(key, 1, nonce, buf);
    tag(&poly, aad, buf)
}

/// Check `tag` over `aad` and the ciphertext in `buf`; if it matches,
/// decrypt `buf` in place and return true. On a bad tag, leave `buf`
/// untouched and return false.
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag_in: &[u8; 16],
) -> bool {
    let poly = poly_key(key, nonce);
    let expected = tag(&poly, aad, buf);
    if !ct_eq(&expected, tag_in) {
        return false;
    }
    chacha::chacha20_xor(key, 1, nonce, buf);
    true
}
