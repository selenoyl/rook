//! HMAC (RFC 2104) over SHA-256 and SHA-512.

use crate::sha2::{Sha256, Sha512, sha256, sha512};

/// HMAC-SHA-256 of `msg` under `key`.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(k) {
        *i ^= k;
        *o ^= k;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finalize()
}

/// HMAC-SHA-512 of `msg` under `key`.
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    const BLOCK: usize = 128;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..64].copy_from_slice(&sha512(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for ((i, o), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(k) {
        *i ^= k;
        *o ^= k;
    }
    let mut inner = Sha512::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finalize()
}
