//! HMAC (RFC 2104) over SHA-256 and SHA-512.
//!
//! Both come as a streaming object (`new`/`update`/`finalize`), so a long
//! or many-part message — such as HKDF's `T(n-1) || info || counter` — is
//! MAC'd without first joining the parts in a buffer, and as a one-shot
//! helper for the common single-slice case.

use crate::sha2::{Sha256, Sha512, sha256, sha512};

/// A streaming HMAC-SHA-256.
pub struct Hmac256 {
    inner: Sha256,
    opad: [u8; 64],
}

impl Hmac256 {
    pub fn new(key: &[u8]) -> Hmac256 {
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
        Hmac256 { inner, opad }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let inner = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&inner);
        outer.finalize()
    }
}

/// A streaming HMAC-SHA-512.
pub struct Hmac512 {
    inner: Sha512,
    opad: [u8; 128],
}

impl Hmac512 {
    pub fn new(key: &[u8]) -> Hmac512 {
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
        Hmac512 { inner, opad }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 64] {
        let inner = self.inner.finalize();
        let mut outer = Sha512::new();
        outer.update(&self.opad);
        outer.update(&inner);
        outer.finalize()
    }
}

/// HMAC-SHA-256 of `msg` under `key`.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = Hmac256::new(key);
    mac.update(msg);
    mac.finalize()
}

/// HMAC-SHA-512 of `msg` under `key`.
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut mac = Hmac512::new(key);
    mac.update(msg);
    mac.finalize()
}
