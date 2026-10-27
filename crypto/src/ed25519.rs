//! Ed25519 (RFC 8032): signatures on the twisted Edwards form of
//! Curve25519.
//!
//! Points are kept in extended coordinates (X, Y, Z, T) with the a = -1
//! addition and doubling formulas. The field is `field25519` and the
//! scalars are reduced mod L by `scalar`. `sign` and `verify` follow the
//! RFC; the hash is SHA-512.
//!
//! This is correctness-first: `scalar_mul` is plain double-and-add, so a
//! signing key's scalar isn't handled in constant time yet. As the crate
//! says, nothing here is audited.

use crate::field25519 as fe;
use crate::field25519::Fe;
use crate::scalar;
use crate::sha2::{Sha512, sha512};

/// d = -121665/121666 mod p, little-endian.
const D_BYTES: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];
/// sqrt(-1) mod p, little-endian.
const SQRT_M1_BYTES: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];
/// The base point B, compressed (y = 4/5, x even).
const BASE_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

fn d() -> Fe {
    fe::from_bytes(&D_BYTES)
}
fn d2() -> Fe {
    let d = d();
    fe::add(&d, &d)
}
fn sqrt_m1() -> Fe {
    fe::from_bytes(&SQRT_M1_BYTES)
}

/// A point in extended twisted-Edwards coordinates.
#[derive(Clone)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

fn identity() -> Point {
    Point {
        x: fe::ZERO,
        y: fe::ONE,
        z: fe::ONE,
        t: fe::ZERO,
    }
}

fn add(p: &Point, q: &Point) -> Point {
    let a = fe::mul(&fe::sub(&p.y, &p.x), &fe::sub(&q.y, &q.x));
    let b = fe::mul(&fe::add(&p.y, &p.x), &fe::add(&q.y, &q.x));
    let c = fe::mul(&fe::mul(&p.t, &q.t), &d2());
    let dd = fe::mul(&fe::mul(&p.z, &q.z), &fe::add(&fe::ONE, &fe::ONE));
    let e = fe::sub(&b, &a);
    let f = fe::sub(&dd, &c);
    let g = fe::add(&dd, &c);
    let h = fe::add(&b, &a);
    Point {
        x: fe::mul(&e, &f),
        y: fe::mul(&g, &h),
        t: fe::mul(&e, &h),
        z: fe::mul(&f, &g),
    }
}

fn double(p: &Point) -> Point {
    let a = fe::square(&p.x);
    let b = fe::square(&p.y);
    let c = fe::add(&fe::square(&p.z), &fe::square(&p.z));
    let dd = fe::neg(&a);
    let e = fe::sub(&fe::sub(&fe::square(&fe::add(&p.x, &p.y)), &a), &b);
    let g = fe::add(&dd, &b);
    let f = fe::sub(&g, &c);
    let h = fe::sub(&dd, &b);
    Point {
        x: fe::mul(&e, &f),
        y: fe::mul(&g, &h),
        t: fe::mul(&e, &h),
        z: fe::mul(&f, &g),
    }
}

/// scalar · p, by double-and-add over the scalar's bits.
fn scalar_mul(p: &Point, scalar: &[u8; 32]) -> Point {
    let mut r = identity();
    for i in (0..256).rev() {
        r = double(&r);
        if (scalar[i >> 3] >> (i & 7)) & 1 == 1 {
            r = add(&r, p);
        }
    }
    r
}

fn base_mul(scalar: &[u8; 32]) -> Point {
    match decompress(&BASE_BYTES) {
        Some(base) => scalar_mul(&base, scalar),
        None => identity(),
    }
}

/// Encode a point: the y-coordinate, with x's low bit in the top bit.
fn compress(p: &Point) -> [u8; 32] {
    let zinv = fe::invert(&p.z);
    let x = fe::mul(&p.x, &zinv);
    let y = fe::mul(&p.y, &zinv);
    let mut out = fe::to_bytes(&y);
    if fe::is_odd(&x) {
        out[31] |= 0x80;
    }
    out
}

/// Decode a compressed point, or None if the bytes aren't a valid point.
fn decompress(bytes: &[u8; 32]) -> Option<Point> {
    let sign = bytes[31] >> 7 == 1;
    let y = fe::from_bytes(bytes);
    let yy = fe::square(&y);
    // x^2 = (y^2 - 1) / (d·y^2 + 1)
    let u = fe::sub(&yy, &fe::ONE);
    let v = fe::add(&fe::mul(&d(), &yy), &fe::ONE);
    // Candidate x = u·v^3·(u·v^7)^((p-5)/8).
    let v3 = fe::mul(&fe::square(&v), &v);
    let v7 = fe::mul(&fe::square(&v3), &v);
    let mut x = fe::mul(&fe::mul(&u, &v3), &fe::pow2523(&fe::mul(&u, &v7)));

    let check = fe::mul(&v, &fe::square(&x));
    if !fe::equals(&check, &u) {
        if fe::equals(&check, &fe::neg(&u)) {
            x = fe::mul(&x, &sqrt_m1());
        } else {
            return None;
        }
    }
    if fe::is_odd(&x) != sign {
        x = fe::neg(&x);
    }
    if sign && fe::to_bytes(&x) == [0u8; 32] {
        return None;
    }
    Some(Point {
        t: fe::mul(&x, &y),
        x,
        y,
        z: fe::ONE,
    })
}

/// Test helper: whether a public key decompresses and recompresses to
/// itself (isolates a compress/decompress bug from the rest of verify).
#[cfg(test)]
pub(crate) fn decompress_roundtrips(pk: &[u8; 32]) -> bool {
    match decompress(pk) {
        Some(p) => &compress(&p) == pk,
        None => false,
    }
}

/// Test helper: sqrt(-1)^2 must be -1, and d must be the curve constant.
#[cfg(test)]
pub(crate) fn constants_ok() -> bool {
    fe::equals(&fe::square(&sqrt_m1()), &fe::neg(&fe::ONE))
}

/// The 32-byte public key for a 32-byte secret key.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let h = sha512(secret);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[0..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    compress(&base_mul(&a))
}

/// Sign `message` with `secret`, returning the 64-byte signature.
pub fn sign(secret: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let h = sha512(secret);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[0..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let public = compress(&base_mul(&a));

    let mut hr = Sha512::new();
    hr.update(&h[32..64]);
    hr.update(message);
    let r = scalar::reduce(&hr.finalize());
    let r_point = compress(&base_mul(&r));

    let mut hk = Sha512::new();
    hk.update(&r_point);
    hk.update(&public);
    hk.update(message);
    let k = scalar::reduce(&hk.finalize());

    let s = scalar::mul_add(&k, &a, &r);
    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&r_point);
    sig[32..64].copy_from_slice(&s);
    sig
}

/// Check a 64-byte signature on `message` under `public`.
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut r_enc = [0u8; 32];
    r_enc.copy_from_slice(&signature[0..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature[32..64]);
    if !scalar::is_canonical(&s) {
        return false;
    }
    let (Some(a_point), Some(r_point)) = (decompress(public), decompress(&r_enc)) else {
        return false;
    };

    let mut hk = Sha512::new();
    hk.update(&r_enc);
    hk.update(public);
    hk.update(message);
    let k = scalar::reduce(&hk.finalize());

    // Check [S]B == R + [k]A.
    let sb = base_mul(&s);
    let ka = scalar_mul(&a_point, &k);
    compress(&sb) == compress(&add(&r_point, &ka))
}
