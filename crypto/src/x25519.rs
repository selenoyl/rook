//! X25519 (RFC 7748): Diffie-Hellman on Curve25519.
//!
//! The Montgomery ladder, following the RFC §5 pseudocode exactly, over
//! the field in `field25519`. The scalar is clamped as the RFC requires,
//! and the ladder is constant-time (the conditional swaps don't branch on
//! the scalar bits).

use crate::field25519 as fe;

/// Compute `scalar · point` on Curve25519 (the shared-secret / public-key
/// operation). `point` is a u-coordinate; the result is one too.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = fe::from_bytes(point);
    let mut x2 = fe::ONE;
    let mut z2 = fe::ZERO;
    let mut x3 = x1;
    let mut z3 = fe::ONE;
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let bit = u64::from((k[t >> 3] >> (t & 7)) & 1);
        swap ^= bit;
        fe::swap(swap, &mut x2, &mut x3);
        fe::swap(swap, &mut z2, &mut z3);
        swap = bit;

        let a = fe::add(&x2, &z2);
        let aa = fe::square(&a);
        let b = fe::sub(&x2, &z2);
        let bb = fe::square(&b);
        let e = fe::sub(&aa, &bb);
        let c = fe::add(&x3, &z3);
        let d = fe::sub(&x3, &z3);
        let da = fe::mul(&d, &a);
        let cb = fe::mul(&c, &b);
        x3 = fe::square(&fe::add(&da, &cb));
        z3 = fe::mul(&x1, &fe::square(&fe::sub(&da, &cb)));
        x2 = fe::mul(&aa, &bb);
        z2 = fe::mul(&e, &fe::add(&aa, &fe::mul_a24(&e)));
    }

    fe::swap(swap, &mut x2, &mut x3);
    fe::swap(swap, &mut z2, &mut z3);

    fe::to_bytes(&fe::mul(&x2, &fe::invert(&z2)))
}

/// The Curve25519 base point, u = 9.
const BASE: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// The public key for a secret `scalar`: `scalar · base point`.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    x25519(scalar, &BASE)
}
