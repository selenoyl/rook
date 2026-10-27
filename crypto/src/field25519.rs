//! Arithmetic in the field modulo 2^255 - 19, for X25519 and Ed25519.
//!
//! A field element is five 51-bit limbs (radix 2^51) held in `u64`, the
//! well-trodden "donna" layout, so a full multiply fits in `u128` and the
//! reductions are cheap. Nothing branches on a value, so it's suitable
//! for secret data; `swap` is a constant-time conditional swap.

/// The low 51 bits.
const MASK: u64 = (1 << 51) - 1;
const MASK128: u128 = MASK as u128;

/// A field element, value = f[0] + f[1]·2^51 + f[2]·2^102 + f[3]·2^153 + f[4]·2^204.
pub type Fe = [u64; 5];

pub const ZERO: Fe = [0, 0, 0, 0, 0];
pub const ONE: Fe = [1, 0, 0, 0, 0];

/// Carry five 128-bit partial sums down into reduced 51-bit limbs,
/// wrapping 2^255 around to 19 (since 2^255 ≡ 19 mod p).
fn reduce(mut t: [u128; 5]) -> Fe {
    t[1] += t[0] >> 51;
    t[2] += t[1] >> 51;
    t[3] += t[2] >> 51;
    t[4] += t[3] >> 51;
    // Fold everything above 2^255 back in as ×19, staying in u128 so the
    // carry can't overflow even when the inputs' limbs are large.
    let mut r0 = (t[0] & MASK128) + 19 * (t[4] >> 51);
    let r1 = (t[1] & MASK128) + (r0 >> 51);
    r0 &= MASK128;
    [
        r0 as u64,
        r1 as u64,
        (t[2] & MASK128) as u64,
        (t[3] & MASK128) as u64,
        (t[4] & MASK128) as u64,
    ]
}

/// a + b, reduced so every limb is small (< 2^52). Keeping add and sub
/// reduced means a later `sub` never underflows its bias, however the
/// results are chained.
pub fn add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ];
    carry(&mut r);
    r
}

/// a - b, computed as a + 2p - b so every limb stays non-negative, then
/// reduced. The bias covers any input whose limbs are below 2^53.
pub fn sub(a: &Fe, b: &Fe) -> Fe {
    const T0: u64 = (1 << 54) - 152; // 4·(2^52 - 38)
    const TN: u64 = (1 << 54) - 8; //   4·(2^52 - 2)
    let mut r = [
        (a[0] + T0).wrapping_sub(b[0]),
        (a[1] + TN).wrapping_sub(b[1]),
        (a[2] + TN).wrapping_sub(b[2]),
        (a[3] + TN).wrapping_sub(b[3]),
        (a[4] + TN).wrapping_sub(b[4]),
    ];
    carry(&mut r);
    r
}

/// a · b mod p.
pub fn mul(a: &Fe, b: &Fe) -> Fe {
    let f: [u128; 5] = [
        a[0] as u128,
        a[1] as u128,
        a[2] as u128,
        a[3] as u128,
        a[4] as u128,
    ];
    let g0 = b[0] as u128;
    let g1 = b[1] as u128;
    let g2 = b[2] as u128;
    let g3 = b[3] as u128;
    let g4 = b[4] as u128;
    // The wrapped-around (·19) copies of the upper limbs.
    let g1_19 = 19 * g1;
    let g2_19 = 19 * g2;
    let g3_19 = 19 * g3;
    let g4_19 = 19 * g4;

    let h = [
        f[0] * g0 + f[1] * g4_19 + f[2] * g3_19 + f[3] * g2_19 + f[4] * g1_19,
        f[0] * g1 + f[1] * g0 + f[2] * g4_19 + f[3] * g3_19 + f[4] * g2_19,
        f[0] * g2 + f[1] * g1 + f[2] * g0 + f[3] * g4_19 + f[4] * g3_19,
        f[0] * g3 + f[1] * g2 + f[2] * g1 + f[3] * g0 + f[4] * g4_19,
        f[0] * g4 + f[1] * g3 + f[2] * g2 + f[3] * g1 + f[4] * g0,
    ];
    reduce(h)
}

/// a^2 mod p.
pub fn square(a: &Fe) -> Fe {
    mul(a, a)
}

/// a · 121665 mod p, the Montgomery-ladder constant (RFC 7748 a24).
pub fn mul_a24(a: &Fe) -> Fe {
    const A24: u128 = 121665;
    reduce([
        a[0] as u128 * A24,
        a[1] as u128 * A24,
        a[2] as u128 * A24,
        a[3] as u128 * A24,
        a[4] as u128 * A24,
    ])
}

/// a^(p-2) = 1/a mod p (a ≠ 0), by square-and-multiply over the fixed
/// public exponent p - 2 = 2^255 - 21, so the steps don't depend on `a`.
pub fn invert(a: &Fe) -> Fe {
    // 2^255 - 21, little-endian: 0xeb, then 0xff ×30, then 0x7f.
    let mut exponent = [0xffu8; 32];
    exponent[0] = 0xeb;
    exponent[31] = 0x7f;

    let mut r = ONE;
    for i in (0..255).rev() {
        r = square(&r);
        if (exponent[i >> 3] >> (i & 7)) & 1 == 1 {
            r = mul(&r, a);
        }
    }
    r
}

/// -a mod p.
pub fn neg(a: &Fe) -> Fe {
    sub(&ZERO, a)
}

/// Whether a and b are the same field element (compared in canonical form).
pub fn equals(a: &Fe, b: &Fe) -> bool {
    to_bytes(a) == to_bytes(b)
}

/// a^((p-5)/8) = a^(2^252 - 3) mod p, a step of the square-root used to
/// decompress Edwards points. Fixed public exponent, so constant time.
pub fn pow2523(a: &Fe) -> Fe {
    // 2^252 - 3, little-endian: 0xfd, then 0xff ×30, then 0x0f.
    let mut exponent = [0xffu8; 32];
    exponent[0] = 0xfd;
    exponent[31] = 0x0f;

    let mut r = ONE;
    for i in (0..252).rev() {
        r = square(&r);
        if (exponent[i >> 3] >> (i & 7)) & 1 == 1 {
            r = mul(&r, a);
        }
    }
    r
}

/// Whether the element is odd (its canonical low bit), the sign bit used
/// in Edwards point compression.
pub fn is_odd(a: &Fe) -> bool {
    to_bytes(a)[0] & 1 == 1
}

/// If `swap` is 1, exchange `a` and `b`; if 0, leave them. Constant time.
pub fn swap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap); // all ones iff swap == 1
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = mask & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

/// Load a field element from 32 little-endian bytes, ignoring bit 255 (as
/// X25519 requires for the u-coordinate).
pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
    let load = |at: usize| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[at..at + 8]);
        u64::from_le_bytes(buf)
    };
    [
        load(0) & MASK,
        (load(6) >> 3) & MASK,
        (load(12) >> 6) & MASK,
        (load(19) >> 1) & MASK,
        (load(24) >> 12) & MASK,
    ]
}

/// Reduce fully and serialize to 32 little-endian bytes.
pub fn to_bytes(a: &Fe) -> [u8; 32] {
    let mut t = *a;
    carry(&mut t);
    carry(&mut t);

    // Add 19; if that overflows 2^255, the value was >= p, so this is the
    // amount to fold back in to land in [0, p).
    let mut q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;
    t[0] += 19 * q;
    t[1] += t[0] >> 51;
    t[0] &= MASK;
    t[2] += t[1] >> 51;
    t[1] &= MASK;
    t[3] += t[2] >> 51;
    t[2] &= MASK;
    t[4] += t[3] >> 51;
    t[3] &= MASK;
    t[4] &= MASK; // drop the 2^255 bit

    let [t0, t1, t2, t3, t4] = t;
    [
        t0 as u8,
        (t0 >> 8) as u8,
        (t0 >> 16) as u8,
        (t0 >> 24) as u8,
        (t0 >> 32) as u8,
        (t0 >> 40) as u8,
        ((t0 >> 48) | (t1 << 3)) as u8,
        (t1 >> 5) as u8,
        (t1 >> 13) as u8,
        (t1 >> 21) as u8,
        (t1 >> 29) as u8,
        (t1 >> 37) as u8,
        ((t1 >> 45) | (t2 << 6)) as u8,
        (t2 >> 2) as u8,
        (t2 >> 10) as u8,
        (t2 >> 18) as u8,
        (t2 >> 26) as u8,
        (t2 >> 34) as u8,
        (t2 >> 42) as u8,
        ((t2 >> 50) | (t3 << 1)) as u8,
        (t3 >> 7) as u8,
        (t3 >> 15) as u8,
        (t3 >> 23) as u8,
        (t3 >> 31) as u8,
        (t3 >> 39) as u8,
        ((t3 >> 47) | (t4 << 4)) as u8,
        (t4 >> 4) as u8,
        (t4 >> 12) as u8,
        (t4 >> 20) as u8,
        (t4 >> 28) as u8,
        (t4 >> 36) as u8,
        (t4 >> 44) as u8,
    ]
}

/// One reduction pass: limbs back under 2^51, folding 2^255 into 19.
fn carry(t: &mut Fe) {
    t[1] += t[0] >> 51;
    t[0] &= MASK;
    t[2] += t[1] >> 51;
    t[1] &= MASK;
    t[3] += t[2] >> 51;
    t[2] &= MASK;
    t[4] += t[3] >> 51;
    t[3] &= MASK;
    t[0] += 19 * (t[4] >> 51);
    t[4] &= MASK;
}
