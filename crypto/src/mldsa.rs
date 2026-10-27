//! ML-DSA-87 (FIPS 204): the module-lattice digital signature.
//!
//! This is the post-quantum half of a Rook node's identity. The design
//! doc pairs it with Ed25519: a handshake is signed by both, so a node
//! stays authentic even if elliptic curves fall to a quantum computer.
//! ML-DSA signatures are large (~4.6 KB) but verification is fast.
//!
//! The maths is Dilithium over the ring Z_q[X]/(X^256 + 1) with the
//! modulus q = 8380417, a number-theoretic transform for fast
//! multiplication, and rejection sampling in signing. The structure
//! mirrors the reference implementation (pq-crystals) and the packed
//! encodings follow FIPS 204 exactly, so the output matches NIST's
//! test vectors byte for byte (see the tests).
//!
//! Signing here is deterministic (the per-signature randomness is zero),
//! which is the "internal interface" NIST tests against and all Rook
//! needs. This crypto is not audited; see the crate root.
//!
//! The index arithmetic in the transform and the bit-packing reads most
//! clearly straight from the spec, so the range-loop lint is off here.
#![allow(clippy::needless_range_loop)]

use crate::sha3::{Shake128Reader, Shake256, Shake256Reader};

// --- Parameters (ML-DSA-87) -------------------------------------------

const N: usize = 256;
const Q: i32 = 8_380_417;
/// q^(-1) mod 2^32, for Montgomery reduction.
const QINV: i32 = 58_728_449;
/// Dropped low bits of t.
const D: i32 = 13;
const GAMMA1: i32 = 1 << 19;
const GAMMA2: i32 = (Q - 1) / 32;
const K: usize = 8;
const L: usize = 7;
const ETA: i32 = 2;
const TAU: usize = 60;
const BETA: i32 = 120;
const OMEGA: usize = 75;

const SEEDBYTES: usize = 32;
const CRHBYTES: usize = 64;
const TRBYTES: usize = 64;
const RNDBYTES: usize = 32;
const CTILDE: usize = 64;

const POLYT1_PACKEDBYTES: usize = 320;
const POLYT0_PACKEDBYTES: usize = 416;
const POLYETA_PACKEDBYTES: usize = 96;
const POLYZ_PACKEDBYTES: usize = 640;
const POLYW1_PACKEDBYTES: usize = 128;

/// Public-key length in bytes.
pub const MLDSA_PK_LEN: usize = SEEDBYTES + K * POLYT1_PACKEDBYTES; // 2592
/// Secret-key length in bytes.
pub const MLDSA_SK_LEN: usize = 2 * SEEDBYTES
    + TRBYTES
    + L * POLYETA_PACKEDBYTES
    + K * POLYETA_PACKEDBYTES
    + K * POLYT0_PACKEDBYTES; // 4896
/// Signature length in bytes.
pub const MLDSA_SIG_LEN: usize = CTILDE + L * POLYZ_PACKEDBYTES + OMEGA + K; // 4627

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

/// A polynomial: 256 signed coefficients.
type Poly = [i32; N];
/// A vector of L polynomials (the width of the secret s1 / signature z).
type VecL = [Poly; L];
/// A vector of K polynomials (the height of the module).
type VecK = [Poly; K];

// --- Modular reduction ------------------------------------------------

/// Montgomery reduction: for `a` with `|a| < q * 2^31`, return `r ≡
/// a * 2^-32 (mod q)` with `|r| < q`.
fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - t as i64 * Q as i64) >> 32) as i32
}

/// Reduce `a` to a representative congruent mod q with `|r| < (q+1)/2`.
fn reduce32(a: i32) -> i32 {
    let a = a as i64;
    let t = (a + (1 << 22)) >> 23;
    (a - t * Q as i64) as i32
}

/// Add q to a coefficient if it is negative, giving a value in `[0, q)`.
fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

// --- Number-theoretic transform ---------------------------------------

/// Powers of the 512th root of unity, in Montgomery form and bit-reversed
/// order, as the forward and inverse transforms consume them.
const ZETAS: [i32; N] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];

/// Forward NTT in place.
fn ntt(a: &mut Poly) {
    let mut k = 0usize;
    let mut len = 128;
    while len > 0 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k] as i64;
            let mut j = start;
            while j < start + len {
                let t = montgomery_reduce(zeta * a[j + len] as i64);
                a[j + len] = a[j] - t;
                a[j] += t;
                j += 1;
            }
            start = j + len;
        }
        len >>= 1;
    }
}

/// Inverse NTT in place, with the result left in Montgomery form.
fn invntt_tomont(a: &mut Poly) {
    // mont^2 / 256 mod q, folding in the 1/256 and the Montgomery factor.
    const F: i64 = 41978;
    let mut k = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -(ZETAS[k] as i64);
            let mut j = start;
            while j < start + len {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce(zeta * a[j + len] as i64);
                j += 1;
            }
            start = j + len;
        }
        len <<= 1;
    }
    for c in a.iter_mut() {
        *c = montgomery_reduce(F * *c as i64);
    }
}

/// `c[i] = a[i] * b[i] * 2^-32 mod q`, the pointwise product in NTT domain.
fn pointwise(a: &Poly, b: &Poly) -> Poly {
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = montgomery_reduce(a[i] as i64 * b[i] as i64);
    }
    c
}

fn reduce_poly(p: &mut Poly) {
    for c in p.iter_mut() {
        *c = reduce32(*c);
    }
}

// --- Rounding, hints --------------------------------------------------

/// Split `a` into high and low bits: `a = a1 * 2^D + a0`, `a0` centered.
fn power2round(a: i32) -> (i32, i32) {
    let a1 = (a + (1 << (D - 1)) - 1) >> D;
    let a0 = a - (a1 << D);
    (a1, a0)
}

/// Decompose `a` into `(a1, a0)` with `a = a1 * 2*GAMMA2 + a0`, `a0`
/// centered, for the GAMMA2 = (q-1)/32 parameter set.
fn decompose(a: i32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;
    let mut a0 = a - a1 * 2 * GAMMA2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a1, a0)
}

/// Whether the low part `a0` (with high part `a1`) needs a carry hint.
fn make_hint(a0: i32, a1: i32) -> i32 {
    i32::from(!(-GAMMA2..=GAMMA2).contains(&a0) || (a0 == -GAMMA2 && a1 != 0))
}

/// Recover the high bits of `a` using the one-bit `hint`.
fn use_hint(a: i32, hint: i32) -> i32 {
    let (a1, a0) = decompose(a);
    if hint == 0 {
        a1
    } else if a0 > 0 {
        (a1 + 1) & 15
    } else {
        (a1 - 1) & 15
    }
}

/// Whether any coefficient of `a` has absolute value `>= b` (the infinity
/// norm check that guards against leaking the secret).
fn poly_chknorm(a: &Poly, b: i32) -> bool {
    if b > (Q - 1) / 8 {
        return true;
    }
    a.iter().any(|&c| c.abs() >= b)
}

fn vecl_chknorm(v: &VecL, b: i32) -> bool {
    v.iter().any(|p| poly_chknorm(p, b))
}

fn veck_chknorm(v: &VecK, b: i32) -> bool {
    v.iter().any(|p| poly_chknorm(p, b))
}

// --- Sampling ---------------------------------------------------------

/// Expand one matrix entry A[i][j] from `rho` by rejection sampling
/// uniform coefficients mod q (ExpandA, via SHAKE128).
fn poly_uniform(rho: &[u8; SEEDBYTES], nonce: u16) -> Poly {
    let mut seed = [0u8; SEEDBYTES + 2];
    seed[..SEEDBYTES].copy_from_slice(rho);
    seed[SEEDBYTES] = nonce as u8;
    seed[SEEDBYTES + 1] = (nonce >> 8) as u8;
    let mut reader = Shake128Reader::new(&seed);
    let mut block = [0u8; SHAKE128_RATE];
    let mut a = [0i32; N];
    let mut ctr = 0;
    while ctr < N {
        reader.next_block(&mut block);
        let mut pos = 0;
        while pos + 3 <= SHAKE128_RATE && ctr < N {
            let t =
                block[pos] as u32 | (block[pos + 1] as u32) << 8 | (block[pos + 2] as u32) << 16;
            let t = (t & 0x7F_FFFF) as i32;
            pos += 3;
            if t < Q {
                a[ctr] = t;
                ctr += 1;
            }
        }
    }
    a
}

/// Expand matrix entry A[i][l] from `rho` on demand (ExpandA). The full
/// K-by-L matrix is 56 KB — too much for a ring-3 stack — so callers
/// stream it one entry at a time rather than materialising it.
fn expand_a(rho: &[u8; SEEDBYTES], i: usize, l: usize) -> Poly {
    poly_uniform(rho, ((i as u16) << 8) + l as u16)
}

/// Row `i` of `A * v` in the NTT domain: the sum over `l` of
/// `A[i][l] (*) v[l]`, expanding each A entry as it is used.
fn matrix_row_mul(rho: &[u8; SEEDBYTES], i: usize, v: &VecL) -> Poly {
    let mut acc = pointwise(&expand_a(rho, i, 0), &v[0]);
    for l in 1..L {
        let prod = pointwise(&expand_a(rho, i, l), &v[l]);
        for j in 0..N {
            acc[j] += prod[j];
        }
    }
    acc
}

/// Sample one secret polynomial with coefficients in `[-eta, eta]`
/// (ExpandS, via SHAKE256) for the ETA = 2 parameter set.
fn poly_uniform_eta(seed: &[u8; CRHBYTES], nonce: u16) -> Poly {
    let mut inbuf = [0u8; CRHBYTES + 2];
    inbuf[..CRHBYTES].copy_from_slice(seed);
    inbuf[CRHBYTES] = nonce as u8;
    inbuf[CRHBYTES + 1] = (nonce >> 8) as u8;
    let mut reader = Shake256Reader::new(&inbuf);
    let mut block = [0u8; SHAKE256_RATE];
    let mut a = [0i32; N];
    let mut ctr = 0;
    while ctr < N {
        reader.next_block(&mut block);
        let mut pos = 0;
        while pos < SHAKE256_RATE && ctr < N {
            let b = block[pos] as u32;
            pos += 1;
            let t0 = b & 0x0F;
            let t1 = b >> 4;
            if t0 < 15 {
                let t0 = t0 - ((205 * t0) >> 10) * 5;
                a[ctr] = 2 - t0 as i32;
                ctr += 1;
            }
            if t1 < 15 && ctr < N {
                let t1 = t1 - ((205 * t1) >> 10) * 5;
                a[ctr] = 2 - t1 as i32;
                ctr += 1;
            }
        }
    }
    a
}

/// Sample the masking polynomial y with coefficients in `(-GAMMA1, GAMMA1]`
/// (ExpandMask), for GAMMA1 = 2^19.
fn poly_uniform_gamma1(seed: &[u8; CRHBYTES], nonce: u16) -> Poly {
    let mut inbuf = [0u8; CRHBYTES + 2];
    inbuf[..CRHBYTES].copy_from_slice(seed);
    inbuf[CRHBYTES] = nonce as u8;
    inbuf[CRHBYTES + 1] = (nonce >> 8) as u8;
    // ceil(640/136) = 5 blocks is enough to unpack one polynomial.
    let mut buf = [0u8; 5 * SHAKE256_RATE];
    let mut sh = Shake256::new();
    sh.absorb(&inbuf);
    sh.finalize(&mut buf);
    let mut a = [0i32; N];
    polyz_unpack(&mut a, &buf[..POLYZ_PACKEDBYTES]);
    a
}

/// Sample the challenge polynomial: TAU coefficients are +-1, the rest 0
/// (SampleInBall), from the 64-byte challenge seed.
fn poly_challenge(seed: &[u8; CTILDE]) -> Poly {
    let mut reader = Shake256Reader::new(seed);
    let mut block = [0u8; SHAKE256_RATE];
    reader.next_block(&mut block);
    let mut signs: u64 = 0;
    for i in 0..8 {
        signs |= (block[i] as u64) << (8 * i);
    }
    let mut pos = 8;
    let mut c = [0i32; N];
    for i in (N - TAU)..N {
        let b = loop {
            if pos >= SHAKE256_RATE {
                reader.next_block(&mut block);
                pos = 0;
            }
            let b = block[pos] as usize;
            pos += 1;
            if b <= i {
                break b;
            }
        };
        c[i] = c[b];
        c[b] = 1 - 2 * ((signs & 1) as i32);
        signs >>= 1;
    }
    c
}

// --- Packing ----------------------------------------------------------

fn polyt1_pack(out: &mut [u8], a: &Poly) {
    for i in 0..N / 4 {
        out[5 * i] = a[4 * i] as u8;
        out[5 * i + 1] = ((a[4 * i] >> 8) | (a[4 * i + 1] << 2)) as u8;
        out[5 * i + 2] = ((a[4 * i + 1] >> 6) | (a[4 * i + 2] << 4)) as u8;
        out[5 * i + 3] = ((a[4 * i + 2] >> 4) | (a[4 * i + 3] << 6)) as u8;
        out[5 * i + 4] = (a[4 * i + 3] >> 2) as u8;
    }
}

fn polyt1_unpack(a: &mut Poly, b: &[u8]) {
    for i in 0..N / 4 {
        a[4 * i] = (b[5 * i] as i32 | (b[5 * i + 1] as i32) << 8) & 0x3FF;
        a[4 * i + 1] = ((b[5 * i + 1] as i32) >> 2 | (b[5 * i + 2] as i32) << 6) & 0x3FF;
        a[4 * i + 2] = ((b[5 * i + 2] as i32) >> 4 | (b[5 * i + 3] as i32) << 4) & 0x3FF;
        a[4 * i + 3] = ((b[5 * i + 3] as i32) >> 6 | (b[5 * i + 4] as i32) << 2) & 0x3FF;
    }
}

fn polyt0_pack(out: &mut [u8], a: &Poly) {
    for i in 0..N / 8 {
        let mut t = [0u32; 8];
        for j in 0..8 {
            t[j] = ((1 << (D - 1)) - a[8 * i + j]) as u32;
        }
        out[13 * i] = t[0] as u8;
        out[13 * i + 1] = (t[0] >> 8) as u8;
        out[13 * i + 1] |= (t[1] << 5) as u8;
        out[13 * i + 2] = (t[1] >> 3) as u8;
        out[13 * i + 3] = (t[1] >> 11) as u8;
        out[13 * i + 3] |= (t[2] << 2) as u8;
        out[13 * i + 4] = (t[2] >> 6) as u8;
        out[13 * i + 4] |= (t[3] << 7) as u8;
        out[13 * i + 5] = (t[3] >> 1) as u8;
        out[13 * i + 6] = (t[3] >> 9) as u8;
        out[13 * i + 6] |= (t[4] << 4) as u8;
        out[13 * i + 7] = (t[4] >> 4) as u8;
        out[13 * i + 8] = (t[4] >> 12) as u8;
        out[13 * i + 8] |= (t[5] << 1) as u8;
        out[13 * i + 9] = (t[5] >> 7) as u8;
        out[13 * i + 9] |= (t[6] << 6) as u8;
        out[13 * i + 10] = (t[6] >> 2) as u8;
        out[13 * i + 11] = (t[6] >> 10) as u8;
        out[13 * i + 11] |= (t[7] << 3) as u8;
        out[13 * i + 12] = (t[7] >> 5) as u8;
    }
}

fn polyt0_unpack(a: &mut Poly, b: &[u8]) {
    for i in 0..N / 8 {
        a[8 * i] = b[13 * i] as i32 | (b[13 * i + 1] as i32) << 8;
        a[8 * i] &= 0x1FFF;
        a[8 * i + 1] = (b[13 * i + 1] as i32) >> 5
            | (b[13 * i + 2] as i32) << 3
            | (b[13 * i + 3] as i32) << 11;
        a[8 * i + 1] &= 0x1FFF;
        a[8 * i + 2] = (b[13 * i + 3] as i32) >> 2 | (b[13 * i + 4] as i32) << 6;
        a[8 * i + 2] &= 0x1FFF;
        a[8 * i + 3] =
            (b[13 * i + 4] as i32) >> 7 | (b[13 * i + 5] as i32) << 1 | (b[13 * i + 6] as i32) << 9;
        a[8 * i + 3] &= 0x1FFF;
        a[8 * i + 4] = (b[13 * i + 6] as i32) >> 4
            | (b[13 * i + 7] as i32) << 4
            | (b[13 * i + 8] as i32) << 12;
        a[8 * i + 4] &= 0x1FFF;
        a[8 * i + 5] = (b[13 * i + 8] as i32) >> 1 | (b[13 * i + 9] as i32) << 7;
        a[8 * i + 5] &= 0x1FFF;
        a[8 * i + 6] = (b[13 * i + 9] as i32) >> 6
            | (b[13 * i + 10] as i32) << 2
            | (b[13 * i + 11] as i32) << 10;
        a[8 * i + 6] &= 0x1FFF;
        a[8 * i + 7] = (b[13 * i + 11] as i32) >> 3 | (b[13 * i + 12] as i32) << 5;
        a[8 * i + 7] &= 0x1FFF;
        for j in 0..8 {
            a[8 * i + j] = (1 << (D - 1)) - a[8 * i + j];
        }
    }
}

fn polyeta_pack(out: &mut [u8], a: &Poly) {
    for i in 0..N / 8 {
        let mut t = [0u32; 8];
        for j in 0..8 {
            t[j] = (ETA - a[8 * i + j]) as u32;
        }
        out[3 * i] = (t[0] | (t[1] << 3) | (t[2] << 6)) as u8;
        out[3 * i + 1] = ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) as u8;
        out[3 * i + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) as u8;
    }
}

fn polyeta_unpack(a: &mut Poly, b: &[u8]) {
    for i in 0..N / 8 {
        a[8 * i] = (b[3 * i] as i32) & 7;
        a[8 * i + 1] = (b[3 * i] as i32 >> 3) & 7;
        a[8 * i + 2] = (b[3 * i] as i32 >> 6 | (b[3 * i + 1] as i32) << 2) & 7;
        a[8 * i + 3] = (b[3 * i + 1] as i32 >> 1) & 7;
        a[8 * i + 4] = (b[3 * i + 1] as i32 >> 4) & 7;
        a[8 * i + 5] = (b[3 * i + 1] as i32 >> 7 | (b[3 * i + 2] as i32) << 1) & 7;
        a[8 * i + 6] = (b[3 * i + 2] as i32 >> 2) & 7;
        a[8 * i + 7] = (b[3 * i + 2] as i32 >> 5) & 7;
        for j in 0..8 {
            a[8 * i + j] = ETA - a[8 * i + j];
        }
    }
}

fn polyz_pack(out: &mut [u8], a: &Poly) {
    for i in 0..N / 2 {
        let t0 = (GAMMA1 - a[2 * i]) as u32;
        let t1 = (GAMMA1 - a[2 * i + 1]) as u32;
        out[5 * i] = t0 as u8;
        out[5 * i + 1] = (t0 >> 8) as u8;
        out[5 * i + 2] = (t0 >> 16) as u8;
        out[5 * i + 2] |= (t1 << 4) as u8;
        out[5 * i + 3] = (t1 >> 4) as u8;
        out[5 * i + 4] = (t1 >> 12) as u8;
    }
}

fn polyz_unpack(a: &mut Poly, b: &[u8]) {
    for i in 0..N / 2 {
        let b0 = b[5 * i] as i32;
        let b1 = b[5 * i + 1] as i32;
        let b2 = b[5 * i + 2] as i32;
        let b3 = b[5 * i + 3] as i32;
        let b4 = b[5 * i + 4] as i32;
        let c0 = (b0 | b1 << 8 | b2 << 16) & 0xF_FFFF;
        let c1 = b2 >> 4 | b3 << 4 | b4 << 12;
        a[2 * i] = GAMMA1 - c0;
        a[2 * i + 1] = GAMMA1 - c1;
    }
}

fn polyw1_pack(out: &mut [u8], a: &Poly) {
    for i in 0..N / 2 {
        out[i] = (a[2 * i] | (a[2 * i + 1] << 4)) as u8;
    }
}

fn pack_pk(rho: &[u8; SEEDBYTES], t1: &VecK) -> [u8; MLDSA_PK_LEN] {
    let mut pk = [0u8; MLDSA_PK_LEN];
    pk[..SEEDBYTES].copy_from_slice(rho);
    for i in 0..K {
        let off = SEEDBYTES + i * POLYT1_PACKEDBYTES;
        polyt1_pack(&mut pk[off..off + POLYT1_PACKEDBYTES], &t1[i]);
    }
    pk
}

struct Pk {
    rho: [u8; SEEDBYTES],
    t1: VecK,
}

fn unpack_pk(pk: &[u8; MLDSA_PK_LEN]) -> Pk {
    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&pk[..SEEDBYTES]);
    let mut t1 = [[0i32; N]; K];
    for i in 0..K {
        let off = SEEDBYTES + i * POLYT1_PACKEDBYTES;
        polyt1_unpack(&mut t1[i], &pk[off..off + POLYT1_PACKEDBYTES]);
    }
    Pk { rho, t1 }
}

fn pack_sk(
    rho: &[u8; SEEDBYTES],
    tr: &[u8; TRBYTES],
    key: &[u8; SEEDBYTES],
    t0: &VecK,
    s1: &VecL,
    s2: &VecK,
) -> [u8; MLDSA_SK_LEN] {
    let mut sk = [0u8; MLDSA_SK_LEN];
    let mut off = 0;
    sk[off..off + SEEDBYTES].copy_from_slice(rho);
    off += SEEDBYTES;
    sk[off..off + SEEDBYTES].copy_from_slice(key);
    off += SEEDBYTES;
    sk[off..off + TRBYTES].copy_from_slice(tr);
    off += TRBYTES;
    for i in 0..L {
        polyeta_pack(&mut sk[off..off + POLYETA_PACKEDBYTES], &s1[i]);
        off += POLYETA_PACKEDBYTES;
    }
    for i in 0..K {
        polyeta_pack(&mut sk[off..off + POLYETA_PACKEDBYTES], &s2[i]);
        off += POLYETA_PACKEDBYTES;
    }
    for i in 0..K {
        polyt0_pack(&mut sk[off..off + POLYT0_PACKEDBYTES], &t0[i]);
        off += POLYT0_PACKEDBYTES;
    }
    sk
}

struct Sk {
    rho: [u8; SEEDBYTES],
    key: [u8; SEEDBYTES],
    tr: [u8; TRBYTES],
    s1: VecL,
    s2: VecK,
    t0: VecK,
}

fn unpack_sk(sk: &[u8; MLDSA_SK_LEN]) -> Sk {
    let mut rho = [0u8; SEEDBYTES];
    let mut key = [0u8; SEEDBYTES];
    let mut tr = [0u8; TRBYTES];
    let mut off = 0;
    rho.copy_from_slice(&sk[off..off + SEEDBYTES]);
    off += SEEDBYTES;
    key.copy_from_slice(&sk[off..off + SEEDBYTES]);
    off += SEEDBYTES;
    tr.copy_from_slice(&sk[off..off + TRBYTES]);
    off += TRBYTES;
    let mut s1 = [[0i32; N]; L];
    for i in 0..L {
        polyeta_unpack(&mut s1[i], &sk[off..off + POLYETA_PACKEDBYTES]);
        off += POLYETA_PACKEDBYTES;
    }
    let mut s2 = [[0i32; N]; K];
    for i in 0..K {
        polyeta_unpack(&mut s2[i], &sk[off..off + POLYETA_PACKEDBYTES]);
        off += POLYETA_PACKEDBYTES;
    }
    let mut t0 = [[0i32; N]; K];
    for i in 0..K {
        polyt0_unpack(&mut t0[i], &sk[off..off + POLYT0_PACKEDBYTES]);
        off += POLYT0_PACKEDBYTES;
    }
    Sk {
        rho,
        key,
        tr,
        s1,
        s2,
        t0,
    }
}

fn pack_sig(ctilde: &[u8; CTILDE], z: &VecL, hint: &VecK) -> [u8; MLDSA_SIG_LEN] {
    let mut sig = [0u8; MLDSA_SIG_LEN];
    sig[..CTILDE].copy_from_slice(ctilde);
    for i in 0..L {
        let off = CTILDE + i * POLYZ_PACKEDBYTES;
        polyz_pack(&mut sig[off..off + POLYZ_PACKEDBYTES], &z[i]);
    }
    // Encode the hint: the positions of the ones in each polynomial, then
    // a running count marking the end of each polynomial's run.
    let base = CTILDE + L * POLYZ_PACKEDBYTES;
    let mut k = 0usize;
    for i in 0..K {
        for j in 0..N {
            if hint[i][j] != 0 {
                sig[base + k] = j as u8;
                k += 1;
            }
        }
        sig[base + OMEGA + i] = k as u8;
    }
    sig
}

struct Sig {
    ctilde: [u8; CTILDE],
    z: VecL,
    hint: VecK,
}

/// Unpack a signature, rejecting any malformed hint encoding (the checks
/// that give ML-DSA its strong unforgeability).
fn unpack_sig(sig: &[u8; MLDSA_SIG_LEN]) -> Option<Sig> {
    let mut ctilde = [0u8; CTILDE];
    ctilde.copy_from_slice(&sig[..CTILDE]);
    let mut z = [[0i32; N]; L];
    for i in 0..L {
        let off = CTILDE + i * POLYZ_PACKEDBYTES;
        polyz_unpack(&mut z[i], &sig[off..off + POLYZ_PACKEDBYTES]);
    }
    let base = CTILDE + L * POLYZ_PACKEDBYTES;
    let mut hint = [[0i32; N]; K];
    let mut k = 0usize;
    for i in 0..K {
        let end = sig[base + OMEGA + i] as usize;
        if end < k || end > OMEGA {
            return None;
        }
        for j in k..end {
            if j > k && sig[base + j] <= sig[base + j - 1] {
                return None;
            }
            hint[i][sig[base + j] as usize] = 1;
        }
        k = end;
    }
    for j in k..OMEGA {
        if sig[base + j] != 0 {
            return None;
        }
    }
    Some(Sig { ctilde, z, hint })
}

// --- Key generation, signing, verification ----------------------------

/// Compute the public key (and the dropped low bits t0) from rho and the
/// secret vectors: t = A*s1 + s2, split into (t1 << D) + t0.
fn compute_public(rho: &[u8; SEEDBYTES], s1: &VecL, s2: &VecK) -> ([u8; MLDSA_PK_LEN], VecK) {
    let mut s1hat = *s1;
    for p in s1hat.iter_mut() {
        ntt(p);
    }
    let mut t = [[0i32; N]; K];
    for i in 0..K {
        let mut acc = matrix_row_mul(rho, i, &s1hat);
        reduce_poly(&mut acc);
        invntt_tomont(&mut acc);
        t[i] = acc;
    }
    let mut t1 = [[0i32; N]; K];
    let mut t0 = [[0i32; N]; K];
    for i in 0..K {
        for j in 0..N {
            let v = caddq(t[i][j] + s2[i][j]);
            let (hi, lo) = power2round(v);
            t1[i][j] = hi;
            t0[i][j] = lo;
        }
    }
    (pack_pk(rho, &t1), t0)
}

/// Generate a key pair deterministically from a 32-byte seed
/// (ML-DSA.KeyGen_internal).
pub fn keygen(seed: &[u8; SEEDBYTES]) -> ([u8; MLDSA_PK_LEN], [u8; MLDSA_SK_LEN]) {
    let mut h_in = [0u8; SEEDBYTES + 2];
    h_in[..SEEDBYTES].copy_from_slice(seed);
    h_in[SEEDBYTES] = K as u8;
    h_in[SEEDBYTES + 1] = L as u8;
    let mut expanded = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut sh = Shake256::new();
    sh.absorb(&h_in);
    sh.finalize(&mut expanded);

    let mut rho = [0u8; SEEDBYTES];
    let mut rhoprime = [0u8; CRHBYTES];
    let mut key = [0u8; SEEDBYTES];
    rho.copy_from_slice(&expanded[..SEEDBYTES]);
    rhoprime.copy_from_slice(&expanded[SEEDBYTES..SEEDBYTES + CRHBYTES]);
    key.copy_from_slice(&expanded[SEEDBYTES + CRHBYTES..]);

    let mut s1 = [[0i32; N]; L];
    for i in 0..L {
        s1[i] = poly_uniform_eta(&rhoprime, i as u16);
    }
    let mut s2 = [[0i32; N]; K];
    for i in 0..K {
        s2[i] = poly_uniform_eta(&rhoprime, (L + i) as u16);
    }

    let (pk, t0) = compute_public(&rho, &s1, &s2);

    let mut tr = [0u8; TRBYTES];
    let mut sh = Shake256::new();
    sh.absorb(&pk);
    sh.finalize(&mut tr);

    let sk = pack_sk(&rho, &tr, &key, &t0, &s1, &s2);
    (pk, sk)
}

/// Recover the public key from a secret key (recomputing t = A*s1 + s2).
/// Useful when only the secret is stored but the peer needs the public
/// half, as a hybrid identity does.
pub fn public_from_secret(sk: &[u8; MLDSA_SK_LEN]) -> [u8; MLDSA_PK_LEN] {
    let s = unpack_sk(sk);
    let (pk, _) = compute_public(&s.rho, &s.s1, &s.s2);
    pk
}

/// Sign `message` with `sk`, deterministically (ML-DSA.Sign_internal with
/// zero randomness — the interface NIST's known-answer tests use).
pub fn sign(message: &[u8], sk: &[u8; MLDSA_SK_LEN]) -> [u8; MLDSA_SIG_LEN] {
    let s = unpack_sk(sk);

    // mu = H(tr || message); rhoprime'' = H(key || 0 || mu).
    let mut mu = [0u8; CRHBYTES];
    let mut h = Shake256::new();
    h.absorb(&s.tr);
    h.absorb(message);
    h.finalize(&mut mu);

    let mut rhoprime = [0u8; CRHBYTES];
    let mut h = Shake256::new();
    h.absorb(&s.key);
    h.absorb(&[0u8; RNDBYTES]);
    h.absorb(&mu);
    h.finalize(&mut rhoprime);

    let rho = s.rho;
    let mut s1 = s.s1;
    let mut s2 = s.s2;
    let mut t0 = s.t0;
    for p in s1.iter_mut() {
        ntt(p);
    }
    for p in s2.iter_mut() {
        ntt(p);
    }
    for p in t0.iter_mut() {
        ntt(p);
    }

    let mut nonce: u16 = 0;
    loop {
        // Sample y and compute w = A*y.
        let mut y = [[0i32; N]; L];
        for i in 0..L {
            y[i] = poly_uniform_gamma1(&rhoprime, nonce);
            nonce += 1;
        }
        let mut z = y;
        for p in z.iter_mut() {
            ntt(p);
        }
        let mut w1 = [[0i32; N]; K];
        let mut w0 = [[0i32; N]; K];
        for i in 0..K {
            let mut acc = matrix_row_mul(&rho, i, &z);
            reduce_poly(&mut acc);
            invntt_tomont(&mut acc);
            for j in 0..N {
                let (hi, lo) = decompose(caddq(acc[j]));
                w1[i][j] = hi;
                w0[i][j] = lo;
            }
        }

        // Challenge c = H(mu || w1).
        let mut w1packed = [0u8; K * POLYW1_PACKEDBYTES];
        for i in 0..K {
            let off = i * POLYW1_PACKEDBYTES;
            polyw1_pack(&mut w1packed[off..off + POLYW1_PACKEDBYTES], &w1[i]);
        }
        let mut ctilde = [0u8; CTILDE];
        let mut h = Shake256::new();
        h.absorb(&mu);
        h.absorb(&w1packed);
        h.finalize(&mut ctilde);
        let mut cp = poly_challenge(&ctilde);
        ntt(&mut cp);

        // z = y + c*s1; reject if its norm leaks the secret.
        let mut zz = [[0i32; N]; L];
        for i in 0..L {
            let mut cs = pointwise(&cp, &s1[i]);
            invntt_tomont(&mut cs);
            for j in 0..N {
                cs[j] += y[i][j];
            }
            reduce_poly(&mut cs);
            zz[i] = cs;
        }
        if vecl_chknorm(&zz, GAMMA1 - BETA) {
            continue;
        }

        // w0 - c*s2 must keep the high bits; its norm must stay small.
        for i in 0..K {
            let mut cs = pointwise(&cp, &s2[i]);
            invntt_tomont(&mut cs);
            for j in 0..N {
                w0[i][j] -= cs[j];
            }
            reduce_poly(&mut w0[i]);
        }
        if veck_chknorm(&w0, GAMMA2 - BETA) {
            continue;
        }

        // c*t0: bounded, and the carries it forces become the hint.
        let mut ct0 = [[0i32; N]; K];
        for i in 0..K {
            let mut cs = pointwise(&cp, &t0[i]);
            invntt_tomont(&mut cs);
            reduce_poly(&mut cs);
            ct0[i] = cs;
        }
        if veck_chknorm(&ct0, GAMMA2) {
            continue;
        }

        let mut hint = [[0i32; N]; K];
        let mut count = 0usize;
        for i in 0..K {
            for j in 0..N {
                w0[i][j] += ct0[i][j];
                let bit = make_hint(w0[i][j], w1[i][j]);
                hint[i][j] = bit;
                count += bit as usize;
            }
        }
        if count > OMEGA {
            continue;
        }
        return pack_sig(&ctilde, &zz, &hint);
    }
}

/// Verify `sig` on `message` under `pk` (ML-DSA.Verify_internal).
pub fn verify(message: &[u8], sig: &[u8], pk: &[u8; MLDSA_PK_LEN]) -> bool {
    if sig.len() != MLDSA_SIG_LEN {
        return false;
    }
    let mut sig_arr = [0u8; MLDSA_SIG_LEN];
    sig_arr.copy_from_slice(sig);
    let unpacked = match unpack_sig(&sig_arr) {
        Some(v) => v,
        None => return false,
    };
    if vecl_chknorm(&unpacked.z, GAMMA1 - BETA) {
        return false;
    }
    let pub_key = unpack_pk(pk);

    // mu = H(H(pk) || message).
    let mut tr = [0u8; TRBYTES];
    let mut h = Shake256::new();
    h.absorb(pk);
    h.finalize(&mut tr);
    let mut mu = [0u8; CRHBYTES];
    let mut h = Shake256::new();
    h.absorb(&tr);
    h.absorb(message);
    h.finalize(&mut mu);

    let mut cp = poly_challenge(&unpacked.ctilde);
    let rho = pub_key.rho;

    let mut z = unpacked.z;
    for p in z.iter_mut() {
        ntt(p);
    }
    ntt(&mut cp);

    // t1 scaled up and transformed, to subtract c * t1 * 2^D.
    let mut t1 = pub_key.t1;
    for p in t1.iter_mut() {
        for c in p.iter_mut() {
            *c <<= D;
        }
        ntt(p);
    }

    let mut w1 = [[0i32; N]; K];
    for i in 0..K {
        let mut acc = matrix_row_mul(&rho, i, &z);
        let ct1 = pointwise(&cp, &t1[i]);
        for j in 0..N {
            acc[j] -= ct1[j];
        }
        reduce_poly(&mut acc);
        invntt_tomont(&mut acc);
        for j in 0..N {
            w1[i][j] = use_hint(caddq(acc[j]), unpacked.hint[i][j]);
        }
    }

    let mut w1packed = [0u8; K * POLYW1_PACKEDBYTES];
    for i in 0..K {
        let off = i * POLYW1_PACKEDBYTES;
        polyw1_pack(&mut w1packed[off..off + POLYW1_PACKEDBYTES], &w1[i]);
    }
    let mut c2 = [0u8; CTILDE];
    let mut h = Shake256::new();
    h.absorb(&mu);
    h.absorb(&w1packed);
    h.finalize(&mut c2);

    unpacked.ctilde == c2
}

#[cfg(test)]
mod tests;
