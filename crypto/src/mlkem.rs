//! ML-KEM-768 (FIPS 203): the module-lattice key-encapsulation mechanism,
//! the post-quantum half of Rook's hybrid key exchange.
//!
//! This follows FIPS 203 for the ML-KEM-768 parameter set (k = 3, η = 2,
//! d_u = 10, d_v = 4) over the ring Z_q[X]/(X^256 + 1), q = 3329. The
//! number-theoretic transform, Montgomery/Barrett reductions and the
//! sampling follow the well-trodden reference arithmetic; the hashing and
//! the Fujisaki–Okamoto transform follow the standard (G = SHA3-512,
//! H = SHA3-256, J = SHAKE256, the PRF = SHAKE256), including ML-KEM's
//! domain separation `G(d ‖ k)`, its use of the message directly (no
//! pre-hash), implicit rejection, and no final KDF.
//!
//! The deterministic internal functions are exposed: the caller supplies
//! the random seeds (`d`, `z`, `m`), so this is pure and testable, and the
//! KATs pin it to the NIST vectors. Like the rest of `crypto`, it is not
//! audited.

use crate::sha3::{Shake128Reader, sha3_256, sha3_512, shake256};

const N: usize = 256;
const Q: i32 = 3329;
const K: usize = 3;
const ETA: usize = 2;
// Compression widths d_u = 10 and d_v = 4 are baked into the pack/unpack
// routines (the 0x3ff and 0xf masks and the byte counts below).

const SYM: usize = 32;
const POLYBYTES: usize = 384; // 256 coefficients, 12 bits each
const POLYVECBYTES: usize = K * POLYBYTES; // 1152
const POLYCOMPRESSED: usize = 128; // d_v = 4: 256 * 4 / 8
const POLYVECCOMPRESSED: usize = K * 320; // d_u = 10: K * 256 * 10 / 8 = 960

/// Encapsulation-key length (the public key).
pub const EK_LEN: usize = POLYVECBYTES + SYM; // 1184
/// Decapsulation-key length (the private key).
pub const DK_LEN: usize = POLYVECBYTES + EK_LEN + 2 * SYM; // 2400
/// Ciphertext length.
pub const CT_LEN: usize = POLYVECCOMPRESSED + POLYCOMPRESSED; // 1088
/// Shared-secret length.
pub const SS_LEN: usize = 32;

const QINV: i32 = -3327; // q^-1 mod 2^16

/// A ring element: 256 coefficients.
type Poly = [i16; N];
const ZERO: Poly = [0; N];

/// Montgomery reduction: for input `a`, returns `a · 2^-16 mod q` in
/// (-q, q).
fn montgomery_reduce(a: i32) -> i16 {
    let t = a.wrapping_mul(QINV) as i16;
    ((a - (t as i32) * Q) >> 16) as i16
}

/// Barrett reduction: `a mod q`, result in about [-q/2, q/2].
fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = 20159; // round(2^26 / q)
    let t = ((V * a as i32) + (1 << 25)) >> 26;
    (a as i32 - t * Q) as i16
}

/// Montgomery multiply: `a · b · 2^-16 mod q`.
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

/// Map a coefficient to [0, q).
fn freeze(a: i16) -> u16 {
    let a = barrett_reduce(a);
    (a + ((a >> 15) & Q as i16)) as u16
}

/// The 128 NTT twiddle factors, in Montgomery form, bit-reversed order.
const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// The forward NTT, in place.
fn ntt(r: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// The inverse NTT (with the Montgomery/1-over-256 scaling), in place.
fn invntt(r: &mut Poly) {
    const F: i16 = 1441; // mont^2 / 128
    let mut k = 127usize;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] -= t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in r.iter_mut() {
        *c = fqmul(*c, F);
    }
}

/// The base-case product of two degree-1 elements (a0 + a1·X)(b0 + b1·X)
/// modulo X^2 - zeta, in the NTT domain.
fn basemul(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    r[0] = fqmul(fqmul(a[1], b[1]), zeta) + fqmul(a[0], b[0]);
    r[1] = fqmul(a[0], b[1]) + fqmul(a[1], b[0]);
}

/// Pointwise multiply two polynomials in the NTT domain.
fn poly_basemul(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N / 4 {
        let z = ZETAS[64 + i];
        basemul(&mut r[4 * i..4 * i + 2], &a[4 * i..], &b[4 * i..], z);
        basemul(
            &mut r[4 * i + 2..4 * i + 4],
            &a[4 * i + 2..],
            &b[4 * i + 2..],
            -z,
        );
    }
}

fn poly_add(r: &mut Poly, a: &Poly) {
    for i in 0..N {
        r[i] += a[i];
    }
}

fn poly_sub(r: &mut Poly, a: &Poly) {
    for i in 0..N {
        r[i] -= a[i];
    }
}

fn poly_reduce(r: &mut Poly) {
    for c in r.iter_mut() {
        *c = barrett_reduce(*c);
    }
}

/// Multiply every coefficient into the Montgomery domain (×2^16 mod q).
fn poly_tomont(r: &mut Poly) {
    const F: i16 = 1353; // 2^32 mod q
    for c in r.iter_mut() {
        *c = fqmul(*c, F);
    }
}

/// r[i] += sum over the module of A[i]·v, in the NTT domain.
fn matrix_vec(a: &[[Poly; K]; K], v: &[Poly; K]) -> [Poly; K] {
    let mut out = [ZERO; K];
    for i in 0..K {
        let mut acc = ZERO;
        for j in 0..K {
            let mut t = ZERO;
            poly_basemul(&mut t, &a[i][j], &v[j]);
            poly_add(&mut acc, &t);
        }
        out[i] = acc;
    }
    out
}

/// Sample a polynomial in the NTT domain by rejection from SHAKE128 seeded
/// with `rho ‖ x ‖ y` (FIPS 203 SampleNTT).
fn sample_ntt(rho: &[u8; SYM], x: u8, y: u8) -> Poly {
    let mut seed = [0u8; SYM + 2];
    seed[..SYM].copy_from_slice(rho);
    seed[SYM] = x;
    seed[SYM + 1] = y;
    let mut reader = Shake128Reader::new(&seed);
    let mut poly = ZERO;
    let mut j = 0;
    while j < N {
        let mut block = [0u8; 168];
        reader.next_block(&mut block);
        let mut i = 0;
        while i + 3 <= 168 && j < N {
            let d1 = (block[i] as u16) | (((block[i + 1] as u16) & 0xf) << 8);
            let d2 = ((block[i + 1] as u16) >> 4) | ((block[i + 2] as u16) << 4);
            if (d1 as i32) < Q {
                poly[j] = d1 as i16;
                j += 1;
            }
            if j < N && (d2 as i32) < Q {
                poly[j] = d2 as i16;
                j += 1;
            }
            i += 3;
        }
    }
    poly
}

/// Generate the matrix Â from `rho`. When `transposed`, entry [i][j] is
/// sampled with indices (i, j); otherwise with (j, i) — the two orders
/// K-PKE keygen and encryption need.
fn gen_matrix(rho: &[u8; SYM], transposed: bool) -> [[Poly; K]; K] {
    let mut a = [[ZERO; K]; K];
    for (i, row) in a.iter_mut().enumerate() {
        for (j, cell) in row.iter_mut().enumerate() {
            let (x, y) = if transposed {
                (i as u8, j as u8)
            } else {
                (j as u8, i as u8)
            };
            *cell = sample_ntt(rho, x, y);
        }
    }
    a
}

/// The PRF: SHAKE256(seed ‖ nonce) filling `out`.
fn prf(seed: &[u8; SYM], nonce: u8, out: &mut [u8]) {
    let mut input = [0u8; SYM + 1];
    input[..SYM].copy_from_slice(seed);
    input[SYM] = nonce;
    shake256(&input, out);
}

/// Sample a polynomial from the centered binomial distribution η = 2, from
/// 128 bytes of PRF output.
fn cbd2(buf: &[u8]) -> Poly {
    let mut poly = ZERO;
    for i in 0..N / 8 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            poly[8 * i + j] = a - b;
        }
    }
    poly
}

fn poly_getnoise(seed: &[u8; SYM], nonce: u8) -> Poly {
    let mut buf = [0u8; ETA * 64];
    prf(seed, nonce, &mut buf);
    cbd2(&buf)
}

// --- Encoding and compression ---

/// Encode a polynomial's coefficients at 12 bits each (384 bytes).
fn poly_tobytes(a: &Poly, out: &mut [u8]) {
    for i in 0..N / 2 {
        let t0 = freeze(a[2 * i]);
        let t1 = freeze(a[2 * i + 1]);
        out[3 * i] = t0 as u8;
        out[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
}

/// Decode a 12-bit-packed polynomial (384 bytes).
fn poly_frombytes(a: &[u8]) -> Poly {
    let mut r = ZERO;
    for i in 0..N / 2 {
        let b0 = a[3 * i] as u16;
        let b1 = a[3 * i + 1] as u16;
        let b2 = a[3 * i + 2] as u16;
        r[2 * i] = ((b0 | (b1 << 8)) & 0xfff) as i16;
        r[2 * i + 1] = (((b1 >> 4) | (b2 << 4)) & 0xfff) as i16;
    }
    r
}

fn polyvec_tobytes(v: &[Poly; K], out: &mut [u8]) {
    for i in 0..K {
        poly_tobytes(&v[i], &mut out[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }
}

fn polyvec_frombytes(a: &[u8]) -> [Poly; K] {
    let mut v = [ZERO; K];
    for i in 0..K {
        v[i] = poly_frombytes(&a[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }
    v
}

/// Compress and pack a vector at d_u = 10 bits (960 bytes).
fn polyvec_compress(v: &[Poly; K], out: &mut [u8]) {
    let mut off = 0;
    for vi in v.iter() {
        for j in 0..N / 4 {
            let mut t = [0u16; 4];
            for (k, slot) in t.iter_mut().enumerate() {
                let x = freeze(vi[4 * j + k]) as u32;
                *slot = ((((x << 10) + (Q as u32 / 2)) / Q as u32) & 0x3ff) as u16;
            }
            out[off] = t[0] as u8;
            out[off + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
            out[off + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
            out[off + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
            out[off + 4] = (t[3] >> 2) as u8;
            off += 5;
        }
    }
}

/// Decompress a d_u = 10 vector.
fn polyvec_decompress(a: &[u8]) -> [Poly; K] {
    let mut v = [ZERO; K];
    let mut off = 0;
    for vi in v.iter_mut() {
        for j in 0..N / 4 {
            let t = [
                (a[off] as u16) | ((a[off + 1] as u16) << 8),
                ((a[off + 1] as u16) >> 2) | ((a[off + 2] as u16) << 6),
                ((a[off + 2] as u16) >> 4) | ((a[off + 3] as u16) << 4),
                ((a[off + 3] as u16) >> 6) | ((a[off + 4] as u16) << 2),
            ];
            for (k, &tk) in t.iter().enumerate() {
                let c = (tk & 0x3ff) as u32;
                vi[4 * j + k] = ((c * Q as u32 + 512) >> 10) as i16;
            }
            off += 5;
        }
    }
    v
}

/// Compress and pack a polynomial at d_v = 4 bits (128 bytes).
fn poly_compress(a: &Poly, out: &mut [u8]) {
    for i in 0..N / 2 {
        let t0 = ((((freeze(a[2 * i]) as u32) << 4) + (Q as u32 / 2)) / Q as u32) & 0xf;
        let t1 = ((((freeze(a[2 * i + 1]) as u32) << 4) + (Q as u32 / 2)) / Q as u32) & 0xf;
        out[i] = (t0 | (t1 << 4)) as u8;
    }
}

/// Decompress a d_v = 4 polynomial.
fn poly_decompress(a: &[u8]) -> Poly {
    let mut r = ZERO;
    for i in 0..N / 2 {
        r[2 * i] = (((a[i] & 0xf) as u32 * Q as u32 + 8) >> 4) as i16;
        r[2 * i + 1] = (((a[i] >> 4) as u32 * Q as u32 + 8) >> 4) as i16;
    }
    r
}

/// Decode a 32-byte message into a polynomial (0 or (q+1)/2 per bit).
fn poly_frommsg(msg: &[u8; SYM]) -> Poly {
    let mut r = ZERO;
    for i in 0..SYM {
        for j in 0..8 {
            let bit = ((msg[i] >> j) & 1) as i16;
            r[8 * i + j] = (-bit) & ((Q as i16 + 1) / 2);
        }
    }
    r
}

/// Encode a polynomial back into a 32-byte message.
fn poly_tomsg(a: &Poly) -> [u8; SYM] {
    let mut msg = [0u8; SYM];
    for i in 0..SYM {
        for j in 0..8 {
            let t = ((((freeze(a[8 * i + j]) as u32) << 1) + (Q as u32 / 2)) / Q as u32) & 1;
            msg[i] |= (t << j) as u8;
        }
    }
    msg
}

// --- K-PKE ---

/// K-PKE key generation from the 32-byte seed `d`. Returns (ek_pke,
/// dk_pke).
fn kpke_keygen(d: &[u8; SYM]) -> ([u8; EK_LEN], [u8; POLYVECBYTES]) {
    let mut g_in = [0u8; SYM + 1];
    g_in[..SYM].copy_from_slice(d);
    g_in[SYM] = K as u8; // ML-KEM domain separation: G(d ‖ k)
    let g = sha3_512(&g_in);
    let mut rho = [0u8; SYM];
    let mut sigma = [0u8; SYM];
    rho.copy_from_slice(&g[..SYM]);
    sigma.copy_from_slice(&g[SYM..]);

    let a = gen_matrix(&rho, false);
    let mut s = [ZERO; K];
    let mut e = [ZERO; K];
    let mut nonce = 0u8;
    for poly in s.iter_mut() {
        *poly = poly_getnoise(&sigma, nonce);
        nonce += 1;
    }
    for poly in e.iter_mut() {
        *poly = poly_getnoise(&sigma, nonce);
        nonce += 1;
    }
    for poly in s.iter_mut() {
        ntt(poly);
    }
    for poly in e.iter_mut() {
        ntt(poly);
    }

    let mut t = matrix_vec(&a, &s);
    for i in 0..K {
        poly_tomont(&mut t[i]);
        poly_add(&mut t[i], &e[i]);
        poly_reduce(&mut t[i]);
    }

    let mut ek = [0u8; EK_LEN];
    polyvec_tobytes(&t, &mut ek[..POLYVECBYTES]);
    ek[POLYVECBYTES..].copy_from_slice(&rho);
    let mut dk = [0u8; POLYVECBYTES];
    polyvec_tobytes(&s, &mut dk);
    (ek, dk)
}

/// K-PKE encryption of a 32-byte message under `ek` with coins `r`.
fn kpke_encrypt(ek: &[u8; EK_LEN], msg: &[u8; SYM], coins: &[u8; SYM]) -> [u8; CT_LEN] {
    let t = polyvec_frombytes(&ek[..POLYVECBYTES]);
    let mut rho = [0u8; SYM];
    rho.copy_from_slice(&ek[POLYVECBYTES..]);
    let at = gen_matrix(&rho, true);

    let mut r = [ZERO; K];
    let mut e1 = [ZERO; K];
    let mut nonce = 0u8;
    for poly in r.iter_mut() {
        *poly = poly_getnoise(coins, nonce);
        nonce += 1;
    }
    for poly in e1.iter_mut() {
        *poly = poly_getnoise(coins, nonce);
        nonce += 1;
    }
    let e2 = poly_getnoise(coins, nonce);
    for poly in r.iter_mut() {
        ntt(poly);
    }

    let mut u = matrix_vec(&at, &r);
    for i in 0..K {
        invntt(&mut u[i]);
        poly_add(&mut u[i], &e1[i]);
        poly_reduce(&mut u[i]);
    }

    let mut v = ZERO;
    for j in 0..K {
        let mut tmp = ZERO;
        poly_basemul(&mut tmp, &t[j], &r[j]);
        poly_add(&mut v, &tmp);
    }
    invntt(&mut v);
    poly_add(&mut v, &e2);
    poly_add(&mut v, &poly_frommsg(msg));
    poly_reduce(&mut v);

    let mut c = [0u8; CT_LEN];
    polyvec_compress(&u, &mut c[..POLYVECCOMPRESSED]);
    poly_compress(&v, &mut c[POLYVECCOMPRESSED..]);
    c
}

/// K-PKE decryption of ciphertext `c` with `dk_pke`.
fn kpke_decrypt(dk: &[u8; POLYVECBYTES], c: &[u8; CT_LEN]) -> [u8; SYM] {
    let mut u = polyvec_decompress(&c[..POLYVECCOMPRESSED]);
    let v = poly_decompress(&c[POLYVECCOMPRESSED..]);
    let s = polyvec_frombytes(dk);

    for poly in u.iter_mut() {
        ntt(poly);
    }
    let mut w = ZERO;
    for j in 0..K {
        let mut tmp = ZERO;
        poly_basemul(&mut tmp, &s[j], &u[j]);
        poly_add(&mut w, &tmp);
    }
    invntt(&mut w);

    let mut mp = v;
    poly_sub(&mut mp, &w);
    poly_reduce(&mut mp);
    poly_tomsg(&mp)
}

// --- ML-KEM ---

/// ML-KEM key generation from seeds `d` and `z`. Returns (ek, dk).
pub fn keygen(d: &[u8; SYM], z: &[u8; SYM]) -> ([u8; EK_LEN], [u8; DK_LEN]) {
    let (ek, dk_pke) = kpke_keygen(d);
    let mut dk = [0u8; DK_LEN];
    dk[..POLYVECBYTES].copy_from_slice(&dk_pke);
    dk[POLYVECBYTES..POLYVECBYTES + EK_LEN].copy_from_slice(&ek);
    dk[POLYVECBYTES + EK_LEN..POLYVECBYTES + EK_LEN + SYM].copy_from_slice(&sha3_256(&ek));
    dk[POLYVECBYTES + EK_LEN + SYM..].copy_from_slice(z);
    (ek, dk)
}

/// ML-KEM encapsulation under `ek` with message `m`. Returns (ciphertext,
/// shared secret).
pub fn encaps(ek: &[u8; EK_LEN], m: &[u8; SYM]) -> ([u8; CT_LEN], [u8; SS_LEN]) {
    let mut g_in = [0u8; 2 * SYM];
    g_in[..SYM].copy_from_slice(m);
    g_in[SYM..].copy_from_slice(&sha3_256(ek));
    let g = sha3_512(&g_in);
    let mut key = [0u8; SS_LEN];
    key.copy_from_slice(&g[..SYM]);
    let mut coins = [0u8; SYM];
    coins.copy_from_slice(&g[SYM..]);
    let c = kpke_encrypt(ek, m, &coins);
    (c, key)
}

/// ML-KEM decapsulation of `c` with `dk`. Returns the shared secret,
/// using implicit rejection on a bad ciphertext.
pub fn decaps(dk: &[u8; DK_LEN], c: &[u8; CT_LEN]) -> [u8; SS_LEN] {
    let mut dk_pke = [0u8; POLYVECBYTES];
    dk_pke.copy_from_slice(&dk[..POLYVECBYTES]);
    let mut ek = [0u8; EK_LEN];
    ek.copy_from_slice(&dk[POLYVECBYTES..POLYVECBYTES + EK_LEN]);
    let h = &dk[POLYVECBYTES + EK_LEN..POLYVECBYTES + EK_LEN + SYM];
    let z = &dk[POLYVECBYTES + EK_LEN + SYM..];

    let m = kpke_decrypt(&dk_pke, c);
    let mut g_in = [0u8; 2 * SYM];
    g_in[..SYM].copy_from_slice(&m);
    g_in[SYM..].copy_from_slice(h);
    let g = sha3_512(&g_in);
    let mut key = [0u8; SS_LEN];
    key.copy_from_slice(&g[..SYM]);
    let mut coins = [0u8; SYM];
    coins.copy_from_slice(&g[SYM..]);

    // Implicit rejection: K = J(z ‖ c) if the re-encryption disagrees.
    let mut reject_in = [0u8; SYM + CT_LEN];
    reject_in[..SYM].copy_from_slice(z);
    reject_in[SYM..].copy_from_slice(c);
    let mut reject = [0u8; SS_LEN];
    shake256(&reject_in, &mut reject);

    let c2 = kpke_encrypt(&ek, &m, &coins);
    let equal = ct_eq(c, &c2);
    for i in 0..SS_LEN {
        key[i] = (key[i] & equal) | (reject[i] & !equal);
    }
    key
}

/// Constant-time equality of two ciphertexts: 0xff if equal, 0 if not.
fn ct_eq(a: &[u8; CT_LEN], b: &[u8; CT_LEN]) -> u8 {
    let mut diff = 0u8;
    for i in 0..CT_LEN {
        diff |= a[i] ^ b[i];
    }
    // diff == 0  ->  0xff, else 0
    (((diff as i32 - 1) >> 8) & 0xff) as u8
}

#[cfg(test)]
mod tests;
