//! SLH-DSA (FIPS 205): stateless hash-based signatures, the SPHINCS+
//! design. This is the SLH-DSA-SHAKE-128f parameter set, built on SHAKE256
//! alone, following FIPS 205 to the letter.
//!
//! The scheme is a hypertree of XMSS trees (each a Merkle tree over WOTS+
//! one-time keys) signing the roots below it, with a FORS few-time
//! signature at the bottom chosen by the message digest. Its security
//! rests only on the hash function, so it is conservative and
//! post-quantum — the signature half of Rook's planned hybrid identity.
//!
//! Signing here is deterministic (the randomizer is derived from the
//! secret key and message), which matches the FIPS 205 internal functions
//! and the NIST ACVP vectors this is pinned to. Verification is cheap;
//! signing is not. Like the rest of `crypto`, it is not audited.

use crate::sha3::Shake256;

// SLH-DSA-SHAKE-128f parameters (FIPS 205, Table 2).
const N: usize = 16;
const H: usize = 66;
const D: usize = 22;
const HP: usize = H / D; // 3, height of each XMSS tree
const A: usize = 6; // FORS tree height
const K: usize = 33; // number of FORS trees
const LGW: usize = 4;
const W: u32 = 16;
const LEN1: usize = 32; // ceil(8n / lg_w)
const LEN2: usize = 3;
const LEN: usize = LEN1 + LEN2; // 35
const M_DIGEST: usize = 34; // H_msg output

const MD_LEN: usize = 25; // ceil(k*a/8)
const TREE_IDX_LEN: usize = 8; // ceil((h - h/d)/8)
const LEAF_IDX_LEN: usize = 1; // ceil(h / (8 d))

/// Key and signature sizes.
pub const PK_LEN: usize = 2 * N; // 32
pub const SK_LEN: usize = 4 * N; // 64
pub const SIG_LEN: usize = N + K * (1 + A) * N + D * (LEN + HP) * N; // 17088

const FORS_SIG_LEN: usize = K * (1 + A) * N; // 3696

// ADRS types.
const WOTS_HASH: u32 = 0;
const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

/// A 32-byte hash address (the full ADRS the SHAKE parameter sets use).
#[derive(Clone, Copy)]
struct Adrs([u8; 32]);

impl Adrs {
    fn new() -> Adrs {
        Adrs([0u8; 32])
    }
    fn set_layer(&mut self, l: u32) {
        self.0[0..4].copy_from_slice(&l.to_be_bytes());
    }
    fn set_tree(&mut self, t: u64) {
        self.0[4..8].copy_from_slice(&[0, 0, 0, 0]);
        self.0[8..16].copy_from_slice(&t.to_be_bytes());
    }
    fn set_type_and_clear(&mut self, y: u32) {
        self.0[16..20].copy_from_slice(&y.to_be_bytes());
        self.0[20..32].copy_from_slice(&[0u8; 12]);
    }
    fn set_key_pair(&mut self, i: u32) {
        self.0[20..24].copy_from_slice(&i.to_be_bytes());
    }
    fn key_pair(&self) -> u32 {
        u32::from_be_bytes([self.0[20], self.0[21], self.0[22], self.0[23]])
    }
    fn set_chain(&mut self, i: u32) {
        self.0[24..28].copy_from_slice(&i.to_be_bytes());
    }
    fn set_tree_height(&mut self, i: u32) {
        self.0[24..28].copy_from_slice(&i.to_be_bytes());
    }
    fn set_hash(&mut self, i: u32) {
        self.0[28..32].copy_from_slice(&i.to_be_bytes());
    }
    fn set_tree_index(&mut self, i: u32) {
        self.0[28..32].copy_from_slice(&i.to_be_bytes());
    }
    fn tree_index(&self) -> u32 {
        u32::from_be_bytes([self.0[28], self.0[29], self.0[30], self.0[31]])
    }
}

// --- Hash functions (FIPS 205 §11.1, SHAKE) ---

/// F / H / T_len: SHAKE256(PK.seed ∥ ADRS ∥ M), n bytes.
fn t_hash(pkseed: &[u8; N], adrs: &Adrs, msg: &[u8]) -> [u8; N] {
    let mut s = Shake256::new();
    s.absorb(pkseed);
    s.absorb(&adrs.0);
    s.absorb(msg);
    let mut out = [0u8; N];
    s.finalize(&mut out);
    out
}

/// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed ∥ ADRS ∥ SK.seed), n bytes.
fn prf(pkseed: &[u8; N], skseed: &[u8; N], adrs: &Adrs) -> [u8; N] {
    let mut s = Shake256::new();
    s.absorb(pkseed);
    s.absorb(&adrs.0);
    s.absorb(skseed);
    let mut out = [0u8; N];
    s.finalize(&mut out);
    out
}

/// H_msg(R, PK.seed, PK.root, M), m bytes.
fn h_msg(r: &[u8; N], pkseed: &[u8; N], pkroot: &[u8; N], msg: &[u8]) -> [u8; M_DIGEST] {
    let mut s = Shake256::new();
    s.absorb(r);
    s.absorb(pkseed);
    s.absorb(pkroot);
    s.absorb(msg);
    let mut out = [0u8; M_DIGEST];
    s.finalize(&mut out);
    out
}

/// PRF_msg(SK.prf, opt_rand, M), n bytes.
fn prf_msg(skprf: &[u8; N], optrand: &[u8; N], msg: &[u8]) -> [u8; N] {
    let mut s = Shake256::new();
    s.absorb(skprf);
    s.absorb(optrand);
    s.absorb(msg);
    let mut out = [0u8; N];
    s.finalize(&mut out);
    out
}

/// Convert bytes to `out.len()` base-2^b digits (FIPS 205 Algorithm 4).
fn base_2b(x: &[u8], b: usize, out: &mut [u32]) {
    let mut in_pos = 0;
    let mut bits = 0usize;
    let mut total: u32 = 0;
    for digit in out.iter_mut() {
        while bits < b {
            total = (total << 8) | x[in_pos] as u32;
            in_pos += 1;
            bits += 8;
        }
        bits -= b;
        *digit = (total >> bits) & ((1 << b) - 1);
    }
}

// --- WOTS+ ---

/// Iterate F `s` times starting at chain position `i` (FIPS 205 Alg 5).
fn chain(x: &[u8; N], i: u32, s: u32, pkseed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let mut tmp = *x;
    for j in i..i + s {
        adrs.set_hash(j);
        tmp = t_hash(pkseed, adrs, &tmp);
    }
    tmp
}

/// The WOTS+ message digits: LEN1 base-w digits of `m`, then LEN2 checksum
/// digits (FIPS 205 Alg 7/8).
fn wots_digits(m: &[u8; N]) -> [u32; LEN] {
    let mut msg = [0u32; LEN];
    base_2b(m, LGW, &mut msg[..LEN1]);
    let mut csum: u32 = 0;
    for &d in &msg[..LEN1] {
        csum += W - 1 - d;
    }
    csum <<= (8 - ((LEN2 * LGW) % 8)) % 8; // align to a byte boundary
    let csum_bytes = [(csum >> 8) as u8, csum as u8];
    base_2b(&csum_bytes, LGW, &mut msg[LEN1..]);
    msg
}

/// A WOTS+ public key: compress the LEN chain tops (FIPS 205 Alg 6).
fn wots_pkgen(skseed: &[u8; N], pkseed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair(adrs.key_pair());
    let mut tmp = [0u8; LEN * N];
    for i in 0..LEN {
        sk_adrs.set_chain(i as u32);
        let sk = prf(pkseed, skseed, &sk_adrs);
        adrs.set_chain(i as u32);
        let top = chain(&sk, 0, W - 1, pkseed, adrs);
        tmp[i * N..i * N + N].copy_from_slice(&top);
    }
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(WOTS_PK);
    pk_adrs.set_key_pair(adrs.key_pair());
    t_hash(pkseed, &pk_adrs, &tmp)
}

/// A WOTS+ signature (FIPS 205 Alg 7).
fn wots_sign(m: &[u8; N], skseed: &[u8; N], pkseed: &[u8; N], adrs: &mut Adrs, out: &mut [u8]) {
    let msg = wots_digits(m);
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair(adrs.key_pair());
    for i in 0..LEN {
        sk_adrs.set_chain(i as u32);
        let sk = prf(pkseed, skseed, &sk_adrs);
        adrs.set_chain(i as u32);
        let sig_i = chain(&sk, 0, msg[i], pkseed, adrs);
        out[i * N..i * N + N].copy_from_slice(&sig_i);
    }
}

/// The WOTS+ public key recovered from a signature (FIPS 205 Alg 8).
fn wots_pk_from_sig(sig: &[u8], m: &[u8; N], pkseed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let msg = wots_digits(m);
    let mut tmp = [0u8; LEN * N];
    for i in 0..LEN {
        adrs.set_chain(i as u32);
        let mut x = [0u8; N];
        x.copy_from_slice(&sig[i * N..i * N + N]);
        let top = chain(&x, msg[i], W - 1 - msg[i], pkseed, adrs);
        tmp[i * N..i * N + N].copy_from_slice(&top);
    }
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(WOTS_PK);
    pk_adrs.set_key_pair(adrs.key_pair());
    t_hash(pkseed, &pk_adrs, &tmp)
}

// --- XMSS ---

/// The XMSS Merkle node at height `z`, index `i` (FIPS 205 Alg 9).
fn xmss_node(skseed: &[u8; N], i: u32, z: u32, pkseed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    if z == 0 {
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair(i);
        wots_pkgen(skseed, pkseed, adrs)
    } else {
        let l = xmss_node(skseed, 2 * i, z - 1, pkseed, adrs);
        let r = xmss_node(skseed, 2 * i + 1, z - 1, pkseed, adrs);
        adrs.set_type_and_clear(TREE);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);
        let mut m = [0u8; 2 * N];
        m[..N].copy_from_slice(&l);
        m[N..].copy_from_slice(&r);
        t_hash(pkseed, adrs, &m)
    }
}

/// An XMSS signature: a WOTS+ signature then the authentication path
/// (FIPS 205 Alg 10). Writes (LEN + HP)·N bytes.
fn xmss_sign(
    m: &[u8; N],
    skseed: &[u8; N],
    idx: u32,
    pkseed: &[u8; N],
    adrs: &mut Adrs,
    out: &mut [u8],
) {
    for j in 0..HP {
        let k = (idx >> j) ^ 1;
        let node = xmss_node(skseed, k, j as u32, pkseed, adrs);
        out[(LEN + j) * N..(LEN + j) * N + N].copy_from_slice(&node);
    }
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair(idx);
    wots_sign(m, skseed, pkseed, adrs, &mut out[..LEN * N]);
}

/// The XMSS root recovered from a signature (FIPS 205 Alg 11).
fn xmss_pk_from_sig(
    idx: u32,
    sig: &[u8],
    m: &[u8; N],
    pkseed: &[u8; N],
    adrs: &mut Adrs,
) -> [u8; N] {
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair(idx);
    let mut node = wots_pk_from_sig(&sig[..LEN * N], m, pkseed, adrs);
    adrs.set_type_and_clear(TREE);
    adrs.set_tree_index(idx);
    for k in 0..HP {
        adrs.set_tree_height(k as u32 + 1);
        let auth = &sig[(LEN + k) * N..(LEN + k) * N + N];
        let mut buf = [0u8; 2 * N];
        if (idx >> k) & 1 == 0 {
            adrs.set_tree_index(adrs.tree_index() / 2);
            buf[..N].copy_from_slice(&node);
            buf[N..].copy_from_slice(auth);
        } else {
            adrs.set_tree_index((adrs.tree_index() - 1) / 2);
            buf[..N].copy_from_slice(auth);
            buf[N..].copy_from_slice(&node);
        }
        node = t_hash(pkseed, adrs, &buf);
    }
    node
}

// --- Hypertree ---

/// A hypertree signature (FIPS 205 Alg 12). Writes D·(LEN + HP)·N bytes.
fn ht_sign(
    m: &[u8; N],
    skseed: &[u8; N],
    pkseed: &[u8; N],
    mut idx_tree: u64,
    mut idx_leaf: u32,
    out: &mut [u8],
) {
    const XMSS: usize = (LEN + HP) * N;
    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    xmss_sign(m, skseed, idx_leaf, pkseed, &mut adrs, &mut out[..XMSS]);
    let mut root = {
        let mut a = Adrs::new();
        a.set_tree(idx_tree);
        xmss_pk_from_sig(idx_leaf, &out[..XMSS], m, pkseed, &mut a)
    };
    for j in 1..D {
        idx_leaf = (idx_tree & ((1 << HP) - 1)) as u32;
        idx_tree >>= HP;
        let mut a = Adrs::new();
        a.set_layer(j as u32);
        a.set_tree(idx_tree);
        let seg = &mut out[j * XMSS..(j + 1) * XMSS];
        xmss_sign(&root, skseed, idx_leaf, pkseed, &mut a, seg);
        if j < D - 1 {
            let mut a2 = Adrs::new();
            a2.set_layer(j as u32);
            a2.set_tree(idx_tree);
            root = xmss_pk_from_sig(idx_leaf, seg, &root, pkseed, &mut a2);
        }
    }
}

/// Verify a hypertree signature against the public root (FIPS 205 Alg 13).
fn ht_verify(
    m: &[u8; N],
    sig: &[u8],
    pkseed: &[u8; N],
    mut idx_tree: u64,
    mut idx_leaf: u32,
    pkroot: &[u8; N],
) -> bool {
    const XMSS: usize = (LEN + HP) * N;
    let mut a = Adrs::new();
    a.set_tree(idx_tree);
    let mut node = xmss_pk_from_sig(idx_leaf, &sig[..XMSS], m, pkseed, &mut a);
    for j in 1..D {
        idx_leaf = (idx_tree & ((1 << HP) - 1)) as u32;
        idx_tree >>= HP;
        let mut aj = Adrs::new();
        aj.set_layer(j as u32);
        aj.set_tree(idx_tree);
        node = xmss_pk_from_sig(
            idx_leaf,
            &sig[j * XMSS..(j + 1) * XMSS],
            &node,
            pkseed,
            &mut aj,
        );
    }
    &node == pkroot
}

// --- FORS ---

fn fors_sk(skseed: &[u8; N], pkseed: &[u8; N], adrs: &Adrs, idx: u32) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(FORS_PRF);
    sk_adrs.set_key_pair(adrs.key_pair());
    sk_adrs.set_tree_index(idx);
    prf(pkseed, skseed, &sk_adrs)
}

/// A FORS Merkle node at height `z`, index `i` (FIPS 205 Alg 14).
fn fors_node(skseed: &[u8; N], i: u32, z: u32, pkseed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    if z == 0 {
        let sk = fors_sk(skseed, pkseed, adrs, i);
        adrs.set_tree_height(0);
        adrs.set_tree_index(i);
        t_hash(pkseed, adrs, &sk)
    } else {
        let l = fors_node(skseed, 2 * i, z - 1, pkseed, adrs);
        let r = fors_node(skseed, 2 * i + 1, z - 1, pkseed, adrs);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);
        let mut m = [0u8; 2 * N];
        m[..N].copy_from_slice(&l);
        m[N..].copy_from_slice(&r);
        t_hash(pkseed, adrs, &m)
    }
}

/// A FORS signature (FIPS 205 Alg 15). Writes K·(1+A)·N bytes.
fn fors_sign(md: &[u8], skseed: &[u8; N], pkseed: &[u8; N], adrs: &mut Adrs, out: &mut [u8]) {
    let mut indices = [0u32; K];
    base_2b(md, A, &mut indices);
    let step = (1 + A) * N;
    for (i, &index) in indices.iter().enumerate() {
        let base = i * step;
        let leaf = (i as u32) * (1 << A) + index;
        let sk = fors_sk(skseed, pkseed, adrs, leaf);
        out[base..base + N].copy_from_slice(&sk);
        for j in 0..A {
            let s = (index >> j) ^ 1;
            let node = fors_node(
                skseed,
                (i as u32) * (1 << (A - j)) + s,
                j as u32,
                pkseed,
                adrs,
            );
            out[base + (1 + j) * N..base + (2 + j) * N].copy_from_slice(&node);
        }
    }
}

/// The FORS public key recovered from a signature (FIPS 205 Alg 16).
fn fors_pk_from_sig(sig: &[u8], md: &[u8], pkseed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let mut indices = [0u32; K];
    base_2b(md, A, &mut indices);
    let step = (1 + A) * N;
    let mut roots = [0u8; K * N];
    for i in 0..K {
        let base = i * step;
        let mut node = {
            let mut sk = [0u8; N];
            sk.copy_from_slice(&sig[base..base + N]);
            adrs.set_tree_height(0);
            adrs.set_tree_index((i as u32) * (1 << A) + indices[i]);
            t_hash(pkseed, adrs, &sk)
        };
        for j in 0..A {
            adrs.set_tree_height(j as u32 + 1);
            let auth = &sig[base + (1 + j) * N..base + (2 + j) * N];
            let mut buf = [0u8; 2 * N];
            if (indices[i] >> j) & 1 == 0 {
                adrs.set_tree_index(adrs.tree_index() / 2);
                buf[..N].copy_from_slice(&node);
                buf[N..].copy_from_slice(auth);
            } else {
                adrs.set_tree_index((adrs.tree_index() - 1) / 2);
                buf[..N].copy_from_slice(auth);
                buf[N..].copy_from_slice(&node);
            }
            node = t_hash(pkseed, adrs, &buf);
        }
        roots[i * N..i * N + N].copy_from_slice(&node);
    }
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(FORS_ROOTS);
    pk_adrs.set_key_pair(adrs.key_pair());
    t_hash(pkseed, &pk_adrs, &roots)
}

// --- SLH-DSA top level (internal functions) ---

/// Key generation from the three seeds. Returns (pk, sk).
pub fn keygen(skseed: &[u8; N], skprf: &[u8; N], pkseed: &[u8; N]) -> ([u8; PK_LEN], [u8; SK_LEN]) {
    let mut adrs = Adrs::new();
    adrs.set_layer((D - 1) as u32);
    let pkroot = xmss_node(skseed, 0, HP as u32, pkseed, &mut adrs);
    let mut pk = [0u8; PK_LEN];
    pk[..N].copy_from_slice(pkseed);
    pk[N..].copy_from_slice(&pkroot);
    let mut sk = [0u8; SK_LEN];
    sk[..N].copy_from_slice(skseed);
    sk[N..2 * N].copy_from_slice(skprf);
    sk[2 * N..3 * N].copy_from_slice(pkseed);
    sk[3 * N..].copy_from_slice(&pkroot);
    (pk, sk)
}

/// Split a message digest into the FORS indices bytes and the tree/leaf
/// indices (FIPS 205 §9.2).
fn split_digest(digest: &[u8; M_DIGEST]) -> (&[u8], u64, u32) {
    let md = &digest[..MD_LEN];
    let mut tree_bytes = [0u8; 8];
    tree_bytes.copy_from_slice(&digest[MD_LEN..MD_LEN + TREE_IDX_LEN]);
    let idx_tree = u64::from_be_bytes(tree_bytes) & ((1u64 << (H - HP)) - 1);
    let leaf_byte = digest[MD_LEN + TREE_IDX_LEN..MD_LEN + TREE_IDX_LEN + LEAF_IDX_LEN][0];
    let idx_leaf = (leaf_byte as u32) & ((1 << HP) - 1);
    (md, idx_tree, idx_leaf)
}

/// Sign `msg` with `sk`, deterministically (FIPS 205 Alg 19 with the
/// deterministic randomizer). Returns the signature.
pub fn sign(msg: &[u8], sk: &[u8; SK_LEN]) -> [u8; SIG_LEN] {
    let mut skseed = [0u8; N];
    let mut skprf = [0u8; N];
    let mut pkseed = [0u8; N];
    let mut pkroot = [0u8; N];
    skseed.copy_from_slice(&sk[..N]);
    skprf.copy_from_slice(&sk[N..2 * N]);
    pkseed.copy_from_slice(&sk[2 * N..3 * N]);
    pkroot.copy_from_slice(&sk[3 * N..]);

    // Deterministic: opt_rand = PK.seed.
    let r = prf_msg(&skprf, &pkseed, msg);
    let digest = h_msg(&r, &pkseed, &pkroot, msg);
    let (md, idx_tree, idx_leaf) = split_digest(&digest);

    let mut sig = [0u8; SIG_LEN];
    sig[..N].copy_from_slice(&r);

    let mut fors_adrs = Adrs::new();
    fors_adrs.set_tree(idx_tree);
    fors_adrs.set_type_and_clear(FORS_TREE);
    fors_adrs.set_key_pair(idx_leaf);
    let fors_sig = &mut sig[N..N + FORS_SIG_LEN];
    fors_sign(md, &skseed, &pkseed, &mut fors_adrs, fors_sig);

    let mut pk_adrs = Adrs::new();
    pk_adrs.set_tree(idx_tree);
    pk_adrs.set_type_and_clear(FORS_TREE);
    pk_adrs.set_key_pair(idx_leaf);
    let pk_fors = fors_pk_from_sig(&sig[N..N + FORS_SIG_LEN], md, &pkseed, &mut pk_adrs);

    ht_sign(
        &pk_fors,
        &skseed,
        &pkseed,
        idx_tree,
        idx_leaf,
        &mut sig[N + FORS_SIG_LEN..],
    );
    sig
}

/// Verify `sig` on `msg` under `pk` (FIPS 205 Alg 20).
pub fn verify(msg: &[u8], sig: &[u8], pk: &[u8; PK_LEN]) -> bool {
    if sig.len() != SIG_LEN {
        return false;
    }
    let mut pkseed = [0u8; N];
    let mut pkroot = [0u8; N];
    pkseed.copy_from_slice(&pk[..N]);
    pkroot.copy_from_slice(&pk[N..]);
    let mut r = [0u8; N];
    r.copy_from_slice(&sig[..N]);
    let digest = h_msg(&r, &pkseed, &pkroot, msg);
    let (md, idx_tree, idx_leaf) = split_digest(&digest);

    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair(idx_leaf);
    let pk_fors = fors_pk_from_sig(&sig[N..N + FORS_SIG_LEN], md, &pkseed, &mut adrs);

    ht_verify(
        &pk_fors,
        &sig[N + FORS_SIG_LEN..],
        &pkseed,
        idx_tree,
        idx_leaf,
        &pkroot,
    )
}

#[cfg(test)]
mod tests;
