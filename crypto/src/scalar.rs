//! Arithmetic modulo the Ed25519 group order
//! L = 2^252 + 27742317777372353535851937790883648493.
//!
//! Scalars are little-endian bytes. The reduction is plain schoolbook
//! long division in 64-bit limbs — slower than the packed-limb reference
//! code, but short and easy to see is correct, which matters more here.

/// L in 64-bit little-endian limbs.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// Load up to 64 little-endian bytes into nine 64-bit limbs.
fn load(bytes: &[u8]) -> [u64; 9] {
    let mut x = [0u64; 9];
    for (limb, chunk) in x.iter_mut().zip(bytes.chunks(8)) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        *limb = u64::from_le_bytes(buf);
    }
    x
}

fn load4(bytes: &[u8; 32]) -> [u64; 4] {
    let mut x = [0u64; 4];
    for (limb, chunk) in x.iter_mut().zip(bytes.chunks(8)) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(buf);
    }
    x
}

fn to_bytes(x: &[u64; 9]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(&x[..4]) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// a >= b, for nine-limb values.
fn ge(a: &[u64; 9], b: &[u64; 9]) -> bool {
    for i in (0..9).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// a -= b, assuming a >= b.
fn sub_assign(a: &mut [u64; 9], b: &[u64; 9]) {
    let mut borrow: i128 = 0;
    for (a, b) in a.iter_mut().zip(b) {
        let v = *a as i128 - *b as i128 - borrow;
        if v < 0 {
            *a = (v + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            *a = v as u64;
            borrow = 0;
        }
    }
}

/// L shifted left by `shift` bits, in nine limbs (`shift` <= 264, so it
/// always fits).
fn l_shifted(shift: usize) -> [u64; 9] {
    let mut out = [0u64; 9];
    let (word, bit) = (shift / 64, shift % 64);
    for (i, &limb) in L.iter().enumerate() {
        if let Some(slot) = out.get_mut(i + word) {
            *slot |= if bit == 0 { limb } else { limb << bit };
        }
        if bit != 0
            && let Some(slot) = out.get_mut(i + word + 1)
        {
            *slot |= limb >> (64 - bit);
        }
    }
    out
}

/// Reduce a nine-limb value modulo L by long division.
fn reduce_wide(mut x: [u64; 9]) -> [u8; 32] {
    // The quotient is under 2^260, so shifts up to 264 cover every bit.
    for shift in (0..=264).rev() {
        let shifted = l_shifted(shift);
        if ge(&x, &shifted) {
            sub_assign(&mut x, &shifted);
        }
    }
    to_bytes(&x)
}

/// Reduce up to 64 little-endian bytes modulo L. Used on the 64-byte hash
/// outputs Ed25519 turns into scalars.
pub fn reduce(bytes: &[u8]) -> [u8; 32] {
    reduce_wide(load(bytes))
}

/// (a·b + c) mod L, the step that builds an Ed25519 signature's S.
pub fn mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let (a, b) = (load4(a), load4(b));
    // Schoolbook 256×256 -> up to 512 bits, with the carry kept inside u128.
    let mut p = [0u64; 9];
    for (i, &ai) in a.iter().enumerate() {
        let mut carry: u128 = 0;
        for (j, &bj) in b.iter().enumerate() {
            let t = p[i + j] as u128 + ai as u128 * bj as u128 + carry;
            p[i + j] = t as u64;
            carry = t >> 64;
        }
        p[i + 4] = (p[i + 4] as u128 + carry) as u64;
    }
    // Add c.
    let mut carry: u128 = 0;
    for (p, &c) in p.iter_mut().zip(&load4(c)) {
        let t = *p as u128 + c as u128 + carry;
        *p = t as u64;
        carry = t >> 64;
    }
    for p in p.iter_mut().skip(4) {
        if carry == 0 {
            break;
        }
        let t = *p as u128 + carry;
        *p = t as u64;
        carry = t >> 64;
    }
    reduce_wide(p)
}

/// Whether `s` is already reduced (s < L): the canonical-S check a
/// verifier makes before trusting a signature.
pub fn is_canonical(s: &[u8; 32]) -> bool {
    let s = load4(s);
    for i in (0..4).rev() {
        if s[i] != L[i] {
            return s[i] < L[i];
        }
    }
    false
}
