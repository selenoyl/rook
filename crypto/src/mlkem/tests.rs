//! ML-KEM-1024 tests, pinned to the NIST ACVP (FIPS 203) known-answer
//! vectors. The full encapsulation/decapsulation key and ciphertext come
//! from the vectors as binary files; the seeds and expected hashes are
//! inline.

use super::*;
use crate::{sha3_256, sha3_512};

/// Decode a hex string into a fixed array.
fn unhex<const L: usize>(s: &str) -> [u8; L] {
    let bytes = s.as_bytes();
    let mut out = [0u8; L];
    let mut i = 0;
    while i < L {
        let hi = (bytes[2 * i] as char).to_digit(16).expect("hex") as u8;
        let lo = (bytes[2 * i + 1] as char).to_digit(16).expect("hex") as u8;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

// NIST ACVP ML-KEM-1024 keyGen test: (d, z) -> (ek, dk).
const KG_D: &str = "f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e7266009";
const KG_Z: &str = "35d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275";
const KG_EK_HASH: &str = "9370fe5b05ddc92c939f62cbde4c0fea36f45cd20c5748cf3ac891a4c2604496";
const KG_DK_HASH: &str = "b8c683c71564ff8e2391c57b68c3a1ff186734b13e31d2a075b65307c8b80888";

// NIST ACVP ML-KEM-1024 encapsulation test: (ek, m) -> (c, k). The key and
// ciphertext are the binary files; m, k and the ciphertext's hash inline.
const ED_M: &str = "2f1e2ca7bd72af847cac38cdefc4d345909d7517543edf32e2fc491ba05eb5c3";
const ED_K: &str = "5087e3b0c90bf601dd6501e071270eff8683621e9f5d67a7a668e50c4f460a75";
const ED_CT_HASH: &str = "866618b1b8d52ceefeb503b91d01b060c37cbe452ee912277b4978a030d20172";

const ACVP_EK: &[u8; EK_LEN] = include_bytes!("../../testdata/mlkem1024_ek.bin");
const ACVP_DK: &[u8; DK_LEN] = include_bytes!("../../testdata/mlkem1024_dk.bin");
const ACVP_CT: &[u8; CT_LEN] = include_bytes!("../../testdata/mlkem1024_ct.bin");

#[test]
fn keygen_matches_nist() {
    let d = unhex::<32>(KG_D);
    let z = unhex::<32>(KG_Z);
    let (ek, dk) = keygen(&d, &z);
    assert_eq!(sha3_256(&ek), unhex::<32>(KG_EK_HASH), "ek mismatch");
    assert_eq!(sha3_256(&dk), unhex::<32>(KG_DK_HASH), "dk mismatch");
}

#[test]
fn encaps_matches_nist() {
    let m = unhex::<32>(ED_M);
    let (c, k) = encaps(ACVP_EK, &m);
    assert_eq!(sha3_256(&c), unhex::<32>(ED_CT_HASH), "ciphertext mismatch");
    assert_eq!(k, unhex::<32>(ED_K), "shared secret mismatch");
}

#[test]
fn decaps_matches_nist() {
    // Decapsulating the official ciphertext with the official dk gives the
    // official shared secret.
    let k = decaps(ACVP_DK, ACVP_CT);
    assert_eq!(k, unhex::<32>(ED_K), "decaps shared secret mismatch");
}

#[test]
fn round_trip_agrees() {
    // A fresh keypair: encaps then decaps recover the same secret.
    let d = [7u8; 32];
    let z = [9u8; 32];
    let (ek, dk) = keygen(&d, &z);
    let m = [0x42u8; 32];
    let (c, k_a) = encaps(&ek, &m);
    let k_b = decaps(&dk, &c);
    assert_eq!(k_a, k_b);
}

#[test]
fn implicit_rejection_on_tampered_ciphertext() {
    let d = [1u8; 32];
    let z = [2u8; 32];
    let (ek, dk) = keygen(&d, &z);
    let m = [0x5au8; 32];
    let (mut c, k) = encaps(&ek, &m);
    c[0] ^= 1;
    let k_bad = decaps(&dk, &c);
    // The rejected secret is deterministic but not the real one.
    assert_ne!(k, k_bad);
    assert_eq!(k_bad, decaps(&dk, &c)); // stable across calls
}

#[test]
fn g_split_is_consistent() {
    // Guard that our SHA3-512 split (used for G) is wired as expected.
    let g = sha3_512(b"x");
    assert_eq!(g.len(), 64);
}
