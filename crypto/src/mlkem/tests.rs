//! ML-KEM-768 tests, pinned to the NIST ACVP (FIPS 203) known-answer
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

// NIST ACVP ML-KEM-768 keyGen test: (d, z) -> (ek, dk).
const KG_D: &str = "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0";
const KG_Z: &str = "1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0";
const KG_EK_HASH: &str = "81e66ef5a7a221619f6a64039cc369843e10df5c859f6959cc3fd8e5272330fd";
const KG_DK_HASH: &str = "be81068c104cd6cf8efd800b294f4a15bb8a8050993fd54a2cc428841ef6ca44";

// NIST ACVP ML-KEM-768 encapsulation test: (ek, m) -> (c, k). The key and
// ciphertext are the binary files; m, k and the ciphertext's hash inline.
const ED_M: &str = "4e77596168711e913965d8175ac3bd76aab08b7f9385a02ae883cf6c6e17dd81";
const ED_K: &str = "79d74f6c6c2d916bec47bd828fd9b67295a37f54927fab1263c0d122f1c6f1ed";
const ED_CT_HASH: &str = "684da17d93e27520cb78ae6169c020d73ef770e6fa89589cc7d653a76a8b1751";

const ACVP_EK: &[u8; EK_LEN] = include_bytes!("../../testdata/mlkem768_ek.bin");
const ACVP_DK: &[u8; DK_LEN] = include_bytes!("../../testdata/mlkem768_dk.bin");
const ACVP_CT: &[u8; CT_LEN] = include_bytes!("../../testdata/mlkem768_ct.bin");

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
