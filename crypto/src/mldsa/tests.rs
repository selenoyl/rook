//! ML-DSA-87 tests, pinned to the NIST ACVP (FIPS 204) vectors.
//!
//! keyGen is checked by hashing the generated keys; signing is checked
//! against the deterministic "internal interface" signature; verification
//! is checked against that same NIST signature, with the public key
//! recomputed from the secret key.

use super::*;
use crate::sha3_256;

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

// NIST ACVP ML-DSA-87 keyGen (tcId 51).
const KG_SEED: &str = "A16F5B0796703E2D1A0140A35CBF36EFABE70E752BA59B6A9A0E9C4B05302F73";
const KG_PK_HASH: &str = "9df39232077a88b3b36c0d4b37d2d369f942baaaa436cf5486a1f09d45d7ce0b";
const KG_SK_HASH: &str = "c41388f22cf3bc0ce79eb5fccfafeee5ec31e3d4321a8befe7f230d6c4841cf0";

// NIST ACVP ML-DSA-87 sigGen (deterministic, internal interface; tcId 166).
const SG_SIG_HASH: &str = "6e5acdd7e94baa713889f026582f978d3310d478c8749110e77df9586f96880f";

const ACVP_SK: &[u8; MLDSA_SK_LEN] = include_bytes!("../../testdata/mldsa87_sk.bin");
const ACVP_MSG: &[u8] = include_bytes!("../../testdata/mldsa87_msg.bin");
const ACVP_SIG: &[u8; MLDSA_SIG_LEN] = include_bytes!("../../testdata/mldsa87_sig.bin");

#[test]
fn keygen_matches_nist() {
    let (pk, sk) = keygen(&unhex::<32>(KG_SEED));
    assert_eq!(sha3_256(&pk), unhex::<32>(KG_PK_HASH), "pk mismatch");
    assert_eq!(sha3_256(&sk), unhex::<32>(KG_SK_HASH), "sk mismatch");
}

#[test]
fn sign_matches_nist() {
    let sig = sign(ACVP_MSG, ACVP_SK);
    assert_eq!(sig.len(), MLDSA_SIG_LEN);
    assert_eq!(
        sha3_256(&sig),
        unhex::<32>(SG_SIG_HASH),
        "signature mismatch"
    );
}

#[test]
fn verify_matches_nist() {
    // Recompute the public key from the secret key, then verify the NIST
    // signature under it.
    let pk = public_from_secret(ACVP_SK);
    assert!(verify(ACVP_MSG, ACVP_SIG, &pk), "valid signature rejected");
}

#[test]
fn public_key_matches_keygen() {
    // The key recomputed from a secret key equals the one keyGen produced,
    // which is itself pinned to NIST above.
    let (pk, sk) = keygen(&unhex::<32>(KG_SEED));
    assert_eq!(public_from_secret(&sk), pk, "recomputed public key differs");
}

#[test]
fn tampered_signature_is_rejected() {
    let pk = public_from_secret(ACVP_SK);
    let mut sig = [0u8; MLDSA_SIG_LEN];
    sig.copy_from_slice(ACVP_SIG);
    sig[1000] ^= 1;
    assert!(!verify(ACVP_MSG, &sig, &pk), "tampered signature accepted");
}

#[test]
fn wrong_message_is_rejected() {
    let pk = public_from_secret(ACVP_SK);
    let mut msg = [0u8; 32];
    msg.copy_from_slice(&ACVP_MSG[..32]);
    msg[0] ^= 0xFF;
    assert!(
        !verify(&msg, ACVP_SIG, &pk),
        "signature verified wrong message"
    );
}

#[test]
fn round_trip_small_message() {
    let (pk, sk) = keygen(&[7u8; 32]);
    let msg = b"rook stands watch";
    let sig = sign(msg, &sk);
    assert!(verify(msg, &sig, &pk), "own signature rejected");
    assert!(
        !verify(b"rook stands down!", &sig, &pk),
        "signature verified a different message"
    );
}
