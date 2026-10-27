//! SLH-DSA-SHAKE-128f tests, pinned to the NIST ACVP (FIPS 205) vectors.
//! The message and the 17 KB signature are binary files; the seeds, keys
//! and the signature's hash are inline.

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

// NIST ACVP SLH-DSA-SHAKE-128f keyGen.
const KG_SK_SEED: &str = "3956ab391b4d22fc907af0740326d061";
const KG_SK_PRF: &str = "ab0eb206436f2b86ebe086d77739b3e4";
const KG_PK_SEED: &str = "56505c229f4e7fa6b201714c7dcc9da3";
const KG_PK: &str = "56505c229f4e7fa6b201714c7dcc9da366578f1f24c3fe371c97c14ce0e79cdc";
const KG_SK: &str = "3956ab391b4d22fc907af0740326d061ab0eb206436f2b86ebe086d77739b3e456505c229f4e7fa6b201714c7dcc9da366578f1f24c3fe371c97c14ce0e79cdc";

// NIST ACVP SLH-DSA-SHAKE-128f sigGen (internal interface, deterministic).
const SG_SK: &str = "0d14224f8d2681f7773da988b7eb42928d6ff7458342409943d2d5b1956fd49ca038bd657fcf031cf1332e6e809c2f880851fc0245419023deb2463590ccb00a";
const SG_SIG_HASH: &str = "b0e0badb439998605ac949bbb369fce329a57a6f371bc07ac20875f42b091bde";

const ACVP_MSG: &[u8] = include_bytes!("../../testdata/slhdsa_msg.bin");
const ACVP_SIG: &[u8] = include_bytes!("../../testdata/slhdsa_sig.bin");

#[test]
fn keygen_matches_nist() {
    let (pk, sk) = keygen(
        &unhex::<16>(KG_SK_SEED),
        &unhex::<16>(KG_SK_PRF),
        &unhex::<16>(KG_PK_SEED),
    );
    assert_eq!(pk, unhex::<32>(KG_PK), "pk mismatch");
    assert_eq!(sk, unhex::<64>(KG_SK), "sk mismatch");
}

#[test]
fn sign_matches_nist() {
    let sk = unhex::<64>(SG_SK);
    let sig = sign(ACVP_MSG, &sk);
    assert_eq!(sig.len(), SIG_LEN);
    assert_eq!(
        sha3_256(&sig),
        unhex::<32>(SG_SIG_HASH),
        "signature mismatch"
    );
}

#[test]
fn verify_matches_nist() {
    // pk is the last 32 bytes of sk (PK.seed ‖ PK.root).
    let sk = unhex::<64>(SG_SK);
    let mut pk = [0u8; PK_LEN];
    pk.copy_from_slice(&sk[32..64]);
    assert!(verify(ACVP_MSG, ACVP_SIG, &pk), "valid signature rejected");
}

#[test]
fn tampered_signature_is_rejected() {
    let sk = unhex::<64>(SG_SK);
    let mut pk = [0u8; PK_LEN];
    pk.copy_from_slice(&sk[32..64]);
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(ACVP_SIG);
    sig[100] ^= 1;
    assert!(!verify(ACVP_MSG, &sig, &pk), "tampered signature accepted");
}

#[test]
fn round_trip_small_message() {
    let (pk, sk) = keygen(&[1u8; 16], &[2u8; 16], &[3u8; 16]);
    let msg = b"rook stands watch";
    let sig = sign(msg, &sk);
    assert!(verify(msg, &sig, &pk));
    // A different message must not verify under this signature.
    assert!(!verify(b"rook stands down!", &sig, &pk));
}
