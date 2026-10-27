//! Drawbridge: Rook's authenticated, encrypted session between two tasks.
//!
//! Two parties that each hold a long-term Ed25519 identity run a short
//! handshake and come away with a [`Session`] that seals and opens
//! messages with ChaCha20-Poly1305. The handshake is a SIGMA-style
//! exchange:
//!
//! 1. Each side sends a fresh ephemeral X25519 public key, so the agreed
//!    key is forward-secret — recording the traffic and later stealing an
//!    identity key does not reveal it.
//! 2. Each side signs the transcript (both ephemeral keys) with its
//!    identity key, proving who it is and binding the signature to this
//!    exact exchange. The signatures and identities travel encrypted under
//!    the agreed key, so an eavesdropper learns neither, and a correct tag
//!    also confirms the peer really computed the same key.
//!
//! The result: mutual authentication, forward secrecy, and confidentiality,
//! the properties the design doc asks of Drawbridge. The data channel
//! numbers every message with a per-direction counter, so a replayed or
//! reordered message is refused; this assumes the transport delivers in
//! order (the Keep's message passing does, and Courier will).
//!
//! Caveats, stated plainly: the ephemeral and identity secret keys are
//! supplied by the caller, who is responsible for real randomness — this
//! crate has no entropy source of its own. And like everything under
//! `crypto`, none of this has been audited, so it protects nothing real
//! yet. The shape is sound; the assurance is not here.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod handshake;
mod session;

pub use handshake::{Initiator, InitiatorDone, Responder, ResponderDone};
pub use session::Session;

use crypto::{MLKEM_CT_LEN, MLKEM_EK_LEN, Sha512, expand_sha512, extract_sha512, shake256};

/// Public ephemeral sizes.
const X_PUB: usize = 32; // X25519 public key
const SEALED: usize = 96 + 16; // seal(identity 32 || signature 64) + tag

/// Bytes on the wire for the three handshake messages.
/// msg1 = e_i ‖ ML-KEM ek
pub const MSG1_LEN: usize = X_PUB + MLKEM_EK_LEN;
/// msg2 = e_r ‖ ML-KEM ciphertext ‖ seal(id_r ‖ sig_r)
pub const MSG2_LEN: usize = X_PUB + MLKEM_CT_LEN + SEALED;
/// msg3 = seal(id_i ‖ sig_i)
pub const MSG3_LEN: usize = SEALED;

/// Domain-separation label mixed into the transcript hash. v2 is the
/// hybrid X25519 + ML-KEM-1024 handshake.
const PROTO: &[u8] = b"rook-drawbridge-v2-hybrid";
/// Role labels prefixed to the signed transcript, so a responder's
/// signature can never be replayed as an initiator's, or the reverse.
const ROLE_RESPONDER: &[u8] = b"drawbridge responder";
const ROLE_INITIATOR: &[u8] = b"drawbridge initiator";
/// Each handshake key encrypts exactly one message, so a fixed nonce is
/// safe (the key is never reused).
const HS_NONCE: [u8; 12] = [0u8; 12];

/// Why a handshake step or a sealed message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A ciphertext's authentication tag did not check: tampering, the
    /// wrong key, or a replayed/reordered message.
    BadTag,
    /// An identity's signature over the transcript did not verify.
    BadSignature,
    /// The peer authenticated, but as an identity the caller pinned
    /// against.
    IdentityRejected,
    /// The Diffie-Hellman gave the all-zero shared secret, which means the
    /// peer sent a low-order point. Refused (RFC 7748 §6.1).
    WeakKey,
    /// The message counter for this direction is exhausted; the session
    /// must be torn down rather than reuse a nonce.
    CounterExhausted,
}

/// A long-term identity: an Ed25519 key pair, held as its 32-byte secret
/// and the public key derived from it.
#[derive(Clone)]
pub struct Identity {
    pub(crate) secret: [u8; 32],
    public: [u8; 32],
}

impl Identity {
    /// Build an identity from a 32-byte secret (the caller's to generate
    /// from real randomness and to keep secret).
    pub fn from_secret(secret: &[u8; 32]) -> Identity {
        Identity {
            secret: *secret,
            public: crypto::public_key(secret),
        }
    }

    /// The 32-byte public key others pin and verify against.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

/// The four keys the handshake derives from the shared secret and the
/// transcript: two to encrypt the handshake messages, two for the data
/// channel (one per direction).
pub(crate) struct Keys {
    pub hs_r: [u8; 32],
    pub hs_i: [u8; 32],
    pub r2i: [u8; 32],
    pub i2r: [u8; 32],
}

/// SHA-512 over the protocol label and every public value of the
/// handshake — the two X25519 ephemerals, the ML-KEM encapsulation key and
/// its ciphertext. Both sides sign it and mix it into the key schedule, so
/// a tampered handshake gives a different transcript and fails.
pub(crate) fn transcript(
    e_i: &[u8; 32],
    ek: &[u8; MLKEM_EK_LEN],
    e_r: &[u8; 32],
    ct: &[u8; MLKEM_CT_LEN],
) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(PROTO);
    h.update(e_i);
    h.update(ek);
    h.update(e_r);
    h.update(ct);
    h.finalize()
}

/// HKDF-SHA-512 the two shared secrets and the transcript into the four
/// session keys. The input keying material is the X25519 secret followed
/// by the ML-KEM secret, so breaking the session needs breaking *both* a
/// classical and a post-quantum problem; the transcript is the salt, so
/// every key is bound to the exact handshake.
pub(crate) fn derive(dh: &[u8; 32], pq: &[u8; 32], th: &[u8; 64]) -> Keys {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh);
    ikm[32..].copy_from_slice(pq);
    let prk = extract_sha512(th, &ikm);
    let mut okm = [0u8; 128];
    expand_sha512(&prk, b"drawbridge keys v2", &mut okm);
    let mut keys = Keys {
        hs_r: [0; 32],
        hs_i: [0; 32],
        r2i: [0; 32],
        i2r: [0; 32],
    };
    keys.hs_r.copy_from_slice(&okm[0..32]);
    keys.hs_i.copy_from_slice(&okm[32..64]);
    keys.r2i.copy_from_slice(&okm[64..96]);
    keys.i2r.copy_from_slice(&okm[96..128]);
    keys
}

/// Build `role || transcript` into a fixed buffer for signing or
/// verifying. The longest role label is 20 bytes, so 84 bytes is always
/// enough.
pub(crate) fn signed_message(role: &[u8], th: &[u8; 64]) -> ([u8; 96], usize) {
    let mut buf = [0u8; 96];
    buf[..role.len()].copy_from_slice(role);
    buf[role.len()..role.len() + 64].copy_from_slice(th);
    (buf, role.len() + 64)
}

/// True if every byte is zero (the rejected weak-key DH output).
pub(crate) fn is_zero(x: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for &b in x {
        acc |= b;
    }
    acc == 0
}

/// Expand a 32-byte handshake seed into one ephemeral secret, domain-
/// separated by `label`, with SHAKE256. Each side derives the several
/// secrets it needs (X25519 and ML-KEM) from its single random seed.
pub(crate) fn expand_seed(seed: &[u8; 32], label: u8) -> [u8; 32] {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    input[32] = label;
    let mut out = [0u8; 32];
    shake256(&input, &mut out);
    out
}

const LABEL_X25519: u8 = 1;
const LABEL_MLKEM_D: u8 = 2;
const LABEL_MLKEM_Z: u8 = 3;
const LABEL_MLKEM_M: u8 = 4;

/// Run a full handshake between two fixed identities, exchange a message
/// each way, and confirm tampering is caught. Returns true only if every
/// step behaves. This is the check the `check` program runs in ring 3.
pub fn self_test() -> bool {
    let id_i = Identity::from_secret(&[0x11; 32]);
    let id_r = Identity::from_secret(&[0x22; 32]);

    // The initiator pins the responder's identity; both ephemerals here
    // are fixed test values (a real caller supplies fresh randomness).
    let (initiator, msg1) = Initiator::start(&id_i, &[0x33; 32], Some(id_r.public()));
    let (responder, msg2) = match Responder::respond(&id_r, &[0x44; 32], &msg1) {
        Ok(pair) => pair,
        Err(_) => return false,
    };
    let InitiatorDone {
        msg3,
        session: mut sess_i,
        peer_identity: seen_r,
    } = match initiator.finish(&msg2) {
        Ok(done) => done,
        Err(_) => return false,
    };
    let ResponderDone {
        session: mut sess_r,
        peer_identity: seen_i,
    } = match responder.finish(&msg3) {
        Ok(done) => done,
        Err(_) => return false,
    };

    // Each side must have learned the other's true identity.
    if seen_r != id_r.public() || seen_i != id_i.public() {
        return false;
    }

    // Initiator -> responder.
    let mut buf = *b"the drawbridge is down";
    let tag = match sess_i.seal(&mut buf) {
        Ok(tag) => tag,
        Err(_) => return false,
    };
    if sess_r.open(&mut buf, &tag).is_err() || &buf != b"the drawbridge is down" {
        return false;
    }

    // Responder -> initiator.
    let mut reply = *b"enter, friend";
    let tag = match sess_r.seal(&mut reply) {
        Ok(tag) => tag,
        Err(_) => return false,
    };
    if sess_i.open(&mut reply, &tag).is_err() || &reply != b"enter, friend" {
        return false;
    }

    // A flipped ciphertext byte must be refused, not decrypted.
    let mut buf = *b"tamper";
    let mut tag = match sess_i.seal(&mut buf) {
        Ok(tag) => tag,
        Err(_) => return false,
    };
    tag[0] ^= 1;
    sess_r.open(&mut buf, &tag).is_err()
}

#[cfg(test)]
mod tests;
