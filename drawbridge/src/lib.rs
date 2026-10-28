//! Drawbridge: Rook's authenticated, encrypted session between two tasks.
//!
//! Two parties that each hold a long-term hybrid identity — an Ed25519 key
//! and an ML-DSA-87 key — run a short handshake and come away with a
//! [`Session`] that seals and opens messages with ChaCha20-Poly1305. The
//! handshake is a SIGMA-style exchange:
//!
//! 1. Each side sends a fresh ephemeral X25519 public key and an ephemeral
//!    ML-KEM-1024 key, so the agreed key is forward-secret (recording the
//!    traffic and later stealing an identity key does not reveal it) and
//!    safe against a future quantum computer.
//! 2. Each side signs the transcript with *both* halves of its identity —
//!    Ed25519 and ML-DSA-87 — proving who it is and binding the signatures
//!    to this exact exchange. A verifier requires both to check, so the
//!    node stays authentic even if elliptic curves fall. The signatures and
//!    identities travel encrypted under the agreed key, so an eavesdropper
//!    learns neither, and a correct tag also confirms the peer really
//!    computed the same key.
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

mod castling;
mod handshake;
mod resume;
mod session;

pub use castling::{
    CASTLE_MSG1_LEN, CASTLE_MSG2_LEN, CastleDone, CastleInitiator, CastleResponderDone, Sas,
    castle_respond, castle_start,
};
pub use handshake::{Initiator, InitiatorDone, Responder, ResponderDone};
pub use resume::{
    RESUME_MSG1_LEN, RESUME_MSG2_LEN, ResumeInitiator, ResumeInitiatorDone, ResumeResponderDone,
    resume as resume_responder,
};
pub use session::Session;

use crypto::{
    MLDSA_PK_LEN, MLDSA_SK_LEN, MLKEM_CT_LEN, MLKEM_EK_LEN, Sha512, expand_sha512, extract_sha512,
    mldsa_keygen, mldsa_sign, mldsa_verify, shake256,
};

/// Public ephemeral sizes.
const X_PUB: usize = 32; // X25519 public key
const ED_PUB: usize = 32; // Ed25519 public key
const ED_SIG: usize = 64; // Ed25519 signature

/// A node's public identity on the wire: an Ed25519 key followed by an
/// ML-DSA-87 key. Pinning or trusting a peer means pinning these bytes.
pub const ID_LEN: usize = ED_PUB + MLDSA_PK_LEN; // 2624
/// A hybrid signature over the transcript: Ed25519 then ML-DSA-87.
const SIG_LEN: usize = ED_SIG + crypto::MLDSA_SIG_LEN; // 4691
/// The sealed handshake payload: identity ‖ signature.
const PAYLOAD: usize = ID_LEN + SIG_LEN; // 7315
/// That payload once sealed: plus the 16-byte AEAD tag.
const SEALED: usize = PAYLOAD + 16;

/// Bytes on the wire for the three handshake messages.
/// msg1 = e_i ‖ ML-KEM ek
pub const MSG1_LEN: usize = X_PUB + MLKEM_EK_LEN;
/// msg2 = e_r ‖ ML-KEM ciphertext ‖ seal(id_r ‖ sig_r)
pub const MSG2_LEN: usize = X_PUB + MLKEM_CT_LEN + SEALED;
/// msg3 = seal(id_i ‖ sig_i)
pub const MSG3_LEN: usize = SEALED;

/// Domain-separation label mixed into the transcript hash. v3 is the
/// hybrid X25519 + ML-KEM-1024 exchange with a hybrid Ed25519 + ML-DSA-87
/// identity.
const PROTO: &[u8] = b"rook-drawbridge-v3-hybrid";
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

/// A long-term hybrid identity: an Ed25519 key pair and an ML-DSA-87 key
/// pair. Both are derived from one 32-byte secret, so a caller still holds
/// a single secret, but the node signs and is verified with both schemes.
#[derive(Clone)]
pub struct Identity {
    pub(crate) ed_secret: [u8; 32],
    ed_public: [u8; ED_PUB],
    pub(crate) mldsa_secret: [u8; MLDSA_SK_LEN],
    mldsa_public: [u8; MLDSA_PK_LEN],
}

impl Identity {
    /// Build an identity from a 32-byte secret (the caller's to generate
    /// from real randomness and to keep secret). The Ed25519 key is that
    /// secret; the ML-DSA key is generated from a seed expanded from it, so
    /// both halves are bound to the one secret.
    pub fn from_secret(secret: &[u8; 32]) -> Identity {
        let ed_public = crypto::public_key(secret);
        let mldsa_seed = expand_seed(secret, LABEL_MLDSA_ID);
        let (mldsa_public, mldsa_secret) = mldsa_keygen(&mldsa_seed);
        Identity {
            ed_secret: *secret,
            ed_public,
            mldsa_secret,
            mldsa_public,
        }
    }

    /// The public identity others pin and verify against: the Ed25519 key
    /// followed by the ML-DSA-87 key, `ID_LEN` bytes.
    pub fn public(&self) -> [u8; ID_LEN] {
        let mut out = [0u8; ID_LEN];
        out[..ED_PUB].copy_from_slice(&self.ed_public);
        out[ED_PUB..].copy_from_slice(&self.mldsa_public);
        out
    }
}

/// Sign `msg` with both halves of `id`: Ed25519 then ML-DSA-87, packed into
/// one `SIG_LEN` buffer.
pub(crate) fn hybrid_sign(id: &Identity, msg: &[u8]) -> [u8; SIG_LEN] {
    let mut out = [0u8; SIG_LEN];
    out[..ED_SIG].copy_from_slice(&crypto::sign(&id.ed_secret, msg));
    out[ED_SIG..].copy_from_slice(&mldsa_sign(msg, &id.mldsa_secret));
    out
}

/// Verify a hybrid signature against a public identity. Both the Ed25519
/// and the ML-DSA-87 signature must check — breaking one scheme is not
/// enough to forge.
pub(crate) fn hybrid_verify(id: &[u8; ID_LEN], msg: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    let mut ed_public = [0u8; ED_PUB];
    ed_public.copy_from_slice(&id[..ED_PUB]);
    let mut mldsa_public = [0u8; MLDSA_PK_LEN];
    mldsa_public.copy_from_slice(&id[ED_PUB..]);
    let mut ed_sig = [0u8; ED_SIG];
    ed_sig.copy_from_slice(&sig[..ED_SIG]);
    crypto::verify(&ed_public, msg, &ed_sig) && mldsa_verify(msg, &sig[ED_SIG..], &mldsa_public)
}

/// The four keys the handshake derives from the shared secret and the
/// transcript: two to encrypt the handshake messages, two for the data
/// channel (one per direction).
pub(crate) struct Keys {
    pub hs_r: [u8; 32],
    pub hs_i: [u8; 32],
    pub r2i: [u8; 32],
    pub i2r: [u8; 32],
    /// The root both sides save to run fast resumption handshakes later.
    pub resume: [u8; 32],
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
    let mut okm = [0u8; 160];
    expand_sha512(&prk, b"drawbridge keys v3", &mut okm);
    let mut keys = Keys {
        hs_r: [0; 32],
        hs_i: [0; 32],
        r2i: [0; 32],
        i2r: [0; 32],
        resume: [0; 32],
    };
    keys.hs_r.copy_from_slice(&okm[0..32]);
    keys.hs_i.copy_from_slice(&okm[32..64]);
    keys.r2i.copy_from_slice(&okm[64..96]);
    keys.i2r.copy_from_slice(&okm[96..128]);
    keys.resume.copy_from_slice(&okm[128..160]);
    keys
}

/// The key two paired machines save after a full handshake, to run fast
/// resumption later. It is the handshake's resume root bound to *both*
/// identities, in initiator-then-responder order (both sides know which is
/// which), so a saved key can never be mistaken for one shared with a
/// different peer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SavedKey(pub [u8; 32]);

pub(crate) fn resume_root(resume: &[u8; 32], id_i: &[u8; ID_LEN], id_r: &[u8; ID_LEN]) -> SavedKey {
    let prk = extract_sha512(resume, id_i);
    let mut info = [0u8; ID_LEN];
    info.copy_from_slice(id_r);
    let mut out = [0u8; 32];
    expand_sha512(&prk, &info, &mut out);
    SavedKey(out)
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
/// Expands an identity's 32-byte secret into the seed for its ML-DSA key.
const LABEL_MLDSA_ID: u8 = 5;

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
        ..
    } = match initiator.finish(&msg2) {
        Ok(done) => done,
        Err(_) => return false,
    };
    let ResponderDone {
        session: mut sess_r,
        peer_identity: seen_i,
        ..
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
