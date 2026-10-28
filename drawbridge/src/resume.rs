//! Fast resumption: the one-round handshake two paired machines use after
//! their first full handshake, in the spirit of Noise IKpsk2.
//!
//! ```text
//!   Initiator                                  Responder
//!   ---------                                  ---------
//!   e_i  ------------------ rmsg1 ----------------->
//!        <----------------- rmsg2 ---- e_r, confirm
//! ```
//!
//! There are no signatures and no ML-KEM here — authentication comes from
//! the **saved key**, the secret the two machines derived and stored at
//! first contact (see [`crate::SavedKey`]). Only the genuine peer holds it,
//! so a correct `confirm` tag proves the responder is who the initiator
//! paired with, and the responder is in turn assured once it opens the
//! initiator's first sealed message. A resumption carries over whatever
//! transport Drawbridge runs on — the Keep's IPC here, UDP over an ordinary
//! network through Courier later. Each message is tiny — 32 and 48 bytes —
//! so it also survives the smallest, lossiest link, down to a single LoRa
//! packet, the worst case the design doc sizes for.
//!
//! Every resumption ratchets: both sides derive a fresh session *and* a new
//! saved key from the old saved key and a fresh X25519 exchange. A caller
//! should keep the old saved key until the first resumed message
//! round-trips, then commit the new one, so a dropped `rmsg2` can't leave
//! the two out of step.

use crate::{Error, HS_NONCE, LABEL_X25519, SavedKey, Session, expand_seed, is_zero};
use crypto::{Sha512, aead_open, aead_seal, expand_sha512, extract_sha512, x25519, x25519_base};

/// Domain-separation label for the resumption transcript; the `v3` matches
/// the full handshake's protocol version so the two can't be confused.
const RESUME_PROTO: &[u8] = b"rook-drawbridge-resume-v3";

/// rmsg1 on the wire: the initiator's fresh X25519 ephemeral.
pub const RESUME_MSG1_LEN: usize = 32;
/// rmsg2 on the wire: the responder's ephemeral and a confirm tag.
pub const RESUME_MSG2_LEN: usize = 32 + 16;

/// The keys one resumption derives: a key confirming the responder, the two
/// per-direction data keys, and the ratcheted saved key.
struct ResumeKeys {
    confirm: [u8; 32],
    r2i: [u8; 32],
    i2r: [u8; 32],
    new_saved: [u8; 32],
}

fn resume_transcript(e_i: &[u8; 32], e_r: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(RESUME_PROTO);
    h.update(e_i);
    h.update(e_r);
    h.finalize()
}

/// HKDF-SHA-512 with the saved key as the salt and the fresh X25519 secret
/// as the input: the new session is bound both to the shared saved key and
/// to this exchange, and the saved key ratchets forward.
fn derive_resume(saved: &SavedKey, dh: &[u8; 32], th: &[u8; 64]) -> ResumeKeys {
    let prk = extract_sha512(&saved.0, dh);
    let mut okm = [0u8; 128];
    expand_sha512(&prk, th, &mut okm);
    let mut k = ResumeKeys {
        confirm: [0; 32],
        r2i: [0; 32],
        i2r: [0; 32],
        new_saved: [0; 32],
    };
    k.confirm.copy_from_slice(&okm[0..32]);
    k.r2i.copy_from_slice(&okm[32..64]);
    k.i2r.copy_from_slice(&okm[64..96]);
    k.new_saved.copy_from_slice(&okm[96..128]);
    k
}

/// The initiator's state between sending rmsg1 and receiving rmsg2.
pub struct ResumeInitiator {
    x_secret: [u8; 32],
    e_i: [u8; 32],
    saved: SavedKey,
}

/// What the initiator has once a resumption completes.
pub struct ResumeInitiatorDone {
    pub session: Session,
    /// The ratcheted saved key to store for next time.
    pub new_saved: SavedKey,
}

impl ResumeInitiator {
    /// Begin a resumption against a stored `saved` key. `seed` is 32 fresh
    /// random bytes. Returns the state and rmsg1 (the X25519 ephemeral).
    pub fn start(saved: &SavedKey, seed: &[u8; 32]) -> (ResumeInitiator, [u8; RESUME_MSG1_LEN]) {
        let x_secret = expand_seed(seed, LABEL_X25519);
        let e_i = x25519_base(&x_secret);
        let mut msg1 = [0u8; RESUME_MSG1_LEN];
        msg1.copy_from_slice(&e_i);
        (
            ResumeInitiator {
                x_secret,
                e_i,
                saved: *saved,
            },
            msg1,
        )
    }

    /// Consume rmsg2: agree the key, check the responder's confirm tag, and
    /// produce the session and the ratcheted saved key.
    pub fn finish(self, msg2: &[u8; RESUME_MSG2_LEN]) -> Result<ResumeInitiatorDone, Error> {
        let mut e_r = [0u8; 32];
        e_r.copy_from_slice(&msg2[..32]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&msg2[32..48]);

        let dh = x25519(&self.x_secret, &e_r);
        if is_zero(&dh) {
            return Err(Error::WeakKey);
        }
        let th = resume_transcript(&self.e_i, &e_r);
        let k = derive_resume(&self.saved, &dh, &th);
        if !aead_open(&k.confirm, &HS_NONCE, &th, &mut [], &tag) {
            return Err(Error::BadTag);
        }
        Ok(ResumeInitiatorDone {
            session: Session::new(k.i2r, k.r2i),
            new_saved: SavedKey(k.new_saved),
        })
    }
}

/// What the responder has once it answers a resumption.
pub struct ResumeResponderDone {
    pub msg2: [u8; RESUME_MSG2_LEN],
    pub session: Session,
    /// The ratcheted saved key to store for next time.
    pub new_saved: SavedKey,
}

/// Answer a resumption as the responder: agree the key from the stored
/// `saved` key and rmsg1, and return rmsg2 (carrying the confirm tag), the
/// session, and the ratcheted saved key. `seed` is 32 fresh random bytes.
pub fn resume(
    saved: &SavedKey,
    seed: &[u8; 32],
    msg1: &[u8; RESUME_MSG1_LEN],
) -> Result<ResumeResponderDone, Error> {
    let mut e_i = [0u8; 32];
    e_i.copy_from_slice(msg1);
    let x_secret = expand_seed(seed, LABEL_X25519);
    let e_r = x25519_base(&x_secret);
    let dh = x25519(&x_secret, &e_i);
    if is_zero(&dh) {
        return Err(Error::WeakKey);
    }
    let th = resume_transcript(&e_i, &e_r);
    let k = derive_resume(saved, &dh, &th);
    let tag = aead_seal(&k.confirm, &HS_NONCE, &th, &mut []);
    let mut msg2 = [0u8; RESUME_MSG2_LEN];
    msg2[..32].copy_from_slice(&e_r);
    msg2[32..48].copy_from_slice(&tag);
    Ok(ResumeResponderDone {
        msg2,
        session: Session::new(k.r2i, k.i2r),
        new_saved: SavedKey(k.new_saved),
    })
}
