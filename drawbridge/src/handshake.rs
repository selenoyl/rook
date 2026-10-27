//! The three-message handshake that establishes a [`Session`].
//!
//! ```text
//!   Initiator                                   Responder
//!   ---------                                   ---------
//!   e_i  ------------------- msg1 ------------------>
//!                            msg2    e_r, seal(id_r, sig_r)
//!        <------------------------------------------
//!   msg3    seal(id_i, sig_i)
//!        ------------------------------------------->
//! ```
//!
//! `e_*` are ephemeral X25519 public keys; `id_*` are Ed25519 identity
//! public keys; `sig_*` are signatures over the transcript (both
//! ephemerals). The identities and signatures in msg2/msg3 are sealed with
//! ChaCha20-Poly1305 under keys derived from the shared secret, so they
//! are confidential and a good tag confirms the peer agreed the same key.

use crate::{
    Error, HS_NONCE, Identity, Keys, MSG1_LEN, MSG2_LEN, MSG3_LEN, ROLE_INITIATOR, ROLE_RESPONDER,
    Session, derive, is_zero, signed_message, transcript,
};
use crypto::{aead_open, aead_seal, sign, verify, x25519, x25519_base};

/// The initiator's state between sending msg1 and receiving msg2.
pub struct Initiator {
    identity: Identity,
    eph_secret: [u8; 32],
    eph_public: [u8; 32],
    expect: Option<[u8; 32]>,
}

/// What the initiator has once the handshake completes: the final message
/// to send, the session, and the identity the responder proved.
pub struct InitiatorDone {
    pub msg3: [u8; MSG3_LEN],
    pub session: Session,
    pub peer_identity: [u8; 32],
}

impl Initiator {
    /// Begin a handshake. Returns the state and msg1 to send. `eph_secret`
    /// is 32 fresh random bytes; `expect` optionally pins the responder's
    /// identity, so a handshake with anyone else is refused.
    pub fn start(
        identity: &Identity,
        eph_secret: &[u8; 32],
        expect: Option<[u8; 32]>,
    ) -> (Initiator, [u8; MSG1_LEN]) {
        let eph_public = x25519_base(eph_secret);
        let state = Initiator {
            identity: identity.clone(),
            eph_secret: *eph_secret,
            eph_public,
            expect,
        };
        (state, eph_public)
    }

    /// Consume msg2: agree the key, verify the responder, and produce msg3
    /// and the session.
    pub fn finish(self, msg2: &[u8; MSG2_LEN]) -> Result<InitiatorDone, Error> {
        let mut e_r = [0u8; 32];
        e_r.copy_from_slice(&msg2[0..32]);

        let dh = x25519(&self.eph_secret, &e_r);
        if is_zero(&dh) {
            return Err(Error::WeakKey);
        }
        let th = transcript(&self.eph_public, &e_r);
        let keys = derive(&dh, &th);

        // Open the responder's identity and signature.
        let mut payload = [0u8; 96];
        payload.copy_from_slice(&msg2[32..128]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&msg2[128..144]);
        if !aead_open(&keys.hs_r, &HS_NONCE, &th, &mut payload, &tag) {
            return Err(Error::BadTag);
        }
        let mut peer_identity = [0u8; 32];
        peer_identity.copy_from_slice(&payload[0..32]);
        let mut sig_r = [0u8; 64];
        sig_r.copy_from_slice(&payload[32..96]);

        let (msg, len) = signed_message(ROLE_RESPONDER, &th);
        if !verify(&peer_identity, &msg[..len], &sig_r) {
            return Err(Error::BadSignature);
        }
        if let Some(pinned) = self.expect
            && pinned != peer_identity
        {
            return Err(Error::IdentityRejected);
        }

        // Build msg3: our identity and signature, sealed.
        let (msg, len) = signed_message(ROLE_INITIATOR, &th);
        let sig_i = sign(&self.identity.secret, &msg[..len]);
        let mut payload = [0u8; 96];
        payload[0..32].copy_from_slice(&self.identity.public());
        payload[32..96].copy_from_slice(&sig_i);
        let tag = aead_seal(&keys.hs_i, &HS_NONCE, &th, &mut payload);
        let mut msg3 = [0u8; MSG3_LEN];
        msg3[0..96].copy_from_slice(&payload);
        msg3[96..112].copy_from_slice(&tag);

        Ok(InitiatorDone {
            msg3,
            session: Session::new(keys.i2r, keys.r2i),
            peer_identity,
        })
    }
}

/// The responder's state between sending msg2 and receiving msg3.
pub struct Responder {
    th: [u8; 64],
    keys: Keys,
}

/// What the responder has once the handshake completes: the session and
/// the identity the initiator proved.
pub struct ResponderDone {
    pub session: Session,
    pub peer_identity: [u8; 32],
}

impl Responder {
    /// Consume msg1 and produce msg2 and the pending state. `eph_secret`
    /// is 32 fresh random bytes.
    pub fn respond(
        identity: &Identity,
        eph_secret: &[u8; 32],
        msg1: &[u8; MSG1_LEN],
    ) -> Result<(Responder, [u8; MSG2_LEN]), Error> {
        let e_i = *msg1;
        let e_r = x25519_base(eph_secret);

        let dh = x25519(eph_secret, &e_i);
        if is_zero(&dh) {
            return Err(Error::WeakKey);
        }
        let th = transcript(&e_i, &e_r);
        let keys = derive(&dh, &th);

        // Seal our identity and signature over the transcript.
        let (msg, len) = signed_message(ROLE_RESPONDER, &th);
        let sig_r = sign(&identity.secret, &msg[..len]);
        let mut payload = [0u8; 96];
        payload[0..32].copy_from_slice(&identity.public());
        payload[32..96].copy_from_slice(&sig_r);
        let tag = aead_seal(&keys.hs_r, &HS_NONCE, &th, &mut payload);

        let mut msg2 = [0u8; MSG2_LEN];
        msg2[0..32].copy_from_slice(&e_r);
        msg2[32..128].copy_from_slice(&payload);
        msg2[128..144].copy_from_slice(&tag);

        Ok((Responder { th, keys }, msg2))
    }

    /// Consume msg3: verify the initiator and produce the session. The
    /// caller inspects `peer_identity` to decide whether that initiator is
    /// welcome.
    pub fn finish(self, msg3: &[u8; MSG3_LEN]) -> Result<ResponderDone, Error> {
        let mut payload = [0u8; 96];
        payload.copy_from_slice(&msg3[0..96]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&msg3[96..112]);
        if !aead_open(&self.keys.hs_i, &HS_NONCE, &self.th, &mut payload, &tag) {
            return Err(Error::BadTag);
        }
        let mut peer_identity = [0u8; 32];
        peer_identity.copy_from_slice(&payload[0..32]);
        let mut sig_i = [0u8; 64];
        sig_i.copy_from_slice(&payload[32..96]);

        let (msg, len) = signed_message(ROLE_INITIATOR, &self.th);
        if !verify(&peer_identity, &msg[..len], &sig_i) {
            return Err(Error::BadSignature);
        }

        Ok(ResponderDone {
            session: Session::new(self.keys.r2i, self.keys.i2r),
            peer_identity,
        })
    }
}
