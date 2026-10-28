//! The three-message hybrid handshake that establishes a [`Session`].
//!
//! ```text
//!   Initiator                                         Responder
//!   ---------                                         ---------
//!   e_i, mlkem_ek  ---------------- msg1 ---------------->
//!                  msg2   e_r, mlkem_ct, seal(id_r, sig_r)
//!        <-----------------------------------------------
//!   msg3  seal(id_i, sig_i)
//!        ----------------------------------------------->
//! ```
//!
//! `e_*` are ephemeral X25519 public keys; `mlkem_ek`/`mlkem_ct` are an
//! ephemeral ML-KEM-1024 encapsulation key and the ciphertext encapsulated
//! to it. The agreed key is derived from **both** the X25519 secret and
//! the ML-KEM secret, so an attacker must break classical *and*
//! post-quantum problems. `id_*` are Ed25519 identity keys and `sig_*`
//! signatures over the transcript (every public value above); the
//! identities and signatures travel sealed, so they are confidential and a
//! good tag confirms the peer agreed the same key.
//!
//! Each side draws all its ephemeral secrets from one 32-byte seed, which
//! the caller fills with real randomness.

use crate::{
    Error, HS_NONCE, ID_LEN, Identity, Keys, LABEL_MLKEM_D, LABEL_MLKEM_M, LABEL_MLKEM_Z,
    LABEL_X25519, MSG1_LEN, MSG2_LEN, MSG3_LEN, PAYLOAD, ROLE_INITIATOR, ROLE_RESPONDER, SIG_LEN,
    SavedKey, Session, derive, expand_seed, hybrid_sign, hybrid_verify, is_zero, resume_root,
    signed_message, transcript,
};
use crypto::{
    MLKEM_CT_LEN, MLKEM_DK_LEN, MLKEM_EK_LEN, aead_open, aead_seal, mlkem_decaps, mlkem_encaps,
    mlkem_keygen, x25519, x25519_base,
};

const X_PUB: usize = 32;

/// The initiator's state between sending msg1 and receiving msg2.
pub struct Initiator {
    identity: Identity,
    x_secret: [u8; 32],
    x_public: [u8; 32],
    mlkem_ek: [u8; MLKEM_EK_LEN],
    mlkem_dk: [u8; MLKEM_DK_LEN],
    expect: Option<[u8; ID_LEN]>,
}

/// What the initiator has once the handshake completes.
pub struct InitiatorDone {
    pub msg3: [u8; MSG3_LEN],
    pub session: Session,
    pub peer_identity: [u8; ID_LEN],
    /// The key to store for this peer to run fast resumption later.
    pub saved_key: SavedKey,
}

impl Initiator {
    /// Begin a handshake. `seed` is 32 fresh random bytes; `expect`
    /// optionally pins the responder's identity. Returns the state and
    /// msg1 (the X25519 ephemeral and the ML-KEM encapsulation key).
    pub fn start(
        identity: &Identity,
        seed: &[u8; 32],
        expect: Option<[u8; ID_LEN]>,
    ) -> (Initiator, [u8; MSG1_LEN]) {
        let x_secret = expand_seed(seed, LABEL_X25519);
        let x_public = x25519_base(&x_secret);
        let d = expand_seed(seed, LABEL_MLKEM_D);
        let z = expand_seed(seed, LABEL_MLKEM_Z);
        let (mlkem_ek, mlkem_dk) = mlkem_keygen(&d, &z);

        let mut msg1 = [0u8; MSG1_LEN];
        msg1[..X_PUB].copy_from_slice(&x_public);
        msg1[X_PUB..].copy_from_slice(&mlkem_ek);

        let state = Initiator {
            identity: identity.clone(),
            x_secret,
            x_public,
            mlkem_ek,
            mlkem_dk,
            expect,
        };
        (state, msg1)
    }

    /// Consume msg2: agree the hybrid key, verify the responder, and
    /// produce msg3 and the session.
    pub fn finish(self, msg2: &[u8; MSG2_LEN]) -> Result<InitiatorDone, Error> {
        let mut e_r = [0u8; 32];
        e_r.copy_from_slice(&msg2[..X_PUB]);
        let mut ct = [0u8; MLKEM_CT_LEN];
        ct.copy_from_slice(&msg2[X_PUB..X_PUB + MLKEM_CT_LEN]);

        let dh = x25519(&self.x_secret, &e_r);
        if is_zero(&dh) {
            return Err(Error::WeakKey);
        }
        let pq = mlkem_decaps(&self.mlkem_dk, &ct);
        let th = transcript(&self.x_public, &self.mlkem_ek, &e_r, &ct);
        let keys = derive(&dh, &pq, &th);

        // Open the responder's identity and signature.
        let sealed = &msg2[X_PUB + MLKEM_CT_LEN..];
        let mut payload = [0u8; PAYLOAD];
        payload.copy_from_slice(&sealed[..PAYLOAD]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&sealed[PAYLOAD..PAYLOAD + 16]);
        if !aead_open(&keys.hs_r, &HS_NONCE, &th, &mut payload, &tag) {
            return Err(Error::BadTag);
        }
        let mut peer_identity = [0u8; ID_LEN];
        peer_identity.copy_from_slice(&payload[..ID_LEN]);
        let mut sig_r = [0u8; SIG_LEN];
        sig_r.copy_from_slice(&payload[ID_LEN..]);

        let (msg, len) = signed_message(ROLE_RESPONDER, &th);
        if !hybrid_verify(&peer_identity, &msg[..len], &sig_r) {
            return Err(Error::BadSignature);
        }
        if let Some(pinned) = self.expect
            && pinned != peer_identity
        {
            return Err(Error::IdentityRejected);
        }

        // Build msg3: our identity and signature, sealed.
        let (msg, len) = signed_message(ROLE_INITIATOR, &th);
        let sig_i = hybrid_sign(&self.identity, &msg[..len]);
        let mut payload = [0u8; PAYLOAD];
        payload[..ID_LEN].copy_from_slice(&self.identity.public());
        payload[ID_LEN..].copy_from_slice(&sig_i);
        let tag = aead_seal(&keys.hs_i, &HS_NONCE, &th, &mut payload);
        let mut msg3 = [0u8; MSG3_LEN];
        msg3[..PAYLOAD].copy_from_slice(&payload);
        msg3[PAYLOAD..PAYLOAD + 16].copy_from_slice(&tag);

        let saved_key = resume_root(&keys.resume, &self.identity.public(), &peer_identity);
        Ok(InitiatorDone {
            msg3,
            session: Session::new(keys.i2r, keys.r2i),
            peer_identity,
            saved_key,
        })
    }
}

/// The responder's state between sending msg2 and receiving msg3.
pub struct Responder {
    th: [u8; 64],
    keys: Keys,
    own_id: [u8; ID_LEN],
}

/// What the responder has once the handshake completes.
pub struct ResponderDone {
    pub session: Session,
    pub peer_identity: [u8; ID_LEN],
    /// The key to store for this peer to run fast resumption later.
    pub saved_key: SavedKey,
}

impl Responder {
    /// Consume msg1, encapsulate to the ML-KEM key, and produce msg2 and
    /// the pending state. `seed` is 32 fresh random bytes.
    pub fn respond(
        identity: &Identity,
        seed: &[u8; 32],
        msg1: &[u8; MSG1_LEN],
    ) -> Result<(Responder, [u8; MSG2_LEN]), Error> {
        let mut e_i = [0u8; 32];
        e_i.copy_from_slice(&msg1[..X_PUB]);
        let mut ek = [0u8; MLKEM_EK_LEN];
        ek.copy_from_slice(&msg1[X_PUB..]);

        let x_secret = expand_seed(seed, LABEL_X25519);
        let e_r = x25519_base(&x_secret);
        let dh = x25519(&x_secret, &e_i);
        if is_zero(&dh) {
            return Err(Error::WeakKey);
        }
        let m = expand_seed(seed, LABEL_MLKEM_M);
        let (ct, pq) = mlkem_encaps(&ek, &m);
        let th = transcript(&e_i, &ek, &e_r, &ct);
        let keys = derive(&dh, &pq, &th);

        // Seal our identity and signature over the transcript.
        let (msg, len) = signed_message(ROLE_RESPONDER, &th);
        let sig_r = hybrid_sign(identity, &msg[..len]);
        let mut payload = [0u8; PAYLOAD];
        payload[..ID_LEN].copy_from_slice(&identity.public());
        payload[ID_LEN..].copy_from_slice(&sig_r);
        let tag = aead_seal(&keys.hs_r, &HS_NONCE, &th, &mut payload);

        let mut msg2 = [0u8; MSG2_LEN];
        msg2[..X_PUB].copy_from_slice(&e_r);
        msg2[X_PUB..X_PUB + MLKEM_CT_LEN].copy_from_slice(&ct);
        let sealed = &mut msg2[X_PUB + MLKEM_CT_LEN..];
        sealed[..PAYLOAD].copy_from_slice(&payload);
        sealed[PAYLOAD..PAYLOAD + 16].copy_from_slice(&tag);

        Ok((
            Responder {
                th,
                keys,
                own_id: identity.public(),
            },
            msg2,
        ))
    }

    /// Consume msg3: verify the initiator and produce the session. The
    /// caller inspects `peer_identity` to decide whether that initiator is
    /// welcome.
    pub fn finish(self, msg3: &[u8; MSG3_LEN]) -> Result<ResponderDone, Error> {
        let mut payload = [0u8; PAYLOAD];
        payload.copy_from_slice(&msg3[..PAYLOAD]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&msg3[PAYLOAD..PAYLOAD + 16]);
        if !aead_open(&self.keys.hs_i, &HS_NONCE, &self.th, &mut payload, &tag) {
            return Err(Error::BadTag);
        }
        let mut peer_identity = [0u8; ID_LEN];
        peer_identity.copy_from_slice(&payload[..ID_LEN]);
        let mut sig_i = [0u8; SIG_LEN];
        sig_i.copy_from_slice(&payload[ID_LEN..]);

        let (msg, len) = signed_message(ROLE_INITIATOR, &self.th);
        if !hybrid_verify(&peer_identity, &msg[..len], &sig_i) {
            return Err(Error::BadSignature);
        }

        let saved_key = resume_root(&self.keys.resume, &peer_identity, &self.own_id);
        Ok(ResponderDone {
            session: Session::new(self.keys.r2i, self.keys.i2r),
            peer_identity,
            saved_key,
        })
    }
}
