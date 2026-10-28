//! Castling: pairing two machines in person to share a secret key.
//!
//! When two machines meet over a local channel — IR or a link cable — they
//! castle: a hybrid X25519 + ML-KEM-1024 exchange that hands each one the
//! other's identity and a shared [`crate::SavedKey`], the same key a full
//! network handshake would save. Afterwards the two never need the full
//! handshake again; they resume (see [`crate::resume`]).
//!
//! There are no signatures. Authentication comes from **presence** plus a
//! short **verification code** (a SAS): each machine shows the same six
//! digits, derived from everything exchanged, and the people confirm they
//! match. A relay sitting between the two would make the codes differ, so
//! the check catches it — the one defense a confirm tag alone cannot give,
//! since a relay can complete both halves. Because the pairing is in
//! person, the identities travel in the clear; meeting is the point.
//!
//! ```text
//!   A (initiator)                                   B (responder)
//!   -------------                                   -------------
//!   id_a, e_a, mlkem_ek  --------- msg1 ------------->
//!             msg2   id_b, e_b, mlkem_ct, confirm
//!        <------------------------------------------
//!   (both show the same six-digit code; the people compare)
//! ```

use crate::{
    Error, HS_NONCE, ID_LEN, Identity, LABEL_MLKEM_D, LABEL_MLKEM_M, LABEL_MLKEM_Z, LABEL_X25519,
    SavedKey, expand_seed, is_zero,
};
use crypto::{
    MLKEM_CT_LEN, MLKEM_DK_LEN, MLKEM_EK_LEN, Sha512, aead_open, aead_seal, expand_sha512,
    extract_sha512, mlkem_decaps, mlkem_encaps, mlkem_keygen, x25519, x25519_base,
};

const X_PUB: usize = 32;
const CASTLE_PROTO: &[u8] = b"rook-castling-v1";

/// msg1 on the wire: the initiator's identity, X25519 ephemeral, and
/// ML-KEM encapsulation key.
pub const CASTLE_MSG1_LEN: usize = ID_LEN + X_PUB + MLKEM_EK_LEN;
/// msg2 on the wire: the responder's identity, ephemeral, ML-KEM
/// ciphertext, and a confirm tag.
pub const CASTLE_MSG2_LEN: usize = ID_LEN + X_PUB + MLKEM_CT_LEN + 16;

/// A six-digit verification code the two people compare in person. Equal
/// codes mean no relay sat between the machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sas(pub u32);

struct CastleKeys {
    confirm: [u8; 32],
    saved: [u8; 32],
    sas: u32,
}

#[allow(clippy::too_many_arguments)]
fn castle_transcript(
    id_a: &[u8; ID_LEN],
    e_a: &[u8; 32],
    ek: &[u8; MLKEM_EK_LEN],
    id_b: &[u8; ID_LEN],
    e_b: &[u8; 32],
    ct: &[u8; MLKEM_CT_LEN],
) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(CASTLE_PROTO);
    h.update(id_a);
    h.update(e_a);
    h.update(ek);
    h.update(id_b);
    h.update(e_b);
    h.update(ct);
    h.finalize()
}

fn derive_castle(dh: &[u8; 32], pq: &[u8; 32], th: &[u8; 64]) -> CastleKeys {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh);
    ikm[32..].copy_from_slice(pq);
    let prk = extract_sha512(th, &ikm);
    let mut okm = [0u8; 96];
    expand_sha512(&prk, b"rook castling keys v1", &mut okm);
    let mut confirm = [0u8; 32];
    let mut saved = [0u8; 32];
    confirm.copy_from_slice(&okm[0..32]);
    saved.copy_from_slice(&okm[32..64]);
    let code = u32::from_le_bytes([okm[64], okm[65], okm[66], okm[67]]);
    CastleKeys {
        confirm,
        saved,
        sas: code % 1_000_000,
    }
}

/// What each side holds once a castling completes: the peer's identity, the
/// shared saved key, and the code to compare in person.
pub struct CastleDone {
    pub peer_identity: [u8; ID_LEN],
    pub saved_key: SavedKey,
    pub sas: Sas,
}

/// The initiator's state between sending msg1 and receiving msg2.
pub struct CastleInitiator {
    own_id: [u8; ID_LEN],
    x_secret: [u8; 32],
    e_a: [u8; 32],
    ek: [u8; MLKEM_EK_LEN],
    dk: [u8; MLKEM_DK_LEN],
}

/// Begin castling. `seed` is 32 fresh random bytes. Returns the state and
/// msg1 (identity, X25519 ephemeral, ML-KEM encapsulation key).
pub fn castle_start(me: &Identity, seed: &[u8; 32]) -> (CastleInitiator, [u8; CASTLE_MSG1_LEN]) {
    let x_secret = expand_seed(seed, LABEL_X25519);
    let e_a = x25519_base(&x_secret);
    let d = expand_seed(seed, LABEL_MLKEM_D);
    let z = expand_seed(seed, LABEL_MLKEM_Z);
    let (ek, dk) = mlkem_keygen(&d, &z);
    let own_id = me.public();

    let mut msg1 = [0u8; CASTLE_MSG1_LEN];
    msg1[..ID_LEN].copy_from_slice(&own_id);
    msg1[ID_LEN..ID_LEN + X_PUB].copy_from_slice(&e_a);
    msg1[ID_LEN + X_PUB..].copy_from_slice(&ek);

    (
        CastleInitiator {
            own_id,
            x_secret,
            e_a,
            ek,
            dk,
        },
        msg1,
    )
}

impl CastleInitiator {
    /// Consume msg2: agree the key, learn the peer's identity, check the
    /// confirm tag, and produce the saved key and verification code.
    pub fn finish(self, msg2: &[u8; CASTLE_MSG2_LEN]) -> Result<CastleDone, Error> {
        let mut id_b = [0u8; ID_LEN];
        id_b.copy_from_slice(&msg2[..ID_LEN]);
        let mut e_b = [0u8; 32];
        e_b.copy_from_slice(&msg2[ID_LEN..ID_LEN + X_PUB]);
        let mut ct = [0u8; MLKEM_CT_LEN];
        ct.copy_from_slice(&msg2[ID_LEN + X_PUB..ID_LEN + X_PUB + MLKEM_CT_LEN]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&msg2[ID_LEN + X_PUB + MLKEM_CT_LEN..]);

        let dh = x25519(&self.x_secret, &e_b);
        if is_zero(&dh) {
            return Err(Error::WeakKey);
        }
        let pq = mlkem_decaps(&self.dk, &ct);
        let th = castle_transcript(&self.own_id, &self.e_a, &self.ek, &id_b, &e_b, &ct);
        let k = derive_castle(&dh, &pq, &th);
        if !aead_open(&k.confirm, &HS_NONCE, &th, &mut [], &tag) {
            return Err(Error::BadTag);
        }
        Ok(CastleDone {
            peer_identity: id_b,
            saved_key: SavedKey(k.saved),
            sas: Sas(k.sas),
        })
    }
}

/// What the responder holds once it answers a castling.
pub struct CastleResponderDone {
    pub msg2: [u8; CASTLE_MSG2_LEN],
    pub peer_identity: [u8; ID_LEN],
    pub saved_key: SavedKey,
    pub sas: Sas,
}

/// Answer a castling: learn the initiator's identity, encapsulate to its
/// ML-KEM key, and return msg2 with a confirm tag, the saved key, and the
/// code. `seed` is 32 fresh random bytes.
pub fn castle_respond(
    me: &Identity,
    seed: &[u8; 32],
    msg1: &[u8; CASTLE_MSG1_LEN],
) -> Result<CastleResponderDone, Error> {
    let mut id_a = [0u8; ID_LEN];
    id_a.copy_from_slice(&msg1[..ID_LEN]);
    let mut e_a = [0u8; 32];
    e_a.copy_from_slice(&msg1[ID_LEN..ID_LEN + X_PUB]);
    let mut ek = [0u8; MLKEM_EK_LEN];
    ek.copy_from_slice(&msg1[ID_LEN + X_PUB..]);

    let x_secret = expand_seed(seed, LABEL_X25519);
    let e_b = x25519_base(&x_secret);
    let dh = x25519(&x_secret, &e_a);
    if is_zero(&dh) {
        return Err(Error::WeakKey);
    }
    let m = expand_seed(seed, LABEL_MLKEM_M);
    let (ct, pq) = mlkem_encaps(&ek, &m);
    let own_id = me.public();
    let th = castle_transcript(&id_a, &e_a, &ek, &own_id, &e_b, &ct);
    let k = derive_castle(&dh, &pq, &th);
    let tag = aead_seal(&k.confirm, &HS_NONCE, &th, &mut []);

    let mut msg2 = [0u8; CASTLE_MSG2_LEN];
    msg2[..ID_LEN].copy_from_slice(&own_id);
    msg2[ID_LEN..ID_LEN + X_PUB].copy_from_slice(&e_b);
    msg2[ID_LEN + X_PUB..ID_LEN + X_PUB + MLKEM_CT_LEN].copy_from_slice(&ct);
    msg2[ID_LEN + X_PUB + MLKEM_CT_LEN..].copy_from_slice(&tag);

    Ok(CastleResponderDone {
        msg2,
        peer_identity: id_a,
        saved_key: SavedKey(k.saved),
        sas: Sas(k.sas),
    })
}
