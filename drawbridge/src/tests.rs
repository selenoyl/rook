//! Tests for the Drawbridge handshake and session.

use super::*;

fn ids() -> (Identity, Identity) {
    (
        Identity::from_secret(&[0xa1; 32]),
        Identity::from_secret(&[0xb2; 32]),
    )
}

/// Run a full handshake, returning both sessions and the identities each
/// side learned, or the first error.
fn run(
    id_i: &Identity,
    id_r: &Identity,
    eph_i: &[u8; 32],
    eph_r: &[u8; 32],
    expect: Option<[u8; ID_LEN]>,
) -> Result<(Session, Session, [u8; ID_LEN], [u8; ID_LEN]), Error> {
    let (initiator, msg1) = Initiator::start(id_i, eph_i, expect);
    let (responder, msg2) = Responder::respond(id_r, eph_r, &msg1)?;
    let InitiatorDone {
        msg3,
        session: sess_i,
        peer_identity: seen_r,
    } = initiator.finish(&msg2)?;
    let ResponderDone {
        session: sess_r,
        peer_identity: seen_i,
    } = responder.finish(&msg3)?;
    Ok((sess_i, sess_r, seen_r, seen_i))
}

#[test]
fn self_test_passes() {
    assert!(self_test());
}

#[test]
fn handshake_agrees_and_authenticates() {
    let (id_i, id_r) = ids();
    let Ok((mut sess_i, mut sess_r, seen_r, seen_i)) =
        run(&id_i, &id_r, &[1; 32], &[2; 32], Some(id_r.public()))
    else {
        panic!("handshake failed");
    };

    // Each side learned the other's real identity.
    assert_eq!(seen_r, id_r.public());
    assert_eq!(seen_i, id_i.public());

    // A message each way round-trips.
    let mut buf = *b"hello from the initiator";
    let Ok(tag) = sess_i.seal(&mut buf) else {
        panic!("seal failed");
    };
    assert_ne!(&buf, b"hello from the initiator"); // actually encrypted
    assert!(sess_r.open(&mut buf, &tag).is_ok());
    assert_eq!(&buf, b"hello from the initiator");

    let mut buf = *b"and from the responder..";
    let Ok(tag) = sess_r.seal(&mut buf) else {
        panic!("seal failed");
    };
    assert!(sess_i.open(&mut buf, &tag).is_ok());
    assert_eq!(&buf, b"and from the responder..");
}

#[test]
fn many_messages_in_sequence() {
    let (id_i, id_r) = ids();
    let Ok((mut sess_i, mut sess_r, _, _)) = run(&id_i, &id_r, &[3; 32], &[4; 32], None) else {
        panic!("handshake failed");
    };
    for i in 0..64u8 {
        let mut buf = [i; 40];
        let Ok(tag) = sess_i.seal(&mut buf) else {
            panic!("seal failed");
        };
        assert!(sess_r.open(&mut buf, &tag).is_ok());
        assert_eq!(buf, [i; 40]);
    }
    assert_eq!(sess_i.counters().0, 64);
    assert_eq!(sess_r.counters().1, 64);
}

#[test]
fn tampered_ciphertext_is_refused() {
    let (id_i, id_r) = ids();
    let Ok((mut sess_i, mut sess_r, _, _)) = run(&id_i, &id_r, &[5; 32], &[6; 32], None) else {
        panic!("handshake failed");
    };
    let mut buf = *b"secret orders";
    let Ok(tag) = sess_i.seal(&mut buf) else {
        panic!("seal failed");
    };
    let ciphertext = buf;
    buf[3] ^= 0x20; // tamper
    let tampered = buf;
    assert_eq!(sess_r.open(&mut buf, &tag), Err(Error::BadTag));
    assert_eq!(buf, tampered); // not decrypted — left exactly as handed in

    // The receiver did not advance, so the untampered message still opens.
    let mut good = ciphertext;
    assert!(sess_r.open(&mut good, &tag).is_ok());
    assert_eq!(&good, b"secret orders");
}

#[test]
fn replay_and_reorder_are_refused() {
    let (id_i, id_r) = ids();
    let Ok((mut sess_i, mut sess_r, _, _)) = run(&id_i, &id_r, &[7; 32], &[8; 32], None) else {
        panic!("handshake failed");
    };

    let mut m0 = *b"first.";
    let Ok(t0) = sess_i.seal(&mut m0) else {
        panic!("seal failed");
    };
    let mut m1 = *b"second";
    let Ok(t1) = sess_i.seal(&mut m1) else {
        panic!("seal failed");
    };
    // Capture the ciphertexts, since `open` decrypts in place.
    let c0 = m0;
    let c1 = m1;

    // Delivering the second message first is refused (wrong counter).
    let mut probe = c1;
    assert_eq!(sess_r.open(&mut probe, &t1), Err(Error::BadTag));

    // In order, both open.
    let mut b0 = c0;
    assert!(sess_r.open(&mut b0, &t0).is_ok());
    assert_eq!(&b0, b"first.");
    let mut b1 = c1;
    assert!(sess_r.open(&mut b1, &t1).is_ok());
    assert_eq!(&b1, b"second");

    // Replaying the first is refused — its counter is now in the past.
    let mut replay = c0;
    assert_eq!(sess_r.open(&mut replay, &t0), Err(Error::BadTag));
}

#[test]
fn pinned_identity_mismatch_is_rejected() {
    let (id_i, id_r) = ids();
    let other = Identity::from_secret(&[0xcc; 32]);
    // Initiator pins `other`, but the real responder is `id_r`.
    let err = run(&id_i, &id_r, &[9; 32], &[10; 32], Some(other.public()));
    assert_eq!(err.err(), Some(Error::IdentityRejected));
}

#[test]
fn tampered_handshake_is_refused() {
    let (id_i, id_r) = ids();
    let (initiator, msg1) = Initiator::start(&id_i, &[11; 32], Some(id_r.public()));
    let Ok((_responder, mut msg2)) = Responder::respond(&id_r, &[12; 32], &msg1) else {
        panic!("respond failed");
    };
    // Flip a byte in the responder's sealed identity (the last field of
    // msg2): the initiator must not accept it.
    let last = msg2.len() - 1;
    msg2[last] ^= 1;
    assert_eq!(initiator.finish(&msg2).err(), Some(Error::BadTag));
}

#[test]
fn swapped_ephemeral_breaks_the_handshake() {
    // If a man in the middle alters the initiator's ephemeral, the
    // transcripts and the agreed key differ, so msg2 won't open for the
    // initiator.
    let (id_i, id_r) = ids();
    let (initiator, mut msg1) = Initiator::start(&id_i, &[13; 32], Some(id_r.public()));
    msg1[0] ^= 1; // flip a byte of the initiator's X25519 ephemeral
    let Ok((_responder, msg2)) = Responder::respond(&id_r, &[14; 32], &msg1) else {
        panic!("respond failed");
    };
    assert!(initiator.finish(&msg2).is_err());
}

#[test]
fn tampered_mlkem_ciphertext_breaks_the_handshake() {
    // Flipping a byte of the ML-KEM ciphertext in msg2 changes the
    // post-quantum secret the initiator decapsulates, so the keys diverge.
    let (id_i, id_r) = ids();
    let (initiator, msg1) = Initiator::start(&id_i, &[21; 32], Some(id_r.public()));
    let Ok((_responder, mut msg2)) = Responder::respond(&id_r, &[22; 32], &msg1) else {
        panic!("respond failed");
    };
    msg2[40] ^= 1; // a byte inside the ML-KEM ciphertext
    assert_eq!(initiator.finish(&msg2).err(), Some(Error::BadTag));
}

#[test]
fn weak_point_is_refused() {
    let (_id_i, id_r) = ids();
    // u = 0 is a low-order point; the DH output is all zeros.
    let msg1 = [0u8; MSG1_LEN];
    assert_eq!(
        Responder::respond(&id_r, &[15; 32], &msg1).err(),
        Some(Error::WeakKey)
    );
}

#[test]
fn is_zero_detects_all_zero() {
    assert!(is_zero(&[0; 32]));
    let mut x = [0u8; 32];
    x[31] = 1;
    assert!(!is_zero(&x));
}
