//! Tests for the Signet: everyday MAC approvals and high-value signatures,
//! and every rule that must refuse one.

use super::*;
use drawbridge::ID_LEN;
use std::sync::OnceLock;

const NOW: u64 = 1_000;
const EXPIRY: u64 = 2_000;

fn request() -> Request {
    let mut service = [0u8; SERVICE_LEN];
    service[..5].copy_from_slice(b"login");
    Request {
        service,
        action: 7,
        number: 4242,
        challenge: [0x5a; 32],
        expiry: EXPIRY,
    }
}

// --- Everyday MAC approvals (cheap; no fixture needed) ----------------

#[test]
fn everyday_approval_round_trips() {
    let key = SavedKey([0x11; 32]);
    let req = request();
    let tag = approve(&key, &req);
    assert!(verify_approval(&key, &req, &tag, NOW));
}

#[test]
fn an_expired_approval_is_refused() {
    let key = SavedKey([0x11; 32]);
    let req = request();
    let tag = approve(&key, &req);
    assert!(!verify_approval(&key, &req, &tag, EXPIRY + 1));
}

#[test]
fn an_approval_under_the_wrong_key_is_refused() {
    let req = request();
    let tag = approve(&SavedKey([0x11; 32]), &req);
    assert!(!verify_approval(&SavedKey([0x22; 32]), &req, &tag, NOW));
}

#[test]
fn a_tampered_request_is_refused() {
    let key = SavedKey([0x11; 32]);
    let req = request();
    let tag = approve(&key, &req);
    // Flip the matched number: the MAC was over the old one.
    let forged = Request {
        number: req.number ^ 1,
        ..req
    };
    assert!(!verify_approval(&key, &forged, &tag, NOW));
}

#[test]
fn a_prompt_is_not_an_approval() {
    let key = SavedKey([0x11; 32]);
    let req = request();
    // The service's prompt MAC and the Knight's approval MAC are over the
    // same request but opposite directions, so neither passes as the other.
    let prompt_tag = prompt(&key, &req);
    assert!(!verify_approval(&key, &req, &prompt_tag, NOW));
    let approval_tag = approve(&key, &req);
    assert!(!verify_prompt(&key, &req, &approval_tag, NOW));
}

#[test]
fn a_real_prompt_is_recognized() {
    let key = SavedKey([0x33; 32]);
    let req = request();
    let tag = prompt(&key, &req);
    assert!(verify_prompt(&key, &req, &tag, NOW));
}

// --- High-value full signatures (shared fixture: one hybrid sign) -----

struct Signed {
    knight_public: [u8; ID_LEN],
    other_public: [u8; ID_LEN],
    req: Request,
    sig: [u8; SIG_LEN],
}

fn signed() -> &'static Signed {
    static S: OnceLock<Signed> = OnceLock::new();
    S.get_or_init(|| {
        let knight = Identity::from_secret(&[0x4b; 32]);
        let other = Identity::from_secret(&[0x4c; 32]);
        let req = request();
        let sig = approve_signed(&knight, &req);
        Signed {
            knight_public: knight.public(),
            other_public: other.public(),
            req,
            sig,
        }
    })
}

#[test]
fn high_value_signature_round_trips() {
    let s = signed();
    assert!(verify_signed(&s.knight_public, &s.req, &s.sig, NOW));
}

#[test]
fn a_high_value_signature_binds_the_request() {
    let s = signed();
    let forged = Request {
        action: s.req.action + 1,
        ..s.req
    };
    assert!(!verify_signed(&s.knight_public, &forged, &s.sig, NOW));
}

#[test]
fn a_high_value_signature_from_another_knight_is_refused() {
    let s = signed();
    assert!(!verify_signed(&s.other_public, &s.req, &s.sig, NOW));
}

#[test]
fn an_expired_high_value_signature_is_refused() {
    let s = signed();
    assert!(!verify_signed(&s.knight_public, &s.req, &s.sig, EXPIRY + 1));
}
