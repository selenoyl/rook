//! The Signet: approving a sensitive action from a pocket device.
//!
//! A login, an admin action or an update can be made to need a press on a
//! Knight — the pocket Rook. The service sends a one-time challenge; the
//! Knight shows the request and the person presses A to approve. Two forms
//! carry that approval, and the service's policy — never the request —
//! decides which an action needs:
//!
//! - **Everyday** approvals are a 32-byte MAC under a *short-code key*, a
//!   secret the Knight and the service derived when they first paired (a
//!   [`SavedKey`] from a Drawbridge handshake). It fits in one packet. The
//!   service's prompt carries a MAC too, so the Knight shows only real
//!   requests, not ones an attacker made up.
//! - **High-value** actions take a full hybrid Ed25519 + ML-DSA-87
//!   signature under the Knight's long-term identity — about 4.7 KB, but
//!   quantum-safe and verifiable by anyone holding the Knight's public key.
//!
//! Either way the approval is bound to the exact request: the service, the
//! action, the **matched number** the person compared on both screens, a
//! fresh challenge, the direction, and an expiry past which it is no good.
//! Change any of them and the MAC or signature no longer checks.
//!
//! What this crate is not, yet: the enrollment flow, number-matching UI,
//! batch receipts and key renewal the design doc also describes. It is the
//! cryptographic core those build on. Like the rest, it is not audited.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use crypto::hmac_sha256;
use drawbridge::{ID_LEN, Identity, SIG_LEN, SavedKey, hybrid_sign, hybrid_verify};

/// Length of a service identifier.
pub const SERVICE_LEN: usize = 16;
/// Length of an everyday approval's MAC.
pub const MAC_LEN: usize = 32;

const SIGNET_LABEL: &[u8] = b"rook-signet-v1";
/// An approval travelling from the Knight to the service.
const DIR_TO_SERVICE: u8 = 1;
/// A prompt travelling from the service to the Knight.
const DIR_TO_KNIGHT: u8 = 2;

/// The thing being approved: who is asking, what for, the number the person
/// matched, the service's fresh challenge, and when the approval expires.
#[derive(Clone, Copy)]
pub struct Request {
    pub service: [u8; SERVICE_LEN],
    pub action: u32,
    pub number: u16,
    pub challenge: [u8; 32],
    pub expiry: u64,
}

/// Canonical bytes bound by every MAC and signature: the label, a direction
/// byte, and each field in a fixed order and width.
const MSG_LEN: usize = SIGNET_LABEL.len() + 1 + SERVICE_LEN + 4 + 2 + 32 + 8;

fn message(dir: u8, req: &Request) -> [u8; MSG_LEN] {
    let mut buf = [0u8; MSG_LEN];
    let mut at = 0;
    buf[at..at + SIGNET_LABEL.len()].copy_from_slice(SIGNET_LABEL);
    at += SIGNET_LABEL.len();
    buf[at] = dir;
    at += 1;
    buf[at..at + SERVICE_LEN].copy_from_slice(&req.service);
    at += SERVICE_LEN;
    buf[at..at + 4].copy_from_slice(&req.action.to_le_bytes());
    at += 4;
    buf[at..at + 2].copy_from_slice(&req.number.to_le_bytes());
    at += 2;
    buf[at..at + 32].copy_from_slice(&req.challenge);
    at += 32;
    buf[at..at + 8].copy_from_slice(&req.expiry.to_le_bytes());
    buf
}

/// Constant-time compare of two MACs: no early return on a mismatch.
fn macs_equal(a: &[u8; MAC_LEN], b: &[u8; MAC_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..MAC_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn mac(key: &SavedKey, dir: u8, req: &Request) -> [u8; MAC_LEN] {
    hmac_sha256(&key.0, &message(dir, req))
}

/// The Knight's everyday approval of `req`: a MAC under the short-code key.
pub fn approve(key: &SavedKey, req: &Request) -> [u8; MAC_LEN] {
    mac(key, DIR_TO_SERVICE, req)
}

/// The service checks a Knight's everyday approval: the MAC must match and
/// the request must not have expired at `now`.
pub fn verify_approval(key: &SavedKey, req: &Request, tag: &[u8; MAC_LEN], now: u64) -> bool {
    now <= req.expiry && macs_equal(tag, &mac(key, DIR_TO_SERVICE, req))
}

/// The service's prompt MAC, so a Knight can tell a real request from a
/// forged one before it ever shows the person a prompt.
pub fn prompt(key: &SavedKey, req: &Request) -> [u8; MAC_LEN] {
    mac(key, DIR_TO_KNIGHT, req)
}

/// The Knight checks a prompt really came from the service.
pub fn verify_prompt(key: &SavedKey, req: &Request, tag: &[u8; MAC_LEN], now: u64) -> bool {
    now <= req.expiry && macs_equal(tag, &mac(key, DIR_TO_KNIGHT, req))
}

/// A high-value approval: a full hybrid signature under the Knight's
/// long-term identity.
pub fn approve_signed(knight: &Identity, req: &Request) -> [u8; SIG_LEN] {
    hybrid_sign(knight, &message(DIR_TO_SERVICE, req))
}

/// Verify a high-value approval against the Knight's public identity; both
/// signatures must check and the request must not have expired.
pub fn verify_signed(
    knight_public: &[u8; ID_LEN],
    req: &Request,
    sig: &[u8; SIG_LEN],
    now: u64,
) -> bool {
    now <= req.expiry && hybrid_verify(knight_public, &message(DIR_TO_SERVICE, req), sig)
}

#[cfg(test)]
mod tests;
