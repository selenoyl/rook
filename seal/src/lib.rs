//! The Great Seal: Rook's k-of-n approval for software updates.
//!
//! A machine accepts an update only when enough members of the **Round
//! Table** have signed it. The Table is a small signed policy — a list of
//! seats and a threshold `k` — and the Great Seal is `k` separate seat
//! signatures over the same update manifest. Each seat signs with *both* an
//! Ed25519 and an SLH-DSA key, so the approval survives even if elliptic
//! curves fall; SLH-DSA is the conservative, hash-based signature the
//! design doc reserves for exactly this.
//!
//! Requiring `k` separate signatures (not threshold cryptography) is what
//! lets the Table use SLH-DSA at all, and lets seats live on separate,
//! mostly-offline devices. The threshold stays below the seat count so a
//! lost or offline backup seat can never lock everyone out.
//!
//! Two counters stop rollback: an update names a monotonic image version,
//! and a node refuses anything below the version it has booted; and the
//! Table itself is versioned, so an old Table can't be replayed to re-admit
//! a retired seat. Changing the Table needs the *current* Table's approval.
//!
//! This builds only on `crypto`, holds no secrets itself, and — like the
//! crypto beneath it — has not been audited.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use crypto::{
    SLHDSA_SIG_LEN, SLHDSA_SK_LEN, public_key, sha3_256, shake256, sign as ed25519_sign,
    slhdsa_keygen, slhdsa_sign, slhdsa_verify, verify as ed25519_verify,
};

const ED_PUB: usize = 32;
const ED_SIG: usize = 64;
const SLHDSA_PUB: usize = 32;

/// The most seats a Round Table may hold. Two is the doc's starting Table;
/// it grows from there, and this bounds the fixed storage.
pub const MAX_SEATS: usize = 8;

/// Domain-separation label over an update manifest, with a version byte.
const APPROVAL_LABEL: &[u8] = b"rook-great-seal-v1";
/// Domain-separation label over a Round Table's canonical bytes.
const TABLE_LABEL: &[u8] = b"rook-round-table-v1";
/// Label expanding a seat secret into its three SLH-DSA seeds.
const SEAT_SLHDSA_LABEL: u8 = 1;

/// What an approval is over: an image, or a new Round Table. Mixed into the
/// signed bytes so an image approval can never be replayed as a Table one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Image,
    Table,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Image => 1,
            Kind::Table => 2,
        }
    }
}

/// Why a Great Seal was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The manifest approves a different kind of thing than asked.
    WrongKind,
    /// The approved payload hash is not the one presented.
    HashMismatch,
    /// The image or Table version is not newer than what we hold.
    Rollback,
    /// The manifest names a different Table than the one verifying it.
    WrongTable,
    /// The approval's install-by time has passed.
    Expired,
    /// Fewer than `threshold` distinct seats signed validly.
    NotEnoughSeats,
    /// A seat index points outside the Table.
    BadSeat,
    /// The proposed Table is not well-formed.
    MalformedTable,
}

/// One seat's public half: an Ed25519 key and an SLH-DSA key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Seat {
    pub ed_public: [u8; ED_PUB],
    pub slhdsa_public: [u8; SLHDSA_PUB],
}

impl Seat {
    const ZERO: Seat = Seat {
        ed_public: [0; ED_PUB],
        slhdsa_public: [0; SLHDSA_PUB],
    };
}

/// A seat's secret keys, used only on the seat's own (offline) device to
/// sign. A node verifying updates never holds these.
pub struct SeatKeys {
    ed_secret: [u8; 32],
    slhdsa_secret: [u8; SLHDSA_SK_LEN],
    public: Seat,
}

impl SeatKeys {
    /// Derive a seat's keys from one 32-byte secret: the Ed25519 key is the
    /// secret, and the SLH-DSA key is generated from seeds expanded off it.
    pub fn from_secret(secret: &[u8; 32]) -> SeatKeys {
        let ed_public = public_key(secret);
        let mut seeds = [0u8; 48];
        let mut input = [0u8; 33];
        input[..32].copy_from_slice(secret);
        input[32] = SEAT_SLHDSA_LABEL;
        shake256(&input, &mut seeds);
        let mut sk_seed = [0u8; 16];
        let mut prf = [0u8; 16];
        let mut pk_seed = [0u8; 16];
        sk_seed.copy_from_slice(&seeds[..16]);
        prf.copy_from_slice(&seeds[16..32]);
        pk_seed.copy_from_slice(&seeds[32..]);
        let (slhdsa_public, slhdsa_secret) = slhdsa_keygen(&sk_seed, &prf, &pk_seed);
        SeatKeys {
            ed_secret: *secret,
            slhdsa_secret,
            public: Seat {
                ed_public,
                slhdsa_public,
            },
        }
    }

    /// The public seat to place in a Round Table.
    pub fn public(&self) -> Seat {
        self.public
    }

    /// Sign a manifest, producing this seat's approval.
    pub fn approve(&self, m: &Manifest) -> SeatApproval {
        let msg = manifest_message(m);
        SeatApproval {
            ed_sig: ed25519_sign(&self.ed_secret, &msg),
            slhdsa_sig: slhdsa_sign(&msg, &self.slhdsa_secret),
        }
    }
}

/// One seat's hybrid signature over a manifest (~17 KB, dominated by the
/// SLH-DSA signature).
#[derive(Clone)]
pub struct SeatApproval {
    pub ed_sig: [u8; ED_SIG],
    pub slhdsa_sig: [u8; SLHDSA_SIG_LEN],
}

/// A seat's approval tagged with which seat it is, as handed to the
/// verifier.
pub struct Approval<'a> {
    pub seat: usize,
    pub sig: &'a SeatApproval,
}

/// The Round Table: the policy that says who may approve and how many must.
#[derive(Clone)]
pub struct RoundTable {
    version: u64,
    threshold: u8,
    seats: [Seat; MAX_SEATS],
    count: usize,
}

impl RoundTable {
    /// Build a Table from its seats and threshold. Returns `None` unless it
    /// is well-formed: at least two seats, and a threshold that is at least
    /// one but strictly below the seat count (the doc's rule, so a missing
    /// backup seat can never lock everyone out).
    pub fn new(version: u64, threshold: u8, seats: &[Seat]) -> Option<RoundTable> {
        let count = seats.len();
        if !(2..=MAX_SEATS).contains(&count) {
            return None;
        }
        if threshold == 0 || usize::from(threshold) >= count {
            return None;
        }
        let mut stored = [Seat::ZERO; MAX_SEATS];
        stored[..count].copy_from_slice(seats);
        Some(RoundTable {
            version,
            threshold,
            seats: stored,
            count,
        })
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn seats(&self) -> &[Seat] {
        &self.seats[..self.count]
    }
}

/// What a set of seats approves: a payload hash, bound to an image version,
/// the Table version that authorized it, and an install-by expiry.
#[derive(Clone, Copy)]
pub struct Manifest {
    pub kind: Kind,
    pub payload_hash: [u8; 32],
    pub version: u64,
    pub table_version: u64,
    pub expiry: u64,
}

/// The canonical bytes a seat signs for a manifest.
const MSG_LEN: usize = APPROVAL_LABEL.len() + 1 + 32 + 8 + 8 + 8;

fn manifest_message(m: &Manifest) -> [u8; MSG_LEN] {
    let mut buf = [0u8; MSG_LEN];
    let mut at = 0;
    buf[at..at + APPROVAL_LABEL.len()].copy_from_slice(APPROVAL_LABEL);
    at += APPROVAL_LABEL.len();
    buf[at] = m.kind.byte();
    at += 1;
    buf[at..at + 32].copy_from_slice(&m.payload_hash);
    at += 32;
    buf[at..at + 8].copy_from_slice(&m.version.to_le_bytes());
    at += 8;
    buf[at..at + 8].copy_from_slice(&m.table_version.to_le_bytes());
    at += 8;
    buf[at..at + 8].copy_from_slice(&m.expiry.to_le_bytes());
    buf
}

/// The SHA3-256 hash of an image, as used in a manifest.
pub fn image_hash(image: &[u8]) -> [u8; 32] {
    sha3_256(image)
}

/// The canonical hash of a Round Table, as a Table-change approval signs.
pub fn table_hash(t: &RoundTable) -> [u8; 32] {
    const MAX: usize = TABLE_LABEL.len() + 8 + 1 + 1 + MAX_SEATS * (ED_PUB + SLHDSA_PUB);
    let mut buf = [0u8; MAX];
    let mut at = 0;
    buf[at..at + TABLE_LABEL.len()].copy_from_slice(TABLE_LABEL);
    at += TABLE_LABEL.len();
    buf[at..at + 8].copy_from_slice(&t.version.to_le_bytes());
    at += 8;
    buf[at] = t.threshold;
    at += 1;
    buf[at] = t.count as u8;
    at += 1;
    for seat in t.seats() {
        buf[at..at + ED_PUB].copy_from_slice(&seat.ed_public);
        at += ED_PUB;
        buf[at..at + SLHDSA_PUB].copy_from_slice(&seat.slhdsa_public);
        at += SLHDSA_PUB;
    }
    sha3_256(&buf[..at])
}

/// Verify one seat's hybrid signature over a manifest: both the Ed25519 and
/// the SLH-DSA signature must check.
pub fn verify_seat(seat: &Seat, m: &Manifest, approval: &SeatApproval) -> bool {
    let msg = manifest_message(m);
    ed25519_verify(&seat.ed_public, &msg, &approval.ed_sig)
        && slhdsa_verify(&msg, &approval.slhdsa_sig, &seat.slhdsa_public)
}

/// The core k-of-n check: the manifest names this Table, has not expired,
/// and at least `threshold` *distinct* seats signed it validly. Invalid or
/// repeated approvals are ignored, not fatal; only a seat index outside the
/// Table is rejected outright.
fn enough_seats(
    table: &RoundTable,
    m: &Manifest,
    approvals: &[Approval],
    now: u64,
) -> Result<(), SealError> {
    if m.table_version != table.version {
        return Err(SealError::WrongTable);
    }
    if now > m.expiry {
        return Err(SealError::Expired);
    }
    let mut counted = [false; MAX_SEATS];
    let mut valid = 0usize;
    for a in approvals {
        if a.seat >= table.count {
            return Err(SealError::BadSeat);
        }
        if counted[a.seat] {
            continue;
        }
        if verify_seat(&table.seats[a.seat], m, a.sig) {
            counted[a.seat] = true;
            valid += 1;
        }
    }
    if valid >= usize::from(table.threshold) {
        Ok(())
    } else {
        Err(SealError::NotEnoughSeats)
    }
}

/// Verify a Great Seal over a software image. The manifest must approve
/// this exact image, be no older than `current_version` (the version the
/// node has booted), name the node's `table`, be unexpired at `now`, and
/// carry `threshold` distinct valid seat signatures.
pub fn verify_image(
    table: &RoundTable,
    m: &Manifest,
    image: &[u8; 32],
    approvals: &[Approval],
    now: u64,
    current_version: u64,
) -> Result<(), SealError> {
    if m.kind != Kind::Image {
        return Err(SealError::WrongKind);
    }
    if &m.payload_hash != image {
        return Err(SealError::HashMismatch);
    }
    if m.version < current_version {
        return Err(SealError::Rollback);
    }
    enough_seats(table, m, approvals, now)
}

/// Verify a Great Seal over a replacement Round Table. The new Table must
/// be well-formed, carry a strictly higher version than the current one,
/// and be approved by the *current* Table's threshold.
pub fn verify_table_change(
    current: &RoundTable,
    next: &RoundTable,
    m: &Manifest,
    approvals: &[Approval],
    now: u64,
) -> Result<(), SealError> {
    if m.kind != Kind::Table {
        return Err(SealError::WrongKind);
    }
    if next.version <= current.version {
        return Err(SealError::Rollback);
    }
    if m.version != next.version {
        return Err(SealError::MalformedTable);
    }
    if m.payload_hash != table_hash(next) {
        return Err(SealError::HashMismatch);
    }
    enough_seats(current, m, approvals, now)
}

#[cfg(test)]
mod tests;
