//! Raphael, the healer: the angel that applies verified updates. He takes
//! an update's **Great Seal** — a Round Table's k-of-n hybrid signatures
//! over the image — verifies it, and only then applies it, swapping the
//! ward into its new image through an Update Writ the Keep granted.
//!
//! The security property this stands on: no code is ever applied unless
//! enough of the Round Table signed it. Raphael checks that here, in ring
//! 3, with the `seal` crate; the Keep provides only the mechanism (the A/B
//! swap), gated by the capability.
//!
//! Honest simplifications of the demo, called out so they are not mistaken
//! for the real thing: the Round Table and the signed manifest are built
//! here rather than arriving from offline seats over the network, and the
//! manifest's payload hash is a fixed stand-in rather than the hash of the
//! bytes actually in the B image. What is genuine is the verification — the
//! Ed25519 + SLH-DSA seat signatures must check, and a tampered seal is
//! refused before anything is applied.
//!
//! The Keep seeds his capability table at boot:
//!   handle 0  an Update Writ for the ward (apply its B image)

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use seal::{Approval, Kind, Manifest, RoundTable, SeatKeys, image_hash, verify_image};
use user::abi::check;

/// Handle of the Update Writ for the ward.
const UPDATE: u64 = 0;

/// Two Round Table seats, from fixed secrets (a real Table's seats live on
/// separate offline devices; here they are known so the demo is reproducible).
const SEAT_ONE: [u8; 32] = [0xA1; 32];
const SEAT_TWO: [u8; 32] = [0xA2; 32];

user::program!(main);

fn main(_: u64) -> ! {
    let _ = user::log("raphael, the healer: an update has arrived for the ward");

    // The Round Table: two seats, one signature required (k-of-n, k < n so a
    // lost seat never locks everyone out).
    let one = SeatKeys::from_secret(&SEAT_ONE);
    let two = SeatKeys::from_secret(&SEAT_TWO);
    let Some(table) = RoundTable::new(1, 1, &[one.public(), two.public()]) else {
        let _ = user::log("raphael: the Round Table is malformed");
        user::exit(1);
    };

    // The update manifest, and a seat's Great Seal over it. In a deployment
    // the seats sign offline and the seal travels with the image; here one
    // seat signs so Raphael has a real seal to verify.
    let hash = image_hash(b"rook ward image, version 2");
    let manifest = Manifest {
        kind: Kind::Image,
        payload_hash: hash,
        version: 1,
        table_version: 1,
        expiry: u64::MAX,
    };
    let seal = one.approve(&manifest);
    let now = user::now();

    // The seal must verify against the Round Table, or nothing is applied.
    let approvals = [Approval {
        seat: 0,
        sig: &seal,
    }];
    if verify_image(&table, &manifest, &hash, &approvals, now, 0).is_err() {
        let _ = user::log("raphael: the update's seal did NOT verify; refusing it");
        user::exit(1);
    }
    let _ = user::log("raphael: the Round Table's seal verifies (Ed25519 + SLH-DSA, k of n)");

    // A tampered seal must be refused — the whole point is that no unsigned
    // code is ever trusted. Flip one byte of the signature and confirm.
    let mut forged = seal.clone();
    forged.slhdsa_sig[0] ^= 1;
    let forged_approvals = [Approval {
        seat: 0,
        sig: &forged,
    }];
    if verify_image(&table, &manifest, &hash, &forged_approvals, now, 0).is_ok() {
        let _ = user::log("raphael: a tampered seal was accepted — refusing to trust it");
        user::exit(1);
    }
    let _ = user::log("raphael: a tampered seal is refused");

    // Verified. Apply the update through the Update Writ: the Keep swaps the
    // ward into its new (B) image. Version 2 rides above the low byte.
    if user::update(UPDATE, check::WARD | (2 << 8)).is_err() {
        let _ = user::log("raphael: could not apply the verified update");
        user::exit(1);
    }
    let _ = user::log("raphael: seal verified, update applied; the ward will come up anew");
    user::exit(0)
}
