//! Tests for the Great Seal: a 2-of-3 Round Table approving images and a
//! Table change, and every rule that must refuse one.
//!
//! SLH-DSA signing is expensive, so the common 2-of-3 Table, its seats and
//! their approvals over one image manifest are built once in a shared
//! fixture; the tests that need a different manifest sign their own.

use super::*;
use std::sync::OnceLock;

const NOW: u64 = 1_000;
const SOON: u64 = 2_000; // a comfortable expiry
const IMG_VERSION: u64 = 5;

struct Fixture {
    table: RoundTable,
    seats: [SeatKeys; 3],
    img: [u8; 32],
    manifest: Manifest,
    a0: SeatApproval,
    a1: SeatApproval,
    a2: SeatApproval,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let seats = [
            SeatKeys::from_secret(&[0x01; 32]),
            SeatKeys::from_secret(&[0x02; 32]),
            SeatKeys::from_secret(&[0x03; 32]),
        ];
        let publics = [seats[0].public(), seats[1].public(), seats[2].public()];
        let table = RoundTable::new(1, 2, &publics).expect("well-formed table");
        let img = image_hash(b"a trustworthy update");
        let manifest = Manifest {
            kind: Kind::Image,
            payload_hash: img,
            version: IMG_VERSION,
            table_version: 1,
            expiry: SOON,
        };
        let a0 = seats[0].approve(&manifest);
        let a1 = seats[1].approve(&manifest);
        let a2 = seats[2].approve(&manifest);
        Fixture {
            table,
            seats,
            img,
            manifest,
            a0,
            a1,
            a2,
        }
    })
}

#[test]
fn two_of_three_seats_seal_an_image() {
    let f = fixture();
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 1,
            sig: &f.a1,
        },
    ];
    assert_eq!(
        verify_image(&f.table, &f.manifest, &f.img, &approvals, NOW, 0),
        Ok(())
    );
}

#[test]
fn one_seat_is_not_enough() {
    let f = fixture();
    let approvals = [Approval {
        seat: 0,
        sig: &f.a0,
    }];
    assert_eq!(
        verify_image(&f.table, &f.manifest, &f.img, &approvals, NOW, 0),
        Err(SealError::NotEnoughSeats)
    );
}

#[test]
fn the_same_seat_twice_counts_once() {
    let f = fixture();
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 0,
            sig: &f.a0,
        },
    ];
    assert_eq!(
        verify_image(&f.table, &f.manifest, &f.img, &approvals, NOW, 0),
        Err(SealError::NotEnoughSeats)
    );
}

#[test]
fn a_wrong_signature_does_not_count() {
    let f = fixture();
    // Seat 1's slot carries seat 2's signature — invalid for seat 1, so it
    // does not count, leaving only one good seat.
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 1,
            sig: &f.a2,
        },
    ];
    assert_eq!(
        verify_image(&f.table, &f.manifest, &f.img, &approvals, NOW, 0),
        Err(SealError::NotEnoughSeats)
    );
}

#[test]
fn a_tampered_image_hash_is_refused() {
    let f = fixture();
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 1,
            sig: &f.a1,
        },
    ];
    let other = image_hash(b"a swapped image");
    assert_eq!(
        verify_image(&f.table, &f.manifest, &other, &approvals, NOW, 0),
        Err(SealError::HashMismatch)
    );
}

#[test]
fn an_older_image_version_is_refused() {
    let f = fixture();
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 1,
            sig: &f.a1,
        },
    ];
    // The node has already booted a newer version than this manifest names.
    assert_eq!(
        verify_image(
            &f.table,
            &f.manifest,
            &f.img,
            &approvals,
            NOW,
            IMG_VERSION + 1
        ),
        Err(SealError::Rollback)
    );
}

#[test]
fn an_expired_approval_is_refused() {
    let f = fixture();
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 1,
            sig: &f.a1,
        },
    ];
    assert_eq!(
        verify_image(&f.table, &f.manifest, &f.img, &approvals, SOON + 1, 0),
        Err(SealError::Expired)
    );
}

#[test]
fn a_seat_index_outside_the_table_is_refused() {
    let f = fixture();
    let approvals = [Approval {
        seat: 9,
        sig: &f.a0,
    }];
    assert_eq!(
        verify_image(&f.table, &f.manifest, &f.img, &approvals, NOW, 0),
        Err(SealError::BadSeat)
    );
}

#[test]
fn a_manifest_for_another_table_is_refused() {
    let f = fixture();
    // A manifest naming Table version 2, but this node is on 1. The Table
    // mismatch is caught before any signature is checked, so the fixture's
    // approvals stand in (and this also guards that check ordering).
    let m = Manifest {
        table_version: 2,
        ..f.manifest
    };
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 1,
            sig: &f.a1,
        },
    ];
    assert_eq!(
        verify_image(&f.table, &m, &f.img, &approvals, NOW, 0),
        Err(SealError::WrongTable)
    );
}

#[test]
fn an_image_manifest_is_not_a_table_manifest() {
    let f = fixture();
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 1,
            sig: &f.a1,
        },
    ];
    let next = f.table.clone();
    assert_eq!(
        verify_table_change(&f.table, &next, &f.manifest, &approvals, NOW),
        Err(SealError::WrongKind)
    );
}

#[test]
fn the_current_table_can_authorize_a_new_one() {
    let f = fixture();
    // The new Table adds a fourth seat and raises the threshold to 3.
    let fourth = SeatKeys::from_secret(&[0x04; 32]);
    let publics = [
        f.seats[0].public(),
        f.seats[1].public(),
        f.seats[2].public(),
        fourth.public(),
    ];
    let next = RoundTable::new(2, 3, &publics).expect("well-formed next table");
    let m = Manifest {
        kind: Kind::Table,
        payload_hash: table_hash(&next),
        version: next.version(),
        table_version: f.table.version(),
        expiry: SOON,
    };
    // Two seats of the current 2-of-3 Table approve the change.
    let a0 = f.seats[0].approve(&m);
    let a1 = f.seats[1].approve(&m);
    let approvals = [
        Approval { seat: 0, sig: &a0 },
        Approval { seat: 1, sig: &a1 },
    ];
    assert_eq!(
        verify_table_change(&f.table, &next, &m, &approvals, NOW),
        Ok(())
    );
}

#[test]
fn a_table_change_cannot_roll_the_version_back() {
    let f = fixture();
    // A "new" Table at the same version 1 is a replay.
    let next = RoundTable::new(1, 2, f.table.seats()).expect("table");
    let m = Manifest {
        kind: Kind::Table,
        payload_hash: table_hash(&next),
        version: 1,
        table_version: f.table.version(),
        expiry: SOON,
    };
    // The version check precedes signature verification, so placeholders.
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 1,
            sig: &f.a1,
        },
    ];
    assert_eq!(
        verify_table_change(&f.table, &next, &m, &approvals, NOW),
        Err(SealError::Rollback)
    );
}

#[test]
fn a_table_change_binds_the_new_table_hash() {
    let f = fixture();
    let next = RoundTable::new(2, 2, f.table.seats()).expect("table");
    // The manifest's payload hash is for a different (well-formed) table.
    let decoy = RoundTable::new(2, 1, &[f.seats[0].public(), f.seats[2].public()]).expect("decoy");
    let m = Manifest {
        kind: Kind::Table,
        payload_hash: table_hash(&decoy),
        version: 2,
        table_version: f.table.version(),
        expiry: SOON,
    };
    // The payload-hash check precedes signature verification, so placeholders.
    let approvals = [
        Approval {
            seat: 0,
            sig: &f.a0,
        },
        Approval {
            seat: 1,
            sig: &f.a1,
        },
    ];
    assert_eq!(
        verify_table_change(&f.table, &next, &m, &approvals, NOW),
        Err(SealError::HashMismatch)
    );
}

#[test]
fn malformed_tables_are_refused() {
    let f = fixture();
    let s = f.table.seats();
    // Threshold equal to the seat count (no slack for a lost backup).
    assert!(RoundTable::new(1, 3, s).is_none());
    // Threshold of zero.
    assert!(RoundTable::new(1, 0, s).is_none());
    // Fewer than two seats.
    assert!(RoundTable::new(1, 1, &s[..1]).is_none());
    // A sound 2-of-3 is accepted.
    assert!(RoundTable::new(1, 2, s).is_some());
}
