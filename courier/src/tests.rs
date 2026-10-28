//! Tests for Courier over a simulated datagram link: delivery that is
//! reliable and in order per stream even when the link loses, reorders and
//! duplicates packets, and independent across streams.

use super::*;

/// Two ends of a connection: A sends under k1 (B receives under k1), and B
/// sends under k2 (A receives under k2).
fn pair() -> (Courier, Courier) {
    let k1 = [0x11u8; 32];
    let k2 = [0x22u8; 32];
    (Courier::new(k1, k2), Courier::new(k2, k1))
}

/// Drain every packet an end wants to transmit now.
fn transmit_all(end: &mut Courier) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut buf = [0u8; MAX_PACKET];
    while let Some(n) = end.poll_transmit(&mut buf) {
        packets.push(buf[..n].to_vec());
    }
    packets
}

fn feed(end: &mut Courier, packets: &[Vec<u8>]) {
    for p in packets {
        let _ = end.on_packet(p);
    }
}

/// Drain every message ready for in-order delivery.
fn deliver_all(end: &mut Courier) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut buf = [0u8; MAX_MSG];
    while let Some((stream, n)) = end.poll_deliver(&mut buf) {
        out.push((stream, buf[..n].to_vec()));
    }
    out
}

#[test]
fn delivers_in_order_over_a_perfect_link() {
    let (mut a, mut b) = pair();
    a.send(0, b"one").unwrap();
    a.send(0, b"two").unwrap();
    a.send(0, b"three").unwrap();
    feed(&mut b, &transmit_all(&mut a));
    assert_eq!(
        deliver_all(&mut b),
        vec![
            (0, b"one".to_vec()),
            (0, b"two".to_vec()),
            (0, b"three".to_vec())
        ]
    );
    // B's acknowledgements clear A's send window.
    feed(&mut a, &transmit_all(&mut b));
    assert!(a.idle());
}

#[test]
fn a_lost_packet_is_retransmitted() {
    let (mut a, mut b) = pair();
    a.send(0, b"hello").unwrap();
    let _dropped = transmit_all(&mut a); // thrown away: the link lost it
    assert!(deliver_all(&mut b).is_empty());
    a.tick(); // the retransmit timer fires
    feed(&mut b, &transmit_all(&mut a));
    assert_eq!(deliver_all(&mut b), vec![(0, b"hello".to_vec())]);
}

#[test]
fn reordered_packets_are_delivered_in_order() {
    let (mut a, mut b) = pair();
    a.send(0, b"first").unwrap();
    a.send(0, b"second").unwrap();
    let mut packets = transmit_all(&mut a);
    packets.reverse(); // the link delivers them out of order
    feed(&mut b, &packets);
    assert_eq!(
        deliver_all(&mut b),
        vec![(0, b"first".to_vec()), (0, b"second".to_vec())]
    );
}

#[test]
fn a_loss_on_one_stream_does_not_stall_another() {
    let (mut a, mut b) = pair();
    a.send(0, b"s0m0").unwrap();
    a.send(1, b"s1m0").unwrap();
    a.send(1, b"s1m1").unwrap();
    let packets = transmit_all(&mut a); // [stream0 seq0, stream1 seq0, stream1 seq1]

    // Lose stream 0's only packet; deliver stream 1's two.
    feed(&mut b, &[packets[1].clone(), packets[2].clone()]);
    assert_eq!(
        deliver_all(&mut b),
        vec![(1, b"s1m0".to_vec()), (1, b"s1m1".to_vec())],
        "stream 1 flows while stream 0 has a gap"
    );

    // The missing stream-0 packet finally arrives.
    feed(&mut b, &[packets[0].clone()]);
    assert_eq!(deliver_all(&mut b), vec![(0, b"s0m0".to_vec())]);
}

#[test]
fn a_duplicate_is_delivered_once() {
    let (mut a, mut b) = pair();
    a.send(0, b"once").unwrap();
    let packets = transmit_all(&mut a);
    feed(&mut b, &[packets[0].clone(), packets[0].clone()]);
    assert_eq!(deliver_all(&mut b), vec![(0, b"once".to_vec())]);
}

#[test]
fn a_tampered_packet_is_refused() {
    let (mut a, mut b) = pair();
    a.send(0, b"x").unwrap();
    let mut packets = transmit_all(&mut a);
    let last = packets[0].len() - 1;
    packets[0][last] ^= 1;
    assert_eq!(b.on_packet(&packets[0]), Err(Error::BadPacket));
    assert!(deliver_all(&mut b).is_empty());
}

#[test]
fn the_wrong_keys_cannot_open_a_packet() {
    let mut a = Courier::new([1; 32], [2; 32]);
    let mut stranger = Courier::new([9; 32], [8; 32]);
    a.send(0, b"secret").unwrap();
    let packets = transmit_all(&mut a);
    assert_eq!(stranger.on_packet(&packets[0]), Err(Error::BadPacket));
}

#[test]
fn bad_arguments_are_refused() {
    let (mut a, _b) = pair();
    assert_eq!(a.send(9, b"x"), Err(Error::BadStream));
    assert_eq!(a.send(0, &[0u8; MAX_MSG + 1]), Err(Error::TooLong));
}

#[test]
fn a_full_exchange_settles_quiet() {
    let (mut a, mut b) = pair();
    a.send(0, b"ping").unwrap();
    b.send(0, b"pong").unwrap();
    // A few rounds of carrying each side's packets to the other.
    for _ in 0..4 {
        let from_a = transmit_all(&mut a);
        feed(&mut b, &from_a);
        let from_b = transmit_all(&mut b);
        feed(&mut a, &from_b);
    }
    assert_eq!(deliver_all(&mut a), vec![(0, b"pong".to_vec())]);
    assert_eq!(deliver_all(&mut b), vec![(0, b"ping".to_vec())]);
    assert!(
        a.idle() && b.idle(),
        "both ends quiet once everything is acked"
    );
}
