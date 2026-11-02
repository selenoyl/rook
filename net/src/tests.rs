//! Tests for the packet framing: each layer round-trips, checksums are
//! right, and malformed input is refused.

use super::*;

const SRC_MAC: Mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
const DST_MAC: Mac = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
const SRC_IP: Ip = [10, 0, 2, 15];
const DST_IP: Ip = [10, 0, 2, 2];

#[test]
fn ethernet_round_trips() {
    let mut out = [0u8; 64];
    let n = build_eth(&DST_MAC, &SRC_MAC, ETHERTYPE_IPV4, b"payload", &mut out).unwrap();
    let eth = parse_eth(&out[..n]).unwrap();
    assert_eq!(eth.dst, DST_MAC);
    assert_eq!(eth.src, SRC_MAC);
    assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
    assert_eq!(eth.payload, b"payload");
}

#[test]
fn a_short_ethernet_frame_is_refused() {
    assert!(parse_eth(&[0u8; 10]).is_none());
}

#[test]
fn arp_round_trips() {
    let req = Arp {
        op: ARP_REQUEST,
        sender_mac: SRC_MAC,
        sender_ip: SRC_IP,
        target_mac: [0; 6],
        target_ip: DST_IP,
    };
    let mut out = [0u8; ARP_LEN];
    build_arp(&req, &mut out).unwrap();
    let got = parse_arp(&out).unwrap();
    assert_eq!(got.op, ARP_REQUEST);
    assert_eq!(got.sender_mac, SRC_MAC);
    assert_eq!(got.target_ip, DST_IP);
}

#[test]
fn a_non_ethernet_arp_is_refused() {
    let mut out = [0u8; ARP_LEN];
    build_arp(
        &Arp {
            op: ARP_REQUEST,
            sender_mac: SRC_MAC,
            sender_ip: SRC_IP,
            target_mac: [0; 6],
            target_ip: DST_IP,
        },
        &mut out,
    )
    .unwrap();
    out[0] = 0xff; // corrupt the hardware type
    assert!(parse_arp(&out).is_none());
    assert!(parse_arp(&out[..10]).is_none()); // too short
}

#[test]
fn ipv4_round_trips_and_checks_its_checksum() {
    let mut out = [0u8; 128];
    let n = build_ipv4(&SRC_IP, &DST_IP, PROTO_UDP, 0x1234, b"inside", &mut out).unwrap();
    let ip = parse_ipv4(&out[..n]).unwrap();
    assert_eq!(ip.src, SRC_IP);
    assert_eq!(ip.dst, DST_IP);
    assert_eq!(ip.protocol, PROTO_UDP);
    assert_eq!(ip.payload, b"inside");

    // A corrupted header fails the checksum.
    let mut bad = out;
    bad[12] ^= 0xff; // flip a source-address byte
    assert!(parse_ipv4(&bad[..n]).is_none());
}

#[test]
fn a_non_ipv4_header_is_refused() {
    let mut out = [0u8; 128];
    let n = build_ipv4(&SRC_IP, &DST_IP, PROTO_UDP, 1, b"x", &mut out).unwrap();
    out[0] = 0x65; // version 6, header length 5
    assert!(parse_ipv4(&out[..n]).is_none());
    assert!(parse_ipv4(&out[..10]).is_none()); // truncated
}

#[test]
fn udp_round_trips_with_a_valid_checksum() {
    let mut out = [0u8; 64];
    let n = build_udp(&SRC_IP, &DST_IP, 4321, 53, b"query", &mut out).unwrap();
    let udp = parse_udp(&out[..n]).unwrap();
    assert_eq!(udp.src_port, 4321);
    assert_eq!(udp.dst_port, 53);
    assert_eq!(udp.payload, b"query");

    // The checksum field, left in place, makes the whole thing fold to zero.
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&SRC_IP);
    pseudo[4..8].copy_from_slice(&DST_IP);
    pseudo[9] = PROTO_UDP;
    pseudo[10..12].copy_from_slice(&(n as u16).to_be_bytes());
    assert_eq!(fold(add(add(0, &pseudo), &out[..n])), 0);
}

#[test]
fn the_full_stack_round_trips() {
    let payload = b"a courier packet on the wire";
    let mut udp = [0u8; 128];
    let un = build_udp(&SRC_IP, &DST_IP, 7000, 7000, payload, &mut udp).unwrap();
    let mut ip = [0u8; 160];
    let ipn = build_ipv4(&SRC_IP, &DST_IP, PROTO_UDP, 0x4242, &udp[..un], &mut ip).unwrap();
    let mut frame = [0u8; 256];
    let fend = build_eth(&DST_MAC, &SRC_MAC, ETHERTYPE_IPV4, &ip[..ipn], &mut frame).unwrap();

    let eth = parse_eth(&frame[..fend]).unwrap();
    assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
    let ip = parse_ipv4(eth.payload).unwrap();
    assert_eq!(ip.protocol, PROTO_UDP);
    let udp = parse_udp(ip.payload).unwrap();
    assert_eq!((udp.src_port, udp.dst_port), (7000, 7000));
    assert_eq!(udp.payload, payload);
}

// --- Fuzzing: the parsers are a Gatehouse, fed bytes straight off the
// wire. These randomized tests hammer them with arbitrary and corrupted
// input and assert they never panic (no out-of-bounds, no overflow under
// the test build's checks) and never hand back a payload reaching past the
// bytes they were given. A hand-rolled PRNG keeps it dependency-free and
// deterministic, so a failure reproduces.

/// A tiny xorshift64 PRNG: deterministic, no dependencies.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    /// A value in `0..n` (for n > 0).
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn parsers_survive_arbitrary_bytes() {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15);
    let mut buf = [0u8; 2048];
    for _ in 0..200_000 {
        let len = rng.below(buf.len() + 1);
        for b in &mut buf[..len] {
            *b = rng.byte();
        }
        let frame = &buf[..len];
        // Each parser must return cleanly on any bytes, and any payload it
        // hands back must lie within what it was given.
        if let Some(eth) = parse_eth(frame) {
            assert!(eth.payload.len() <= len);
            let _ = parse_arp(eth.payload);
            if let Some(ip) = parse_ipv4(eth.payload) {
                assert!(ip.payload.len() <= eth.payload.len());
                if let Some(udp) = parse_udp(ip.payload) {
                    assert!(udp.payload.len() <= ip.payload.len());
                }
            }
        }
        let _ = parse_arp(frame);
        let _ = parse_ipv4(frame);
        let _ = parse_udp(frame);
        let _ = checksum(frame);
    }
}

#[test]
fn mutating_a_valid_packet_never_panics() {
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..100_000 {
        // Build a valid Ethernet/IPv4/UDP packet with varied fields.
        let n = rng.below(96);
        let mut pl = [0u8; 96];
        for b in &mut pl[..n] {
            *b = rng.byte();
        }
        let mut udp = [0u8; 128];
        let un = build_udp(
            &SRC_IP,
            &DST_IP,
            rng.next() as u16,
            rng.next() as u16,
            &pl[..n],
            &mut udp,
        )
        .unwrap();
        let mut ip = [0u8; 160];
        let ipn = build_ipv4(
            &SRC_IP,
            &DST_IP,
            PROTO_UDP,
            rng.next() as u16,
            &udp[..un],
            &mut ip,
        )
        .unwrap();
        let mut frame = [0u8; 192];
        let fend = build_eth(&DST_MAC, &SRC_MAC, ETHERTYPE_IPV4, &ip[..ipn], &mut frame).unwrap();

        // Flip a handful of random bits anywhere, then re-run the whole
        // parse chain. Corruption must be refused or parsed, never crash.
        for _ in 0..rng.below(6) {
            let pos = rng.below(fend);
            frame[pos] ^= 1u8 << rng.below(8);
        }
        if let Some(eth) = parse_eth(&frame[..fend])
            && let Some(ip) = parse_ipv4(eth.payload)
        {
            let _ = parse_udp(ip.payload);
        }
    }
}

#[test]
fn ipv4_udp_round_trip_at_random_lengths() {
    let mut rng = Rng::new(0x0123_4567_89AB_CDEF);
    for _ in 0..20_000 {
        let n = rng.below(600);
        let mut pl = [0u8; 600];
        for b in &mut pl[..n] {
            *b = rng.byte();
        }
        let (sp, dp) = (rng.next() as u16, rng.next() as u16);
        let mut udp = [0u8; 640];
        let un = build_udp(&SRC_IP, &DST_IP, sp, dp, &pl[..n], &mut udp).unwrap();
        let parsed = parse_udp(&udp[..un]).unwrap();
        assert_eq!(parsed.src_port, sp);
        assert_eq!(parsed.dst_port, dp);
        assert_eq!(parsed.payload, &pl[..n]);

        let mut ip = [0u8; 680];
        let ipn = build_ipv4(
            &SRC_IP,
            &DST_IP,
            PROTO_UDP,
            rng.next() as u16,
            &udp[..un],
            &mut ip,
        )
        .unwrap();
        let pip = parse_ipv4(&ip[..ipn]).unwrap();
        assert_eq!(pip.protocol, PROTO_UDP);
        assert_eq!(pip.payload, &udp[..un]);
    }
}
