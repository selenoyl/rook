//! Packet framing: Ethernet, ARP, IPv4 and UDP — enough to carry Courier
//! over a real network, parsed and built under the Gatehouse rules.
//!
//! Every parser checks lengths and fields before trusting them and returns
//! `None` on anything malformed rather than reading past the end or
//! panicking; IPv4 header checksums are verified. Builders write into a
//! caller buffer and return the number of bytes written, or `None` if it
//! would not fit. Nothing here allocates or keeps state — they are pure
//! functions over byte slices, so the same code frames packets for the NIC
//! driver and is exhaustively testable on the host.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// A 48-bit Ethernet (MAC) address.
pub type Mac = [u8; 6];
/// A 32-bit IPv4 address.
pub type Ip = [u8; 4];

/// The all-ones broadcast MAC.
pub const BROADCAST: Mac = [0xff; 6];

pub const ETH_HDR: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

pub const ARP_LEN: usize = 28;
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

pub const IPV4_HDR: usize = 20;
pub const PROTO_UDP: u8 = 17;

pub const UDP_HDR: usize = 8;

// --- Internet checksum ------------------------------------------------

fn add(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The ones'-complement internet checksum of `data`. A valid header whose
/// checksum field is in place folds back to zero.
pub fn checksum(data: &[u8]) -> u16 {
    fold(add(0, data))
}

// --- Ethernet ---------------------------------------------------------

/// A parsed Ethernet frame: its addresses, type, and the payload after the
/// 14-byte header.
pub struct Eth<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse_eth(frame: &[u8]) -> Option<Eth<'_>> {
    if frame.len() < ETH_HDR {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    Some(Eth {
        dst,
        src,
        ethertype: u16::from_be_bytes([frame[12], frame[13]]),
        payload: &frame[ETH_HDR..],
    })
}

pub fn build_eth(
    dst: &Mac,
    src: &Mac,
    ethertype: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = ETH_HDR + payload.len();
    if out.len() < total {
        return None;
    }
    out[0..6].copy_from_slice(dst);
    out[6..12].copy_from_slice(src);
    out[12..14].copy_from_slice(&ethertype.to_be_bytes());
    out[ETH_HDR..total].copy_from_slice(payload);
    Some(total)
}

// --- ARP (IPv4 over Ethernet) -----------------------------------------

pub struct Arp {
    pub op: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ip,
    pub target_mac: Mac,
    pub target_ip: Ip,
}

pub fn parse_arp(b: &[u8]) -> Option<Arp> {
    if b.len() < ARP_LEN {
        return None;
    }
    // Only Ethernet/IPv4 ARP: htype 1, ptype 0x0800, hlen 6, plen 4.
    if u16::from_be_bytes([b[0], b[1]]) != 1
        || u16::from_be_bytes([b[2], b[3]]) != ETHERTYPE_IPV4
        || b[4] != 6
        || b[5] != 4
    {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    let mut sender_ip = [0u8; 4];
    let mut target_mac = [0u8; 6];
    let mut target_ip = [0u8; 4];
    sender_mac.copy_from_slice(&b[8..14]);
    sender_ip.copy_from_slice(&b[14..18]);
    target_mac.copy_from_slice(&b[18..24]);
    target_ip.copy_from_slice(&b[24..28]);
    Some(Arp {
        op: u16::from_be_bytes([b[6], b[7]]),
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

pub fn build_arp(a: &Arp, out: &mut [u8]) -> Option<usize> {
    if out.len() < ARP_LEN {
        return None;
    }
    out[0..2].copy_from_slice(&1u16.to_be_bytes());
    out[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    out[4] = 6;
    out[5] = 4;
    out[6..8].copy_from_slice(&a.op.to_be_bytes());
    out[8..14].copy_from_slice(&a.sender_mac);
    out[14..18].copy_from_slice(&a.sender_ip);
    out[18..24].copy_from_slice(&a.target_mac);
    out[24..28].copy_from_slice(&a.target_ip);
    Some(ARP_LEN)
}

// --- IPv4 -------------------------------------------------------------

/// A parsed IPv4 datagram: its addresses, protocol, and payload. Options
/// are skipped (the header length is honoured) but not interpreted.
pub struct Ipv4<'a> {
    pub src: Ip,
    pub dst: Ip,
    pub protocol: u8,
    pub payload: &'a [u8],
}

pub fn parse_ipv4(b: &[u8]) -> Option<Ipv4<'_>> {
    if b.len() < IPV4_HDR || b[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(b[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([b[2], b[3]]));
    if ihl < IPV4_HDR || ihl > b.len() || total < ihl || total > b.len() {
        return None;
    }
    if checksum(&b[..ihl]) != 0 {
        return None;
    }
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&b[12..16]);
    dst.copy_from_slice(&b[16..20]);
    Some(Ipv4 {
        src,
        dst,
        protocol: b[9],
        payload: &b[ihl..total],
    })
}

/// Build an IPv4 datagram (no options) carrying `payload`.
pub fn build_ipv4(
    src: &Ip,
    dst: &Ip,
    protocol: u8,
    ident: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = IPV4_HDR + payload.len();
    if out.len() < total || total > 0xffff {
        return None;
    }
    out[0] = 0x45; // version 4, header length 5 words
    out[1] = 0; // DSCP/ECN
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[4..6].copy_from_slice(&ident.to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    out[8] = 64; // TTL
    out[9] = protocol;
    out[10..12].copy_from_slice(&[0, 0]); // checksum, filled below
    out[12..16].copy_from_slice(src);
    out[16..20].copy_from_slice(dst);
    let ck = checksum(&out[..IPV4_HDR]);
    out[10..12].copy_from_slice(&ck.to_be_bytes());
    out[IPV4_HDR..total].copy_from_slice(payload);
    Some(total)
}

// --- UDP --------------------------------------------------------------

/// A parsed UDP datagram.
pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(b: &[u8]) -> Option<Udp<'_>> {
    if b.len() < UDP_HDR {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([b[4], b[5]]));
    if len < UDP_HDR || len > b.len() {
        return None;
    }
    Some(Udp {
        src_port: u16::from_be_bytes([b[0], b[1]]),
        dst_port: u16::from_be_bytes([b[2], b[3]]),
        payload: &b[UDP_HDR..len],
    })
}

fn udp_checksum(src: &Ip, dst: &Ip, segment: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(src);
    pseudo[4..8].copy_from_slice(dst);
    pseudo[9] = PROTO_UDP;
    pseudo[10..12].copy_from_slice(&(segment.len() as u16).to_be_bytes());
    let ck = fold(add(add(0, &pseudo), segment));
    // A computed checksum of zero is sent as all ones, so the field is
    // never zero (which would mean "no checksum").
    if ck == 0 { 0xffff } else { ck }
}

/// Build a UDP datagram with its checksum (over the IPv4 pseudo-header).
pub fn build_udp(
    src_ip: &Ip,
    dst_ip: &Ip,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = UDP_HDR + payload.len();
    if out.len() < total || total > 0xffff {
        return None;
    }
    out[0..2].copy_from_slice(&src_port.to_be_bytes());
    out[2..4].copy_from_slice(&dst_port.to_be_bytes());
    out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    out[6..8].copy_from_slice(&[0, 0]); // checksum, filled below
    out[UDP_HDR..total].copy_from_slice(payload);
    let ck = udp_checksum(src_ip, dst_ip, &out[..total]);
    out[6..8].copy_from_slice(&ck.to_be_bytes());
    Some(total)
}

#[cfg(test)]
mod tests;
