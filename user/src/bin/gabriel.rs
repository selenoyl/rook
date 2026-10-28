//! Gabriel, the messenger: the angel that carries messages between Rook
//! machines over the network. For now he brings up the network card and
//! proves it carries real traffic, climbing the stack one layer at a time:
//! he ARPs the gateway (Ethernet), then sends a DHCP DISCOVER and reads the
//! server's OFFER (IPv4 + UDP), a real datagram round-trip. Carrying Courier
//! and Drawbridge over the link comes next.
//!
//! The Keep seeds his capability table at boot:
//!   handle 0  an I/O Writ for the network card's ports

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use net::{
    ARP_LEN, ARP_REPLY, ARP_REQUEST, Arp, BROADCAST, ETHERTYPE_ARP, ETHERTYPE_IPV4, Ip, Mac,
    PROTO_UDP,
};
use user::ne2000::Ne2000;

/// Handle of the I/O Writ covering the network card's ports.
const NIC: u64 = 0;

/// QEMU's user network hands the guest 10.0.2.15 and a gateway at 10.0.2.2.
const MY_IP: Ip = [10, 0, 2, 15];
const GATEWAY: Ip = [10, 0, 2, 2];
const UNSET_IP: Ip = [0, 0, 0, 0];
const BROADCAST_IP: Ip = [255, 255, 255, 255];

/// BOOTP/DHCP client and server ports.
const DHCP_CLIENT: u16 = 68;
const DHCP_SERVER: u16 = 67;
/// A fixed transaction id ("Rook"); the server echoes it back.
const XID: [u8; 4] = *b"Rook";

/// Poll attempts for the reply, each after a 10 ms sleep, so the card and
/// the network have time to answer without the task spinning or hanging.
const TRIES: u32 = 100;

user::program!(main);

fn main(_: u64) -> ! {
    let Some(mut nic) = Ne2000::open(NIC) else {
        let _ = user::log("gabriel: no network card found");
        user::exit(1);
    };
    let mac = nic.mac();
    user::logln!(
        "gabriel: NIC up, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );

    // Layer 2: ARP the gateway and learn its MAC from the reply.
    let Some(gw) = resolve_gateway(&mut nic, &mac) else {
        let _ = user::log("gabriel: no ARP reply from the gateway");
        user::exit(1);
    };
    user::logln!(
        "gabriel: ARP reply, gateway 10.0.2.2 is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        gw[0],
        gw[1],
        gw[2],
        gw[3],
        gw[4],
        gw[5]
    );

    // Layers 3 and 4: a DHCP DISCOVER/OFFER exchange, a real UDP round-trip.
    let Some(offer) = dhcp_probe(&mut nic, &mac) else {
        let _ = user::log("gabriel: no DHCP offer came back");
        user::exit(1);
    };
    user::logln!(
        "gabriel: DHCP offer of {}.{}.{}.{}, IPv4/UDP datagrams round-trip",
        offer[0],
        offer[1],
        offer[2],
        offer[3]
    );

    let _ = user::log("gabriel: network card sends and receives on a real link");
    user::exit(0)
}

/// Broadcast an ARP request for the gateway and return its MAC from the
/// reply, or None if none comes back in time.
fn resolve_gateway(nic: &mut Ne2000, mac: &Mac) -> Option<Mac> {
    let mut arp = [0u8; ARP_LEN];
    net::build_arp(
        &Arp {
            op: ARP_REQUEST,
            sender_mac: *mac,
            sender_ip: MY_IP,
            target_mac: [0; 6],
            target_ip: GATEWAY,
        },
        &mut arp,
    )?;
    let mut frame = [0u8; 64];
    let n = net::build_eth(&BROADCAST, mac, ETHERTYPE_ARP, &arp, &mut frame)?;
    nic.send(&frame[..n])?;

    let mut buf = [0u8; 1536];
    for _ in 0..TRIES {
        while let Some(len) = nic.poll(&mut buf) {
            if let Some(reply) = gateway_from_arp(&buf[..len]) {
                return Some(reply);
            }
        }
        let _ = user::sleep(1);
    }
    None
}

/// If `frame` is an ARP reply from the gateway, return its MAC.
fn gateway_from_arp(frame: &[u8]) -> Option<Mac> {
    let eth = net::parse_eth(frame)?;
    if eth.ethertype != ETHERTYPE_ARP {
        return None;
    }
    let arp = net::parse_arp(eth.payload)?;
    if arp.op == ARP_REPLY && arp.sender_ip == GATEWAY {
        Some(arp.sender_mac)
    } else {
        None
    }
}

/// Broadcast a DHCP DISCOVER and return the address the server offers,
/// taken from its OFFER, or None if none arrives in time. QEMU's user
/// network runs a DHCP server at the gateway, so this is a genuine UDP
/// round-trip over the card: a DISCOVER out, an OFFER back.
fn dhcp_probe(nic: &mut Ne2000, mac: &Mac) -> Option<Ip> {
    // The BOOTP/DHCP DISCOVER: a request from our MAC, broadcast flag set
    // so the server's reply comes back to us before we have an address,
    // the magic cookie, then one option saying "DHCP DISCOVER" and end.
    // The whole thing is padded to 300 bytes — the BOOTP minimum (RFC
    // 1542) that servers, QEMU's among them, expect before they answer.
    let mut dhcp = [0u8; 300];
    dhcp[0] = 1; // op: request
    dhcp[1] = 1; // htype: Ethernet
    dhcp[2] = 6; // hlen: six-byte MAC
    dhcp[4..8].copy_from_slice(&XID);
    dhcp[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
    dhcp[28..34].copy_from_slice(mac); // chaddr
    dhcp[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
    dhcp[240..243].copy_from_slice(&[53, 1, 1]); // option 53 = DISCOVER
    dhcp[243] = 0xff; // end of options (the rest is zero padding)

    // Wrap it: UDP 68 -> 67, IPv4 0.0.0.0 -> 255.255.255.255, broadcast.
    let mut udp = [0u8; 312];
    let un = net::build_udp(
        &UNSET_IP,
        &BROADCAST_IP,
        DHCP_CLIENT,
        DHCP_SERVER,
        &dhcp,
        &mut udp,
    )?;
    let mut ip = [0u8; 332];
    let ipn = net::build_ipv4(&UNSET_IP, &BROADCAST_IP, PROTO_UDP, 0, &udp[..un], &mut ip)?;
    let mut frame = [0u8; 352];
    let n = net::build_eth(&BROADCAST, mac, ETHERTYPE_IPV4, &ip[..ipn], &mut frame)?;
    nic.send(&frame[..n])?;

    let mut buf = [0u8; 1536];
    for _ in 0..TRIES {
        while let Some(len) = nic.poll(&mut buf) {
            if let Some(offer) = offer_from_frame(&buf[..len]) {
                return Some(offer);
            }
        }
        let _ = user::sleep(1);
    }
    None
}

/// If `frame` is a DHCP OFFER answering our DISCOVER, return the offered
/// address (the BOOTP `yiaddr`). Every layer is checked before the next is
/// trusted, and anything that does not match is dropped.
fn offer_from_frame(frame: &[u8]) -> Option<Ip> {
    let eth = net::parse_eth(frame)?;
    if eth.ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let ipv4 = net::parse_ipv4(eth.payload)?;
    if ipv4.protocol != PROTO_UDP {
        return None;
    }
    let udp = net::parse_udp(ipv4.payload)?;
    if udp.src_port != DHCP_SERVER || udp.dst_port != DHCP_CLIENT {
        return None;
    }
    // A BOOTP reply (op 2) carrying our transaction id; yiaddr is at 16.
    let dhcp = udp.payload;
    if dhcp.len() < 240 || dhcp[0] != 2 || dhcp[4..8] != XID {
        return None;
    }
    let mut yiaddr = [0u8; 4];
    yiaddr.copy_from_slice(&dhcp[16..20]);
    Some(yiaddr)
}
