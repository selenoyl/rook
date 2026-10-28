//! Gabriel, the messenger: the angel that carries messages between Rook
//! machines over the network. He runs in one of three roles, chosen by his
//! start argument:
//!
//!   * the default, over QEMU's user network: ARP the gateway (Ethernet),
//!     then a DHCP round-trip (IPv4 + UDP), proving the card drives a real
//!     link on its own;
//!   * `server` and `client`, for the two-node test, where two Keeps are
//!     wired to one Ethernet and talk to each other over the wire.
//!
//! Everything is built and parsed with the `net` crate under the Gatehouse
//! rules, and driven through the capability-gated NE2000 driver in ring 3.
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

/// The point-to-point link used by the two-node test: the two Keeps share
/// one Ethernet with static addresses (no DHCP), and talk over this UDP
/// port.
const SERVER_IP: Ip = [10, 9, 0, 1];
const CLIENT_IP: Ip = [10, 9, 0, 2];
const PORT: u16 = 7000;
const PING: &[u8] = b"rook-ping";
const PONG: &[u8] = b"rook-pong";

/// Poll attempts for a reply, each after a 10 ms sleep, so the card and the
/// network have time to answer without the task spinning or hanging.
const TRIES: u32 = 100;
/// The server polls this many ticks for a client before giving up, long
/// enough for the other Keep to boot and reach it.
const SERVER_TRIES: u32 = 1500;
/// The client resends its ARP / ping this many times, polling `WAIT` ticks
/// between each, so an answer from a still-booting peer is not missed.
const ROUNDS: u32 = 60;
const WAIT: u32 = 10;

user::program!(main);

fn main(arg: u64) -> ! {
    let Some((mut nic, mac)) = open_nic() else {
        let _ = user::log("gabriel: no network card found");
        user::exit(1);
    };
    log_mac(&mac);
    match arg {
        abi::gabriel::SERVER => server(&mut nic, &mac),
        abi::gabriel::CLIENT => client(&mut nic, &mac),
        _ => dhcp_demo(&mut nic, &mac),
    }
}

/// Open the network card through the I/O Writ and read its MAC.
fn open_nic() -> Option<(Ne2000, Mac)> {
    let nic = Ne2000::open(NIC)?;
    let mac = nic.mac();
    Some((nic, mac))
}

/// Log the card's MAC address.
fn log_mac(mac: &Mac) {
    user::logln!(
        "gabriel: NIC up, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
}

// --- The default role: prove the card over QEMU's user network ----------

/// ARP the gateway, then a DHCP round-trip, proving Ethernet, IPv4 and UDP
/// on a real link.
fn dhcp_demo(nic: &mut Ne2000, mac: &Mac) -> ! {
    // Layer 2: ARP the gateway and learn its MAC from the reply.
    let Some(gw) = arp_resolve(nic, mac, MY_IP, GATEWAY) else {
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
    let Some(offer) = dhcp_probe(nic, mac) else {
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
/// address (the BOOTP `yiaddr`). The reply's destination is not pinned (the
/// server may unicast it or broadcast it before we hold an address); the
/// UDP ports and the transaction id identify it. Every layer is checked
/// before the next is trusted, and anything that does not match is dropped.
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

// --- The two-node roles: two Keeps on one wire --------------------------

/// Listen on the point-to-point link for the client, answer its ARP, and
/// reply to its ping, proving two Rook machines reach each other over UDP.
fn server(nic: &mut Ne2000, mac: &Mac) -> ! {
    let _ = user::log("gabriel: server up, listening for a Rook on the wire");
    let mut buf = [0u8; 1536];
    for _ in 0..SERVER_TRIES {
        while let Some(len) = nic.poll(&mut buf) {
            answer_arp(nic, mac, &buf[..len]);
            if let Some((peer_mac, peer_ip, peer_port, payload)) = udp_from(&buf[..len], SERVER_IP)
                && peer_port == PORT
                && payload == PING
            {
                let _ = send_udp(
                    nic, mac, &peer_mac, SERVER_IP, peer_ip, PORT, peer_port, PONG,
                );
                user::logln!(
                    "gabriel: server answered a ping from {}.{}.{}.{} over UDP",
                    peer_ip[0],
                    peer_ip[1],
                    peer_ip[2],
                    peer_ip[3]
                );
                let _ = user::log("gabriel: two Rook machines talk over a regular network");
                user::exit(0);
            }
        }
        let _ = user::sleep(1);
    }
    let _ = user::log("gabriel: server heard no client");
    user::exit(1)
}

/// Find the server with ARP, then ping it over UDP and wait for the pong,
/// resending if an answer is missed while the peer is still coming up.
fn client(nic: &mut Ne2000, mac: &Mac) -> ! {
    let Some(server_mac) = arp_resolve(nic, mac, CLIENT_IP, SERVER_IP) else {
        let _ = user::log("gabriel: no ARP reply from the server");
        user::exit(1);
    };
    user::logln!(
        "gabriel: ARP reply, server 10.9.0.1 is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        server_mac[0],
        server_mac[1],
        server_mac[2],
        server_mac[3],
        server_mac[4],
        server_mac[5]
    );

    let mut buf = [0u8; 1536];
    for _ in 0..ROUNDS {
        let _ = send_udp(
            nic,
            mac,
            &server_mac,
            CLIENT_IP,
            SERVER_IP,
            PORT,
            PORT,
            PING,
        );
        for _ in 0..WAIT {
            while let Some(len) = nic.poll(&mut buf) {
                if let Some((_, _, src_port, payload)) = udp_from(&buf[..len], CLIENT_IP)
                    && src_port == PORT
                    && payload == PONG
                {
                    let _ =
                        user::log("gabriel: pong from the server; two Rook machines talk over UDP");
                    user::exit(0);
                }
            }
            let _ = user::sleep(1);
        }
    }
    let _ = user::log("gabriel: no pong from the server");
    user::exit(1)
}

// --- Link helpers, shared by every role ---------------------------------

/// Broadcast an ARP request for `target_ip` and return its MAC from the
/// reply, resending until one comes back or the rounds run out.
fn arp_resolve(nic: &mut Ne2000, mac: &Mac, my_ip: Ip, target_ip: Ip) -> Option<Mac> {
    let mut buf = [0u8; 1536];
    for _ in 0..ROUNDS {
        send_arp(nic, mac, ARP_REQUEST, my_ip, &BROADCAST, target_ip)?;
        for _ in 0..WAIT {
            while let Some(len) = nic.poll(&mut buf) {
                if let Some(m) = arp_reply_from(&buf[..len], target_ip) {
                    return Some(m);
                }
            }
            let _ = user::sleep(1);
        }
    }
    None
}

/// If `frame` is an ARP reply from `from_ip`, return its sender MAC.
fn arp_reply_from(frame: &[u8], from_ip: Ip) -> Option<Mac> {
    let eth = net::parse_eth(frame)?;
    if eth.ethertype != ETHERTYPE_ARP {
        return None;
    }
    let arp = net::parse_arp(eth.payload)?;
    if arp.op == ARP_REPLY && arp.sender_ip == from_ip {
        Some(arp.sender_mac)
    } else {
        None
    }
}

/// If `frame` is an ARP request for our address, answer it.
fn answer_arp(nic: &Ne2000, mac: &Mac, frame: &[u8]) {
    let Some(eth) = net::parse_eth(frame) else {
        return;
    };
    if eth.ethertype != ETHERTYPE_ARP {
        return;
    }
    let Some(arp) = net::parse_arp(eth.payload) else {
        return;
    };
    if arp.op == ARP_REQUEST && arp.target_ip == SERVER_IP {
        let _ = send_arp(
            nic,
            mac,
            ARP_REPLY,
            SERVER_IP,
            &arp.sender_mac,
            arp.sender_ip,
        );
    }
}

/// Build and send one ARP frame to `to_mac`.
fn send_arp(nic: &Ne2000, mac: &Mac, op: u16, my_ip: Ip, to_mac: &Mac, to_ip: Ip) -> Option<()> {
    let mut arp = [0u8; ARP_LEN];
    net::build_arp(
        &Arp {
            op,
            sender_mac: *mac,
            sender_ip: my_ip,
            target_mac: if op == ARP_REQUEST { [0; 6] } else { *to_mac },
            target_ip: to_ip,
        },
        &mut arp,
    )?;
    let mut frame = [0u8; 64];
    let n = net::build_eth(to_mac, mac, ETHERTYPE_ARP, &arp, &mut frame)?;
    nic.send(&frame[..n])
}

/// Build Ethernet/IPv4/UDP around `payload` and send it to `dst_mac`.
#[allow(clippy::too_many_arguments)]
fn send_udp(
    nic: &Ne2000,
    mac: &Mac,
    dst_mac: &Mac,
    src_ip: Ip,
    dst_ip: Ip,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<()> {
    let mut udp = [0u8; 1500];
    let un = net::build_udp(&src_ip, &dst_ip, src_port, dst_port, payload, &mut udp)?;
    let mut ip = [0u8; 1520];
    let ipn = net::build_ipv4(&src_ip, &dst_ip, PROTO_UDP, 0, &udp[..un], &mut ip)?;
    let mut frame = [0u8; 1536];
    let n = net::build_eth(dst_mac, mac, ETHERTYPE_IPV4, &ip[..ipn], &mut frame)?;
    nic.send(&frame[..n])
}

/// Parse `frame` as a UDP datagram addressed to `my_ip`, returning the
/// sender's MAC and IP, its source port, and the payload. Every layer is
/// bounds-checked before the next is trusted.
fn udp_from(frame: &[u8], my_ip: Ip) -> Option<(Mac, Ip, u16, &[u8])> {
    let eth = net::parse_eth(frame)?;
    if eth.ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let ipv4 = net::parse_ipv4(eth.payload)?;
    if ipv4.protocol != PROTO_UDP || ipv4.dst != my_ip {
        return None;
    }
    let udp = net::parse_udp(ipv4.payload)?;
    Some((eth.src, ipv4.src, udp.src_port, udp.payload))
}
