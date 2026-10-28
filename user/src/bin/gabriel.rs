//! Gabriel, the messenger: the angel that carries messages between Rook
//! machines over the network. He runs in one of three roles, chosen by his
//! start argument:
//!
//!   * the default, over QEMU's user network: ARP the gateway (Ethernet),
//!     then a DHCP round-trip (IPv4 + UDP), proving the card drives a real
//!     link on its own;
//!   * `server` and `client`, for the two-node test, where two Keeps are
//!     wired to one Ethernet and run a full Drawbridge handshake over UDP,
//!     then exchange an application message through Courier — Rook's
//!     authenticated, post-quantum channel carried over a regular network.
//!
//! The Drawbridge handshake messages are larger than one Ethernet frame, so
//! they travel as *parcels*: each UDP datagram carries a one-byte kind, the
//! message's total length, and this fragment's offset, and the far side
//! reassembles them. Courier packets already fit one datagram, so each is a
//! single-fragment parcel. Everything is built and parsed with the `net`
//! crate under the Gatehouse rules and driven through the capability-gated
//! NE2000 driver in ring 3.
//!
//! The Keep seeds his capability table at boot:
//!   handle 0  an I/O Writ for the network card's ports

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use courier::Courier;
use drawbridge::{Identity, Initiator, Responder};
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

/// Fixed test identities for the two ends. A real caller would generate
/// these from entropy and know only the *public* half of its peer; here
/// both secrets are compiled in so the handshake is reproducible. Like the
/// rest of the crypto, these protect nothing real.
const CLIENT_SECRET: [u8; 32] = [0x11; 32];
const SERVER_SECRET: [u8; 32] = [0x22; 32];
/// The application message the client sends through Courier; the server
/// echoes it back.
const HAIL: &[u8] = b"Gabriel: a message from one Rook to another";

/// Parcel kinds: the three handshake messages, and a Courier packet.
const P_MSG1: u8 = 1;
const P_MSG2: u8 = 2;
const P_MSG3: u8 = 3;
const P_DATA: u8 = 4;
/// Message bytes carried per parcel, well under the Ethernet MTU.
const FRAG: usize = 1024;
/// Parcel header: kind, total length (u16), this fragment's offset (u16).
const PHDR: usize = 5;
/// The largest message reassembled from parcels (the handshake's msg2).
const MAX_PARCEL_MSG: usize = drawbridge::MSG2_LEN;

/// Poll attempts for a reply, each after a 10 ms sleep, so the card and the
/// network have time to answer without the task spinning or hanging.
const TRIES: u32 = 100;
/// The server polls this many rounds for the client before giving up, long
/// enough for the other Keep to boot and complete the exchange.
const SERVER_TRIES: u32 = 2000;
/// The client resends its ARP / handshake message this many rounds, polling
/// `WAIT` ticks between each, so an answer from a still-booting or busy peer
/// is not missed.
const ROUNDS: u32 = 30;
const WAIT: u32 = 10;
/// Ticks to await a handshake reply, longer because the peer computes
/// post-quantum crypto before answering.
const WAIT_HS: u32 = 100;
/// Rounds the client drives Courier waiting for the echo.
const COURIER_ROUNDS: u32 = 400;
/// Extra rounds a side pumps after it is done, to flush acknowledgements.
const GRACE: u32 = 200;

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

/// The server: answer the client's ARP, run the Drawbridge handshake as the
/// responder, then receive the client's Courier message and echo it. All of
/// it driven off one receive loop, since the client drives the exchange.
fn server(nic: &mut Ne2000, mac: &Mac) -> ! {
    let id = Identity::from_secret(&SERVER_SECRET);
    let client_pub = Identity::from_secret(&CLIENT_SECRET).public();
    let mut seed = [0u8; 32];
    if user::random(&mut seed).is_err() {
        let _ = user::log("gabriel: no entropy for the handshake");
        user::exit(1);
    }
    let _ = user::log("gabriel: server up, listening for a Rook on the wire");

    let mut re = Reassembler::new();
    let mut buf = [0u8; 1536];
    let mut responder: Option<Responder> = None;
    let mut msg2 = [0u8; drawbridge::MSG2_LEN];
    let mut courier: Option<Courier> = None;
    let mut peer: Option<(Mac, Ip)> = None;
    let mut served = false;
    let mut grace = 0u32;

    for _ in 0..SERVER_TRIES {
        while let Some(len) = nic.poll(&mut buf) {
            let frame = &buf[..len];
            answer_arp(nic, mac, frame);
            let Some((pmac, pip, sport, payload)) = udp_from(frame, SERVER_IP) else {
                continue;
            };
            if sport != PORT {
                continue;
            }
            peer = Some((pmac, pip));
            let Some((kind, m)) = re.feed(payload) else {
                continue;
            };
            match kind {
                P_MSG1 => {
                    if responder.is_none()
                        && courier.is_none()
                        && let Ok(m1) = <&[u8; drawbridge::MSG1_LEN]>::try_from(m)
                        && let Ok((r, m2)) = Responder::respond(&id, &seed, m1)
                    {
                        responder = Some(r);
                        msg2 = m2;
                    }
                    if responder.is_some() {
                        let _ = send_parcel(nic, mac, &pmac, SERVER_IP, pip, P_MSG2, &msg2);
                    }
                }
                P_MSG3 => {
                    if courier.is_none()
                        && let Ok(m3) = <&[u8; drawbridge::MSG3_LEN]>::try_from(m)
                        && let Some(r) = responder.take()
                    {
                        match r.finish(m3) {
                            Ok(done) if done.peer_identity == client_pub => {
                                let _ = user::log(
                                    "gabriel: server completed the Drawbridge handshake, authenticated the client",
                                );
                                let (c2s, s2c) = courier_keys(&done.saved_key);
                                courier = Some(Courier::new(s2c, c2s));
                            }
                            _ => {
                                let _ = user::log("gabriel: server rejected the client's identity");
                                user::exit(1);
                            }
                        }
                    }
                }
                P_DATA => {
                    if let Some(c) = courier.as_mut() {
                        let _ = c.on_packet(m);
                    }
                }
                _ => {}
            }
        }

        // Deliver the client's message, echo it, and keep the wire moving.
        if let (Some(c), Some((pmac, pip))) = (courier.as_mut(), peer) {
            let mut out = [0u8; courier::MAX_MSG];
            while let Some((_s, n)) = c.poll_deliver(&mut out) {
                if !served {
                    user::logln!(
                        "gabriel: server read a {}-byte Courier message from the client",
                        n
                    );
                    let _ = c.send(0, &out[..n]);
                    served = true;
                    let _ = user::log(
                        "gabriel: Courier carries application data between two Rook machines",
                    );
                }
            }
            drain_tx(nic, mac, &pmac, SERVER_IP, pip, c);
        }

        if served {
            let idle = courier.as_ref().is_some_and(Courier::idle);
            if idle || grace > GRACE {
                user::exit(0);
            }
            grace += 1;
        }
        let _ = user::sleep(1);
    }
    let _ = user::log("gabriel: server never finished with the client");
    user::exit(1)
}

/// The client: find the server with ARP, run the Drawbridge handshake as the
/// initiator (pinning the server's identity), then send an application
/// message through Courier and wait for the echo.
fn client(nic: &mut Ne2000, mac: &Mac) -> ! {
    let id = Identity::from_secret(&CLIENT_SECRET);
    let server_pub = Identity::from_secret(&SERVER_SECRET).public();

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

    let mut seed = [0u8; 32];
    if user::random(&mut seed).is_err() {
        let _ = user::log("gabriel: no entropy for the handshake");
        user::exit(1);
    }
    let (initiator, msg1) = Initiator::start(&id, &seed, Some(server_pub));

    // Send msg1 and reassemble the server's msg2, resending while it works.
    let mut re = Reassembler::new();
    let mut buf = [0u8; 1536];
    let mut msg2 = [0u8; drawbridge::MSG2_LEN];
    if !exchange(
        nic,
        mac,
        &server_mac,
        CLIENT_IP,
        SERVER_IP,
        P_MSG1,
        &msg1,
        P_MSG2,
        &mut re,
        &mut buf,
        &mut msg2,
    ) {
        let _ = user::log("gabriel: no handshake reply from the server");
        user::exit(1);
    }
    let done = match initiator.finish(&msg2) {
        Ok(done) => done,
        Err(_) => {
            let _ = user::log("gabriel: the server's handshake did not verify");
            user::exit(1);
        }
    };
    let _ = user::log(
        "gabriel: client completed the Drawbridge handshake, authenticated the server (X25519+ML-KEM-1024, Ed25519+ML-DSA-87)",
    );
    let _ = send_parcel(
        nic,
        mac,
        &server_mac,
        CLIENT_IP,
        SERVER_IP,
        P_MSG3,
        &done.msg3,
    );

    // The sealed channel is open; carry an application message over Courier.
    let (c2s, s2c) = courier_keys(&done.saved_key);
    let mut courier = Courier::new(c2s, s2c);
    if courier.send(0, HAIL).is_err() {
        let _ = user::log("gabriel: could not queue the Courier message");
        user::exit(1);
    }

    let mut out = [0u8; courier::MAX_MSG];
    let mut echoed = false;
    for round in 0..COURIER_ROUNDS {
        drain_tx(nic, mac, &server_mac, CLIENT_IP, SERVER_IP, &mut courier);
        while let Some(len) = nic.poll(&mut buf) {
            let frame = &buf[..len];
            if let Some((_, _, sport, payload)) = udp_from(frame, CLIENT_IP)
                && sport == PORT
                && let Some((kind, m)) = re.feed(payload)
                && kind == P_DATA
            {
                let _ = courier.on_packet(m);
            }
        }
        while let Some((_s, n)) = courier.poll_deliver(&mut out) {
            if &out[..n] == HAIL {
                echoed = true;
            }
        }
        if echoed && courier.idle() {
            break;
        }
        if round % 20 == 19 {
            courier.tick();
        }
        let _ = user::sleep(1);
    }

    if echoed {
        let _ = user::log("gabriel: Courier round-trip complete between two Rook machines");
        user::exit(0);
    }
    let _ = user::log("gabriel: no Courier echo from the server");
    user::exit(1)
}

/// Resend `send_msg` as `send_kind` parcels and reassemble a reply of
/// `want_kind` into `out`, round by round, until it arrives or the rounds
/// run out. `out.len()` is the exact length the reply must have.
#[allow(clippy::too_many_arguments)]
fn exchange(
    nic: &mut Ne2000,
    mac: &Mac,
    dst_mac: &Mac,
    my_ip: Ip,
    peer_ip: Ip,
    send_kind: u8,
    send_msg: &[u8],
    want_kind: u8,
    re: &mut Reassembler,
    buf: &mut [u8; 1536],
    out: &mut [u8],
) -> bool {
    for _ in 0..ROUNDS {
        let _ = send_parcel(nic, mac, dst_mac, my_ip, peer_ip, send_kind, send_msg);
        for _ in 0..WAIT_HS {
            while let Some(len) = nic.poll(buf) {
                let frame = &buf[..len];
                if let Some((_, _, sport, payload)) = udp_from(frame, my_ip)
                    && sport == PORT
                    && let Some((kind, m)) = re.feed(payload)
                    && kind == want_kind
                    && m.len() == out.len()
                {
                    out.copy_from_slice(m);
                    return true;
                }
            }
            let _ = user::sleep(1);
        }
    }
    false
}

/// Send every packet Courier has queued for the wire as a `P_DATA` parcel.
fn drain_tx(nic: &Ne2000, mac: &Mac, dst_mac: &Mac, my_ip: Ip, peer_ip: Ip, courier: &mut Courier) {
    let mut pkt = [0u8; courier::MAX_PACKET];
    while let Some(n) = courier.poll_transmit(&mut pkt) {
        let _ = send_parcel(nic, mac, dst_mac, my_ip, peer_ip, P_DATA, &pkt[..n]);
    }
}

/// Derive Courier's two directional keys from the handshake's saved key:
/// `(client->server, server->client)`. Both ends derive both and pick which
/// is theirs to send with by role.
fn courier_keys(saved: &drawbridge::SavedKey) -> ([u8; 32], [u8; 32]) {
    (courier_key(&saved.0, b"c2s"), courier_key(&saved.0, b"s2c"))
}

fn courier_key(saved: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut input = [0u8; 48];
    input[..32].copy_from_slice(saved);
    let n = label.len().min(16);
    input[32..32 + n].copy_from_slice(&label[..n]);
    let mut out = [0u8; 32];
    crypto::shake256(&input[..32 + n], &mut out);
    out
}

// --- Parcels: fragment and reassemble a message over datagrams ----------

/// Split `msg` into `P`-kind parcels that fit the MTU and send each as a UDP
/// datagram. Each parcel is `kind ‖ total ‖ offset ‖ fragment`.
#[allow(clippy::too_many_arguments)]
fn send_parcel(
    nic: &Ne2000,
    mac: &Mac,
    dst_mac: &Mac,
    my_ip: Ip,
    peer_ip: Ip,
    kind: u8,
    msg: &[u8],
) -> Option<()> {
    let total = msg.len();
    let mut off = 0;
    while off < total {
        let end = (off + FRAG).min(total);
        let mut payload = [0u8; PHDR + FRAG];
        payload[0] = kind;
        payload[1..3].copy_from_slice(&(total as u16).to_be_bytes());
        payload[3..5].copy_from_slice(&(off as u16).to_be_bytes());
        payload[PHDR..PHDR + (end - off)].copy_from_slice(&msg[off..end]);
        send_udp(
            nic,
            mac,
            dst_mac,
            my_ip,
            peer_ip,
            PORT,
            PORT,
            &payload[..PHDR + (end - off)],
        )?;
        off = end;
    }
    Some(())
}

/// Reassembles one message at a time from in-order parcels. The link under
/// it (QEMU's socket netdev) is a reliable ordered stream, so a message's
/// fragments arrive in order; a resent message simply restarts at offset 0.
struct Reassembler {
    kind: u8,
    total: usize,
    filled: usize,
    buf: [u8; MAX_PARCEL_MSG],
}

impl Reassembler {
    fn new() -> Reassembler {
        Reassembler {
            kind: 0,
            total: 0,
            filled: 0,
            buf: [0u8; MAX_PARCEL_MSG],
        }
    }

    /// Feed one parcel. Returns the kind and the whole message once its last
    /// fragment lands, or None while it is still arriving or on anything
    /// malformed.
    fn feed(&mut self, parcel: &[u8]) -> Option<(u8, &[u8])> {
        if parcel.len() < PHDR {
            return None;
        }
        let kind = parcel[0];
        let total = usize::from(u16::from_be_bytes([parcel[1], parcel[2]]));
        let off = usize::from(u16::from_be_bytes([parcel[3], parcel[4]]));
        let data = &parcel[PHDR..];
        if total == 0 || total > MAX_PARCEL_MSG || off > total || off + data.len() > total {
            return None;
        }
        if off == 0 {
            self.kind = kind;
            self.total = total;
            self.filled = 0;
        } else if kind != self.kind || off != self.filled {
            return None; // out of order on an ordered link: drop it
        }
        self.buf[off..off + data.len()].copy_from_slice(data);
        self.filled = off + data.len();
        if self.filled == self.total {
            Some((self.kind, &self.buf[..self.total]))
        } else {
            None
        }
    }
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

/// If `frame` is an ARP request for the server's address, answer it.
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
