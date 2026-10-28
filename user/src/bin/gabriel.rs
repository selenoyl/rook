//! Gabriel, the messenger: the angel that carries messages between Rook
//! machines over the network. For now he brings up the network card and
//! proves it carries real traffic — he ARPs the gateway and waits for its
//! reply. Carrying Courier and Drawbridge over the link comes next.
//!
//! The Keep seeds his capability table at boot:
//!   handle 0  an I/O Writ for the network card's ports

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use net::{ARP_LEN, ARP_REPLY, ARP_REQUEST, Arp, BROADCAST, ETHERTYPE_ARP, Ip, Mac};
use user::ne2000::Ne2000;

/// Handle of the I/O Writ covering the network card's ports.
const NIC: u64 = 0;

/// QEMU's user network hands the guest 10.0.2.15 and a gateway at 10.0.2.2.
const MY_IP: Ip = [10, 0, 2, 15];
const GATEWAY: Ip = [10, 0, 2, 2];

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

    match resolve_gateway(&mut nic, &mac) {
        Some(gw) => {
            user::logln!(
                "gabriel: ARP reply, gateway 10.0.2.2 is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                gw[0],
                gw[1],
                gw[2],
                gw[3],
                gw[4],
                gw[5]
            );
            let _ = user::log("gabriel: network card sends and receives on a real link");
            user::exit(0)
        }
        None => {
            let _ = user::log("gabriel: no ARP reply from the gateway");
            user::exit(1)
        }
    }
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
