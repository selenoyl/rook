//! Michael, the supervisor: the first task the Keep starts. In time he
//! launches, watches, restarts and stops every other angel. For now he
//! opens a Drawbridge session with the task he watches — authenticating it
//! over the Keep's message passing and trading a sealed message — then
//! keeps watch through a Task Writ until it finishes.
//!
//! The Keep seeds his capability table at boot:
//!   handle 0  receive requests from the task he watches
//!   handle 1  send replies to it
//!   handle 2  watch it (a Task Writ)

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use drawbridge::{Identity, MSG1_LEN, MSG3_LEN, Responder, ResponderDone};
use user::abi::{check, michael, status};
use user::demo_identity::{CHECK_SECRET, ephemeral};

const REQUEST: u64 = 0;
const REPLY: u64 = 1;
const WARD: u64 = 2;

/// How long to wait between checks once the ward is running on its own.
const ROUND: u64 = 50;

user::program!(main);

fn main(arg: u64) -> ! {
    if arg == michael::HEAL {
        heal_ward();
    }
    let _ = user::log("supervisor, standing watch");

    // Open a secure channel with the ward: a Drawbridge handshake and a
    // sealed exchange, carried over the two endpoints the Keep granted.
    if serve_drawbridge().is_none() {
        let _ = user::log("drawbridge: could not open a session with the ward");
    }

    // Keep watch until the ward finishes, then report how it ended.
    loop {
        match user::watch(WARD) {
            Ok(s) if status::kind(s) == status::EXITED => {
                user::logln!("the task I watch exited with {}", status::code(s));
                break;
            }
            Ok(s) if status::kind(s) == status::FAULTED => {
                let _ = user::log("the task I watch faulted; it has been ended");
                break;
            }
            _ => {
                let _ = user::sleep(ROUND);
            }
        }
    }

    loop {
        let _ = user::sleep(ROUND * 20);
    }
}

/// Heal mode: watch a ward through a Task Writ and, when it falls, restart
/// it through a Restart Writ until it comes back. The Keep grants handle 0
/// to watch the ward and handle 1 to restart it. Exits 0 once the ward has
/// recovered — the supervisor healed a fallen angel.
fn heal_ward() -> ! {
    const WARD: u64 = 0;
    const RESTART: u64 = 1;
    let _ = user::log("supervisor, watching over an angel to heal it");
    let mut restarts: u64 = 0;
    loop {
        match user::watch(WARD) {
            Ok(s) if status::kind(s) == status::FAULTED => {
                restarts = restarts.saturating_add(1);
                user::logln!("an angel has fallen; restarting it (restart {restarts})");
                // Bring it up a generation on, so it starts healed.
                if user::restart(RESTART, check::RESTART | (restarts << 8)).is_err() {
                    let _ = user::log("could not restart the angel");
                    user::exit(1);
                }
            }
            Ok(s) if status::kind(s) == status::EXITED => {
                user::logln!("the angel recovered and exited with {}", status::code(s));
                let _ = user::log("michael: a fallen angel was restarted and stands again");
                user::exit(0);
            }
            _ => {
                let _ = user::sleep(ROUND);
            }
        }
    }
}

/// Act as the Drawbridge responder: answer the ward's handshake, pin its
/// identity, open its sealed report, and send a sealed reply. Returns the
/// ward's badge on success, or None if any step is refused.
fn serve_drawbridge() -> Option<u64> {
    let me = Identity::from_secret(&user::demo_identity::MICHAEL_SECRET);
    let ward = Identity::from_secret(&CHECK_SECRET).public();

    let mut msg1 = [0u8; MSG1_LEN];
    let badge = user::recv_blob(REQUEST, &mut msg1).ok()?;
    let (responder, msg2) = Responder::respond(&me, &ephemeral(b'M'), &msg1).ok()?;
    user::send_blob(REPLY, &msg2).ok()?;

    let mut msg3 = [0u8; MSG3_LEN];
    user::recv_blob(REQUEST, &mut msg3).ok()?;
    let ResponderDone {
        mut session,
        peer_identity,
        ..
    } = responder.finish(&msg3).ok()?;
    // Only the task we were paired with may pass.
    if peer_identity != ward {
        return None;
    }

    // Open the ward's sealed report (ciphertext then tag, 48 bytes).
    let mut incoming = [0u8; 48];
    user::recv_blob(REQUEST, &mut incoming).ok()?;
    let mut report = [0u8; 32];
    let mut tag = [0u8; 16];
    report.copy_from_slice(&incoming[..32]);
    tag.copy_from_slice(&incoming[32..]);
    session.open(&mut report, &tag).ok()?;
    user::logln!("drawbridge: authenticated task {badge}, opened its sealed report");

    // The ward is now blocked waiting for our reply, so it is alive: a good
    // moment to prove the Task Writ still sees it.
    match user::watch(WARD) {
        Ok(s) if status::kind(s) == status::ALIVE => {
            user::logln!("task {badge} is alive and well");
        }
        _ => {
            user::logln!("task {badge} is already gone");
        }
    }

    // Seal a reply back.
    let mut reply: [u8; 32] = *b"welcome; you have the watch now.";
    let rtag = session.seal(&mut reply).ok()?;
    let mut outgoing = [0u8; 48];
    outgoing[..32].copy_from_slice(&reply);
    outgoing[32..].copy_from_slice(&rtag);
    user::send_blob(REPLY, &outgoing).ok()?;

    Some(badge)
}
