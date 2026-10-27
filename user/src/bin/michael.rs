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
use user::abi::status;
use user::demo_identity::{CHECK_SECRET, ephemeral};

const REQUEST: u64 = 0;
const REPLY: u64 = 1;
const WARD: u64 = 2;

/// How long to wait between checks once the ward is running on its own.
const ROUND: u64 = 50;

user::program!(main);

fn main(_: u64) -> ! {
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
