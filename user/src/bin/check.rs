//! check: the Keep's user-mode test program, run at every boot.
//!
//! Started with `abi::check::CALLS`, it checks that the system calls work,
//! that the Keep refuses bad arguments and Writs it wasn't given, and that
//! it can trade a message with the supervisor; then it exits with 0, or
//! with 1 naming the check that failed. Started with `abi::check::CRASH`,
//! it crashes on purpose: the Keep must end it and carry on.
//!
//! The Keep seeds its capability table at boot:
//!   handle 0  send requests to the supervisor
//!   handle 1  receive replies from it

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use drawbridge::{Identity, Initiator, InitiatorDone, MSG2_LEN};
use user::Error;
use user::abi::{MAX_LOG, check};
use user::demo_identity::{MICHAEL_SECRET, ephemeral};

const TO_SUPERVISOR: u64 = 0;
const FROM_SUPERVISOR: u64 = 1;
const TO_VAULT: u64 = 2;
const FROM_VAULT: u64 = 3;
/// A handle the Keep granted no Writ, for the refusal check.
const ABSENT_HANDLE: u64 = 7;

/// Where the Keep's image starts: memory no user task may read.
const KEEP_IMAGE: u64 = 0xFFFF_FFFF_8000_0000;
const MESSAGE: &str = "running in ring 3";

user::program!(main);

fn main(mode: u64) -> ! {
    if mode == check::CRASH {
        let _ = user::log("crashing on purpose");
        user::sys::crash();
    }
    match run_checks() {
        Ok(()) => {
            let _ = user::log("all checks passed");
            user::exit(0)
        }
        Err(failed) => {
            let _ = user::log("a check FAILED:");
            let _ = user::log(failed);
            user::exit(1)
        }
    }
}

fn expect(ok: bool, name: &'static str) -> Result<(), &'static str> {
    if ok { Ok(()) } else { Err(name) }
}

fn refused<T>(result: Result<T, user::Refused>, error: Error) -> bool {
    matches!(result, Err(Some(e)) if e == error)
}

/// The most times the preemption loop spins before giving up. A timer
/// tick is 10 ms and each turn makes a quick call, so a tick arrives in
/// far fewer than this; reaching it means the timer never preempted.
const SPIN_LIMIT: u64 = 100_000_000;

fn run_checks() -> Result<(), &'static str> {
    expect(user::sys::privilege_level() == 3, "privilege level 3")?;
    expect(user::log(MESSAGE).is_ok(), "log")?;

    let before = user::now();
    expect(user::sleep(3).is_ok(), "sleep")?;
    expect(
        user::now() >= before.saturating_add(3),
        "sleep lasts as long as asked",
    )?;
    expect(user::yield_now().is_ok(), "yield")?;

    // Preemption: spin in ring 3 until the clock advances, which only
    // happens if the timer interrupts this loop.
    let start = user::now();
    let mut spins: u64 = 0;
    while user::now() == start {
        spins = spins.saturating_add(1);
        if spins >= SPIN_LIMIT {
            return Err("the timer never preempted the task");
        }
    }

    // Bad arguments must come back as errors.
    let message = MESSAGE.as_ptr() as u64;
    expect(
        refused(user::log_raw(0, 16), Error::BadAddress),
        "log from address 0 is refused",
    )?;
    expect(
        refused(user::log_raw(KEEP_IMAGE, 16), Error::BadAddress),
        "log from the Keep's memory is refused",
    )?;
    expect(
        refused(user::log_raw(u64::MAX - 4, 16), Error::BadAddress),
        "log from a range that wraps around is refused",
    )?;
    expect(
        refused(user::log_raw(message, MAX_LOG + 1), Error::TooLong),
        "an overlong log is refused",
    )?;
    expect(
        refused(user::sleep(u64::MAX), Error::BadArgument),
        "an overlong sleep is refused",
    )?;
    expect(
        refused(user::call_raw(99, [0; 4]), Error::NoSuchCall),
        "an unknown call is refused",
    )?;

    // Entropy: the Keep hands out random bytes, and two draws differ and
    // aren't all zero.
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    expect(
        user::random(&mut first).is_ok() && user::random(&mut second).is_ok(),
        "drawing randomness from the Keep",
    )?;
    expect(
        first != second && first != [0u8; 32],
        "the randomness looks random",
    )?;
    let _ = user::log("entropy: random bytes drawn from the Keep, and they differ");

    // Cryptography: every primitive against its official test vector,
    // computed here in ring 3.
    expect(crypto::self_test(), "cryptography known-answer vectors")?;
    let _ = user::log(
        "crypto: SHA-2/3, ChaCha20-Poly1305, X25519, Ed25519, ML-KEM-1024, ML-DSA-87, SLH-DSA verified",
    );

    // Drawbridge: a full handshake and sealed exchange, in ring 3.
    expect(drawbridge::self_test(), "Drawbridge handshake and session")?;
    let _ = user::log("drawbridge: authenticated session established and verified");

    // Writs: a task may use only the ones the Keep gave it.
    expect(
        refused(user::recv(TO_SUPERVISOR), Error::BadCapability),
        "receiving on a send-only Writ is refused",
    )?;
    expect(
        refused(user::send(ABSENT_HANDLE, [0; 4]), Error::BadCapability),
        "using a handle with no Writ is refused",
    )?;
    // The I/O capability is enforced: this task holds no I/O Writ, so it
    // cannot touch a device port — the ATA command port here.
    expect(
        refused(user::io_in(TO_SUPERVISOR, 0x1f7), Error::BadCapability),
        "port I/O without an I/O Writ is refused",
    )?;
    expect(
        refused(user::io_out(ABSENT_HANDLE, 0x1f7, 0), Error::BadCapability),
        "writing a device port without an I/O Writ is refused",
    )?;

    // Message passing, for real: run a Drawbridge handshake with the
    // supervisor over the two endpoints, then trade a sealed message.
    drawbridge_over_ipc()?;
    let _ = user::log("drawbridge over IPC: sealed channel with the supervisor");

    // The storage service: open a Drawbridge session with the Vault and
    // read a file over it — encrypted and authenticated end to end.
    vault_request()?;
    let _ = user::log("vault: read motd over a sealed Drawbridge channel, verified");
    Ok(())
}

/// Open a Drawbridge session with the Vault, then ask it for the "motd"
/// file over that sealed channel and confirm the bytes — a user-space
/// storage service reached through a capability and an authenticated,
/// post-quantum-hybrid session.
fn vault_request() -> Result<(), &'static str> {
    let me = Identity::from_secret(&user::demo_identity::CHECK_SECRET);
    let vault = crypto::public_key(&user::demo_identity::VAULT_SECRET);

    let (initiator, msg1) = Initiator::start(&me, &ephemeral(b'v'), Some(vault));
    expect(
        user::send_blob(TO_VAULT, &msg1).is_ok(),
        "opening a channel to the vault",
    )?;
    let mut msg2 = [0u8; MSG2_LEN];
    expect(
        user::recv_blob(FROM_VAULT, &mut msg2).is_ok(),
        "the vault's handshake reply",
    )?;
    let InitiatorDone {
        msg3,
        mut session,
        peer_identity,
    } = initiator.finish(&msg2).map_err(|_| "the vault handshake")?;
    expect(peer_identity == vault, "the vault's identity")?;
    expect(
        user::send_blob(TO_VAULT, &msg3).is_ok(),
        "finishing the vault handshake",
    )?;

    // Sealed request: the 16-byte name, then its tag.
    let mut name = [0u8; 16];
    name[..4].copy_from_slice(b"motd");
    let tag = session.seal(&mut name).map_err(|_| "sealing the request")?;
    let mut request = [0u8; 32];
    request[..16].copy_from_slice(&name);
    request[16..].copy_from_slice(&tag);
    expect(
        user::send_blob(TO_VAULT, &request).is_ok(),
        "sending the sealed request",
    )?;

    // Sealed reply: 64-byte body (status, length, data) then its tag.
    let mut incoming = [0u8; 80];
    expect(
        user::recv_blob(FROM_VAULT, &mut incoming).is_ok(),
        "the vault's sealed reply",
    )?;
    let mut reply = [0u8; 64];
    let mut rtag = [0u8; 16];
    reply.copy_from_slice(&incoming[..64]);
    rtag.copy_from_slice(&incoming[64..]);
    session
        .open(&mut reply, &rtag)
        .map_err(|_| "opening the sealed reply")?;
    expect(reply[0] == 0, "the vault found the file")?;
    let len = reply[1] as usize;
    expect(
        len <= 62 && &reply[2..2 + len] == b"The Keep holds. Rook stands watch.\n",
        "the vault served the right bytes",
    )?;
    Ok(())
}

/// The check task is the Drawbridge initiator. It sends the handshake over
/// `TO_SUPERVISOR` and hears the answer over `FROM_SUPERVISOR`, pins the
/// supervisor's identity, then seals a report and opens the sealed reply —
/// all over the Keep's real message passing, fragmented by `send_blob`.
fn drawbridge_over_ipc() -> Result<(), &'static str> {
    let me = Identity::from_secret(&user::demo_identity::CHECK_SECRET);
    let supervisor = crypto::public_key(&MICHAEL_SECRET);

    let (initiator, msg1) = Initiator::start(&me, &ephemeral(b'C'), Some(supervisor));
    expect(
        user::send_blob(TO_SUPERVISOR, &msg1).is_ok(),
        "sending the handshake's first message",
    )?;
    let mut msg2 = [0u8; MSG2_LEN];
    expect(
        user::recv_blob(FROM_SUPERVISOR, &mut msg2).is_ok(),
        "receiving the handshake's second message",
    )?;
    let InitiatorDone {
        msg3,
        mut session,
        peer_identity,
    } = initiator
        .finish(&msg2)
        .map_err(|_| "completing the handshake")?;
    expect(peer_identity == supervisor, "the supervisor's identity")?;
    expect(
        user::send_blob(TO_SUPERVISOR, &msg3).is_ok(),
        "sending the handshake's third message",
    )?;

    // A sealed report to the supervisor (32 bytes of plaintext).
    let mut report: [u8; 32] = *b"reporting for duty, supervisor!!";
    let tag = session
        .seal(&mut report)
        .map_err(|_| "sealing the report")?;
    expect(
        user::send_blob(TO_SUPERVISOR, &framed(&report, &tag)).is_ok(),
        "sending the sealed report",
    )?;

    // The supervisor's sealed reply must open and read as expected.
    let mut incoming = [0u8; 48];
    expect(
        user::recv_blob(FROM_SUPERVISOR, &mut incoming).is_ok(),
        "receiving the sealed reply",
    )?;
    let (mut reply, tag) = unframe(&incoming);
    session
        .open(&mut reply, &tag)
        .map_err(|_| "opening the sealed reply")?;
    expect(
        &reply == b"welcome; you have the watch now.",
        "the sealed reply",
    )?;
    Ok(())
}

/// Pack a 32-byte ciphertext and its 16-byte tag into one 48-byte frame.
fn framed(ciphertext: &[u8; 32], tag: &[u8; 16]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..32].copy_from_slice(ciphertext);
    out[32..].copy_from_slice(tag);
    out
}

/// Split a 48-byte frame back into ciphertext and tag.
fn unframe(frame: &[u8; 48]) -> ([u8; 32], [u8; 16]) {
    let mut ciphertext = [0u8; 32];
    let mut tag = [0u8; 16];
    ciphertext.copy_from_slice(&frame[..32]);
    tag.copy_from_slice(&frame[32..]);
    (ciphertext, tag)
}
