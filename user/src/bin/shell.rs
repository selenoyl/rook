//! A tiny interactive shell: Rook's first way to talk back. It reads the
//! keyboard through a PS/2 driver, echoes to the VGA console, and runs a
//! handful of commands that exercise the Keep — the cryptography, a
//! Drawbridge handshake, a Great Seal, the random source. Everything it
//! needs is device-free beyond the keyboard and the screen, so it is what
//! the GRUB ISO boots into on a plain PC or VM.
//!
//! The Keep seeds his capability table at boot:
//!   handle 0  an I/O Writ for the PS/2 keyboard ports

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use seal::{Approval, Kind, Manifest, RoundTable, SeatKeys, image_hash, verify_image};
use user::ps2::Keyboard;

/// Handle of the I/O Writ for the keyboard.
const KEYBOARD: u64 = 0;

const WELCOME: &str = "Rook - the Keep stands. You are at the console.\n\
                       Type 'help' for commands.\n\n";

user::program!(main);

fn main(_: u64) -> ! {
    let mut kbd = Keyboard::new(KEYBOARD);
    user::print("\x0c"); // clear the boot banner
    user::print(WELCOME);
    prompt();

    let mut line = [0u8; 120];
    let mut len = 0usize;
    loop {
        let Some(ch) = kbd.poll() else {
            let _ = user::sleep(1); // nothing waiting; yield the CPU
            continue;
        };
        match ch {
            b'\n' => {
                user::print("\n");
                run(&line[..len]);
                len = 0;
                prompt();
            }
            0x08 => {
                if len > 0 {
                    len -= 1;
                    user::print("\x08"); // erase the last character
                }
            }
            0x20..=0x7e if len < line.len() => {
                line[len] = ch;
                len += 1;
                echo(ch);
            }
            _ => {}
        }
    }
}

fn prompt() {
    user::print("rook> ");
}

fn echo(ch: u8) {
    let one = [ch];
    user::print(core::str::from_utf8(&one).unwrap_or(""));
}

/// Run one command line.
fn run(line_bytes: &[u8]) {
    let line = core::str::from_utf8(line_bytes).unwrap_or("").trim();
    if line.is_empty() {
        return;
    }
    let (cmd, rest) = match line.find(' ') {
        Some(i) => (&line[..i], line[i + 1..].trim_start()),
        None => (line, ""),
    };
    match cmd {
        "help" => help(),
        "about" => user::scrln!(
            "Rook: a from-scratch, security-first microkernel OS. \
             No external crates; the Keep is under 10,000 lines of Rust."
        ),
        "crypto" => user::scrln!(
            "crypto: {}",
            yes_no(
                crypto::self_test(),
                "SHA-2/3, ChaCha20-Poly1305, X25519, Ed25519, ML-KEM-1024, ML-DSA-87, SLH-DSA verified",
            )
        ),
        "drawbridge" => user::scrln!(
            "drawbridge: {}",
            yes_no(
                drawbridge::self_test(),
                "post-quantum handshake and sealed channel verified",
            )
        ),
        "seal" => seal_demo(),
        "rand" => rand_demo(),
        "ticks" => user::scrln!("ticks since boot: {} (100 per second)", user::now()),
        "echo" => user::scrln!("{rest}"),
        "clear" => user::print("\x0c"),
        _ => user::scrln!("unknown command: {cmd}  (try 'help')"),
    }
}

fn yes_no(ok: bool, good: &'static str) -> &'static str {
    if ok { good } else { "a check FAILED" }
}

fn help() {
    user::print(
        "commands:\n\
         \x20 help        this list\n\
         \x20 about       what Rook is\n\
         \x20 crypto      run the cryptography self-check\n\
         \x20 drawbridge  run a Drawbridge handshake\n\
         \x20 seal        verify a Great Seal (a Round Table's k-of-n)\n\
         \x20 rand        draw random bytes from the Keep\n\
         \x20 ticks       uptime, in timer ticks\n\
         \x20 echo TEXT   print TEXT back\n\
         \x20 clear       clear the screen\n",
    );
}

/// Build a two-seat Round Table, sign an image manifest with one seat, and
/// verify the Great Seal — the same check Raphael makes before an update.
fn seal_demo() {
    let one = SeatKeys::from_secret(&[0xc1; 32]);
    let two = SeatKeys::from_secret(&[0xc2; 32]);
    let Some(table) = RoundTable::new(1, 1, &[one.public(), two.public()]) else {
        user::scrln!("seal: could not build the Round Table");
        return;
    };
    let hash = image_hash(b"rook console demo image");
    let manifest = Manifest {
        kind: Kind::Image,
        payload_hash: hash,
        version: 1,
        table_version: 1,
        expiry: u64::MAX,
    };
    let sig = one.approve(&manifest);
    let approvals = [Approval { seat: 0, sig: &sig }];
    let ok = verify_image(&table, &manifest, &hash, &approvals, user::now(), 0).is_ok();
    user::scrln!(
        "seal: {}",
        yes_no(ok, "the Round Table's seal verifies (Ed25519 + SLH-DSA)")
    );
}

/// Draw sixteen random bytes from the Keep's CSPRNG and show them.
fn rand_demo() {
    let mut buf = [0u8; 16];
    if user::random(&mut buf).is_err() {
        user::scrln!("rand: the Keep refused");
        return;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 32];
    for (i, &b) in buf.iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 0x0f)];
    }
    user::scrln!("rand: {}", core::str::from_utf8(&out).unwrap_or(""));
}
