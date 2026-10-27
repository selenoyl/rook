//! The Vault: Rook's storage service, a ring-3 task that owns the disk.
//!
//! It holds an I/O Writ for the ATA bus and nothing else of the hardware,
//! drives the disk through the capability-gated I/O system calls, and
//! reads the Vault filesystem off it. Then it serves files to other tasks
//! over an endpoint: a client sends a name, the Vault answers with the
//! file's length and bytes. This is Rook's model — a device driver and a
//! filesystem as an ordinary user task, reached only through Writs.
//!
//! The Keep seeds its capability table at boot:
//!   handle 0  the ATA bus (an I/O Writ)
//!   handle 1  receive file requests
//!   handle 2  send replies

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use drawbridge::{Identity, MSG1_LEN, MSG3_LEN, Responder, ResponderDone, Session};
use user::ata::Ata;
use user::demo_identity::{CHECK_SECRET, VAULT_SECRET, ephemeral};
use vault::{NAME_LEN, Vault};

const DISK: u64 = 0;
const REQUEST: u64 = 1;
const REPLY: u64 = 2;

/// The sealed reply: status byte, length byte, then up to this many bytes
/// of file. 64 total keeps it to two IPC messages plus a tag.
const REPLY_BODY: usize = 64;
const REPLY_DATA: usize = REPLY_BODY - 2;

user::program!(main);

fn main(_: u64) -> ! {
    serve(mount())
}

/// Bring up the disk and mount the filesystem, logging what's there.
fn mount() -> Option<Vault<Ata>> {
    let mut ata = match Ata::open(DISK) {
        Some(ata) => ata,
        None => {
            let _ = user::log("no disk on the ATA bus");
            return None;
        }
    };
    disk_self_test(&mut ata);
    match Vault::open(ata) {
        Ok(mut fs) => {
            user::logln!(
                "disk {} blocks, filesystem has {} file(s), {} blocks free",
                fs.blocks(),
                fs.file_count(),
                fs.free_blocks()
            );
            fs.for_each(|e| {
                user::logln!("  {} ({} bytes)", Name(e.name()), e.len);
            });
            report_motd(&mut fs);
            Some(fs)
        }
        Err(_) => {
            let _ = user::log("disk found, but it holds no Vault filesystem");
            None
        }
    }
}

/// Prove the ATA write path works: write a known pattern to a scratch
/// block past the filesystem and read it back. The block is fixed, so this
/// is the same every boot and never disturbs the filesystem's blocks.
fn disk_self_test(ata: &mut Ata) {
    use vault::BlockDevice;
    let scratch = ata.blocks().saturating_sub(1);
    if scratch == 0 {
        return;
    }
    let mut pattern = [0u8; vault::BLOCK];
    for (i, b) in pattern.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xa5;
    }
    let mut back = [0u8; vault::BLOCK];
    let ok = ata.write_block(scratch, &pattern).is_ok()
        && ata.read_block(scratch, &mut back).is_ok()
        && back == pattern;
    let _ = user::log(if ok {
        "disk: write and read-back verified"
    } else {
        "disk: write/read-back FAILED"
    });
}

/// Open a Drawbridge session with the client, then answer sealed file
/// requests over it: every request and reply is encrypted and
/// authenticated end to end, so even the bytes on the endpoints are
/// confidential. A request is a sealed 16-byte name; a reply is a sealed
/// `(status, length, data)`.
fn serve(mut fs: Option<Vault<Ata>>) -> ! {
    let me = Identity::from_secret(&VAULT_SECRET);
    let client = crypto::public_key(&CHECK_SECRET);
    let mut session = match handshake(&me, client) {
        Some(session) => {
            let _ = user::log("drawbridge: secure channel open with the client");
            session
        }
        None => {
            let _ = user::log("drawbridge: could not open a channel with the client");
            idle();
        }
    };

    loop {
        let mut framed = [0u8; NAME_LEN + 16];
        if user::recv_blob(REQUEST, &mut framed).is_err() {
            continue;
        }
        let mut name = [0u8; NAME_LEN];
        let mut tag = [0u8; 16];
        name.copy_from_slice(&framed[..NAME_LEN]);
        tag.copy_from_slice(&framed[NAME_LEN..]);
        if session.open(&mut name, &tag).is_err() {
            continue;
        }

        let used = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let mut reply = [0u8; REPLY_BODY];
        let mut body = [0u8; REPLY_DATA];
        match fs
            .as_mut()
            .and_then(|v| v.read(&name[..used], &mut body).ok())
        {
            Some(len) if len <= REPLY_DATA => {
                reply[0] = 0;
                reply[1] = len as u8;
                reply[2..2 + len].copy_from_slice(&body[..len]);
            }
            _ => reply[0] = 1,
        }
        let Ok(rtag) = session.seal(&mut reply) else {
            idle();
        };
        let mut out = [0u8; REPLY_BODY + 16];
        out[..REPLY_BODY].copy_from_slice(&reply);
        out[REPLY_BODY..].copy_from_slice(&rtag);
        let _ = user::send_blob(REPLY, &out);
    }
}

/// Act as the Drawbridge responder for the client's handshake, pinning its
/// identity.
fn handshake(me: &Identity, client: [u8; 32]) -> Option<Session> {
    let mut msg1 = [0u8; MSG1_LEN];
    user::recv_blob(REQUEST, &mut msg1).ok()?;
    let (responder, msg2) = Responder::respond(me, &ephemeral(b'V'), &msg1).ok()?;
    user::send_blob(REPLY, &msg2).ok()?;
    let mut msg3 = [0u8; MSG3_LEN];
    user::recv_blob(REQUEST, &mut msg3).ok()?;
    let ResponderDone {
        session,
        peer_identity,
    } = responder.finish(&msg3).ok()?;
    (peer_identity == client).then_some(session)
}

/// Nothing more to serve: sleep forever.
fn idle() -> ! {
    loop {
        let _ = user::sleep(1000);
    }
}

/// Read the "motd" file and log it, to show a real read off the disk.
fn report_motd(fs: &mut Vault<Ata>) {
    let mut buf = [0u8; 256];
    match fs.read(b"motd", &mut buf) {
        Ok(len) => {
            let len = core::cmp::min(len, buf.len());
            match core::str::from_utf8(&buf[..len]) {
                Ok(text) => {
                    user::logln!("motd: {}", text.trim_end());
                }
                Err(_) => {
                    let _ = user::log("motd: (not text)");
                }
            }
        }
        Err(_) => {
            let _ = user::log("motd: not found");
        }
    }
}

/// A file name for logging: printable bytes, a dot for the rest.
struct Name<'a>(&'a [u8]);

impl core::fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for &b in self.0 {
            let c = if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            };
            write!(f, "{c}")?;
        }
        Ok(())
    }
}
