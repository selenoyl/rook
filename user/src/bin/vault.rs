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

use user::ata::Ata;
use vault::{NAME_LEN, Vault};

const DISK: u64 = 0;
const REQUEST: u64 = 1;
const REPLY: u64 = 2;

/// The largest file the Vault serves in one reply, bounding its buffer.
const MAX_FILE: usize = 512;

user::program!(main);

fn main(_: u64) -> ! {
    serve(mount())
}

/// Bring up the disk and mount the filesystem, logging what's there.
fn mount() -> Option<Vault<Ata>> {
    match Ata::open(DISK).map(Vault::open) {
        Some(Ok(mut fs)) => {
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
        Some(Err(_)) => {
            let _ = user::log("disk found, but it holds no Vault filesystem");
            None
        }
        None => {
            let _ = user::log("no disk on the ATA bus");
            None
        }
    }
}

/// Answer file requests forever. Each request is a name; the reply is a
/// header message `(status, length)` — status 0 for a hit, 1 for a miss —
/// and, on a hit, the file's bytes. Every request gets an answer, even
/// without a filesystem, so a client never blocks waiting for one.
fn serve(mut fs: Option<Vault<Ata>>) -> ! {
    let _ = user::log("serving files over the request endpoint");
    let mut file = [0u8; MAX_FILE];
    loop {
        let mut name = [0u8; NAME_LEN];
        if user::recv_blob(REQUEST, &mut name).is_err() {
            continue;
        }
        let used = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let served = fs
            .as_mut()
            .and_then(|v| v.read(&name[..used], &mut file).ok());
        match served {
            Some(len) => {
                let len = core::cmp::min(len, file.len());
                let _ = user::send(REPLY, [0, len as u64, 0, 0]);
                let _ = user::send_blob(REPLY, &file[..len]);
            }
            None => {
                let _ = user::send(REPLY, [1, 0, 0, 0]);
            }
        }
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
