//! The Vault: Rook's storage service, a ring-3 task that owns the disk.
//!
//! It holds an I/O Writ for the ATA bus and nothing else of the hardware,
//! drives the disk through the capability-gated I/O system calls, and
//! reads the Vault filesystem off it. This proves Rook's model: a device
//! driver and a filesystem as an ordinary user task, reaching the metal
//! only through a Writ the Keep granted.
//!
//! The Keep seeds its capability table at boot:
//!   handle 0  the ATA bus (an I/O Writ)

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use user::ata::Ata;
use vault::Vault;

const DISK: u64 = 0;

/// How long to wait between idle checks once the Vault is up.
const ROUND: u64 = 100;

user::program!(main);

fn main(_: u64) -> ! {
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
        }
        Some(Err(_)) => {
            let _ = user::log("disk found, but it holds no Vault filesystem");
        }
        None => {
            let _ = user::log("no disk on the ATA bus");
        }
    }

    loop {
        let _ = user::sleep(ROUND);
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
