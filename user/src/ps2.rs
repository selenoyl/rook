//! A small PS/2 keyboard reader, in ring 3.
//!
//! Like the ATA and NE2000 drivers, it reaches the hardware only through an
//! I/O Writ — here the PS/2 controller's status port (0x64) and data port
//! (0x60) — and it only ever reads. It decodes scancode set 1, what the
//! controller sends by default, into ASCII for the keys a shell needs, and
//! tracks the Shift keys. It polls; there is no keyboard interrupt wired up.

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
/// Status bit 0: a byte is waiting in the controller's output buffer.
const OUTPUT_FULL: u8 = 0x01;

/// A PS/2 keyboard, holding its I/O Writ handle and the Shift state.
pub struct Keyboard {
    io: u64,
    shift: bool,
}

impl Keyboard {
    /// A keyboard reached through the I/O Writ at `io` (covering 0x60 and
    /// 0x64).
    pub fn new(io: u64) -> Keyboard {
        Keyboard { io, shift: false }
    }

    /// Poll for one typed character, or `None` if no key is waiting — or the
    /// key was a modifier or a release, which are consumed silently.
    pub fn poll(&mut self) -> Option<u8> {
        let status = crate::io_in(self.io, STATUS).ok()?;
        if status & OUTPUT_FULL == 0 {
            return None;
        }
        let code = crate::io_in(self.io, DATA).ok()?;
        match code {
            0x2a | 0x36 => {
                self.shift = true;
                None
            }
            0xaa | 0xb6 => {
                self.shift = false;
                None
            }
            // Any other key release (high bit set) is ignored.
            c if c & 0x80 != 0 => None,
            c => ascii(c, self.shift),
        }
    }
}

/// Scancode set 1 make-code to ASCII, for the keys a shell uses. A zero
/// entry is a key with no character (a modifier, Esc, Tab), which is
/// dropped. `\n` is Enter and 0x08 is Backspace.
fn ascii(code: u8, shift: bool) -> Option<u8> {
    #[rustfmt::skip]
    const LOWER: [u8; 58] = [
        0, 0, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
        b'9', b'0', b'-', b'=', 0x08, 0, b'q', b'w', b'e', b'r',
        b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n', 0,
        b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';',
        b'\'', b'`', 0, b'\\', b'z', b'x', b'c', b'v', b'b', b'n',
        b'm', b',', b'.', b'/', 0, b'*', 0, b' ',
    ];
    #[rustfmt::skip]
    const UPPER: [u8; 58] = [
        0, 0, b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*',
        b'(', b')', b'_', b'+', 0x08, 0, b'Q', b'W', b'E', b'R',
        b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', b'\n', 0,
        b'A', b'S', b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':',
        b'"', b'~', 0, b'|', b'Z', b'X', b'C', b'V', b'B', b'N',
        b'M', b'<', b'>', b'?', 0, b'*', 0, b' ',
    ];
    let table = if shift { &UPPER } else { &LOWER };
    match table.get(usize::from(code)) {
        Some(&0) | None => None,
        Some(&c) => Some(c),
    }
}
