//! The boot log, written to the serial port.

#![forbid(unsafe_code)]

use core::fmt::{self, Write};

struct Serial;

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::arch::serial::write_str(s);
        Ok(())
    }
}

/// Print one line to the boot log.
macro_rules! kprintln {
    ($($arg:tt)*) => {
        $crate::log::print_line(format_args!($($arg)*))
    };
}

/// Interrupts stay off while a line is written, so a task switch can't
/// splice another task's line into the middle of it.
pub fn print_line(args: fmt::Arguments) {
    crate::arch::cpu::without_interrupts(|| {
        let _ = Serial.write_fmt(args);
        let _ = Serial.write_str("\n");
    });
}
