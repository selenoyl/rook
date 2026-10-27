//! State shared between tasks and interrupt handlers.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// A value that one piece of code at a time may use, with interrupts off
/// while it does, so an interrupt handler never finds it half-changed.
pub struct Exclusive<T> {
    busy: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the value is only reached through `with`, which hands it to
// one caller at a time (the busy flag), so sharing an Exclusive between
// tasks and interrupt handlers is sound as long as the value itself may
// move between them, which `T: Send` says.
unsafe impl<T: Send> Sync for Exclusive<T> {}

impl<T> Exclusive<T> {
    pub const fn new(value: T) -> Exclusive<T> {
        Exclusive {
            busy: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Run `f` on the value, with interrupts off. Returns None without
    /// running `f` if the value is already in use, which only happens if
    /// `f`, or a trap inside it, comes back here.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let were_on = super::cpu::disable_interrupts();
        let result = if self.busy.swap(true, Ordering::Acquire) {
            None
        } else {
            // SAFETY: the busy flag was clear and this call set it, so no
            // other reference to the value exists until it's cleared.
            let result = f(unsafe { &mut *self.value.get() });
            self.busy.store(false, Ordering::Release);
            Some(result)
        };
        super::cpu::restore_interrupts(were_on);
        result
    }
}
