//! The data channel: once the handshake agrees keys, a `Session` seals and
//! opens messages with ChaCha20-Poly1305.
//!
//! Each direction has its own key and its own 64-bit counter. The counter
//! is the message's nonce, so every message uses a fresh nonce, and the
//! receiver only accepts the next counter in sequence — an old message
//! replayed, or one that arrives out of order, fails to open. The counter
//! is 64 bits; a session that somehow sent 2^64 messages would be torn
//! down rather than wrap a nonce.

use crate::Error;
use crypto::{aead_open, aead_seal};

/// An established Drawbridge session. `seal` encrypts an outgoing message
/// in place and returns its tag; `open` checks an incoming message's tag
/// and decrypts it in place.
pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    recv_counter: u64,
}

impl Session {
    pub(crate) fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Session {
        Session {
            send_key,
            recv_key,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// The 12-byte nonce for a message counter: four zero bytes then the
    /// counter, big-endian.
    fn nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    /// Encrypt `buf` in place and return its 16-byte tag. Advances the send
    /// counter, so the next message gets a fresh nonce.
    pub fn seal(&mut self, buf: &mut [u8]) -> Result<[u8; 16], Error> {
        if self.send_counter == u64::MAX {
            return Err(Error::CounterExhausted);
        }
        let nonce = Self::nonce(self.send_counter);
        let tag = aead_seal(&self.send_key, &nonce, &[], buf);
        self.send_counter += 1;
        Ok(tag)
    }

    /// Check `tag` over `buf` at the next expected counter; if it holds,
    /// decrypt `buf` in place and advance. On any failure `buf` is left
    /// untouched and the counter does not move.
    pub fn open(&mut self, buf: &mut [u8], tag: &[u8; 16]) -> Result<(), Error> {
        if self.recv_counter == u64::MAX {
            return Err(Error::CounterExhausted);
        }
        let nonce = Self::nonce(self.recv_counter);
        if !aead_open(&self.recv_key, &nonce, &[], buf, tag) {
            return Err(Error::BadTag);
        }
        self.recv_counter += 1;
        Ok(())
    }

    /// How many messages this session has sealed and opened — exposed so a
    /// caller can notice a dropped message (the counters would disagree
    /// with its own tally) and tear the session down.
    pub fn counters(&self) -> (u64, u64) {
        (self.send_counter, self.recv_counter)
    }
}
