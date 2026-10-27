//! The Keep's randomness: a ChaCha20 fast-key-erasure CSPRNG, seeded from
//! the CPU's hardware random generator.
//!
//! [`seed`] gathers key material from RDSEED (or RDRAND). [`fill`] runs
//! ChaCha20 over zeros to make keystream: its first 32 bytes become the
//! new key, erasing the old, so output can never be run backwards to
//! recover earlier bytes; the rest answers the request. If the CPU has no
//! hardware source, the key is mixed from the timestamp counter — weak,
//! and said so loudly at boot; real hardware has RDSEED.
//!
//! The generator is behind the interrupt-safe cell, so a syscall and an
//! interrupt can't draw from it at the same time.

#![forbid(unsafe_code)]

use crate::arch::cpu;
use crate::arch::sync::Exclusive;
use abi::MAX_RANDOM;

const KEY: usize = 32;
const NONCE: [u8; 12] = [0u8; 12];
const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;

struct Rng {
    key: [u8; KEY],
}

static RNG: Exclusive<Rng> = Exclusive::new(Rng { key: [0; KEY] });

/// Seed the CSPRNG. Returns the hardware source's name (`"RDSEED"` or
/// `"RDRAND"`), or None if the CPU has neither and a weak timestamp seed
/// was used instead.
pub fn seed() -> Option<&'static str> {
    let mut words = [0u64; KEY / 8];
    let source = cpu::hardware_random(&mut words);
    if source.is_none() {
        for (i, word) in words.iter_mut().enumerate() {
            *word = cpu::timestamp().wrapping_mul(SPREAD).wrapping_add(i as u64);
        }
    }
    let _ = RNG.with(|r| {
        for (chunk, word) in r.key.chunks_exact_mut(8).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    });
    source
}

/// Fill `out` (at most `MAX_RANDOM` bytes) with random bytes, rekeying from
/// fresh keystream each time so earlier output can't be recovered.
pub fn fill(out: &mut [u8]) {
    let n = out.len().min(MAX_RANDOM as usize);
    let _ = RNG.with(|r| {
        let mut block = [0u8; KEY + MAX_RANDOM as usize];
        let span = &mut block[..KEY + n];
        crypto::chacha20_xor(&r.key, 0, &NONCE, span);
        r.key.copy_from_slice(&block[..KEY]);
        out[..n].copy_from_slice(&block[KEY..KEY + n]);
    });
}
