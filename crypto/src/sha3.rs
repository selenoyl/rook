//! SHA-3 and SHAKE (FIPS 202): the Keccak sponge.
//!
//! One permutation, Keccak-f[1600] over twenty-five 64-bit lanes, drives
//! all four functions; they differ only in the sponge's rate and the
//! domain-separation byte. SHA3-256 and SHA3-512 give a fixed-length
//! digest; SHAKE128 and SHAKE256 are extendable-output, filling a buffer
//! of any length. The work is plain integer arithmetic with no
//! input-dependent branching.
//!
//! These are the hash and XOF the post-quantum primitives build on.

/// Keccak-f[1600] round constants.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets, indexed by lane `x + 5*y`.
const ROT: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// The widest rate of the four functions (SHAKE128: 1600 - 2*128 bits).
const MAX_RATE: usize = 168;

/// Apply Keccak-f[1600] to the state in place.
fn keccak_f1600(a: &mut [u64; 25]) {
    for &rc in RC.iter() {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // rho and pi
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROT[x + 5 * y]);
            }
        }
        // chi
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // iota
        a[0] ^= rc;
    }
}

/// XOR a rate-sized block of little-endian bytes into the state lanes.
fn absorb_block(a: &mut [u64; 25], block: &[u8], rate: usize) {
    for (i, lane) in block[..rate].chunks_exact(8).enumerate() {
        a[i] ^= u64::from_le_bytes([
            lane[0], lane[1], lane[2], lane[3], lane[4], lane[5], lane[6], lane[7],
        ]);
    }
}

/// Absorb `input` with the given `rate` and domain-separation byte,
/// returning the state ready to squeeze (its first `rate` bytes are the
/// first output block).
fn absorb(rate: usize, domain: u8, input: &[u8]) -> [u64; 25] {
    let mut a = [0u64; 25];
    let mut chunks = input.chunks_exact(rate);
    for block in chunks.by_ref() {
        absorb_block(&mut a, block, rate);
        keccak_f1600(&mut a);
    }
    // Final block: the remainder, then pad10*1 with the domain byte.
    let rem = chunks.remainder();
    let mut block = [0u8; MAX_RATE];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] = domain;
    block[rate - 1] |= 0x80;
    absorb_block(&mut a, &block, rate);
    keccak_f1600(&mut a);
    a
}

/// The Keccak sponge: absorb `input` with the given `rate` and
/// domain-separation byte, then squeeze `out.len()` bytes into `out`.
fn keccak(rate: usize, domain: u8, input: &[u8], out: &mut [u8]) {
    let mut a = absorb(rate, domain, input);
    let mut done = 0;
    loop {
        for &word in &a[..rate / 8] {
            if done >= out.len() {
                return;
            }
            let bytes = word.to_le_bytes();
            let take = core::cmp::min(8, out.len() - done);
            out[done..done + take].copy_from_slice(&bytes[..take]);
            done += take;
        }
        if done >= out.len() {
            return;
        }
        keccak_f1600(&mut a);
    }
}

/// A streaming SHAKE256: absorb the input in pieces, then squeeze any
/// number of output bytes. SLH-DSA hashes long, multi-part messages, so it
/// needs this rather than the one-shot form.
pub struct Shake256 {
    a: [u64; 25],
    block: [u8; RATE_256],
    filled: usize,
}

impl Default for Shake256 {
    fn default() -> Shake256 {
        Shake256 {
            a: [0u64; 25],
            block: [0u8; RATE_256],
            filled: 0,
        }
    }
}

impl Shake256 {
    pub fn new() -> Shake256 {
        Shake256::default()
    }

    /// Absorb more input.
    pub fn absorb(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = core::cmp::min(RATE_256 - self.filled, data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == RATE_256 {
                absorb_block(&mut self.a, &self.block, RATE_256);
                keccak_f1600(&mut self.a);
                self.filled = 0;
            }
        }
    }

    /// Pad and squeeze the output into `out`.
    pub fn finalize(mut self, out: &mut [u8]) {
        for b in self.block[self.filled..].iter_mut() {
            *b = 0;
        }
        self.block[self.filled] ^= 0x1f;
        self.block[RATE_256 - 1] ^= 0x80;
        absorb_block(&mut self.a, &self.block, RATE_256);
        keccak_f1600(&mut self.a);
        let mut done = 0;
        loop {
            for &word in &self.a[..RATE_256 / 8] {
                if done >= out.len() {
                    return;
                }
                let bytes = word.to_le_bytes();
                let take = core::cmp::min(8, out.len() - done);
                out[done..done + take].copy_from_slice(&bytes[..take]);
                done += take;
            }
            if done >= out.len() {
                return;
            }
            keccak_f1600(&mut self.a);
        }
    }
}

/// A SHAKE128 reader for squeezing a block at a time, as ML-KEM's matrix
/// sampling needs. Its rate, 168 bytes, is a multiple of 3, so the sampler
/// never straddles a block boundary.
pub struct Shake128Reader {
    a: [u64; 25],
}

impl Shake128Reader {
    /// Start a SHAKE128 reader over `input`.
    pub fn new(input: &[u8]) -> Shake128Reader {
        Shake128Reader {
            a: absorb(RATE_128, 0x1f, input),
        }
    }

    /// Fill `out` (168 bytes) with the next output block.
    pub fn next_block(&mut self, out: &mut [u8; RATE_128]) {
        for (chunk, &word) in out.chunks_exact_mut(8).zip(&self.a[..RATE_128 / 8]) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        keccak_f1600(&mut self.a);
    }
}

// Rates in bytes: (1600 - 2*capacity) / 8, capacity = 2 * security level.
const RATE_256: usize = 136; // SHA3-256 and SHAKE256
const RATE_512: usize = 72; // SHA3-512
const RATE_128: usize = 168; // SHAKE128

/// SHA3-256 of `input`.
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    keccak(RATE_256, 0x06, input, &mut out);
    out
}

/// SHA3-512 of `input`.
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    keccak(RATE_512, 0x06, input, &mut out);
    out
}

/// SHAKE128 of `input`, filling `out` with as many bytes as it is long.
pub fn shake128(input: &[u8], out: &mut [u8]) {
    keccak(RATE_128, 0x1f, input, out);
}

/// SHAKE256 of `input`, filling `out` with as many bytes as it is long.
pub fn shake256(input: &[u8], out: &mut [u8]) {
    keccak(RATE_256, 0x1f, input, out);
}
