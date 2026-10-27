//! Poly1305 (RFC 8439), the one-time authenticator.
//!
//! Arithmetic modulo 2^130 - 5 in five 26-bit limbs, the well-trodden
//! "donna" layout, so the 130-bit multiply-and-reduce fits in `u64` and
//! the tag fits in `u128`. No step branches on the message or the key.

const MASK: u32 = 0x3ff_ffff;

/// A streaming Poly1305 over one key (use the key once).
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u8; 16],
    buffer: [u8; 16],
    filled: usize,
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Poly1305 {
        let r = [
            word(key, 0) & 0x3ff_ffff,
            (word(key, 3) >> 2) & 0x3ff_ff03,
            (word(key, 6) >> 4) & 0x3ff_c0ff,
            (word(key, 9) >> 6) & 0x3f0_3fff,
            (word(key, 12) >> 8) & 0x00f_ffff,
        ];
        let mut pad = [0u8; 16];
        pad.copy_from_slice(&key[16..32]);
        Poly1305 {
            r,
            h: [0; 5],
            pad,
            buffer: [0; 16],
            filled: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.filled > 0 {
            let take = (16 - self.filled).min(data.len());
            self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < 16 {
                return; // buffer still partial, input exhausted
            }
            let block = self.buffer;
            self.block(&block, true);
            self.filled = 0;
        }
        while data.len() >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[..16]);
            self.block(&block, true);
            data = &data[16..];
        }
        self.buffer[..data.len()].copy_from_slice(data);
        self.filled = data.len();
    }

    /// Add one 16-byte block to the accumulator. `full` sets the extra
    /// high bit a complete block carries; the padded final block clears it.
    fn block(&mut self, block: &[u8; 16], full: bool) {
        let hibit = if full { 1 << 24 } else { 0 };
        let [r0, r1, r2, r3, r4] = self.r;
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);

        let h0 = self.h[0] + (word(block, 0) & MASK);
        let h1 = self.h[1] + ((word(block, 3) >> 2) & MASK);
        let h2 = self.h[2] + ((word(block, 6) >> 4) & MASK);
        let h3 = self.h[3] + ((word(block, 9) >> 6) & MASK);
        let h4 = self.h[4] + ((word(block, 12) >> 8) | hibit);

        let m = |a: u32, b: u32| u64::from(a) * u64::from(b);
        let d0 = m(h0, r0) + m(h1, s4) + m(h2, s3) + m(h3, s2) + m(h4, s1);
        let d1 = m(h0, r1) + m(h1, r0) + m(h2, s4) + m(h3, s3) + m(h4, s2);
        let d2 = m(h0, r2) + m(h1, r1) + m(h2, r0) + m(h3, s4) + m(h4, s3);
        let d3 = m(h0, r3) + m(h1, r2) + m(h2, r1) + m(h3, r0) + m(h4, s4);
        let d4 = m(h0, r4) + m(h1, r3) + m(h2, r2) + m(h3, r1) + m(h4, r0);

        let mut c = (d0 >> 26) as u32;
        let h0 = d0 as u32 & MASK;
        let d1 = d1 + u64::from(c);
        c = (d1 >> 26) as u32;
        let h1 = d1 as u32 & MASK;
        let d2 = d2 + u64::from(c);
        c = (d2 >> 26) as u32;
        let h2 = d2 as u32 & MASK;
        let d3 = d3 + u64::from(c);
        c = (d3 >> 26) as u32;
        let h3 = d3 as u32 & MASK;
        let d4 = d4 + u64::from(c);
        c = (d4 >> 26) as u32;
        let h4 = d4 as u32 & MASK;
        let h0 = h0 + c * 5;
        let c = h0 >> 26;
        let h0 = h0 & MASK;
        let h1 = h1 + c;

        self.h = [h0, h1, h2, h3, h4];
    }

    pub fn finalize(mut self) -> [u8; 16] {
        if self.filled > 0 {
            let mut block = [0u8; 16];
            block[..self.filled].copy_from_slice(&self.buffer[..self.filled]);
            block[self.filled] = 1;
            self.block(&block, false);
        }

        // Fully carry h.
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c = h1 >> 26;
        h1 &= MASK;
        h2 += c;
        c = h2 >> 26;
        h2 &= MASK;
        h3 += c;
        c = h3 >> 26;
        h3 &= MASK;
        h4 += c;
        c = h4 >> 26;
        h4 &= MASK;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= MASK;
        h1 += c;

        // Compute h + -p, and pick it if h >= p (constant time).
        let mut g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= MASK;
        let mut g1 = h1 + c;
        c = g1 >> 26;
        g1 &= MASK;
        let mut g2 = h2 + c;
        c = g2 >> 26;
        g2 &= MASK;
        let mut g3 = h3 + c;
        c = g3 >> 26;
        g3 &= MASK;
        let mut g4 = (h4 + c).wrapping_sub(1 << 26);

        let keep = (g4 >> 31).wrapping_sub(1); // all ones if h >= p
        g0 &= keep;
        g1 &= keep;
        g2 &= keep;
        g3 &= keep;
        g4 &= keep;
        let drop = !keep;
        h0 = (h0 & drop) | g0;
        h1 = (h1 & drop) | g1;
        h2 = (h2 & drop) | g2;
        h3 = (h3 & drop) | g3;
        h4 = (h4 & drop) | g4;

        // The reduced h, low 128 bits, plus the pad, modulo 2^128.
        let h = u128::from(h0)
            | (u128::from(h1) << 26)
            | (u128::from(h2) << 52)
            | (u128::from(h3) << 78)
            | (u128::from(h4) << 104);
        let pad = u128::from_le_bytes(self.pad);
        h.wrapping_add(pad).to_le_bytes()
    }
}

/// One-shot Poly1305 of `msg` under `key`.
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(key);
    mac.update(msg);
    mac.finalize()
}
