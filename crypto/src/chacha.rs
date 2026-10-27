//! ChaCha20 (RFC 8439), the stream cipher.

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The 64-byte keystream block for `counter` (RFC 8439 §2.3).
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut start = [0u32; 16];
    start[0..4].copy_from_slice(&CONSTANTS);
    for (i, slot) in start[4..12].iter_mut().enumerate() {
        *slot = word(key, i * 4);
    }
    start[12] = counter;
    for (i, slot) in start[13..16].iter_mut().enumerate() {
        *slot = word(nonce, i * 4);
    }

    let mut s = start;
    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&s[i].wrapping_add(start[i]).to_le_bytes());
    }
    out
}

/// XOR `buf` in place with the ChaCha20 keystream from `counter` up.
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], buf: &mut [u8]) {
    let mut ctr = counter;
    for chunk in buf.chunks_mut(64) {
        let ks = block(key, ctr, nonce);
        for (b, k) in chunk.iter_mut().zip(ks) {
            *b ^= k;
        }
        ctr = ctr.wrapping_add(1);
    }
}
