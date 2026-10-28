//! Courier: reliable, multi-stream delivery over an unreliable datagram
//! link — the transport Rook carries inside Drawbridge over UDP (and so
//! over an ordinary Wi-Fi or Ethernet network), modelled on QUIC rather
//! than a modified TCP.
//!
//! A datagram link loses, reorders and duplicates packets. Courier turns
//! that into a set of independent **streams**, each an ordered, reliable
//! run of messages: a loss on one stream never stalls another, and only
//! the packets that actually went missing are resent. Every packet is
//! sealed with ChaCha20-Poly1305 under a **monotonic packet number** as its
//! nonce, so — unlike a Drawbridge [`Session`], which assumes the transport
//! keeps order — Courier needs no in-order delivery underneath it, and a
//! reordered or replayed packet is handled, not fatal.
//!
//! The two directional keys come from a Drawbridge handshake: Courier is
//! what runs *inside* the sealed channel once it is open. This crate is the
//! transport engine, driven by a pull API so it is fully testable over a
//! simulated lossy channel with no network card yet:
//!
//! - [`Courier::send`] queues a message on a stream;
//! - [`Courier::poll_transmit`] produces the next sealed packet for the
//!   wire (an ack, a new message, or a retransmit);
//! - [`Courier::on_packet`] takes a received sealed packet;
//! - [`Courier::poll_deliver`] returns the next in-order message;
//! - [`Courier::tick`] marks unacknowledged packets for retransmit.
//!
//! Deferred, and noted so: flow and congestion control, connection
//! migration between links, byte-stream framing, and binding to a real NIC
//! and UDP. Like the crypto beneath it, this is not audited.
//!
//! [`Session`]: ../drawbridge/struct.Session.html

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use crypto::{aead_open, aead_seal};

/// Independent streams a connection multiplexes (ids `0..MAX_STREAMS`).
pub const MAX_STREAMS: usize = 4;
/// The most bytes in one message.
pub const MAX_MSG: usize = 256;
/// Messages that may be in flight (sent, awaiting acknowledgement) at once.
const SEND_WINDOW: usize = 16;
/// Received messages held awaiting in-order delivery.
const RECV_WINDOW: usize = 16;
/// Acknowledgements queued to send.
const ACK_WINDOW: usize = 16;

const T_DATA: u8 = 1;
const T_ACK: u8 = 2;
/// Frame header: type, stream, 4-byte sequence, 2-byte length.
const HEADER: usize = 8;
/// Largest plaintext frame: header plus a full message.
const FRAME: usize = HEADER + MAX_MSG;
/// Largest sealed packet: 8-byte packet number, frame, 16-byte tag.
pub const MAX_PACKET: usize = 8 + FRAME + 16;

/// Why a Courier call was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The stream id is not below `MAX_STREAMS`.
    BadStream,
    /// The message is longer than `MAX_MSG`.
    TooLong,
    /// The send window is full; drain it with `poll_transmit` and let acks
    /// come back before sending more.
    WouldBlock,
    /// The packet-number space is exhausted; the connection must be torn
    /// down rather than reuse a nonce.
    Exhausted,
    /// A received packet was malformed or failed authentication.
    BadPacket,
}

/// A message sent and awaiting acknowledgement; `due` means it should be
/// (re)transmitted on the next `poll_transmit`.
#[derive(Clone, Copy)]
struct InFlight {
    stream: u8,
    seq: u32,
    data: [u8; MAX_MSG],
    len: usize,
    due: bool,
}

/// A received message not yet delivered in order.
#[derive(Clone, Copy)]
struct Received {
    stream: u8,
    seq: u32,
    data: [u8; MAX_MSG],
    len: usize,
}

/// One end of a Courier connection.
pub struct Courier {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    /// Next packet-number nonce for an outgoing packet.
    tx_pn: u64,
    /// Next sequence number to assign per send stream.
    next_seq: [u32; MAX_STREAMS],
    inflight: [Option<InFlight>; SEND_WINDOW],
    /// Next sequence number to deliver per receive stream.
    recv_next: [u32; MAX_STREAMS],
    recv_buf: [Option<Received>; RECV_WINDOW],
    acks: [Option<(u8, u32)>; ACK_WINDOW],
}

fn nonce(pn: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&pn.to_be_bytes());
    n
}

impl Courier {
    /// A connection end with the two directional keys from a Drawbridge
    /// handshake: `send_key` protects what this end sends, `recv_key` what
    /// it receives. The peer is constructed with the two keys swapped.
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Courier {
        Courier {
            send_key,
            recv_key,
            tx_pn: 0,
            next_seq: [0; MAX_STREAMS],
            inflight: [None; SEND_WINDOW],
            recv_next: [0; MAX_STREAMS],
            recv_buf: [None; RECV_WINDOW],
            acks: [None; ACK_WINDOW],
        }
    }

    /// Queue `data` as the next message on `stream`. It is delivered to the
    /// peer reliably and in order with the stream's other messages.
    pub fn send(&mut self, stream: u8, data: &[u8]) -> Result<(), Error> {
        if usize::from(stream) >= MAX_STREAMS {
            return Err(Error::BadStream);
        }
        if data.len() > MAX_MSG {
            return Err(Error::TooLong);
        }
        let slot = self
            .inflight
            .iter()
            .position(Option::is_none)
            .ok_or(Error::WouldBlock)?;
        let seq = self.next_seq[usize::from(stream)];
        self.next_seq[usize::from(stream)] = seq.wrapping_add(1);
        let mut buf = [0u8; MAX_MSG];
        buf[..data.len()].copy_from_slice(data);
        self.inflight[slot] = Some(InFlight {
            stream,
            seq,
            data: buf,
            len: data.len(),
            due: true,
        });
        Ok(())
    }

    /// Produce the next sealed packet to put on the wire, or `None` when
    /// there is nothing to send. Acknowledgements go first, then any
    /// message due for its first send or a retransmit.
    pub fn poll_transmit(&mut self, out: &mut [u8]) -> Option<usize> {
        if let Some(slot) = self.acks.iter().position(Option::is_some) {
            let (stream, seq) = self.acks[slot].take()?;
            let mut frame = [0u8; HEADER];
            frame[0] = T_ACK;
            frame[1] = stream;
            frame[2..6].copy_from_slice(&seq.to_le_bytes());
            return self.seal(&frame[..6], out);
        }
        let slot = self
            .inflight
            .iter()
            .position(|f| matches!(f, Some(m) if m.due))?;
        let msg = self.inflight[slot].as_mut()?;
        msg.due = false;
        let stream = msg.stream;
        let seq = msg.seq;
        let len = msg.len;
        let mut frame = [0u8; FRAME];
        frame[0] = T_DATA;
        frame[1] = stream;
        frame[2..6].copy_from_slice(&seq.to_le_bytes());
        frame[6..8].copy_from_slice(&(len as u16).to_le_bytes());
        frame[HEADER..HEADER + len].copy_from_slice(&msg.data[..len]);
        self.seal(&frame[..HEADER + len], out)
    }

    /// Seal `frame` into `out` with a fresh packet number as the nonce.
    fn seal(&mut self, frame: &[u8], out: &mut [u8]) -> Option<usize> {
        let total = 8 + frame.len() + 16;
        if out.len() < total || self.tx_pn == u64::MAX {
            return None;
        }
        let pn = self.tx_pn;
        self.tx_pn += 1;
        let pn_bytes = pn.to_be_bytes();
        out[..8].copy_from_slice(&pn_bytes);
        out[8..8 + frame.len()].copy_from_slice(frame);
        let tag = aead_seal(
            &self.send_key,
            &nonce(pn),
            &pn_bytes,
            &mut out[8..8 + frame.len()],
        );
        out[8 + frame.len()..total].copy_from_slice(&tag);
        Some(total)
    }

    /// Take a received sealed packet: authenticate it, acknowledge the
    /// message, and buffer it for in-order delivery.
    pub fn on_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        if packet.len() < 8 + 16 || packet.len() > MAX_PACKET {
            return Err(Error::BadPacket);
        }
        let mut pn = [0u8; 8];
        pn.copy_from_slice(&packet[..8]);
        let body = &packet[8..packet.len() - 16];
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&packet[packet.len() - 16..]);
        let mut frame = [0u8; FRAME];
        frame[..body.len()].copy_from_slice(body);
        if !aead_open(
            &self.recv_key,
            &nonce(u64::from_be_bytes(pn)),
            &pn,
            &mut frame[..body.len()],
            &tag,
        ) {
            return Err(Error::BadPacket);
        }
        self.handle_frame(&frame[..body.len()])
    }

    fn handle_frame(&mut self, frame: &[u8]) -> Result<(), Error> {
        match frame.first() {
            Some(&T_ACK) if frame.len() >= 6 => {
                let (stream, seq) = (frame[1], read_u32(frame, 2));
                if let Some(slot) = self
                    .inflight
                    .iter()
                    .position(|f| matches!(f, Some(m) if m.stream == stream && m.seq == seq))
                {
                    self.inflight[slot] = None;
                }
                Ok(())
            }
            Some(&T_DATA) if frame.len() >= HEADER => {
                let stream = frame[1];
                let seq = read_u32(frame, 2);
                let len = usize::from(u16::from_le_bytes([frame[6], frame[7]]));
                if usize::from(stream) >= MAX_STREAMS || len > MAX_MSG || HEADER + len > frame.len()
                {
                    return Err(Error::BadPacket);
                }
                self.queue_ack(stream, seq);
                self.buffer(stream, seq, &frame[HEADER..HEADER + len]);
                Ok(())
            }
            _ => Err(Error::BadPacket),
        }
    }

    /// Queue an acknowledgement for `(stream, seq)`. A full queue is fine to
    /// drop from: the sender retransmits, and we acknowledge again.
    fn queue_ack(&mut self, stream: u8, seq: u32) {
        if let Some(slot) = self.acks.iter().position(Option::is_none) {
            self.acks[slot] = Some((stream, seq));
        }
    }

    /// Buffer a received message for delivery, unless it was already
    /// delivered or is already held. A full buffer drops it; the sender
    /// will resend.
    fn buffer(&mut self, stream: u8, seq: u32, data: &[u8]) {
        if seq < self.recv_next[usize::from(stream)] {
            return;
        }
        let known = self
            .recv_buf
            .iter()
            .any(|r| matches!(r, Some(m) if m.stream == stream && m.seq == seq));
        if known {
            return;
        }
        if let Some(slot) = self.recv_buf.iter().position(Option::is_none) {
            let mut buf = [0u8; MAX_MSG];
            buf[..data.len()].copy_from_slice(data);
            self.recv_buf[slot] = Some(Received {
                stream,
                seq,
                data: buf,
                len: data.len(),
            });
        }
    }

    /// Return the next in-order message ready on any stream, writing its
    /// bytes into `out` and returning `(stream, len)`, or `None` if the
    /// next message on every stream is still missing.
    pub fn poll_deliver(&mut self, out: &mut [u8]) -> Option<(u8, usize)> {
        for slot in 0..RECV_WINDOW {
            if let Some(m) = self.recv_buf[slot]
                && m.seq == self.recv_next[usize::from(m.stream)]
            {
                let len = m.len.min(out.len());
                out[..len].copy_from_slice(&m.data[..len]);
                self.recv_next[usize::from(m.stream)] = m.seq.wrapping_add(1);
                self.recv_buf[slot] = None;
                return Some((m.stream, m.len));
            }
        }
        None
    }

    /// The retransmit timer fired: mark every unacknowledged message for
    /// resend on the next `poll_transmit`.
    pub fn tick(&mut self) {
        for slot in self.inflight.iter_mut().flatten() {
            slot.due = true;
        }
    }

    /// Whether nothing is queued to send, in flight, or awaiting delivery —
    /// the connection is quiet.
    pub fn idle(&self) -> bool {
        self.inflight.iter().all(Option::is_none)
            && self.acks.iter().all(Option::is_none)
            && self.recv_buf.iter().all(Option::is_none)
    }
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[cfg(test)]
mod tests;
