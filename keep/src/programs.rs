//! The user programs the Keep ships, embedded as ELF images.
//!
//! `keep/build.rs` copies each built program into `OUT_DIR`; these are
//! those bytes. The loader in `crate::user` parses and maps them.

#![forbid(unsafe_code)]

/// Michael, the supervisor: the first task the Keep starts.
pub const MICHAEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/michael.elf"));

/// check: the user-mode test program, run at every boot.
pub const CHECK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/check.elf"));

/// vault: the storage service that owns the disk.
pub const VAULT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vault.elf"));

/// gabriel: the messenger, who drives the network card.
pub const GABRIEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/gabriel.elf"));
