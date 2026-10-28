//! Links the Keep with its linker script, and embeds the user programs.
//!
//! The user programs (an ELF each) must be built before the Keep, which
//! includes them with `include_bytes!`. The Makefile builds them first
//! and points `ROOK_USER_DIR` at them; this script copies each into
//! `OUT_DIR` so the Keep's source can include it by a fixed name.

use std::path::{Path, PathBuf};

/// The user programs the Keep embeds.
const PROGRAMS: [&str; 4] = ["michael", "check", "vault", "gabriel"];

fn main() {
    let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") else {
        panic!("CARGO_MANIFEST_DIR is not set");
    };
    println!("cargo:rustc-link-arg=-T{manifest}/linker.ld");
    println!("cargo:rerun-if-changed=linker.ld");

    let Ok(out) = std::env::var("OUT_DIR").map(PathBuf::from) else {
        panic!("OUT_DIR is not set");
    };
    let user_dir = user_dir(&manifest);
    println!("cargo:rerun-if-env-changed=ROOK_USER_DIR");
    for program in PROGRAMS {
        let from = user_dir.join(program);
        if !from.is_file() {
            panic!("user program {from:?} is missing; build the user programs first (run `make`)");
        }
        std::fs::copy(&from, out.join(format!("{program}.elf")))
            .unwrap_or_else(|e| panic!("copying {from:?}: {e}"));
        println!("cargo:rerun-if-changed={}", from.display());
    }
}

/// Where the built user programs are: `ROOK_USER_DIR` if set, else the
/// workspace's default release directory for the bare-metal target.
fn user_dir(manifest: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("ROOK_USER_DIR") {
        return PathBuf::from(dir);
    }
    let Some(workspace) = Path::new(manifest).parent() else {
        panic!("CARGO_MANIFEST_DIR has no parent");
    };
    workspace.join("target/x86_64-unknown-none/release")
}
