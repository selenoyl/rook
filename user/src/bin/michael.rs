//! Michael, the supervisor: the first task the Keep starts. In time he
//! launches, watches, restarts and stops every other angel. For now he
//! hears one task report in over an endpoint, checks on it through a Task
//! Writ, replies, and then keeps watch until it finishes.
//!
//! The Keep seeds his capability table at boot:
//!   handle 0  receive requests from the task he watches
//!   handle 1  send replies to it
//!   handle 2  watch it (a Task Writ)

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use user::abi::status;

const REQUEST: u64 = 0;
const REPLY: u64 = 1;
const WARD: u64 = 2;

/// How long to wait between checks once the ward is running on its own.
const ROUND: u64 = 50;

user::program!(main);

fn main(_: u64) -> ! {
    let _ = user::log("supervisor, standing watch");

    // Wait for the task to report in, then look it over and reply.
    if let Ok((badge, words)) = user::recv(REQUEST) {
        user::logln!("heard from task {badge}: {:#x}", words[0]);
        match user::watch(WARD) {
            Ok(s) if status::kind(s) == status::ALIVE => {
                user::logln!("task {badge} is alive and well");
            }
            _ => {
                user::logln!("task {badge} is already gone");
            }
        }
        let _ = user::send(REPLY, [0; 4]);
    }

    // Keep watch until the ward finishes, then report how it ended.
    loop {
        match user::watch(WARD) {
            Ok(s) if status::kind(s) == status::EXITED => {
                user::logln!("the task I watch exited with {}", status::code(s));
                break;
            }
            Ok(s) if status::kind(s) == status::FAULTED => {
                let _ = user::log("the task I watch faulted; it has been ended");
                break;
            }
            _ => {
                let _ = user::sleep(ROUND);
            }
        }
    }

    loop {
        let _ = user::sleep(ROUND * 20);
    }
}
