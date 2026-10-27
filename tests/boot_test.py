#!/usr/bin/env python3
"""Boot tests for the Keep, run in QEMU without a window.

Usage: boot_test.py KERNEL

Each case boots the Keep with a kernel command line, waits for it to exit
QEMU through the isa-debug-exit device, and checks the exit status and
the serial log. QEMU exits with (code << 1) | 1: 33 means the Keep
reported success, 35 that it stopped on a failure.
"""
import os
import subprocess
import sys

TIMEOUT = 30
PASSED, STOPPED = 33, 35

CASES = [
    (
        "boots, raises the ring-0/3 walls, runs ring 3, and passes its self-test",
        "selftest",
        PASSED,
        [
            "[keep] Rook Keep v",
            "[keep] memory: 127 MiB usable",
            "[keep] gdt: ring-0 and ring-3 segments",
            "[keep] idt: 32 exception gates, plus timer, yield, syscall and spurious",
            "[keep] self-check: passed",
            "[keep] memory: own page tables loaded",
            "[keep] user: loaded michael",
            "[keep] user: loaded check",
            "allocator sealed",
            "walls: no-user-execute on, no-user-access on, hide-tables on",
            "[keep] sched: task 1 (michael) ready in ring 3",
            "[keep] sched: timer on, 100 ticks a second",
            "[michael] supervisor, standing watch",
            "[check] running in ring 3",
            "[keep] entropy: CSPRNG seeded from the CPU (RDSEED)",
            "[check] entropy: random bytes drawn from the Keep, and they differ",
            "[check] crypto: SHA-2/3, ChaCha20-Poly1305, X25519, Ed25519, ML-KEM-768, ML-DSA-87, SLH-DSA verified",
            "[check] drawbridge: authenticated session established and verified",
            "[check] drawbridge over IPC: sealed channel with the supervisor",
            "[michael] drawbridge: authenticated task 2, opened its sealed report",
            "[michael] task 2 is alive and well",
            "[vault] disk: write and read-back verified",
            "[vault] disk 256 blocks, filesystem has 3 file(s), 252 blocks free",
            "[vault] motd: The Keep holds. Rook stands watch.",
            "[vault] drawbridge: secure channel open with the client",
            "[check] vault: read motd over a sealed Drawbridge channel, verified",
            "[check] all checks passed",
            "the ring-3 test program ran its checks and exited with 0",
            "[keep] user: ring 3 works",
            "[keep] selftest: passed",
        ],
    ),
    (
        "a ring-3 task that crashes is ended, and the Keep keeps running",
        "selftest test=crash",
        PASSED,
        [
            "[check] crashing on purpose",
            "invalid opcode (vector 6)",
            "ending the task",
            "the Keep ended it, and Michael is still on watch",
            "[keep] user: ring 3 works",
            "[keep] selftest: passed",
        ],
    ),
    (
        "reading the null page faults and fails closed",
        "selftest test=null",
        STOPPED,
        ["[keep] test: reading address 0", "touching 0x0 (error 0x0); stopping"],
    ),
    (
        "writing to the Keep's code faults (W^X)",
        "selftest test=wx",
        STOPPED,
        ["[keep] test: writing to the Keep's code", "(error 0x3); stopping"],
    ),
    (
        "executing data faults (no-execute)",
        "selftest test=nx",
        STOPPED,
        ["[keep] test: executing data", "(error 0x11); stopping"],
    ),
    (
        "an interrupt with no gate fails closed",
        "selftest test=stray",
        STOPPED,
        [
            "[keep] test: raising an interrupt nothing handles",
            "general protection fault (vector 13)",
            "interrupt 0x40 arrived, and it has no gate",
        ],
    ),
    (
        "overflowing the boot stack hits its guard page and double-faults safely",
        "selftest test=stack",
        STOPPED,
        [
            "[keep] test: overflowing the stack",
            "double fault (vector 8)",
            "is in the guard page below the boot stack: a stack overflow",
        ],
    ),
    (
        "overflowing a kernel task's stack hits its guard and stops the machine",
        "selftest test=taskstack",
        STOPPED,
        [
            "[keep] test: overflowing a kernel task's stack",
            "double fault (vector 8)",
            "is in the guard below task 2's stack: a stack overflow",
            "[keep] trap: task 2 (overflow) was running",
        ],
    ),
]


def run(kernel, cmdline, log):
    if os.path.exists(log):
        os.remove(log)
    command = [
        "qemu-system-x86_64", "-cpu", "max", "-kernel", kernel, "-append", cmdline,
        "-m", "128M", "-display", "none", "-no-reboot",
        "-serial", f"file:{log}",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]
    # Attach the Vault's disk image if it was built next to the kernel, so
    # the storage service has a disk to drive.
    disk = os.path.join(os.path.dirname(os.path.abspath(kernel)), "disk.img")
    if os.path.exists(disk):
        command += ["-drive", f"file={disk},format=raw,if=ide"]
    try:
        proc = subprocess.run(command, timeout=TIMEOUT)
        status = proc.returncode
    except subprocess.TimeoutExpired:
        status = None
    output = open(log, errors="replace").read() if os.path.exists(log) else ""
    return status, output


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    kernel = sys.argv[1]
    log_dir = os.path.join(os.path.dirname(os.path.abspath(kernel)), "test-logs")
    os.makedirs(log_dir, exist_ok=True)

    failures = 0
    for i, (name, cmdline, want_status, want_lines) in enumerate(CASES):
        log = os.path.join(log_dir, f"case{i}.log")
        status, output = run(kernel, cmdline, log)
        problems = []
        if status is None:
            problems.append(f"timed out after {TIMEOUT}s")
        elif status != want_status:
            problems.append(f"exit status {status}, expected {want_status}")
        problems += [f"missing {line!r}" for line in want_lines if line not in output]
        if problems:
            failures += 1
            print(f"FAIL  {name}")
            for p in problems:
                print(f"      {p}")
            print(f"      serial log: {log}")
        else:
            print(f"ok    {name}")
    print(f"{len(CASES) - failures} of {len(CASES)} boot tests passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
