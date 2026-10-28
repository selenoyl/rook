#!/usr/bin/env python3
"""Two-node network test: two Keeps on one wire talk to each other.

Usage: net_test.py KERNEL

Boots two Keeps linked by QEMU's socket netdev, which carries their
Ethernet frames between the two processes over a local TCP stream — a
real wire with another machine on the far end, not QEMU's user network.
One boots as the server (net=server), the other as the client
(net=client); Gabriel drives the NE2000 in ring 3 on each. The test
passes when both report success and QEMU exits 33 (the Keep's success
status) for each.

The server is started first and given a moment to begin listening before
the client connects.
"""
import os
import socket
import subprocess
import sys
import time

TIMEOUT = 40
PASSED = 33

SERVER_MAC = "52:54:00:00:00:01"
CLIENT_MAC = "52:54:00:00:00:02"

SERVER_LINES = [
    "[gabriel] gabriel: server up, listening for a Rook on the wire",
    "[gabriel] gabriel: server completed the Drawbridge handshake, authenticated the client",
    "[gabriel] gabriel: Courier carries application data between two Rook machines",
    "[keep] user: gabriel carried traffic on a real link",
]
CLIENT_LINES = [
    "[gabriel] gabriel: ARP reply, server 10.9.0.1 is at",
    "[gabriel] gabriel: client completed the Drawbridge handshake, authenticated the server",
    "[gabriel] gabriel: Courier round-trip complete between two Rook machines",
    "[keep] user: gabriel carried traffic on a real link",
]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def qemu(kernel, role, mac, sockarg, log):
    if os.path.exists(log):
        os.remove(log)
    return subprocess.Popen(
        [
            "qemu-system-x86_64", "-cpu", "max", "-kernel", kernel,
            "-append", f"net={role}", "-m", "128M", "-display", "none",
            "-no-reboot", "-serial", f"file:{log}",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-netdev", f"socket,id=n0,{sockarg}",
            "-device", f"ne2k_isa,netdev=n0,mac={mac}",
        ]
    )


def wait(proc, deadline):
    try:
        proc.wait(timeout=max(0.1, deadline - time.time()))
        return proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        return None


def read(log):
    return open(log, errors="replace").read() if os.path.exists(log) else ""


def check(name, status, output, want_lines):
    problems = []
    if status is None:
        problems.append(f"timed out after {TIMEOUT}s")
    elif status != PASSED:
        problems.append(f"exit status {status}, expected {PASSED}")
    problems += [f"missing {line!r}" for line in want_lines if line not in output]
    if problems:
        print(f"FAIL  {name}")
        for p in problems:
            print(f"      {p}")
        return 1
    print(f"ok    {name}")
    return 0


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    kernel = sys.argv[1]
    log_dir = os.path.join(os.path.dirname(os.path.abspath(kernel)), "test-logs")
    os.makedirs(log_dir, exist_ok=True)
    server_log = os.path.join(log_dir, "net-server.log")
    client_log = os.path.join(log_dir, "net-client.log")

    port = free_port()
    server = qemu(kernel, "server", SERVER_MAC, f"listen=127.0.0.1:{port}", server_log)
    time.sleep(2)  # let the server bind and begin listening
    client = qemu(kernel, "client", CLIENT_MAC, f"connect=127.0.0.1:{port}", client_log)

    deadline = time.time() + TIMEOUT
    client_status = wait(client, deadline)
    server_status = wait(server, deadline)

    failures = 0
    failures += check("server: handshake and Courier with the client over a real wire", server_status, read(server_log), SERVER_LINES)
    failures += check("client: handshake and Courier with the server over a real wire", client_status, read(client_log), CLIENT_LINES)
    if failures:
        print(f"      server log: {server_log}")
        print(f"      client log: {client_log}")
    print(f"{2 - failures} of 2 network nodes passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
