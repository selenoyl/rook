#!/usr/bin/env python3
"""Boot the Keep in QEMU without a window and save the screen as a PNG.

Usage: screenshot.py KERNEL OUT.png

Waits for the Keep to report it is idle on the serial port, then asks
QEMU's monitor for a screen dump. Needs Pillow to write PNG; without it
the raw .ppm is kept instead.
"""
import os
import shutil
import socket
import subprocess
import sys
import time

IDLE = "all quiet"
TIMEOUT = 30


def read_prompt(sock):
    """Read monitor output up to the next "(qemu)" prompt."""
    data = b""
    while b"(qemu)" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    kernel, out_png = sys.argv[1], sys.argv[2]
    work = os.path.join(os.path.dirname(os.path.abspath(out_png)), ".screenshot")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    serial = os.path.join(work, "serial.log")
    monitor = os.path.join(work, "monitor.sock")
    ppm = os.path.join(work, "screen.ppm")

    qemu = subprocess.Popen([
        "qemu-system-x86_64", "-cpu", "max", "-kernel", kernel, "-m", "128M",
        "-display", "none", "-no-reboot",
        "-serial", f"file:{serial}",
        "-monitor", f"unix:{monitor},server,nowait",
    ])
    try:
        deadline = time.time() + TIMEOUT
        while time.time() < deadline:
            if os.path.exists(serial) and IDLE in open(serial, errors="replace").read():
                break
            if qemu.poll() is not None:
                sys.exit("QEMU exited before the Keep went idle")
            time.sleep(0.2)
        else:
            sys.exit(f"the Keep did not report '{IDLE}' within {TIMEOUT}s")

        with socket.socket(socket.AF_UNIX) as s:
            s.connect(monitor)
            s.settimeout(10)
            read_prompt(s)
            s.sendall(f"screendump {ppm}\n".encode())
            read_prompt(s)
            s.sendall(b"quit\n")
            # Keep the connection open until QEMU has read the command;
            # closing straight away can drop it.
            qemu.wait(timeout=10)
    finally:
        if qemu.poll() is None:
            qemu.kill()

    try:
        from PIL import Image
    except ImportError:
        os.replace(ppm, os.path.splitext(out_png)[0] + ".ppm")
        print("Pillow not installed; kept the screen as .ppm")
        return
    img = Image.open(ppm)
    img.save(out_png)
    shutil.rmtree(work, ignore_errors=True)
    print(f"wrote {out_png} ({img.width}x{img.height})")


if __name__ == "__main__":
    main()
