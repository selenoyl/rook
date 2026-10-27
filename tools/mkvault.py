#!/usr/bin/env python3
"""Build a raw disk image holding a Vault filesystem.

The layout must match `vault/src/lib.rs`:

  block 0  superblock: a 32-byte header then fixed 32-byte directory
           entries; files live in contiguous blocks from block 1 up,
           allocated by a bump pointer.

Usage: mkvault.py OUTPUT [BLOCKS]   (BLOCKS defaults to 256 = 128 KiB)

The set of files is fixed here so the image is reproducible and the boot
test can check what the Vault reads back.
"""
import struct
import sys

BLOCK = 512
NAME_LEN = 16
HEADER = 32
ENTRY = 32
MAX_FILES = (BLOCK - HEADER) // ENTRY
MAGIC = b"ROOKVLT1"
FLAG_USED = 1

# The files the image ships with: name -> contents.
FILES = {
    b"motd": b"The Keep holds. Rook stands watch.\n",
    b"readme": b"Rook is a security-first OS, built from scratch.\n",
    b"angels": b"Michael guards. Gabriel speaks. Raphael mends.\n",
}


def build(blocks):
    if blocks < 1:
        sys.exit("need at least one block")
    image = bytearray(blocks * BLOCK)
    sb = bytearray(BLOCK)
    sb[0:8] = MAGIC

    next_free = 1
    file_count = 0
    if len(FILES) > MAX_FILES:
        sys.exit(f"too many files: {len(FILES)} > {MAX_FILES}")
    for i, (name, data) in enumerate(FILES.items()):
        if len(name) > NAME_LEN:
            sys.exit(f"name too long: {name!r}")
        span = (len(data) + BLOCK - 1) // BLOCK
        start = next_free
        if start + span > blocks:
            sys.exit("image too small for its files")
        image[start * BLOCK: start * BLOCK + len(data)] = data
        base = HEADER + i * ENTRY
        sb[base: base + len(name)] = name
        struct.pack_into("<I", sb, base + 16, start)   # start block
        struct.pack_into("<I", sb, base + 20, len(data))  # length in bytes
        struct.pack_into("<I", sb, base + 24, FLAG_USED)  # flags
        next_free += span
        file_count += 1

    struct.pack_into("<I", sb, 8, blocks)
    struct.pack_into("<I", sb, 12, next_free)
    struct.pack_into("<I", sb, 16, file_count)
    image[0:BLOCK] = sb
    return image


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    out = sys.argv[1]
    blocks = int(sys.argv[2]) if len(sys.argv) == 3 else 256
    image = build(blocks)
    with open(out, "wb") as f:
        f.write(image)
    print(f"mkvault: wrote {out}: {blocks} blocks, {len(FILES)} files")


if __name__ == "__main__":
    main()
