#!/usr/bin/env python3
"""Draw a grid in the ROOK wordmark's style (the ANSI Shadow figlet font):
blocks that fade down the rows, a box-line drop shadow, and a reflection
of the bottom row.

Usage: shadow_art.py GRID FADES > ART
  GRID   one row per line, 'X' for a filled cell
  FADES  the block to fill each row with, e.g. ████████▓▒ (the last one
         repeats for any rows after it)

The boot logo is keep/assets/logo.txt, drawn from keep/assets/logo-grid.txt
with the fades ████████▓▒.

An empty cell's shadow character depends only on which of the cells to
its left, above, and above-left are filled, the way the font draws its
letters.
"""
import sys

# (left, above, above-left) filled -> shadow character
SHADOW = {
    (1, 1, 1): "╔", (0, 1, 1): "═", (1, 0, 0): "╗", (0, 0, 1): "╝",
    (1, 0, 1): "║", (0, 1, 0): "╚", (1, 1, 0): "╔", (0, 0, 0): " ",
}


def shadow_art(grid, fades):
    height, width = len(grid), max(map(len, grid))

    def filled(r, c):
        return 0 <= r < height and 0 <= c < len(grid[r]) and grid[r][c] == "X"

    lines = []
    for r in range(height + 1):  # one row more, for the shadow below
        line = ""
        for c in range(width + 1):  # one column more, for the shadow at right
            if filled(r, c):
                line += fades[min(r, len(fades) - 1)]
            else:
                key = (filled(r, c - 1), filled(r - 1, c), filled(r - 1, c - 1))
                line += SHADOW[tuple(int(k) for k in key)]
        lines.append(line.rstrip())
    reflection = "".join("░" if filled(height - 1, c) else " " for c in range(width))
    lines.append(reflection.rstrip())
    return lines


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        grid = [line.rstrip("\n") for line in f if line.strip()]
    print("\n".join(shadow_art(grid, sys.argv[2])))


if __name__ == "__main__":
    main()
