#!/usr/bin/env python3
"""Writes a 1024x1024 solid PNG, the source `cargo tauri icon` needs until a real icon exists.

Pure stdlib on purpose: the runner image is not guaranteed to carry ImageMagick, and a build
that dies on a placeholder icon wastes a full cycle.
"""

import struct
import sys
import zlib

SIZE = 1024
COLOUR = (13, 110, 110)


def chunk(kind, data):
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "icon.png"
    row = b"\x00" + bytes(COLOUR) * SIZE
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(row * SIZE, 9))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as f:
        f.write(png)
    print(f"{path}: {SIZE}x{SIZE} placeholder")


if __name__ == "__main__":
    main()
