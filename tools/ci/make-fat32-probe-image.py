#!/usr/bin/env python3
"""Create the deterministic raw FAT32 volume for the hosted storage probe."""

import argparse
import struct
from pathlib import Path


SECTOR_BYTES = 512
RESERVED = 32
CLUSTERS = 65_536
FAT_SECTORS = ((CLUSTERS + 2) * 4 + SECTOR_BYTES - 1) // SECTOR_BYTES
DATA_START = RESERVED + 2 * FAT_SECTORS
TOTAL_SECTORS = DATA_START + CLUSTERS
PROBE_BYTES = b"MRML FAT32 recovery fixture\n"


def create_image(path: Path) -> None:
    boot = bytearray(SECTOR_BYTES)
    boot[:11] = b"\xeb\x58\x90MRMLTEST"
    struct.pack_into("<HBHB", boot, 11, SECTOR_BYTES, 1, RESERVED, 2)
    boot[21] = 0xF8
    struct.pack_into("<II", boot, 32, TOTAL_SECTORS, FAT_SECTORS)
    # Root cluster occupies bytes 44..48; flags and version are zero.
    struct.pack_into("<IHH", boot, 44, 2, 1, 6)
    boot[64], boot[66] = 0x80, 0x29
    struct.pack_into("<I", boot, 67, 0x4D524D4C)
    boot[71:90] = b"NO NAME    FAT32   "
    boot[510:] = b"\x55\xaa"

    info = bytearray(SECTOR_BYTES)
    struct.pack_into("<I", info, 0, 0x41615252)
    struct.pack_into("<III", info, 484, 0x61417272, CLUSTERS - 2, 4)
    struct.pack_into("<I", info, 508, 0xAA550000)

    fat = bytearray(SECTOR_BYTES)
    struct.pack_into("<IIII", fat, 0, 0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF)

    directory = bytearray(SECTOR_BYTES)
    directory[:11] = b"PROBE   TXT"
    directory[11] = 0x21  # archived, read-only regular file
    struct.pack_into("<HI", directory, 26, 3, len(PROBE_BYTES))

    # Exclusive creation never truncates a user file or follows an existing
    # symlink. All writes use bounded offsets in a newly created regular file.
    with path.open("xb") as image:
        image.truncate(TOTAL_SECTORS * SECTOR_BYTES)
        for lba, data in (
            (0, boot),
            (1, info),
            (6, boot),
            (7, info),
            (RESERVED, fat),
            (RESERVED + FAT_SECTORS, fat),
            (DATA_START, directory),
            (DATA_START + 1, PROBE_BYTES),
        ):
            image.seek(lba * SECTOR_BYTES)
            image.write(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    create_image(args.output)


if __name__ == "__main__":
    main()
