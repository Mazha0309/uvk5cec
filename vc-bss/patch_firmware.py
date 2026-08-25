#!/usr/bin/env python3
"""Inject the BSS tail into the official packed CEC 0.3VC image."""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path


KEY = bytes([
    0x47, 0x22, 0xC0, 0x52, 0x5D, 0x57, 0x48, 0x94, 0xB1, 0x60, 0x60, 0xDB, 0x6F, 0xE3, 0x4C, 0x7C,
    0xD8, 0x4A, 0xD6, 0x8B, 0x30, 0xEC, 0x25, 0xE0, 0x4C, 0xD9, 0x00, 0x7F, 0xBF, 0xE3, 0x54, 0x05,
    0xE9, 0x3A, 0x97, 0x6B, 0xB0, 0x6E, 0x0C, 0xFB, 0xB1, 0x1A, 0xE2, 0xC9, 0xC1, 0x56, 0x47, 0xE9,
    0xBA, 0xF1, 0x42, 0xB6, 0x67, 0x5F, 0x0F, 0x96, 0xF7, 0xC9, 0x3C, 0x84, 0x1B, 0x26, 0xE1, 0x4E,
    0x3B, 0x6F, 0x66, 0xE6, 0xA0, 0x6A, 0xB0, 0xBF, 0xC6, 0xA5, 0x70, 0x3A, 0xBA, 0x18, 0x9E, 0x27,
    0x1A, 0x53, 0x5B, 0x71, 0xB1, 0x94, 0x1E, 0x18, 0xF2, 0xD6, 0x81, 0x02, 0x22, 0xFD, 0x5A, 0x28,
    0x91, 0xDB, 0xBA, 0x5D, 0x64, 0xC6, 0xFE, 0x86, 0x83, 0x9C, 0x50, 0x1C, 0x73, 0x03, 0x11, 0xD6,
    0xAF, 0x30, 0xF4, 0x2C, 0x77, 0xB2, 0x7D, 0xBB, 0x3F, 0x29, 0x28, 0x57, 0x22, 0xD6, 0x92, 0x8B,
])

BASE_PACKED_SHA256 = "3f7c961a4d903f70349b2bff76819e9eee669c90e32bf4da8593b7e0d6d83ba2"
BASE_RAW_SHA256 = "1964f313b32e90ed6f93b7650d1f22a8d01a3d20fe638d90286b5772ab043be4"
CAVE_START = 0x3DC4
CAVE_END = 0x4538
MENU_START = 0xE178
MENU_RECORD_SIZE = 9


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def unpack_firmware(packed_with_crc: bytes) -> tuple[bytearray, bytes]:
    if len(packed_with_crc) < 0x2012:
        raise ValueError("packed firmware is too short")
    packed = packed_with_crc[:-2]
    stored_crc = int.from_bytes(packed_with_crc[-2:], "little")
    calculated_crc = crc16_xmodem(packed)
    if stored_crc != calculated_crc:
        raise ValueError(f"packed CRC mismatch: stored={stored_crc:04x}, calculated={calculated_crc:04x}")
    decoded = bytes(value ^ KEY[index % len(KEY)] for index, value in enumerate(packed))
    return bytearray(decoded[:0x2000] + decoded[0x2010:]), decoded[0x2000:0x2010]


def pack_firmware(raw: bytes, version: bytes) -> bytes:
    if len(version) > 16:
        raise ValueError("packed version is longer than 16 bytes")
    version = version.ljust(16, b"\0")
    plain = raw[:0x2000] + version + raw[0x2000:]
    packed = bytes(value ^ KEY[index % len(KEY)] for index, value in enumerate(plain))
    return packed + crc16_xmodem(packed).to_bytes(2, "little")


def require_bytes(image: bytearray, offset: int, expected: bytes, name: str) -> None:
    actual = bytes(image[offset:offset + len(expected)])
    if actual != expected:
        raise ValueError(f"{name} signature mismatch at 0x{offset:04X}: {actual.hex()} != {expected.hex()}")


def encode_thumb_bl(source: int, target: int) -> bytes:
    offset = target - (source + 4)
    if offset & 1 or not -(1 << 24) <= offset < (1 << 24):
        raise ValueError(f"invalid Thumb BL displacement from 0x{source:X} to 0x{target:X}")
    bits = offset & ((1 << 25) - 1)
    sign = (bits >> 24) & 1
    i1 = (bits >> 23) & 1
    i2 = (bits >> 22) & 1
    imm10 = (bits >> 12) & 0x3FF
    imm11 = (bits >> 1) & 0x7FF
    j1 = (~(i1 ^ sign)) & 1
    j2 = (~(i2 ^ sign)) & 1
    first = 0xF000 | (sign << 10) | imm10
    second = 0xD000 | (j1 << 13) | (j2 << 11) | imm11
    return struct.pack("<HH", first, second)


def encode_thumb_b(source: int, target: int) -> bytes:
    offset = target - (source + 4)
    if offset & 1 or not -2048 <= offset <= 2046:
        raise ValueError(f"invalid Thumb B displacement from 0x{source:X} to 0x{target:X}")
    return struct.pack("<H", 0xE000 | ((offset >> 1) & 0x7FF))


def read_symbols(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    pattern = re.compile(r"^([0-9a-fA-F]+)\s+\w\s+(\S+)$")
    for line in path.read_text().splitlines():
        match = pattern.match(line.strip())
        if match:
            symbols[match.group(2)] = int(match.group(1), 16) & ~1
    return symbols


def remove_digital_menu_items(image: bytearray) -> None:
    records: list[bytes] = []
    for index in range(100):
        start = MENU_START + index * MENU_RECORD_SIZE
        record = bytes(image[start:start + MENU_RECORD_SIZE])
        if len(record) != MENU_RECORD_SIZE:
            raise ValueError("truncated menu table")
        records.append(record)
        if record[0] == 0:
            break
    else:
        raise ValueError("menu terminator not found")

    cw_key = [record for record in records if record[8] == 0x11]
    if len(cw_key) != 1 or cw_key[0][:7].rstrip(b"\0") != b"CW KEY":
        raise ValueError("CEC 0.3VC CW KEY menu record was not found as expected")
    records = [
        b"BSSPOS\0" + record[7:] if record[8] == 0x11 else record
        for record in records
    ]

    removed = [record for record in records if record[8] in (0x1C, 0x1D)]
    if [record[:7].rstrip(b"\0") for record in removed] != [b"DIG.M", b"T.WSPR"]:
        raise ValueError("CEC 0.3VC digital menu records were not found as expected")
    kept = [record for record in records if record[8] not in (0x1C, 0x1D)]
    # Keep a valid 0xFFFF terminator in every vacated record as well.  Normal
    # navigation stops at the first one; the duplicates preserve the original
    # array's defensive last-element fallback.
    packed = b"".join(kept + [records[-1]] * len(removed))
    image[MENU_START:MENU_START + len(packed)] = packed


def patch_image(raw: bytearray, injection: bytes, symbols: dict[str, int]) -> None:
    if hashlib.sha256(raw).hexdigest() != BASE_RAW_SHA256:
        raise ValueError("input is not the exact official CEC 0.3VC raw image")
    if len(injection) > CAVE_END - CAVE_START:
        raise ValueError(f"injection is {len(injection)} bytes; cave holds {CAVE_END - CAVE_START}")
    for required in ("bss_tail_hook", "format_uinfo_label", "roger_option_label", "inject_end"):
        if required not in symbols:
            raise ValueError(f"missing injection symbol: {required}")
    if symbols["bss_tail_hook"] != CAVE_START:
        raise ValueError("bss_tail_hook must be the first cave symbol")
    if not CAVE_START <= symbols["format_uinfo_label"] < CAVE_END:
        raise ValueError("format_uinfo_label is outside the reclaimed cave")

    raw[CAVE_START:CAVE_END] = b"\0" * (CAVE_END - CAVE_START)
    raw[CAVE_START:CAVE_START + len(injection)] = injection

    require_bytes(raw, 0x4C9A, bytes.fromhex("ab1ddb7f"), "APP_EndTransmission hook")
    raw[0x4C9A:0x4C9E] = encode_thumb_bl(0x4C9A, symbols["bss_tail_hook"])

    # MENU_GetLimits: CW KEY is repurposed as the two-state BSS POS switch;
    # Roger gains a fourth BSS mode.
    require_bytes(raw, 0x027B, bytes.fromhex("4f"), "CW KEY menu maximum")
    raw[0x027B] = 0x44  # shared MENU_GetLimits target: maximum 1
    require_bytes(raw, 0x02A0, bytes.fromhex("4f"), "Roger menu maximum")
    raw[0x02A0] = 0x38  # shared MENU_GetLimits target: maximum 3

    # Persist Roger=3 rather than treating it as corrupt at boot.
    require_bytes(raw, 0x7088, bytes.fromhex("022b"), "Roger EEPROM validation")
    raw[0x7088:0x708A] = bytes.fromhex("032b")

    # The old CW key EEPROM byte now stores BSS POS.  Clamp legacy values to
    # OFF, render it with the firmware's existing OFF/ON table, and make both
    # external-key runtime branches unreachable for the new 0/1 values.
    require_bytes(raw, 0x72BA, bytes.fromhex("9342"), "CW KEY EEPROM validation")
    raw[0x72BA:0x72BC] = bytes.fromhex("012b")  # cmp r3, #1
    require_bytes(raw, 0x8E2A, bytes.fromhex("0522"), "CW KEY option stride")
    raw[0x8E2A:0x8E2C] = bytes.fromhex("0422")
    require_bytes(raw, 0x8E32, bytes.fromhex("1631"), "CW KEY option table")
    raw[0x8E32:0x8E34] = bytes.fromhex("3d31")  # 0xDCE4 + 61 = OFF/ON
    require_bytes(raw, 0xB22C, bytes.fromhex("022b"), "iambic key runtime branch")
    raw[0xB22C:0xB22E] = bytes.fromhex("032b")
    require_bytes(raw, 0xB558, bytes.fromhex("0128"), "straight key runtime branch")
    raw[0xB558:0xB55A] = bytes.fromhex("0328")

    # The original Roger label table has no room after its third 6-byte item.
    # Ask the injected helper for a pointer, then reuse the existing copy path.
    require_bytes(
        raw,
        0x9426,
        bytes.fromhex("534b196806234b436149ace4"),
        "Roger option display",
    )
    raw[0x9426:0x9432] = (
        encode_thumb_bl(0x9426, symbols["roger_option_label"])
        + bytes.fromhex("01000023")  # movs r1,r0; movs r3,#0
        + encode_thumb_b(0x942E, 0x8D8C)
        + bytes.fromhex("c046")
    )

    require_bytes(raw, 0x92BE, bytes.fromhex("1a00b53aad49092a05d9"), "U.Info label hook")
    raw[0x92BE:0x92C8] = (
        bytes.fromhex("190004a8")
        + encode_thumb_bl(0x92C2, symbols["format_uinfo_label"])
        + encode_thumb_b(0x92C6, 0x92DA)
    )

    for address, expected in (
        (0x46C0, "fff78cfe"),
        (0x568E, "fef7a5fe"),
        (0xBEAE, "f8f72df9"),
    ):
        require_bytes(raw, address, bytes.fromhex(expected), "removed DigiManager/FT8 call")
        raw[address:address + 4] = bytes.fromhex("c046c046")

    remove_digital_menu_items(raw)

    require_bytes(raw, 0xDC38, b" CEC_0.3V\0\0", "firmware version")
    raw[0xDC38:0xDC43] = b" Mazha0309\0"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--inject", type=Path, required=True)
    parser.add_argument("--symbols", type=Path, required=True)
    parser.add_argument("--raw-output", type=Path, required=True)
    parser.add_argument("--packed-output", type=Path, required=True)
    args = parser.parse_args()

    packed = args.base.read_bytes()
    if hashlib.sha256(packed).hexdigest() != BASE_PACKED_SHA256:
        raise SystemExit("base file is not the exact official cec_0.3VC.packed.bin")
    raw, old_version = unpack_firmware(packed)
    symbols = read_symbols(args.symbols)
    injection = args.inject.read_bytes()
    patch_image(raw, injection, symbols)

    args.raw_output.write_bytes(raw)
    output = pack_firmware(bytes(raw), b"*Mazha0309 03VC")
    args.packed_output.write_bytes(output)
    print(f"base packed version: {old_version.rstrip(bytes([0]))!r}")
    print(f"injection: {len(injection)} / {CAVE_END - CAVE_START} bytes")
    print(f"raw output: {args.raw_output} ({len(raw)} bytes)")
    print(f"packed output: {args.packed_output} ({len(output)} bytes)")


if __name__ == "__main__":
    main()
