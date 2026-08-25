#!/usr/bin/env python3
"""Static safety checks for the generated CEC 0.3VC BSS image."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from patch_firmware import (
    BASE_PACKED_SHA256,
    CAVE_END,
    CAVE_START,
    MENU_RECORD_SIZE,
    MENU_START,
    WELCOME_MESSAGE_END,
    WELCOME_MESSAGE_START,
    encode_thumb_b,
    encode_thumb_bl,
    read_symbols,
    unpack_firmware,
    welcome_message_patch,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--packed", type=Path, required=True)
    parser.add_argument("--symbols", type=Path, required=True)
    args = parser.parse_args()

    base_packed = args.base.read_bytes()
    assert hashlib.sha256(base_packed).hexdigest() == BASE_PACKED_SHA256
    base_raw, _ = unpack_firmware(base_packed)
    raw = args.raw.read_bytes()
    packed_raw, version = unpack_firmware(args.packed.read_bytes())
    assert raw == packed_raw
    assert version.rstrip(b"\0") == b"*Mazha0309 03VC"
    assert raw[0xDC38:0xDC43] == b" Mazha0309\0"
    assert b"CEC 0.3VC BSS | Mazha0309 | assisted by GPT-5.6 Sol\0" in raw[CAVE_START:CAVE_END]

    symbols = read_symbols(args.symbols)
    assert symbols["CEC_APRS_ClockStart"] == 0x0BC4
    assert symbols["BK4819_ReadRegister"] == 0x1178
    assert symbols["BK4819_WriteRegister"] == 0x13C8
    assert symbols["CEC_APRS_Setup"] == 0x1B60
    assert symbols["CEC_APRS_Stop"] == 0x1684
    assert symbols["CEC_HDLC_SendByte"] == 0x1500
    assert symbols["SETTINGS_FetchChannelName"] == 0x7E9A
    assert raw[0x4C9A:0x4C9E] == encode_thumb_bl(0x4C9A, symbols["bss_tail_hook"])
    assert raw[0x4D18:0x4D1C] == base_raw[0x4D18:0x4D1C]
    assert raw[0x92C2:0x92C6] == encode_thumb_bl(0x92C2, symbols["format_uinfo_label"])
    assert raw[0x9426:0x942A] == encode_thumb_bl(0x9426, symbols["roger_option_label"])
    assert raw[0x942A:0x9432] == (
        bytes.fromhex("01000023")
        + encode_thumb_b(0x942E, 0x8D8C)
        + bytes.fromhex("c046")
    )
    assert raw[WELCOME_MESSAGE_START:WELCOME_MESSAGE_END] == welcome_message_patch(
        symbols["SETTINGS_FetchChannelName"]
    )
    assert symbols["inject_end"] <= CAVE_END

    # Menu range, display and persistence patches.
    assert raw[0x027B] == 0x44  # BSS POS max = 1
    assert raw[0x02A0] == 0x38  # Roger max = 3
    assert raw[0x7088:0x708A] == bytes.fromhex("032b")
    assert raw[0x72BA:0x72BC] == bytes.fromhex("012b")
    assert raw[0x8E2A:0x8E2C] == bytes.fromhex("0422")
    assert raw[0x8E32:0x8E34] == bytes.fromhex("3d31")
    assert raw[0xB22C:0xB22E] == bytes.fromhex("032b")
    assert raw[0xB558:0xB55A] == bytes.fromhex("0328")

    # The bit clock is essential: HDLC_SendByte blocks waiting for its tick.
    # Verify the linked firmware keeps the same setup/clock/stop lifecycle as
    # CEC's native APRS sender, in that exact order.
    lifecycle_calls = []
    function_start = symbols["bss_send_tail"]
    function_end = symbols["FirmwareAttribution"]
    for name, target in (
        ("setup", 0x1B60),
        ("clock", 0x0BC4),
        ("stop", 0x1684),
    ):
        hits = [
            address for address in range(function_start, function_end, 2)
            if raw[address:address + 4] == encode_thumb_bl(address, target)
        ]
        assert len(hits) == 1, f"expected one APRS {name} call, got {hits}"
        lifecycle_calls.append(hits[0])
    assert lifecycle_calls == sorted(lifecycle_calls)

    for address in (0x46C0, 0x568E, 0xBEAE):
        assert raw[address:address + 4] == bytes.fromhex("c046c046")

    menu_ids = []
    menu_names = []
    for index in range(100):
        start = MENU_START + index * MENU_RECORD_SIZE
        record = raw[start:start + MENU_RECORD_SIZE]
        if record[0] == 0:
            break
        menu_names.append(record[:7].rstrip(b"\0"))
        menu_ids.append(record[8])
    assert 0x1C not in menu_ids and 0x1D not in menu_ids
    assert b"T.WSPR" not in menu_names and b"DIG.M" not in menu_names
    assert b"T.APRS" in menu_names and b"T.SSTV" in menu_names and b"MySSID" in menu_names
    assert b"BSSPOS" in menu_names and b"CW KEY" not in menu_names
    terminator = bytes(7) + bytes.fromhex("ffff")
    for index in (70, 71, 72):
        start = MENU_START + index * MENU_RECORD_SIZE
        assert raw[start:start + MENU_RECORD_SIZE] == terminator

    allowed = [
        (CAVE_START, CAVE_END),
        (0x027B, 0x027C),
        (0x02A0, 0x02A1),
        (0x46C0, 0x46C4),
        (0x4C9A, 0x4C9E),
        (0x568E, 0x5692),
        (0x7088, 0x708A),
        (0x72BA, 0x72BC),
        (0x8E2A, 0x8E2C),
        (0x8E32, 0x8E34),
        (0x92BE, 0x92C8),
        (0x9426, 0x9432),
        (0xB22C, 0xB22E),
        (0xB558, 0xB55A),
        (0xBEAE, 0xBEB2),
        (WELCOME_MESSAGE_START, WELCOME_MESSAGE_END),
        (0xDC38, 0xDC43),
        (MENU_START, MENU_START + 73 * MENU_RECORD_SIZE),
    ]
    unexpected = [
        offset for offset, (before, after) in enumerate(zip(base_raw, raw))
        if before != after and not any(start <= offset < end for start, end in allowed)
    ]
    assert not unexpected, f"unexpected modified offsets: {unexpected[:16]}"

    print(f"verified raw SHA-256: {hashlib.sha256(raw).hexdigest()}")
    print(f"verified packed SHA-256: {hashlib.sha256(args.packed.read_bytes()).hexdigest()}")
    print(f"injection end: 0x{symbols['inject_end']:04X}; cave end: 0x{CAVE_END:04X}")
    print("menu: Roger adds BSS; BSS POS is OFF/ON; CW KEY, DIG.M and T.WSPR removed")
    print("startup MESSAGE: U.Info MY CALL + MY NAME")


if __name__ == "__main__":
    main()
