from __future__ import annotations

import unittest


def fcs(payload: bytes) -> int:
    crc = 0xFFFF
    for value in payload:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def stuffed_bits(frame: bytes) -> list[int]:
    output: list[int] = []
    ones = 0
    for value in frame:
        for index in range(8):
            bit = (value >> index) & 1
            output.append(bit)
            if bit:
                ones += 1
                if ones == 5:
                    output.append(0)
                    ones = 0
            else:
                ones = 0
    return output


def unstuff(bits: list[int]) -> bytes:
    output: list[int] = []
    ones = 0
    index = 0
    while index < len(bits):
        bit = bits[index]
        output.append(bit)
        index += 1
        if bit:
            ones += 1
            if ones == 5:
                if index >= len(bits) or bits[index] != 0:
                    raise ValueError("missing stuffed zero")
                index += 1
                ones = 0
        else:
            ones = 0
    if len(output) % 8:
        raise ValueError("decoded bit count is not byte aligned")
    return bytes(
        sum(output[offset + bit] << bit for bit in range(8))
        for offset in range(0, len(output), 8)
    )


class HdlcRoundTripTests(unittest.TestCase):
    def test_bss_payload_round_trip(self) -> None:
        payload = bytes.fromhex(
            "018b1234567807204e3043414c4c"
            "0d250dca1637310a00000000ffff"
        )
        checksum = fcs(payload)
        self.assertEqual(checksum, 0x5526)
        framed = payload + checksum.to_bytes(2, "little")
        self.assertEqual(unstuff(stuffed_bits(framed)), framed)
        self.assertEqual(fcs(framed), 0x0F47)  # AX.25 good-frame residue form


if __name__ == "__main__":
    unittest.main()
