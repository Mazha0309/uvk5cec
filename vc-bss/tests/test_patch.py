from __future__ import annotations

import unittest

from patch_firmware import encode_thumb_b, encode_thumb_bl


class ThumbEncodingTests(unittest.TestCase):
    def test_existing_backward_bl(self) -> None:
        self.assertEqual(encode_thumb_bl(0x4D50, 0x1B1C), bytes.fromhex("fcf7e4fe"))

    def test_existing_short_backward_bl(self) -> None:
        self.assertEqual(encode_thumb_bl(0x46C0, 0x43DC), bytes.fromhex("fff78cfe"))

    def test_short_forward_branch(self) -> None:
        self.assertEqual(encode_thumb_b(0x92C6, 0x92DA), bytes.fromhex("08e0"))


if __name__ == "__main__":
    unittest.main()
