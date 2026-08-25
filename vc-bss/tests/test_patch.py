from __future__ import annotations

import unittest

from patch_firmware import encode_thumb_b, encode_thumb_bl, welcome_message_patch


class ThumbEncodingTests(unittest.TestCase):
    def test_existing_backward_bl(self) -> None:
        self.assertEqual(encode_thumb_bl(0x4D50, 0x1B1C), bytes.fromhex("fcf7e4fe"))

    def test_existing_short_backward_bl(self) -> None:
        self.assertEqual(encode_thumb_bl(0x46C0, 0x43DC), bytes.fromhex("fff78cfe"))

    def test_short_forward_branch(self) -> None:
        self.assertEqual(encode_thumb_b(0x92C6, 0x92DA), bytes.fromhex("08e0"))

    def test_welcome_message_patch(self) -> None:
        self.assertEqual(
            welcome_message_patch(0x7E9A),
            bytes.fromhex(
                "06a8aa21fbf785fe2000ab21fbf781fe"
                "c046c046c046c046d7e7"
            ),
        )


if __name__ == "__main__":
    unittest.main()
