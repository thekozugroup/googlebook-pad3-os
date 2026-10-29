import io
import struct
import unittest

from android_disk import checked_hash, inventory, read_at


class RejectCorruptImages(unittest.TestCase):
    def test_truncation(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            read_at(io.BytesIO(b"123"), 0, 4)

    def test_negative_range(self):
        with self.assertRaisesRegex(ValueError, "negative"):
            read_at(io.BytesIO(), -1, 1)

    def test_invalid_signature(self):
        with self.assertRaisesRegex(ValueError, "signature"):
            inventory(io.BytesIO(bytes(2048)), 2048)

    def test_corrupt_gpt_header(self):
        image = bytearray(2048)
        image[512:520] = b"EFI PART"
        struct.pack_into("<I", image, 524, 92)
        with self.assertRaisesRegex(ValueError, "CRC"):
            inventory(io.BytesIO(image), len(image))

    def test_corrupt_metadata_hash(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            checked_hash(bytes(52), 8, 40, bytes(32))


if __name__ == "__main__":
    unittest.main()
