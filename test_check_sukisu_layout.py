import struct
import unittest

from check_sukisu_layout import btf_types, field_offsets
from native_install.patch_sukisu_module import patch


class BtfLayoutTests(unittest.TestCase):
    def test_module_patch_rejects_unrecognized_release_before_mutation(self):
        for data in (b"", b"\x7fELF" + bytes(561180), bytes(561184)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                patch(data)

    def test_duplicate_structs_and_anonymous_union_offsets(self):
        strings = b"\0int\0f_inode\0file\0"
        integer = struct.pack("<IIII", 1, 1 << 24, 4, 32)
        union = struct.pack("<IIIIII", 0, 5 << 24 | 1, 4, 5, 1, 0)
        file = struct.pack("<IIIIII", 13, 4 << 24 | 1, 16, 0, 2, 64)
        body = integer + union + file + file
        blob = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(body), len(body), len(strings)) + body + strings
        types = btf_types(blob)
        self.assertEqual(field_offsets(types, 3, "f_inode"), [64])
        self.assertEqual(field_offsets(types, 4, "f_inode"), [64])
        with self.assertRaises(ValueError):
            btf_types(blob[:-1])
        with self.assertRaises(ValueError):
            btf_types(b"\0" * 24)

    def test_anonymous_member_cycle_is_rejected(self):
        types = [None, {"kind": 4, "members": [{"name": "", "type_id": 1, "bit_offset": 0}]}]
        with self.assertRaises(ValueError):
            field_offsets(types, 1, "f_inode")


if __name__ == "__main__":
    unittest.main()
