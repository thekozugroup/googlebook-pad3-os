import hashlib
import io
import struct
import unittest
import zipfile
import zlib
from unittest.mock import patch

import desktop_repair_gate as gate


def seal(dex):
    dex[12:32] = hashlib.sha1(dex[32:]).digest()
    struct.pack_into("<I", dex, 8, zlib.adler32(dex[12:]) & 0xffffffff)
    return bytes(dex)


def dex_fixture():
    dex = bytearray(gate.INSTRUCTION_OFFSET + 4)
    dex[:8] = b"dex\n039\0"
    struct.pack_into("<III", dex, 32, len(dex), 112, 0x12345678)
    struct.pack_into("<II", dex, 88, 42117, 390084)
    dex[390084 + gate.METHOD_ID * 8:390084 + (gate.METHOD_ID + 1) * 8] = bytes.fromhex("4c02762435720000")
    dex[gate.CODE_OFFSET:gate.INSTRUCTION_OFFSET] = gate.CODE_HEADER
    dex[gate.INSTRUCTION_OFFSET:] = gate.OLD_INSTRUCTIONS
    return seal(dex)


def jar_fixture(dex, compression=zipfile.ZIP_STORED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.comment = b"retained archive comment"
        for name, payload, method in [("metadata.txt", b"compressed payload\n" * 100, zipfile.ZIP_DEFLATED),
                                      ("classes.dex", dex, compression), ("classes2.dex", b"untouched second DEX", 0)]:
            info = zipfile.ZipInfo(name, (2008, 1, 1, 0, 0, 0))
            info.compress_type = method
            info.external_attr = 0o100644 << 16
            info.extra = struct.pack("<HH4s", 0xcafe, 4, b"meta")
            info.comment = b"retained member comment"
            archive.writestr(info, payload)
    return buffer.getvalue()


class RepairGateTests(unittest.TestCase):
    def patch_fixture(self, dex=None, compression=zipfile.ZIP_STORED):
        dex = dex if dex is not None else dex_fixture()
        source = jar_fixture(dex, compression)
        with patch.object(gate, "JAR_SHA256", hashlib.sha256(source).hexdigest()), \
                patch.object(gate, "DEX_SHA256", hashlib.sha256(dex).hexdigest()):
            return source, gate.disable_repair_mode(source)

    def test_one_instruction_checksums_and_other_jar_bytes_are_preserved(self):
        source, result = self.patch_fixture()
        self.assertEqual(len(source), len(result))
        with zipfile.ZipFile(io.BytesIO(source)) as before, zipfile.ZipFile(io.BytesIO(result)) as after:
            self.assertEqual(before.namelist(), after.namelist())
            self.assertEqual(before.comment, after.comment)
            self.assertIsNone(after.testzip())
            for old, new in zip(before.infolist(), after.infolist()):
                for field in ["filename", "header_offset", "compress_type", "compress_size", "file_size", "date_time",
                              "flag_bits", "extra", "comment", "external_attr", "internal_attr", "create_system",
                              "create_version", "extract_version"]:
                    self.assertEqual(getattr(old, field), getattr(new, field), (old.filename, field))
                if old.filename != "classes.dex":
                    self.assertEqual(old.CRC, new.CRC)
                    self.assertEqual(before.read(old), after.read(new))
                    start, end = old.header_offset, old.header_offset + 30 + len(old.filename) + len(old.extra) + old.compress_size
                    self.assertEqual(source[start:end], result[start:end])
            old, new = before.read("classes.dex"), after.read("classes.dex")
        self.assertEqual(new[gate.INSTRUCTION_OFFSET:gate.INSTRUCTION_OFFSET + 4], b"\x12\x00\x0f\x00")
        self.assertTrue(gate.valid_checksums(new))
        delta = {i for i, (a, b) in enumerate(zip(old, new)) if a != b}
        self.assertIn(gate.INSTRUCTION_OFFSET + 1, delta)
        self.assertLessEqual(delta, set(range(8, 32)) | {gate.INSTRUCTION_OFFSET + 1})
        self.assertEqual(new[gate.CODE_OFFSET:gate.INSTRUCTION_OFFSET], gate.CODE_HEADER)

    def test_jar_and_dex_source_hashes_fail_closed(self):
        source = jar_fixture(dex_fixture())
        with self.assertRaisesRegex(ValueError, "JAR source drift"):
            gate.disable_repair_mode(source)
        with patch.object(gate, "JAR_SHA256", hashlib.sha256(source).hexdigest()):
            with self.assertRaisesRegex(ValueError, "DEX source drift"):
                gate.disable_repair_mode(source)

    def test_header_method_code_and_instruction_drift_fail_closed(self):
        for offset, message in [(36, "DEX header"), (390084 + gate.METHOD_ID * 8, "method ID"),
                                (gate.CODE_OFFSET, "code-item header"), (gate.INSTRUCTION_OFFSET + 1, "instructions")]:
            dex = bytearray(dex_fixture())
            dex[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, message):
                self.patch_fixture(seal(dex))

    def test_invalid_checksums_and_compressed_target_are_refused(self):
        dex = bytearray(dex_fixture())
        dex[8] ^= 1
        with self.assertRaisesRegex(ValueError, "source DEX checksums"):
            self.patch_fixture(bytes(dex))
        with self.assertRaisesRegex(ValueError, "must remain stored"):
            self.patch_fixture(compression=zipfile.ZIP_DEFLATED)

    def test_repeat_application_is_refused(self):
        source, result = self.patch_fixture()
        with patch.object(gate, "JAR_SHA256", hashlib.sha256(source).hexdigest()):
            with self.assertRaisesRegex(ValueError, "JAR source drift"):
                gate.disable_repair_mode(result)

    def test_shared_replacement_rejects_size_change(self):
        source = jar_fixture(dex_fixture())
        with self.assertRaisesRegex(ValueError, "replacement size mismatch"):
            gate.replace_stored_dex(source, lambda dex: dex + b"\0")


if __name__ == "__main__":
    unittest.main()
