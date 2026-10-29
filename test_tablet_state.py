import hashlib
import io
import os
from pathlib import Path
import struct
import unittest
import zipfile
from unittest.mock import patch

import tablet_state as tablet
from test_desktop_repair_gate import jar_fixture, seal


ARTIFACT = Path(os.environ.get("PAD3_DESKTOP_SERVICES_JAR", "build-inputs/desktop-services.jar"))
BODY = bytes.fromhex("00005520080912f1380007005520050939000300281e55200909380008005520050939000400"
                     "1211281455200509390004001201280e55200809380004001231280855200809390004001221280200000f01")


def dex_fixture():
    dex = bytearray(tablet.CODE_OFFSET + tablet.CODE_SIZE)
    dex[:8] = b"dex\n039\0"
    struct.pack_into("<III", dex, 32, len(dex), 112, 0x12345678)
    struct.pack_into("<II", dex, 56, 41084, 112)
    struct.pack_into("<II", dex, 64, 4999, 164448)
    struct.pack_into("<II", dex, 72, 10222, 184444)
    struct.pack_into("<II", dex, 88, 42117, 390084)
    start = 390084 + tablet.METHOD_ID * 8
    dex[start:start + 8] = tablet.METHOD_ENTRY
    struct.pack_into("<III", dex, 184444 + 162 * 12, 0, 4, 0)
    for index, string_id in [(868, 1), (4, 2)]:
        struct.pack_into("<I", dex, 164448 + index * 4, string_id)
    offset = 1000000
    for string_id, text in [(1, tablet.METHOD.split("->")[0]), (2, "I"), (30679, "getDeviceState")]:
        payload = bytes([len(text)]) + text.encode() + b"\0"
        struct.pack_into("<I", dex, 112 + string_id * 4, offset)
        dex[offset:offset + len(payload)] = payload
        offset += len(payload)
    dex[tablet.CODE_OFFSET:tablet.INSTRUCTION_OFFSET] = tablet.CODE_HEADER
    dex[tablet.INSTRUCTION_OFFSET:] = BODY
    return seal(dex)


class TabletStateTests(unittest.TestCase):
    def patch_fixture(self, dex=None, compression=zipfile.ZIP_STORED):
        dex = dex_fixture() if dex is None else dex
        source = jar_fixture(dex, compression)
        with patch.object(tablet, "JAR_SHA256", hashlib.sha256(source).hexdigest()), \
                patch.object(tablet, "DEX_SHA256", hashlib.sha256(dex).hexdigest()):
            return source, tablet.patch_tablet_state(source)

    def assert_preserved(self, source, result):
        self.assertEqual(len(source), len(result))
        with zipfile.ZipFile(io.BytesIO(source)) as before, zipfile.ZipFile(io.BytesIO(result)) as after:
            self.assertEqual(before.namelist(), after.namelist())
            self.assertIsNone(after.testzip())
            old, new = before.read("classes.dex"), after.read("classes.dex")
            self.assertTrue(tablet.valid_checksums(new))
            self.assertEqual(new[tablet.RETURN_OFFSET], 0x31)
            self.assertEqual(new[:8], old[:8])
            self.assertEqual(new[32:tablet.RETURN_OFFSET], old[32:tablet.RETURN_OFFSET])
            self.assertEqual(new[tablet.RETURN_OFFSET + 1:], old[tablet.RETURN_OFFSET + 1:])
            info = before.getinfo("classes.dex")
            local = info.header_offset
            name, extra = struct.unpack_from("<HH", source, local + 26)
            payload = local + 30 + name + extra
            central = before.start_dir
            central_crc = None
            for entry in before.infolist():
                if entry.filename == "classes.dex":
                    central_crc = central + 16
                n, e, c = struct.unpack_from("<HHH", source, central + 28)
                central += 46 + n + e + c
                if entry.filename != "classes.dex":
                    self.assertEqual(before.read(entry), after.read(entry.filename))
            self.assertIsNotNone(central_crc)
            # Compare every archive byte outside the operand and required checksum fields.
            allowed = [(local + 14, 4), (central_crc, 4), (payload + 8, 24),
                       (payload + tablet.RETURN_OFFSET, 1)]
            position = 0
            for start, size in sorted(allowed):
                self.assertEqual(source[position:start], result[position:start])
                position = start + size
            self.assertEqual(source[position:], result[position:])

    def test_one_byte_and_all_other_archive_bytes(self):
        self.assert_preserved(*self.patch_fixture())

    def test_hashes_drift_and_reapplication_rejected(self):
        source, result = self.patch_fixture()
        with self.assertRaisesRegex(ValueError, "JAR source drift"):
            tablet.patch_tablet_state(source)
        with patch.object(tablet, "JAR_SHA256", hashlib.sha256(source).hexdigest()):
            with self.assertRaisesRegex(ValueError, "DEX source drift"):
                tablet.patch_tablet_state(source)
            with self.assertRaisesRegex(ValueError, "JAR source drift"):
                tablet.patch_tablet_state(result)

    def test_structural_guards_even_with_rebound_source_hash(self):
        for offset, message in [(36, "DEX header"), (390084 + tablet.METHOD_ID * 8, "method ID"),
                                (1000001, "method signature"), (tablet.CODE_OFFSET, "code-item header"),
                                (tablet.INSTRUCTION_OFFSET + 2, "full method drift"),
                                (tablet.RETURN_OFFSET, "full method drift")]:
            dex = bytearray(dex_fixture())
            dex[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, message):
                self.patch_fixture(seal(dex))

    def test_bad_checksums_and_compression_rejected(self):
        dex = bytearray(dex_fixture())
        dex[8] ^= 1
        with self.assertRaisesRegex(ValueError, "source DEX checksums"):
            self.patch_fixture(bytes(dex))
        with self.assertRaisesRegex(ValueError, "must remain stored"):
            self.patch_fixture(compression=zipfile.ZIP_DEFLATED)

    @unittest.skipUnless(ARTIFACT.is_file(), "private shipped artifact unavailable")
    def test_shipped_artifact_preservation_and_drift(self):
        source = ARTIFACT.read_bytes()
        self.assert_preserved(source, tablet.patch_tablet_state(source))
        for offset in [0, len(source) // 2, len(source) - 1]:
            drift = bytearray(source)
            drift[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "JAR source drift"):
                tablet.patch_tablet_state(bytes(drift))
        with self.assertRaisesRegex(ValueError, "JAR source drift"):
            tablet.patch_tablet_state(tablet.patch_tablet_state(source))


if __name__ == "__main__":
    unittest.main()
