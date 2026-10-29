import hashlib
import io
import struct
import unittest
import warnings
import zipfile
from unittest.mock import patch

import bootanimation_geometry as geometry


def fixture(*, desc=geometry.SOURCE_DESC, trims=None, dimensions=(1402, 1800),
            counts=None, compression=zipfile.ZIP_STORED, omit=(), duplicate=False, reverse=False):
    counts = counts or geometry.PART_FRAME_COUNTS
    # Opaque fixture bytes with an IHDR header, never decoded or rendered.
    png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + struct.pack(">II", *dimensions) + b"original-frame-payload\0\xff"
    entries = [("desc.txt", desc)]
    for part, count in counts.items():
        entries.extend((f"{part}/frame{i:03}.png", png + str(i).encode()) for i in range(count))
        entries.append((part + "/trim.txt", (trims or {}).get(part, geometry.SOURCE_TRIM * count)))
    entries.append(("shader.txt", b"unchanged shader payload\n"))
    if duplicate:
        entries.append(entries[1])
    if reverse:
        entries.reverse()
    buffer = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(buffer, "w") as archive:
        warnings.simplefilter("ignore", UserWarning)
        archive.comment = b"preserved archive comment"
        for name, payload in entries:
            if name in omit:
                continue
            info = zipfile.ZipInfo(name, (2026, 9, 24, 5, 37, 44))
            info.compress_type = compression
            info.create_system = 3
            info.create_version = 30
            info.extract_version = 20
            info.internal_attr = 1
            info.external_attr = 0o100640 << 16
            info.extra = struct.pack("<HH4s", 0xCAFE, 4, b"meta")
            info.comment = b"preserved member comment"
            archive.writestr(info, payload)
    return buffer.getvalue()


class BootanimationGeometryTests(unittest.TestCase):
    def fix_fixture(self, data):
        with patch.object(geometry, "SOURCE_SHA256", hashlib.sha256(data).hexdigest()):
            return geometry.fix_geometry(data)

    def test_only_geometry_text_changes_with_pngs_order_and_metadata_preserved(self):
        data = fixture()
        result = self.fix_fixture(data)
        self.assertEqual(len(result), len(data))
        with zipfile.ZipFile(io.BytesIO(data)) as before, zipfile.ZipFile(io.BytesIO(result)) as after:
            self.assertIsNone(after.testzip())
            self.assertEqual(after.namelist(), before.namelist())
            self.assertEqual(after.comment, before.comment)
            self.assertEqual(after.read("desc.txt"), b"2544 1800 60\nc 1 0 part0\nc 120 0 part1\nc 1 0 part2\n")
            changed = []
            png_count = 0
            for old, new in zip(before.infolist(), after.infolist()):
                for field in ("filename", "date_time", "compress_type", "comment", "extra", "create_system",
                              "create_version", "extract_version", "reserved", "flag_bits", "volume",
                              "internal_attr", "external_attr", "file_size", "compress_size", "header_offset"):
                    self.assertEqual(getattr(new, field), getattr(old, field), (old.filename, field))
                original, actual = before.read(old), after.read(new)
                if original != actual:
                    changed.append(old.filename)
                if old.filename.endswith(".png"):
                    png_count += 1
                    self.assertEqual(hashlib.sha256(original).digest(), hashlib.sha256(actual).digest())
                    self.assertEqual(old.CRC, new.CRC)
                if old.filename.endswith("/trim.txt"):
                    self.assertEqual(actual.splitlines(), [b"1402x1800+571+0"] * len(original.splitlines()))
            self.assertEqual(png_count, 145)
            self.assertEqual(changed, ["desc.txt", "part0/trim.txt", "part1/trim.txt", "part2/trim.txt"])
            self.assertEqual(after.read("shader.txt"), before.read("shader.txt"))
        self.assertEqual((2544 - 1402) // 2, 571)
        self.assertEqual(3392 * 3, 2544 * 4)
        self.assertEqual(2400 * 3, 1800 * 4)

    def test_source_pin_rejects_other_archives_reordering_and_repeat_application(self):
        data = fixture()
        with self.assertRaisesRegex(ValueError, "source ZIP drift"):
            geometry.fix_geometry(data)
        with patch.object(geometry, "SOURCE_SHA256", hashlib.sha256(data).hexdigest()):
            fixed = geometry.fix_geometry(data)
            for invalid in [data + b"drift", fixture(reverse=True), fixed]:
                with self.subTest(invalid=hashlib.sha256(invalid).hexdigest()), self.assertRaisesRegex(ValueError, "source ZIP drift"):
                    geometry.fix_geometry(invalid)

    def test_canvas_fps_parts_and_repetition_drift_rejected(self):
        for desc in [geometry.SOURCE_DESC.replace(b"2880", b"2544"),
                     geometry.SOURCE_DESC.replace(b"60\n", b"30\n"),
                     geometry.SOURCE_DESC.replace(b"c 120", b"c 119"),
                     geometry.SOURCE_DESC.replace(b"part2", b"part3")]:
            with self.subTest(desc=desc), self.assertRaisesRegex(ValueError, "description"):
                self.fix_fixture(fixture(desc=desc))

    def test_all_trim_lines_and_counts_are_guarded(self):
        for part, count in geometry.PART_FRAME_COUNTS.items():
            for trim in [geometry.TARGET_TRIM * count, geometry.SOURCE_TRIM * (count - 1),
                         geometry.SOURCE_TRIM * count + b"\n", b"1402x1799+739+0\n" * count]:
                with self.subTest(part=part, trim=trim[:30]), self.assertRaisesRegex(ValueError, "trim entries"):
                    self.fix_fixture(fixture(trims={part: trim}))

    def test_png_dimensions_and_frame_count_are_guarded(self):
        for dimensions in [(1401, 1800), (1402, 1799)]:
            with self.subTest(dimensions=dimensions), self.assertRaisesRegex(ValueError, "PNG dimensions"):
                self.fix_fixture(fixture(dimensions=dimensions))
        with self.assertRaisesRegex(ValueError, "PNG count"):
            self.fix_fixture(fixture(counts={"part0": 97, "part1": 1, "part2": 46}))

    def test_missing_duplicate_or_recompressed_members_are_rejected(self):
        for omitted in [("desc.txt",), ("part1/trim.txt",)]:
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                self.fix_fixture(fixture(omit=omitted))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.fix_fixture(fixture(duplicate=True))
        with self.assertRaisesRegex(ValueError, "stored"):
            self.fix_fixture(fixture(compression=zipfile.ZIP_DEFLATED))

    def test_input_must_be_immutable_bytes(self):
        for data in [None, "zip", bytearray(b"zip")]:
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, "must be bytes"):
                geometry.fix_geometry(data)


if __name__ == "__main__":
    unittest.main()
