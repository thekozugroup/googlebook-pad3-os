"""Synthetic, offline SOURCE_COPY tests; optional payload-dumper-go verifies independently."""
import base64
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from native_install import payload


def decode_message(data):
    """Independent protobuf wire reader; no producer encoding helpers are used."""
    index = 0

    def integer():
        nonlocal index
        value = 0
        for shift in range(0, 70, 7):
            if index >= len(data):
                raise ValueError("truncated protobuf integer")
            byte = data[index]
            index += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError("oversized protobuf integer")

    fields = {}
    while index < len(data):
        tag = integer()
        number, wire = tag >> 3, tag & 7
        assert number > 0
        if wire == 0:
            value = integer()
        elif wire in (2, 5):
            size = integer() if wire == 2 else 4
            value = data[index:index + size]
            assert len(value) == size
            index += size
            if wire == 5:
                value = int.from_bytes(value, "little")
        else:
            raise ValueError("unsupported protobuf wire type")
        fields.setdefault(number, []).append(value)
    return fields


def decode_payload(blob):
    assert blob[:4] == b"CrAU"
    major, manifest_size, signature_size = struct.unpack_from(">QQI", blob, 4)
    assert major == 2
    end = 24 + manifest_size
    manifest = decode_message(blob[24:end])
    start = end + signature_size
    final_at = start + manifest[4][0]
    assert len(blob[final_at:]) == manifest[5][0] == signature_size
    partitions = {}
    for record in manifest[13]:
        part = decode_message(record)
        name = part[1][0].decode()
        assert name not in partitions
        partitions[name] = part
    return manifest, partitions, end, start, final_at


def reconstruct(blob, sources):
    """Check baseline, hashes, extents and blob coverage before returning images."""
    manifest, partitions, _, start, final_at = decode_payload(blob)
    block = manifest[3][0]
    body = blob[start:final_at]
    cursor, restored = 0, {}
    for name, part in partitions.items():
        info = decode_message(part[7][0])
        size = info[1][0]
        assert size > 0 and size % block == 0
        source = sources.get(name, b"")
        if 6 in part:
            old = decode_message(part[6][0])
            if len(source) != old[1][0] or hashlib.sha256(source).digest() != old[2][0]:
                raise ValueError("source baseline mismatch")
        image, covered = bytearray(size), set()
        for record in part[8]:
            op = decode_message(record)
            assert len(op[6]) == 1
            extent = decode_message(op[6][0])
            first, count = extent[1][0], extent[2][0]
            assert count > 0 and first + count <= size // block
            blocks = set(range(first, first + count))
            assert covered.isdisjoint(blocks)
            covered.update(blocks)
            if op[1] == [4]:
                assert set(op) == {1, 4, 6, 9} and op[4] == op[6]
                data = source[first * block:(first + count) * block]
                if hashlib.sha256(data).digest() != op[9][0]:
                    raise ValueError("source operation hash mismatch")
            else:
                assert op[1] == [0] and set(op) == {1, 2, 3, 6, 8}
                assert op[2] == [cursor] and cursor + op[3][0] <= len(body)
                data = body[cursor:cursor + op[3][0]]
                assert hashlib.sha256(data).digest() == op[8][0]
                cursor += len(data)
            assert len(data) == count * block
            image[first * block:(first + count) * block] = data
        assert covered == set(range(size // block))
        assert hashlib.sha256(image).digest() == info[2][0]
        restored[name] = bytes(image)
    assert cursor == len(body)
    return restored


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for real signing tests")
class SourceCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-source-copy-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.key, cls.cert = cls.directory / "ephemeral.key", cls.directory / "ephemeral.pem"
        payload.openssl("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
                        "-subj", "/CN=Disposable SOURCE_COPY test/", "-keyout", cls.key, "-out", cls.cert)
        cls.image_dir = cls.directory / "images"
        cls.image_dir.mkdir()
        names = ("system", "product", "system_ext", "vendor", "odm", "vendor_dlkm", "system_dlkm",
                 "boot", "init_boot", "vendor_boot", "dtbo", "recovery", "vbmeta", "vbmeta_system", "vbmeta_vendor")
        cls.images = {name: cls.image_dir / (name + ".img") for name in names}
        cls.sentinel = b"synthetic-private-material-only-in-installed-product"
        for index, (name, path) in enumerate(cls.images.items()):
            size = 4 * 1024**2 + 4096 if name in {"system", "product"} else 4096
            data = bytes([index + 65]) * size
            if name == "product":
                data = cls.sentinel + data[len(cls.sentinel):]
            path.write_bytes(data)
        cls.groups = [{"name": "test_dynamic", "maximum_size": 32 * 1024**2,
                       "partitions": list(names[:7])}]
        cls.output = cls.directory / "public.bin"
        cls.properties, cls.hashes = payload.write_payload(
            cls.images, cls.groups, 1793220000, True, cls.key, cls.cert, cls.output, cls.directory,
            source_copy_partitions={"product"})
        cls.copy_names = frozenset({
            "boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system", "vbmeta_vendor",
            "vendor", "odm", "vendor_dlkm", "system_dlkm", "product",
        })
        cls.twelve_output = cls.directory / "twelve-copies.bin"
        cls.twelve_properties, cls.twelve_hashes = payload.write_payload(
            cls.images, cls.groups, 1793220000, True, cls.key, cls.cert, cls.twelve_output, cls.directory,
            source_copy_partitions=cls.copy_names)

    def write(self, images, output, **options):
        return payload.write_payload(images, self.groups, 1793220000, True,
                                     self.key, self.cert, output, self.directory, **options)

    def test_wire_contract_reconstruction_and_no_product_bytes(self):
        blob = self.output.read_bytes()
        manifest, parts, _, start, final_at = decode_payload(blob)
        self.assertEqual(manifest[3], [4096])
        self.assertEqual(manifest[12], [6])
        self.assertEqual(manifest[16], [0])
        dynamic = decode_message(manifest[15][0])
        self.assertEqual(dynamic[2], [1])
        self.assertEqual(dynamic[3], [0])  # VABC stays disabled.
        self.assertEqual(list(parts), list(self.images))
        product = parts["product"]
        self.assertEqual(product[6], product[7])
        self.assertEqual(len(product[8]), 1)
        op = decode_message(product[8][0])
        self.assertEqual(op[1], [4])
        self.assertEqual(set(op), {1, 4, 6, 9})
        self.assertEqual(op[4], op[6])
        self.assertEqual(decode_message(op[4][0]), {1: [0], 2: [self.images["product"].stat().st_size // 4096]})
        self.assertEqual(op[9], decode_message(product[7][0])[2])
        for name, part in parts.items():
            if name != "product":
                self.assertNotIn(6, part)
                self.assertTrue(all(decode_message(record)[1] == [0] for record in part[8]))
        self.assertEqual(len(parts["system"][8]), 2)
        self.assertEqual(blob[start:final_at], b"".join(p.read_bytes() for n, p in self.images.items() if n != "product"))
        self.assertNotIn(self.sentinel, blob)
        expected = {name: path.read_bytes() for name, path in self.images.items()}
        self.assertEqual(reconstruct(blob, {"product": expected["product"]}), expected)
        self.assertEqual(self.hashes, {n: hashlib.sha256(data).hexdigest() for n, data in expected.items()})

    def test_wrong_or_missing_baseline_is_rejected(self):
        original = self.images["product"].read_bytes()
        for source in (None, original[:-4096], b"!" + original[1:]):
            with self.subTest(kind="missing" if source is None else "wrong"):
                with self.assertRaisesRegex(ValueError, "source baseline mismatch"):
                    reconstruct(self.output.read_bytes(), {} if source is None else {"product": source})

    def test_default_and_empty_option_remain_identical_full_payloads(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            first, second = Path(temporary) / "default.bin", Path(temporary) / "empty.bin"
            self.assertEqual(self.write(self.images, first), self.write(self.images, second, source_copy_partitions=set()))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            blob = first.read_bytes()
            manifest, parts, *_ = decode_payload(blob)
            self.assertEqual(manifest[12], [0])
            self.assertTrue(all(6 not in p for p in parts.values()))
            self.assertIn(self.sentinel, blob)
            self.assertEqual(reconstruct(blob, {}), {n: p.read_bytes() for n, p in self.images.items()})

    def test_real_signatures_properties_and_tamper_rejection(self):
        blob = self.output.read_bytes()
        _, _, end, start, final_at = decode_payload(blob)
        public = payload.public_key(self.cert)
        for digest_bytes, encoded in ((blob[:end], blob[end:start]),
                                      (blob[:end] + blob[start:final_at], blob[final_at:])):
            item = decode_message(decode_message(encoded)[1][0])
            signature = item[2][0]
            self.assertEqual(item[3], [len(signature)])
            payload.verify_digest(hashlib.sha256(digest_bytes).digest(), signature, public, self.directory)
            with self.assertRaises(ValueError):
                payload.verify_digest(hashlib.sha256(digest_bytes + b"tamper").digest(), signature, public, self.directory)
        self.assertEqual(self.properties, {
            "FILE_HASH": base64.b64encode(hashlib.sha256(blob).digest()).decode(), "FILE_SIZE": str(len(blob)),
            "METADATA_HASH": base64.b64encode(hashlib.sha256(blob[:end]).digest()).decode(), "METADATA_SIZE": str(end)})

    def test_unsupported_selection_or_missing_partition_leaves_no_output(self):
        output = self.directory / "invalid.bin"
        for selection in ({"system"}, {"system_ext"}, {"recovery"}, {"product", "recovery"},
                          {"unknown"}, ["product"], "product", None):
            with self.subTest(selection=selection), self.assertRaisesRegex(ValueError, "not allowlisted"):
                self.write(self.images, output, source_copy_partitions=selection)
            self.assertFalse(output.exists())
        for name in ("product", "boot"):
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, "missing from images"):
                self.write({"system": self.images["system"]}, output, source_copy_partitions={name})
            self.assertFalse(output.exists())

    def test_empty_or_unaligned_product_leaves_no_output(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            image, output = Path(temporary) / "product.img", Path(temporary) / "payload.bin"
            for data in (b"", b"x", b"x" * 4097):
                image.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "unaligned raw partition"):
                    self.write({"product": image}, output, source_copy_partitions={"product"})
                self.assertFalse(output.exists())

    def test_product_change_between_hash_passes_removes_output(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            image, output = Path(temporary) / "product.img", Path(temporary) / "payload.bin"
            image.write_bytes(b"P" * 4096)
            original_sign, calls = payload.sign_digest, 0

            def sign_then_change(digest, key):
                nonlocal calls
                calls += 1
                if calls == 2:
                    image.write_bytes(b"Q" * 4096)
                return original_sign(digest, key)

            with patch.object(payload, "sign_digest", side_effect=sign_then_change):
                with self.assertRaisesRegex(ValueError, "input changed while packaging: product"):
                    self.write({"product": image}, output, source_copy_partitions={"product"})
            self.assertFalse(output.exists())

    def test_twelve_copy_wire_contract_and_reconstruction(self):
        self.assertEqual(payload.SOURCE_COPY_ALLOWED, self.copy_names)
        blob = self.twelve_output.read_bytes()
        manifest, parts, _, start, final_at = decode_payload(blob)
        self.assertEqual(manifest[12], [6])
        self.assertEqual(manifest[16], [0])
        replacements = {"system", "system_ext", "recovery"}
        self.assertEqual(set(parts) - self.copy_names, replacements)
        for name, part in parts.items():
            with self.subTest(partition=name):
                if name in self.copy_names:
                    self.assertEqual(part[6], part[7])
                    self.assertEqual(len(part[8]), 1)
                    op = decode_message(part[8][0])
                    self.assertEqual(op[1], [4])
                    self.assertEqual(set(op), {1, 4, 6, 9})
                    self.assertEqual(op[4], op[6])
                    self.assertEqual(decode_message(op[4][0]),
                                     {1: [0], 2: [self.images[name].stat().st_size // 4096]})
                    self.assertEqual(op[9], decode_message(part[7][0])[2])
                else:
                    self.assertNotIn(6, part)
                    self.assertTrue(all(decode_message(record)[1] == [0] for record in part[8]))
        self.assertEqual(blob[start:final_at],
                         b"".join(p.read_bytes() for n, p in self.images.items() if n in replacements))
        self.assertNotIn(self.sentinel, blob)
        expected = {name: path.read_bytes() for name, path in self.images.items()}
        sources = {name: expected[name] for name in self.copy_names}
        self.assertEqual(reconstruct(blob, sources), expected)
        self.assertEqual(self.twelve_hashes, self.hashes)
        sources["boot"] = b"!" + sources["boot"][1:]
        with self.assertRaisesRegex(ValueError, "source baseline mismatch"):
            reconstruct(blob, sources)

    @unittest.skipUnless(shutil.which("payload-dumper-go"), "independent payload decoder unavailable")
    def test_independent_decoder_twelve_copies_and_wrong_boot_source(self):
        help_result = subprocess.run(["payload-dumper-go", "-help"], capture_output=True, text=True, timeout=10)
        if "-old " not in help_result.stdout + help_result.stderr:
            self.skipTest("installed independent decoder has no source-image directory support")
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            directory = Path(temporary)
            old = directory / "source"
            old.mkdir()
            for name in self.copy_names:
                shutil.copyfile(self.images[name], old / (name + ".img"))
            private_recovery = b"synthetic-source-recovery-private-diagnostics"
            (old / "recovery.img").write_bytes(private_recovery.ljust(4096, b"\0"))
            result = subprocess.run(["payload-dumper-go", "-c", "2", "-old", str(old),
                                     "-o", str(directory / "decoded"), str(self.twelve_output)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr[-1000:])
            self.assertEqual({n: payload.sha256(directory / "decoded" / (n + ".img")) for n in self.images},
                             self.twelve_hashes)
            self.assertNotIn(private_recovery, (directory / "decoded/recovery.img").read_bytes())
            self.assertNotIn(private_recovery, self.twelve_output.read_bytes())
            boot = old / "boot.img"
            boot.write_bytes(b"!" + boot.read_bytes()[1:])
            result = subprocess.run(["payload-dumper-go", "-c", "2", "-old", str(old), "-p", "boot",
                                     "-o", str(directory / "wrong-boot"), str(self.twelve_output)],
                                    capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertRegex((result.stdout + result.stderr).lower(), r"source.*(hash|verification)")

    @unittest.skipUnless(shutil.which("payload-dumper-go"), "independent payload decoder unavailable")
    def test_independent_decoder_with_old_directory_and_wrong_baseline(self):
        help_result = subprocess.run(["payload-dumper-go", "-help"], capture_output=True, text=True, timeout=10)
        if "-old " not in help_result.stdout + help_result.stderr:
            self.skipTest("installed independent decoder has no source-image directory support")
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            directory = Path(temporary)
            result = subprocess.run(["payload-dumper-go", "-c", "2", "-old", str(self.image_dir),
                                     "-o", str(directory / "decoded"), str(self.output)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr[-1000:])
            self.assertEqual({n: payload.sha256(directory / "decoded" / (n + ".img")) for n in self.images}, self.hashes)
            old = directory / "wrong-source"
            old.mkdir()
            original = self.images["product"].read_bytes()
            for label, data in (("hash", b"!" + original[1:]), ("size", original[:-4096])):
                with self.subTest(baseline=label):
                    (old / "product.img").write_bytes(data)
                    result = subprocess.run(["payload-dumper-go", "-c", "2", "-old", str(old), "-p", "product",
                                             "-o", str(directory / label), str(self.output)],
                                            capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
