import base64
import hashlib
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote

import erofs_overlay as erofs


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("EROFS_TEST_SCRATCH"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, extended=False, nid=7):
        image = self.root / "fixture.img"
        data = bytearray(12288)
        struct.pack_into("<III", data, 1024, 0xE0F5E1E2, 0, 1)
        data[1036] = 12
        struct.pack_into("<H", data, 1038, nid)
        struct.pack_into("<Q", data, 1048, 100)
        struct.pack_into("<II", data, 1064, 1, 2)
        offset = 4096 + nid * 32
        size = 64 if extended else 32
        struct.pack_into("<HHH", data, offset, int(extended) | 4, 2, stat.S_IFDIR | 0o751)
        struct.pack_into("<II" if extended else "<HH", data, offset + 24, 123, 456)
        if extended:
            struct.pack_into("<QI", data, offset + 32, 107, 123456789)
        else:
            struct.pack_into("<I", data, offset + 12, 7)
        blob = bytes(4) + b"\1" + bytes(7) + struct.pack("<I", 128)
        data[offset + size:offset + size + 16] = blob
        name, value = b"selinux", b"u:object_r:system_file:s0\0"
        entry = struct.pack("<BBH", len(name), 6, len(value)) + name + value
        data[8704:8704 + len(entry)] = entry
        image.write_bytes(data)
        return image, offset, size

    def root_metadata(self, image, nid=7):
        with patch.object(erofs.subprocess, "check_output", return_value=f"NID: {nid}\n"):
            return erofs.metadata(image, "/")

    def test_compact_and_extended_root_restored_before_xattr_decode(self):
        for extended in (False, True):
            with self.subTest(extended=extended):
                image, offset, size = self.fixture(extended)
                before = self.root_metadata(image)
                with image.open("r+b") as stream:
                    stream.seek(offset + size)
                    stream.write(bytes(16))
                with self.assertRaisesRegex(ValueError, "prefix"):
                    self.root_metadata(image)
                erofs.restore_root_xattrs(image, before)
                after = self.root_metadata(image)
                self.assertEqual(after["xattrs"], before["xattrs"])
                self.assertEqual((after["mode"], after["uid"], after["gid"], after["mtime"]),
                                 (stat.S_IFDIR | 0o751, 123, 456, 107))

    def test_root_structure_or_shared_entry_changes_refused_without_write(self):
        for position, payload in ((1038, struct.pack("<H", 8)), (1064, struct.pack("<I", 2)),
                                  (1068, struct.pack("<I", 1)), (4320, b"\5\0"),
                                  (4322, b"\3\0"), (8708, b"X")):
            with self.subTest(position=position):
                image, _, _ = self.fixture()
                before = self.root_metadata(image)
                with image.open("r+b") as stream:
                    stream.seek(position)
                    stream.write(payload)
                damaged = image.read_bytes()
                with self.assertRaises(ValueError):
                    erofs.restore_root_xattrs(image, before)
                self.assertEqual(image.read_bytes(), damaged)

    def test_binary_xattrs_round_trip_in_tar(self):
        attrs = {"security.capability": bytes.fromhex("0100000200040000000000000000000000000000"),
                 "security.selinux": b"u:object_r:system_file:s0\0", "user.a=b": b"\xff\n\0\0"}
        info = erofs.tar_info("file", {"mode": stat.S_IFREG | 0o640, "uid": 1,
                                      "gid": 2, "mtime": 3, "xattrs": attrs})
        path = self.root / "xattrs.tar"
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
            archive.addfile(info)
        with tarfile.open(path) as archive:
            actual = {unquote(k.removeprefix("LIBARCHIVE.xattr.")): base64.b64decode(v)
                      for k, v in archive.next().pax_headers.items()}
        self.assertEqual(actual, attrs)

    def test_noncanonical_paths_and_invalid_payload_refused(self):
        for name, data in (("relative", b"x"), ("/a/../b", b"x"), ("//a", b"x"),
                           ("/a//b", b"x"), ("/a/./b", b"x"), ("/a\0b", b"x"),
                           ("/a", "text")):
            with self.subTest(name=name), patch.object(erofs, "metadata") as metadata:
                with self.assertRaises(ValueError):
                    erofs.apply(self.root / "input.img", self.root / "out.img", {name: data}, self.root)
                metadata.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_output_symlink_refused(self):
        image, _, _ = self.fixture()
        output = self.root / "out.img"
        output.symlink_to(self.root / "absent")
        with self.assertRaises(ValueError):
            erofs.apply(image, output, {"/a": b"x"}, self.root)
        self.assertFalse((self.root / "absent").exists())

    def test_truncated_xattr_and_unknown_inode_format_refused(self):
        image, offset, size = self.fixture()
        with image.open("r+b") as stream:
            stream.truncate(offset + size + 15)
        with self.assertRaisesRegex(ValueError, "truncated"):
            self.root_metadata(image)
        image, offset, _ = self.fixture()
        with image.open("r+b") as stream:
            stream.seek(offset)
            stream.write(b"\x10\0")
        with self.assertRaisesRegex(ValueError, "format"):
            self.root_metadata(image)

    def test_binary_capability_survives_actual_erofs_overlay(self):
        if not all(shutil.which(tool) for tool in ("mkfs.erofs", "dump.erofs", "fsck.erofs")):
            self.skipTest("erofs-utils required")
        attrs = {"security.capability": bytes.fromhex("0100000200040000000000000000000000000000"),
                 "security.selinux": b"u:object_r:system_file:s0\0", "user.binary": b"\xff\0\n\0"}
        meta = {"mode": stat.S_IFREG | 0o6751, "uid": 123, "gid": 456,
                "mtime": 1230768000, "xattrs": attrs}
        archive_path = self.root / "source.tar"
        with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT) as archive:
            archive.addfile(erofs.tar_info(".", dict(meta, mode=stat.S_IFDIR | 0o755, xattrs={}), True))
            info = erofs.tar_info("binary", meta)
            info.size = 3
            archive.addfile(info, io.BytesIO(b"old"))
        image = self.root / "source.img"
        subprocess.run(["mkfs.erofs", "--tar=f", "-x0", "-b4096", "-T1230768000", "--workers=2",
                        str(image), str(archive_path)], check=True, stdout=subprocess.DEVNULL)
        self.assertEqual(erofs.metadata(image, "/binary")["xattrs"], attrs)
        output = self.root / "output.img"
        addition_meta = dict(meta, uid=70000, gid=80000, mode=stat.S_IFREG | 0o750,
                             mtime=1700000000, mtime_nsec=0)
        directory_meta = dict(addition_meta, mode=stat.S_IFDIR | 0o751)
        result = erofs.apply(image, output, {"/binary": b"new bytes"}, self.root,
                    additions={"/added": {"data": b"added file", "metadata": addition_meta},
                               "/apps": {"data": b"", "metadata": directory_meta},
                               "/apps/updater": {"data": b"", "metadata": directory_meta},
                               "/apps/updater/Updater.apk": {"data": b"apk payload", "metadata": addition_meta}})
        self.assertEqual(erofs.metadata(output, "/binary")["xattrs"], attrs)
        actual = erofs.metadata(output, "/added")
        for key in ("mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs"):
            self.assertEqual(actual[key], addition_meta[key], key)
        self.assertEqual(erofs.content(output, "/added"), b"added file")
        self.assertEqual(erofs.content(output, "/apps/updater/Updater.apk"), b"apk payload")
        for path in ("/apps", "/apps/updater"):
            actual = erofs.metadata(output, path)
            for key in ("mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs"):
                self.assertEqual(actual[key], directory_meta[key], (path, key))
        self.assertEqual(result["changed_paths"],
                         ["/added", "/apps", "/apps/updater", "/apps/updater/Updater.apk", "/binary"])
        empty = self.root / "empty-directory.img"
        erofs.apply(image, empty, {}, self.root,
                    additions={"/empty": {"data": b"", "metadata": directory_meta}})
        self.assertTrue(stat.S_ISDIR(erofs.metadata(empty, "/empty")["mode"]))
        self.assertEqual(erofs.content(empty, "/binary"), b"old")
        collision_output = self.root / "collision.img"
        with self.assertRaisesRegex(ValueError, "already exists"):
            erofs.apply(image, collision_output, {}, self.root,
                        additions={"/binary": {"data": b"bad", "metadata": meta}})
        self.assertFalse(collision_output.exists())
        failed_output = self.root / "failed.img"
        previous_paths = set(self.root.iterdir())
        with patch.object(erofs.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "mkfs.erofs")):
            with self.assertRaises(subprocess.CalledProcessError):
                erofs.apply(image, failed_output, {"/binary": b"failure"}, self.root)
        self.assertEqual(set(self.root.iterdir()), previous_paths)
        with self.assertRaisesRegex(ValueError, "parent"):
            erofs.apply(image, failed_output, {}, self.root,
                        additions={"/binary/child": {"data": b"bad", "metadata": meta}})
        self.assertFalse(failed_output.exists())

    def test_incomplete_or_invalid_addition_metadata_refused(self):
        valid = {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0, "mtime": 0, "xattrs": {}}
        for meta in ({}, dict(valid, uid=-1), dict(valid, mode=0o644),
                     dict(valid, xattrs={"security.capability": "not bytes"}),
                     dict(valid, mtime_nsec=1000000000)):
            with self.subTest(meta=meta), patch.object(erofs, "metadata") as lookup:
                with self.assertRaises(ValueError):
                    erofs.apply(self.root / "absent.img", self.root / "out.img", {}, self.root,
                                additions={"/new": {"data": b"bytes", "metadata": meta}})
                lookup.assert_not_called()

    def test_directory_payload_and_root_replacement_refused_before_read(self):
        meta = {"mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 0, "mtime": 0, "xattrs": {}}
        for path, data in (("/apps", b"unexpected bytes"), ("/", b"")):
            with self.subTest(path=path), patch.object(erofs, "metadata") as lookup:
                with self.assertRaisesRegex(ValueError, "non-root path and empty data"):
                    erofs.apply(self.root / "absent.img", self.root / "out.img", {}, self.root,
                                additions={path: {"data": data, "metadata": meta}})
                lookup.assert_not_called()


@unittest.skipUnless(os.environ.get("EROFS_TEST_IMAGE"), "set EROFS_TEST_IMAGE for actual donor validation")
class DonorOverlayTests(unittest.TestCase):
    def test_actual_overlay_and_complete_extraction(self):
        image = Path(os.environ["EROFS_TEST_IMAGE"])
        scratch = Path(os.environ["EROFS_TEST_SCRATCH"])
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            work = Path(directory)
            with image.open("rb") as stream:
                original_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            extracted = work / "before"
            subprocess.run(["fsck.erofs", "--extract=" + str(extracted), str(image)], check=True,
                           stdout=subprocess.DEVNULL)
            paths = ["/"] + sorted("/" + str(p.relative_to(extracted)) for p in extracted.rglob("*"))
            before = {p: erofs.metadata(image, p) for p in paths}
            target = "/etc/build.prop"
            replacement = erofs.content(image, target) + b"\n# erofs-overlay-validation\n"
            added_path = "/lib64/erofs-overlay-validation.so"
            added_metadata = {key: before[target][key] for key in ("mode", "uid", "gid", "mtime", "xattrs")}
            added_metadata.update(mode=stat.S_IFREG | 0o750, uid=123, gid=456, mtime=1700000000)
            added_data = b"explicit metadata addition validation\0\xff"
            output = work / "overlay.img"
            result = erofs.apply(image, output, {target: replacement}, work,
                                 additions={added_path: {"data": added_data, "metadata": added_metadata}})
            for path in paths:
                after = erofs.metadata(output, path)
                for key in ("mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs"):
                    self.assertEqual(after[key], before[path][key], (path, key))
            after_dir = work / "after"
            subprocess.run(["fsck.erofs", "--extract=" + str(after_dir), str(output)], check=True,
                           stdout=subprocess.DEVNULL)
            self.assertEqual(sorted(str(p.relative_to(after_dir)) for p in after_dir.rglob("*")),
                             sorted(p.lstrip("/") for p in paths[1:] + [added_path]))
            self.assertEqual((after_dir / added_path[1:]).read_bytes(), added_data)
            added_actual = erofs.metadata(output, added_path)
            for key, value in added_metadata.items():
                self.assertEqual(added_actual[key], value, (added_path, key))
            files = symlinks = 0
            for path in paths[1:]:
                old, new = extracted / path[1:], after_dir / path[1:]
                if old.is_symlink():
                    self.assertEqual(os.readlink(old), os.readlink(new)); symlinks += 1
                elif old.is_file():
                    self.assertEqual(new.read_bytes(), replacement if path == target else old.read_bytes())
                    files += 1
            with image.open("rb") as stream:
                self.assertEqual(hashlib.file_digest(stream, "sha256").hexdigest(), original_hash)
            result.update({"input_sha256": original_hash, "metadata_paths_checked": len(paths),
                           "regular_files_checked": files, "symlinks_checked": symlinks,
                           "full_fsck_extract": True, "input_unchanged": True,
                           "addition_metadata_checked": True, "added_path": added_path})
            (scratch / "validation.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
