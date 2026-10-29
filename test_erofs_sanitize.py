import io
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from erofs_overlay import content, tar_info
from erofs_sanitize import FIELDS, inventory, rewrite, stream_file


@unittest.skipUnless(os.environ.get("EROFS_TEST_SCRATCH"), "supply an active CleanOS task for image tests")
class RewriteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ["EROFS_TEST_SCRATCH"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.marker = b"SYNTHETIC_REMOVED_AUTHORIZATION_AND_OBSOLETE_BYTES"
        attrs = {"security.selinux": b"u:object_r:system_file:s0\0", "user.binary": b"\x00\xff\x01"}
        self.meta = {"mode": stat.S_IFREG | 0o750, "uid": 70000, "gid": 80000,
                     "mtime": 1230768001, "mtime_nsec": 123456789, "xattrs": attrs}
        archive = self.root / "source.tar"
        with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tar:
            for directory in (".", "lib", "empty"):
                tar.addfile(tar_info(directory, dict(self.meta, mode=stat.S_IFDIR | 0o751), True))
            for name, data in (("lib/a", bytes(range(256)) * 30), ("secret", self.marker)):
                info = tar_info(name, self.meta)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            info = tar_info("lib/b", self.meta)
            info.type, info.linkname = tarfile.LNKTYPE, "lib/a"
            tar.addfile(info)
            for name, target in (("link", "lib/a"), ("adb_keys", "secret")):
                info = tar_info(name, dict(self.meta, mode=stat.S_IFLNK | 0o777))
                info.type, info.linkname = tarfile.SYMTYPE, target
                tar.addfile(info)
        self.image = self.root / "source.img"
        subprocess.run(["mkfs.erofs", "--tar=f", "-x0", "-b4096", "-T1230768000", "--mkfs-time",
                        "--preserve-mtime", "-U00000000-0000-4000-8000-000000000001",
                        "-zlz4hc", "--workers=2", "--quiet", str(self.image), str(archive)], check=True)
        # Simulate the unreachable bytes retained by an incremental image overlay.
        with self.image.open("ab") as stream:
            stream.write(self.marker)

    def test_complete_rewrite_preserves_metadata_data_links_and_drops_old_bytes(self):
        output = self.root / "public.img"
        source = self.image.read_bytes()
        report = rewrite(self.image, output, {"/secret", "/adb_keys"}, self.root)
        old, new = inventory(self.image), inventory(output)
        self.assertEqual(new.keys(), old.keys() - {"/secret", "/adb_keys"})
        for path in new:
            for key in FIELDS:
                self.assertEqual(new[path][key], old[path][key], (path, key))
        self.assertEqual(content(output, "/lib/a"), bytes(range(256)) * 30)
        self.assertEqual(content(output, "/link"), b"lib/a")
        self.assertEqual(new["/lib/a"]["nid"], new["/lib/b"]["nid"])
        self.assertNotIn(self.marker, output.read_bytes())
        self.assertEqual(self.image.read_bytes(), source)
        self.assertTrue(report["full_rewrite"])
        self.assertEqual(list(self.root.glob("erofs-rewrite-*")), [])
        second = self.root / "repeat.img"
        repeated = rewrite(self.image, second, {"/secret", "/adb_keys"}, self.root)
        self.assertEqual(report["sha256"], repeated["sha256"])

    def test_no_overwrite_no_directory_deletion_no_unknown_path(self):
        output = self.root / "existing.img"
        output.write_bytes(b"keep")
        with self.assertRaises(ValueError):
            rewrite(self.image, output, {"/secret"}, self.root)
        self.assertEqual(output.read_bytes(), b"keep")
        for removals in ({"/lib"}, {"/absent"}, {"/../secret"}):
            target = self.root / "refused.img"
            with self.subTest(removals=removals), self.assertRaises(ValueError):
                rewrite(self.image, target, removals, self.root)
            self.assertFalse(target.exists())

    def test_failed_build_removes_partial_output_and_tar(self):
        output = self.root / "failed.img"
        actual_run = subprocess.run
        def fail(*args, **kwargs):
            if args[0][0] != "mkfs.erofs":
                return actual_run(*args, **kwargs)
            output.write_bytes(b"partial")
            raise subprocess.CalledProcessError(1, args[0])
        with patch("erofs_sanitize.subprocess.run", side_effect=fail):
            with self.assertRaises(subprocess.CalledProcessError):
                rewrite(self.image, output, {"/secret", "/adb_keys"}, self.root)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob("erofs-rewrite-*")), [])

    def test_truncated_stream_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            stream_file(self.image, "/lib/a", 999999)


class InventoryParserTests(unittest.TestCase):
    def test_unparsed_directory_rows_are_not_silently_lost(self):
        with patch("erofs_sanitize.metadata", return_value={"mode": stat.S_IFDIR, "nid": 1}), \
             patch("erofs_sanitize.subprocess.check_output", return_value="FILENAME\n1 2  .\n1 2  ..\nmalformed\n"):
            with self.assertRaisesRegex(ValueError, "unparsed"):
                inventory(Path("unused.img"))


if __name__ == "__main__":
    unittest.main()
