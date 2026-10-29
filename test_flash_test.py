import hashlib
import json
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

import flash_test


class FlashPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve()
        images = {}
        for name in ("system", "system_ext", "product"):
            data = bytearray(4096)
            data[:len(name)] = name.encode()
            data[1080:1082] = b"\x53\xef"
            (self.path / (name + ".img")).write_bytes(data)
            images[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        (self.path / "manifest.json").write_text(json.dumps({"status": "UNBOOTED_EXPERIMENTAL", "images": images}))
        self.variables = {"is-userspace": "yes", "unlocked": "yes", "product": "OP6190L1",
                          "current-slot": "a", "snapshot-update-status": "none"}

    def check(self):
        with patch.object(flash_test, "getvar", side_effect=lambda serial, name: self.variables[name]), \
                patch.object(flash_test.subprocess, "run") as run:
            result = flash_test.preflight(self.path, "test-serial")
            run.assert_not_called()
            return result

    def test_preflight_is_read_only(self):
        self.assertEqual(self.check()[1], "a")

    def test_wrong_device_locked_bootloader_and_snapshots_rejected(self):
        for name, value in [("product", "mica"), ("unlocked", "no"), ("is-userspace", "no"),
                            ("snapshot-update-status", "merging")]:
            with self.subTest(name=name):
                original = self.variables[name]
                self.variables[name] = value
                with self.assertRaises(RuntimeError):
                    self.check()
                self.variables[name] = original

    def test_tampered_image_rejected_before_device_calls(self):
        (self.path / "system.img").write_bytes(b"tampered")
        with patch.object(flash_test, "getvar") as getvar:
            with self.assertRaises(RuntimeError):
                flash_test.preflight(self.path, "test-serial")
            getvar.assert_not_called()

    def assert_filesystem_rejected(self, data, filesystem):
        for name in ("system", "system_ext", "product"):
            with self.subTest(image=name, filesystem=filesystem):
                path = self.path / (name + ".img")
                original = path.read_bytes()
                manifest_path = self.path / "manifest.json"
                original_manifest = manifest_path.read_text()
                manifest = json.loads(original_manifest)
                path.write_bytes(data)
                manifest["images"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                manifest_path.write_text(json.dumps(manifest))
                with patch.object(flash_test, "getvar") as getvar, \
                        patch.object(flash_test.subprocess, "run") as run:
                    with self.assertRaisesRegex(RuntimeError, name + ": " + filesystem + ".*requires raw EXT4"):
                        flash_test.preflight(self.path, "test-serial")
                    getvar.assert_not_called()
                    run.assert_not_called()
                path.write_bytes(original)
                manifest_path.write_text(original_manifest)

    def test_erofs_images_rejected_before_device_calls(self):
        data = bytearray(4096)
        data[1024:1028] = b"\xe2\xe1\xf5\xe0"
        self.assert_filesystem_rejected(data, "EROFS")

    def test_unknown_images_rejected_before_device_calls(self):
        self.assert_filesystem_rejected(bytes(4096), "unknown")
        self.assert_filesystem_rejected(b"\x53\xef", "unknown")

    def test_flash_requires_acknowledgement_and_writes_only_three_images(self):
        args = ["flash_test.py", "--serial", "test-serial", "--directory", str(self.path), "--flash"]
        with patch.object(sys, "argv", args), \
                patch.object(flash_test, "getvar", side_effect=lambda serial, name: self.variables[name]), \
                patch.object(flash_test.subprocess, "run") as run:
            with self.assertRaises(RuntimeError):
                flash_test.main()
            run.assert_not_called()
        with patch.object(sys, "argv", args + ["--acknowledge-unbooted-test-and-formatted-data"]), \
                patch.object(flash_test, "getvar", side_effect=lambda serial, name: self.variables[name]), \
                patch.object(flash_test.subprocess, "run") as run:
            flash_test.main()
            self.assertEqual([call.args[0] for call in run.call_args_list], [
                ["fastboot", "-s", "test-serial", "flash", name + "_a", str(self.path / (name + ".img"))]
                for name in ("system", "system_ext", "product")])


if __name__ == "__main__":
    unittest.main()
