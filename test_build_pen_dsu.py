import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

import build_pen_dsu as pen


class BaseIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = {p: (p + " trusted image").encode() for p in ("system", "system_ext", "product")}
        self.expected = {p: {"sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)} for p, b in self.data.items()}
        self.report = {"status": "UNBOOTED_PRIVATE_DSU_DIAGNOSTIC_V9", "images": self.expected}
        self.pin = patch.object(pen, "EXPECTED_IMAGES", self.expected)
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def archive(self, name="base.zip", data=None, report=None, extra=None):
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for p, b in (data or self.data).items():
                z.writestr(p + ".img", b)
            z.writestr("diagnostic-report.json", json.dumps(self.report if report is None else report))
            z.writestr("README.md", "unbooted test fixture")
            if extra:
                z.writestr(*extra)
        return path

    def test_canonical_fast_path_and_cold_zip_full_image_validation(self):
        canonical = self.archive()
        with patch.object(pen, "BASE_ZIP_SHA256", pen.sha256(canonical)):
            report, validation = pen.verify_base(canonical)
            self.assertTrue(validation["canonical_zip_fast_path"])
            changed_report = dict(self.report, report_path="fresh cold workspace")
            cold = self.archive("cold.zip", report=changed_report)
            _, validation = pen.verify_base(cold)
            self.assertFalse(validation["canonical_zip_fast_path"])
            self.assertEqual(validation["sha256"], pen.sha256(cold))
            self.assertEqual(validation["image_integrity_method"], "all three decompressed image hashes")
            self.assertEqual(report["images"], self.expected)

    def test_embedded_claims_never_authorize_altered_image(self):
        for part in self.data:
            changed = dict(self.data)
            changed[part] = changed[part][:-1] + b"!"
            path = self.archive(part + ".zip", data=changed)
            with self.subTest(part=part), self.assertRaisesRegex(ValueError, "decompressed image hash"):
                pen.verify_base(path)

    def test_wrong_declared_hash_shape_size_and_oversized_report(self):
        wrong = copy.deepcopy(self.report)
        wrong["images"]["system"]["sha256"] = "0" * 64
        cases = [self.archive("wrong.zip", report=wrong),
                 self.archive("extra.zip", extra=("boot.img", b"forbidden")),
                 self.archive("large-report.zip", report=dict(self.report, padding="x" * (1024 * 1024))),
                 self.archive("size.zip", data=dict(self.data, system=b"wrong size"))]
        for path in cases:
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                pen.verify_base(path)

    def test_symlink_base_rejected(self):
        path = self.archive()
        link = self.root / "link.zip"
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "regular ZIP"):
            pen.verify_base(link)


class ApkIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.apk = Path(self.temp.name) / "pen.apk"
        self.apk.write_bytes(b"signed APK test fixture")
        self.cert = b"test public certificate"
        for name, value in [("APK_SHA256", pen.sha256(self.apk)), ("APK_BYTES", self.apk.stat().st_size),
                            ("CERT_SHA256", hashlib.sha256(self.cert).hexdigest())]:
            patcher = patch.object(pen, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.permissions = "package: org.lineageos.pen\n" + "".join(
            "uses-permission: name='android.permission." + name + "'\n" for name in
            ("BLUETOOTH", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN", "POST_NOTIFICATIONS", "RECEIVE_BOOT_COMPLETED"))
        self.signer = "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(self.cert).decode() + "\n-----END CERTIFICATE-----\n"

    def verify(self, signer=None, permissions=None, manifest="manifest without shared UID"):
        with patch.object(pen, "tool_output", side_effect=[self.signer if signer is None else signer,
                          self.permissions if permissions is None else permissions, manifest]) as run:
            result = pen.verify_apk(self.apk, self.cert, {"apksigner": "signer", "aapt2": "aapt2"}, {})
            self.assertIn("verify", run.call_args_list[0].args[0])
            return result

    def test_exact_signer_package_and_permission_checks(self):
        self.assertTrue(self.verify()["exact_der_match"])
        for args in [{"signer": self.signer + self.signer}, {"signer": self.signer.replace(base64.b64encode(self.cert).decode(), "eA==")},
                     {"permissions": self.permissions.replace("org.lineageos.pen", "other.app")},
                     {"permissions": self.permissions + "uses-permission: name='android.permission.RESTRICT_DISPLAY_MODES'\n"},
                     {"manifest": "android:sharedUserId=android.uid.system"}]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.verify(**args)

    def test_wrong_apk_or_certificate_fails_before_tools(self):
        with patch.object(pen, "tool_output") as run:
            with self.assertRaisesRegex(ValueError, "public pen certificate"):
                pen.verify_apk(self.apk, b"wrong certificate", {"apksigner": "unused"}, {})
            self.apk.write_bytes(b"modified")
            with self.assertRaisesRegex(ValueError, "input hash/size"):
                pen.verify_apk(self.apk, self.cert, {"apksigner": "unused"}, {})
            run.assert_not_called()


class OverlayScope(unittest.TestCase):
    def test_protected_content_metadata_and_path_inventory(self):
        before = {"/Google.apk": {"sha256": "trusted", "mode": 0o100644},
                  "/policy": {"sha256": "old", "mode": 0o100644}}
        after = copy.deepcopy(before)
        after["/policy"]["sha256"] = hashlib.sha256(b"policy").hexdigest()
        after[pen.APK_PATH] = {"sha256": "new"}
        self.assertTrue(pen.verify_preserved(before, after, {"/policy": b"policy"}, {pen.APK_PATH: {}})["all_other_content_preserved"])
        for field, value in [("sha256", "altered"), ("mode", 0o100777)]:
            bad = copy.deepcopy(after)
            bad["/Google.apk"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "protected V9"):
                pen.verify_preserved(before, bad, {"/policy": b"policy"}, {pen.APK_PATH: {}})
        with self.assertRaisesRegex(ValueError, "path added/removed"):
            pen.verify_preserved(before, dict(after, unexpected={}), {"/policy": b"policy"}, {pen.APK_PATH: {}})

    def test_full_only_schema_and_manual_limit_readme(self):
        root = ET.fromstring(pen.USER_XML)
        node = root.find("install-in-user-type")
        self.assertEqual(node.attrib, {"package": "org.lineageos.pen"})
        self.assertEqual([(n.tag, n.attrib) for n in node], [("install-in", {"user-type": "FULL"}),
                                                           ("do-not-install-in", {"user-type": "SYSTEM"})])
        self.assertIn("120 Hz manually", pen.README)
        self.assertIn("UNBOOTED_PEN_V10", pen.README)

    @unittest.skipUnless(os.environ.get("PEN_DSU_TEST_WORK"), "active CleanOS task needed")
    def test_existing_output_is_never_overwritten(self):
        work = Path(os.environ["PEN_DSU_TEST_WORK"])
        existing = work / "pen-v10"
        existing.mkdir()
        try:
            sentinel = existing / "preserve.txt"
            sentinel.write_text("preserve")
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                pen.build(work, Path("unused"), Path("unused"), Path("unused"))
            self.assertEqual(sentinel.read_text(), "preserve")
        finally:
            sentinel.unlink()
            existing.rmdir()


if __name__ == "__main__":
    unittest.main()
