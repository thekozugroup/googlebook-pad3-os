import hashlib
import json
import os
import shutil
import tempfile
import unittest
import zipfile
import copy
from pathlib import Path

from build_dsu_diagnostic import (NATIVE_BASE_SUPPLIED_BY_OWNER, PARTITIONS, ZIP_NAME,
                                  SOURCE, build, compressed_sha256, package, product_overlay_unchanged,
                                  preserved_system_payloads, read_public_key, verify_images, verify_policy_profile)
from port_changes import TIPS_SYSCONFIG_PATH


class DiagnosticBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.images = {}
        self.expected = {}
        for part in PARTITIONS:
            path = self.root / (part + ".img")
            path.write_bytes((part + " image\n").encode())
            self.images[part] = path
            self.expected[part] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.report = {"images": {p: {"sha256": self.expected[p]} for p in PARTITIONS},
                       "native_base_supplied_by_owner": NATIVE_BASE_SUPPLIED_BY_OWNER}

    def test_input_hashes_partition_set_and_symlinks_fail_closed(self):
        verify_images(self.root, self.expected)
        for expected in [dict(self.expected, vendor="unexpected"), dict(self.expected, system="bad")]:
            with self.assertRaises(ValueError):
                verify_images(self.root, expected)
        self.images["system"].unlink()
        self.images["system"].symlink_to(self.images["product"])
        with self.assertRaises(ValueError):
            verify_images(self.root, self.expected)

    def test_zip_has_only_userspace_and_evidence_and_preserves_inputs(self):
        result = package(self.images, self.report, self.root)
        path = Path(result["path"])
        self.assertEqual(result["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(set(archive.namelist()), {p + ".img" for p in PARTITIONS} |
                             {"README.md", "diagnostic-report.json"})
            report = json.loads(archive.read("diagnostic-report.json"))
            self.assertEqual(report, self.report)
            self.assertIs(report["native_base_supplied_by_owner"]["update_already_activated"], True)
            self.assertNotIn("pending_update_requires_reboot", report["native_base_supplied_by_owner"])
            for part in PARTITIONS:
                self.assertEqual(archive.read(part + ".img"), self.images[part].read_bytes())
        self.assertFalse((self.root / (ZIP_NAME + ".part.zip")).exists())
        before = path.read_bytes()
        with self.assertRaises(ValueError):
            package(self.images, self.report, self.root)
        self.assertEqual(path.read_bytes(), before)

    def test_changed_image_leaves_no_partial_bundle(self):
        self.images["product"].write_bytes(b"changed")
        with self.assertRaises(ValueError):
            package(self.images, self.report, self.root)
        self.assertFalse((self.root / ZIP_NAME).exists())
        self.assertFalse((self.root / (ZIP_NAME + ".part.zip")).exists())

    def test_package_accepts_custom_readme_on_refresh(self):
        package(self.images, self.report, self.root)
        result = package({"system_ext": self.images["system_ext"]}, self.report, self.root,
                         reuse_existing_payloads=True, readme="Pen V10: unbooted; select <=120 Hz.\n")
        with zipfile.ZipFile(result["path"]) as archive:
            self.assertEqual(archive.read("README.md"), b"Pen V10: unbooted; select <=120 Hz.\n")
        self.assertEqual(set(self.report["reused_payload_compressed_sha256"]), {"system", "product"})

    def test_product_reuse_requires_all_overlay_paths_and_hashes_to_match(self):
        changes = {"product": {"/media/bootanimation.zip": b"fixed geometry"}}
        additions = {"product": {"/etc/security/adb_keys": {"data": b"public test key"}}}
        payloads = changes["product"] | {path: entry["data"] for path, entry in additions["product"].items()}
        previous = {"images": {"product": {"changed_paths": list(payloads)}},
                    "metadata": {"product:" + path: {"sha256": hashlib.sha256(data).hexdigest()}
                                 for path, data in payloads.items()}}
        self.assertTrue(product_overlay_unchanged(changes, additions, previous))
        with_property = {"product": changes["product"] | {"/etc/build.prop": b"ro.setupwizard.require_network=\n"}}
        property_report = json.loads(json.dumps(previous))
        property_report["images"]["product"]["changed_paths"].append("/etc/build.prop")
        property_report["metadata"]["product:/etc/build.prop"] = {
            "sha256": hashlib.sha256(with_property["product"]["/etc/build.prop"]).hexdigest()}
        self.assertTrue(product_overlay_unchanged(with_property, additions, property_report))
        self.assertFalse(product_overlay_unchanged(changes, additions, None))
        for altered in [{"product": {}}, {"product": {"/media/bootanimation.zip": b"changed geometry"}},
                        {"product": changes["product"] | {"/another/file": b"new"}}]:
            with self.subTest(altered=altered):
                self.assertFalse(product_overlay_unchanged(altered, additions, previous))
        previous["metadata"].pop("product:/etc/security/adb_keys")
        self.assertFalse(product_overlay_unchanged(changes, additions, previous))

    def test_refresh_preserves_unchanged_compressed_payloads(self):
        for rebuilt in [("system",), ("product",), ("system", "product"), PARTITIONS]:
            with self.subTest(rebuilt=rebuilt), tempfile.TemporaryDirectory(dir=self.root) as directory:
                work = Path(directory)
                report = json.loads(json.dumps(self.report))
                previous = package(self.images, report, work)
                target = Path(previous["path"])
                with zipfile.ZipFile(target) as archive:
                    before = {part: compressed_sha256(target, archive.getinfo(part + ".img"))
                              for part in PARTITIONS if part not in rebuilt}
                updated = {}
                for part in rebuilt:
                    updated[part] = work / (part + ".img")
                    updated[part].write_bytes(("new " + part + "\n").encode())
                    report["images"][part]["sha256"] = hashlib.sha256(updated[part].read_bytes()).hexdigest()
                result = package(updated, report, work, reuse_existing_payloads=True)
                self.assertNotEqual(result["sha256"], previous["sha256"])
                with zipfile.ZipFile(target) as archive:
                    self.assertEqual(len(archive.namelist()), 5)
                    self.assertEqual(len(set(archive.namelist())), 5)
                    self.assertIsNone(archive.testzip())
                    for part in PARTITIONS:
                        self.assertEqual(archive.read(part + ".img"), updated.get(part, self.images[part]).read_bytes())
                    for part, digest in before.items():
                        self.assertEqual(compressed_sha256(target, archive.getinfo(part + ".img")), digest)
                    manifest = json.loads(archive.read("diagnostic-report.json"))
                    self.assertEqual(manifest["previous_bundle_sha256"], previous["sha256"])
                    self.assertEqual(manifest["reused_payload_compressed_sha256"], before)
                self.assertEqual(len(list(work.glob("*.zip"))), 1)

    def test_failed_refresh_preserves_existing_candidate(self):
        previous = package(self.images, self.report, self.root)
        for part in ("system", "product"):
            self.images[part].write_bytes(b"unverified change")
            with self.subTest(part=part), self.assertRaises(ValueError):
                package({part: self.images[part]}, self.report, self.root, reuse_existing_payloads=True)
            self.assertEqual(hashlib.sha256(Path(previous["path"]).read_bytes()).hexdigest(), previous["sha256"])
            self.assertFalse((self.root / (ZIP_NAME + ".part.zip")).exists())

    def test_refresh_rejects_unexpected_or_unavailable_changed_images(self):
        previous = package(self.images, self.report, self.root)
        for images in [{}, {"vendor": self.images["system"]}]:
            with self.subTest(images=images), self.assertRaisesRegex(ValueError, "packaged image set"):
                package(images, self.report, self.root, reuse_existing_payloads=True)
        self.report["images"]["product"]["sha256"] = "changed without rebuilt image"
        with self.assertRaisesRegex(ValueError, "reused payload hash changed: product"):
            package({"system": self.images["system"]}, self.report, self.root, reuse_existing_payloads=True)
        self.assertEqual(hashlib.sha256(Path(previous["path"]).read_bytes()).hexdigest(), previous["sha256"])
        self.assertFalse((self.root / (ZIP_NAME + ".part.zip")).exists())

    def test_system_and_product_refresh_atomically_preserves_published_hardlink(self):
        previous = package(self.images, self.report, self.root)
        target = Path(previous["path"])
        published = self.root / "canonical-v2.zip"
        os.link(target, published)
        checksum = self.root / (ZIP_NAME + ".sha256")
        published_checksum = self.root / "canonical-v2.zip.sha256"
        os.link(checksum, published_checksum)
        previous_checksum = published_checksum.read_bytes()
        self.assertEqual(target.stat().st_ino, published.stat().st_ino)
        for part in ("system", "product"):
            self.images[part].write_bytes(("new " + part + "\n").encode())
            self.report["images"][part]["sha256"] = hashlib.sha256(self.images[part].read_bytes()).hexdigest()
        package({p: self.images[p] for p in ("system", "product")}, self.report, self.root, reuse_existing_payloads=True)
        self.assertNotEqual(target.stat().st_ino, published.stat().st_ino)
        self.assertEqual(hashlib.sha256(published.read_bytes()).hexdigest(), previous["sha256"])
        self.assertEqual(published_checksum.read_bytes(), previous_checksum)

    def test_unassigned_scratch_and_noncanonical_key_are_refused(self):
        with self.assertRaises(ValueError):
            build(self.root)
        with self.assertRaises(ValueError):
            read_public_key(self.root / "other.pub")

    def test_durable_policy_profile_rejects_same_size_corruption(self):
        profile = self.root / "profile"
        shutil.copytree(SOURCE / "profiles/erhai-crdroid-20261025", profile)
        self.assertEqual(verify_policy_profile(profile)["compiled_policy_sha256"],
                         "bf755eca668fd4f96281899785e10e60a75956ebf7b248194ce82568c86dfce5")
        target = profile / "policy/vendor/vendor_sepolicy.cil"
        data = target.read_bytes()
        target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        with self.assertRaisesRegex(ValueError, "native policy profile drift"):
            verify_policy_profile(profile)

    def test_v9_preservation_allows_only_new_tips_file(self):
        changes = {"system": {"/old-file": b"unchanged"}}
        additions = {"system": {TIPS_SYSCONFIG_PATH: {"data": b"reviewed Tips configuration"}}}
        previous = {"images": {"system": {"changed_paths": ["/old-file"]}},
                    "metadata": {"system:/old-file": {"sha256": hashlib.sha256(b"unchanged").hexdigest()}}}
        self.assertEqual(preserved_system_payloads(changes, additions, previous),
                         {"/old-file": hashlib.sha256(b"unchanged").hexdigest()})
        for altered in [{"system": {"/old-file": b"changed"}}, {"system": {}},
                        {"system": changes["system"] | {"/unreviewed-file": b"new"}}]:
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                preserved_system_payloads(altered, additions, previous)
        unexpected_additions = copy.deepcopy(additions)
        unexpected_additions["system"]["/unreviewed-addition"] = {"data": b"new"}
        with self.assertRaisesRegex(ValueError, "overlay file set"):
            preserved_system_payloads(changes, unexpected_additions, previous)


if __name__ == "__main__":
    unittest.main()
