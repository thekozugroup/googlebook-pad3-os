"""Privacy and ownership checks use synthetic inputs, never owner credentials."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import export_public as public


class PublicExport(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="public-export-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name).resolve()
        self.source = self.work / "source"
        self.source.mkdir()
        self.destination = self.work / "candidate"
        self.scanner = public.Scanner()
        self.personal = "/" + "Users/reviewer/private-input"
        for name in public.ALLOWLIST:
            self.put(name, b"# reviewed synthetic source\n")
        self.put("build_dsu_diagnostic.py", "import os\nfrom pathlib import Path\nPUBLIC_KEY = Path(" + repr(self.personal) + ")\n")
        with (self.source / "build_dsu_diagnostic.py").open("a") as stream:
            stream.write("BASELINE = 'reports/dsu-staging-report.json'\n")
        self.put("cold_build_dsu.py", "BASELINE = 'reports/dsu-staging-report.json'\n")
        self.put("check_updates.py", "SOURCE_PROFILE = 'reports/lineage-source-review.json'\n")
        self.put("test_build_oplus_pen.py", "import os\nimport unittest\nclass PenBuildTests(unittest.TestCase):\n    pass\n")
        self.put("test_stability_probe.py", "def test_mocked_cli_and_rotation_keep_output_private_and_bounded():\n    probe.main(['--output', 'mock'])\n")
        self.put("build_pen_dsu.py", "import os\nfrom pathlib import Path\nCACHE = Path(" + repr(self.personal) + ")\nROOT = Path('.')\ncertificate = (ROOT / 'profiles/pad3-components/certificate.der').read_bytes()\n")
        self.put("test_pen_policy.py", "from pathlib import Path\ndef test_actual_baseline_and_augmented_strict_compile():\n    cache = Path(" + repr(self.personal) + ")\n")
        self.put("stability_probe.py", "import os\ndef main(parser):\n    parser.add_argument('--serial', default='synthetic-device')\n")
        self.put("build.sh", '#!/bin/bash\n[[ "$SOURCE" == ' + self.personal + ' ]] || { echo \'Keep this source outside cloud sync.\' >&2; exit 2; }\n')
        self.put("build_native_rom.py", "import os\nfrom pathlib import Path\nROOT = Path('.')\nPUBLIC_REPO = "
                 + repr(public.PUBLIC_REPOSITORY) + "\nFEED_URL = " + repr(public.PUBLIC_FEED)
                 + "\nCHECKER = ROOT / 'native_install/manager/SukiSUManagerCheck.jar'\n")
        self.put("build_updater.py", "import os\nimport json\nfrom pathlib import Path\nFEED = " + repr(public.PUBLIC_FEED)
                 + "\ndef build(work):\n    image = Path(" + repr(self.personal) + ")\n"
                 + "    report_path = work / 'reports/updater-integration.json'\n"
                 + "    report = json.loads(report_path.read_text())\n"
                 + "    report.update(status='APK_BUILT_NOT_DEVICE_VALIDATED')\n    return report\n")
        self.put("test_build_updater.py", "import os\nfrom pathlib import Path\n"
                 + "def test_actual_native_writer_zip32_and_zip64_match_consumer(self):\n"
                 + "    lock = {'java_home': 'build-inputs/jdk-21'}\n    java = Path(lock['java_home']) / 'bin'\n    return java\n")
        self.put("native_install/bootcontrol/build_probe.py", "from pathlib import Path\ndef build(output):\n"
                 + "    sdk = Path(" + repr(self.personal) + ")\n"
                 + "    jdk = Path('/opt/local-host-only/jdk/bin')\n    return sdk, jdk\n")
        self.put("native_install/manager/build_checker.py", (self.source / "native_install/bootcontrol/build_probe.py").read_bytes())
        self.put("test_patch_taskmanager.py", "import os\nimport unittest\nclass TaskManagerPatchTest(unittest.TestCase):\n    pass\n")
        self.put("native_install/tools.example.json", json.dumps({"avbtool": {
            "path": self.personal + "/avbtool.py", "sha256": "a" * 64}, "avb_public_keys": {}}))
        self.put("native_install/plan.example.json", json.dumps({"repository": "OWNER/PUBLIC_REPO", "capture": {
            "hardware": {"boot": {"path": "/ABSOLUTE/CAPTURE/boot_b.img", "sha256": "REPLACE_WITH_SHA256"}}}}))
        self.put("components/updater/toolchain.json", json.dumps({"java_home": self.personal,
            "sdk_platform": "android-37.2", "build_tools": "36.0.0", "tools": {
            "android_jar": {"path": self.personal + "/android.jar", "sha256": "b" * 64}}}))
        self.put("native_install/source-pins.json", json.dumps({"sources": [{"local": "native_install/tools/avbtool.py",
            "sha256": public.digest((self.source / "native_install/tools/avbtool.py").read_bytes())}],
            "filtered_layout_baseline_sha256": public.digest((self.source / "native_install/sukisu-layout-baseline.json").read_bytes())}))
        self.put("patch_taskmanager.py", "import os\nfrom pathlib import Path\nSDK = Path(" + repr(self.personal)
                 + ")\nJAVA = Path('/opt/host-only/jdk')\nJADX = Path('/opt/host-only/jadx.jar')\nJADX_SHA256 = '" + "a" * 64 + "'\n")
        self.put(public.COMPONENT + "toolchain.json", json.dumps({
            "java_home": self.personal, "sdk_platform": "android-37.2", "build_tools": "36.0.0",
            "dependencies": {"compiler": {"path": self.personal + "/compiler.jar", "sha256": "a" * 64}},
            "tools": {"android_jar": {"path": self.personal + "/android.jar", "sha256": "b" * 64},
                      "r8_jar": {"path": self.personal + "/d8.jar", "sha256": "c" * 64}}}))
        self.put(public.COMPONENT + "donor-inputs.json", json.dumps({
            "images": [{"path": self.personal + "/system_a.img", "sha256": "d" * 64}],
            "files": [{"image": self.personal + "/system_a.img", "sha256": "e" * 64}]}))
        self.put(public.COMPONENT + "integration/requirements.json", json.dumps({"policy_source": {
            "image": self.personal + "/system_ext.img", "sha256": "f" * 64}}))
        manifest = {"files": [self.pin("upstream/" + n, n) for n in public.UPSTREAM_FILES],
                    "license_text": self.pin("LICENSE"), "patch": self.pin("patches/googlebook.patch")}
        self.put(public.COMPONENT + "upstream-manifest.json", json.dumps(manifest))
        self.put("reports/dsu-staging-report.json", json.dumps({"image_sha256": {
            "system": "1" * 64, "system_ext": "2" * 64, "product": "3" * 64},
            "private_runtime_note": "never export this field"}))
        self.put("reports/lineage-source-review.json", json.dumps({"branch": "lineage-24.0",
            "current_kernel_source": "4" * 40, "heads": {k: "5" * 40 for k in
            ("device_erhai", "sm8750_common", "kernel", "modules", "devicetrees")}, "reviewer": "private reviewer"}))

    def put(self, name, data):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)

    def pin(self, actual, name=None):
        data = (self.source / public.COMPONENT / actual).read_bytes()
        return {"path": name or actual, "sha256": public.digest(data), "bytes": len(data)}

    def run_export(self):
        return public.export(self.source, self.destination, self.scanner)

    def assert_blocked(self, report, classification):
        self.assertEqual(report["status"], "blocked")
        self.assertIn(classification, {f["classification"] for f in report["findings"]})
        self.assertFalse(self.destination.exists())

    def test_exact_inventory_excludes_private_data_and_history(self):
        self.assertEqual(len(public.ALLOWLIST), len(set(public.ALLOWLIST)))
        for name in ("artifacts/private/owner-pin.json", "backups/save", "reports/device.json",
                     "profiles/pad3-components/certificate.der", "test_owner_pin.py", ".git/config",
                     "native_install/capture-manifest.json", "native_install/bootcontrol/NativeBootControlProbe.dex.jar",
                     "components/updater/Pad3Updater-unsigned.apk",
                     "components/taskmanager-compat/candidate/private.verification.json"):
            self.put(name, "private fixture only")
        report = self.run_export()
        self.assertEqual(report["status"], "candidate_exported_requires_manual_review")
        actual = {p.relative_to(self.destination).as_posix() for p in self.destination.rglob("*") if p.is_file()}
        self.assertEqual(actual, set(public.ALLOWLIST) | set(public.GENERATED)
                         | {v["output"] for v in public.METADATA_SELECTION.values()} | {public.MANIFEST})
        self.assertFalse(report["history_scanned"])
        self.assertFalse(report["history_copied"])
        self.assertFalse(report["artifacts_copied"])
        self.assertNotIn(public.PRIVATE_CAPTURE, actual)
        self.assertEqual(report["known_secret_scan"], "not_supplied")
        self.assertEqual(report["provided_pattern_count"], 0)
        self.assertEqual(report["derived_device_pattern_count"], 1)
        self.assertNotIn("components/taskmanager-compat/candidate/private.verification.json", report["pending_review_paths"])

    def test_portability_rules_are_explicit_and_preserve_source_and_hashes(self):
        original = {n: (self.source / n).read_bytes() for n in public.ALLOWLIST}
        self.scanner.add_secret(b"synthetic-device", "known_device_identifier")
        report = self.run_export()
        self.assertFalse(report["findings"])
        for name, data in original.items():
            self.assertEqual((self.source / name).read_bytes(), data)
        for entry in report["manifest"]["files"].values():
            self.assertRegex(entry["sha256"], r"^[a-f0-9]{64}$")
        lock = json.loads((self.destination / public.COMPONENT / "toolchain.json").read_text())
        self.assertEqual(lock["dependencies"]["compiler"]["sha256"], "a" * 64)
        self.assertEqual(lock["tools"]["r8_jar"]["path"], "build-inputs/android-sdk/build-tools/36.0.0/lib/d8.jar")
        self.assertIn("ANDROID_SERIAL", (self.destination / "stability_probe.py").read_text())
        self.assertIn("GOOGLEBOOK_CERTIFICATE", (self.destination / "build_pen_dsu.py").read_text())
        self.assertNotIn("synthetic-device", (self.destination / "stability_probe.py").read_text())
        self.assertNotIn(self.personal, json.dumps(report))

    def test_only_named_metadata_pins_leave_excluded_reports(self):
        report = self.run_export()
        self.assertFalse(report["findings"])
        seeds = json.loads((self.destination / "profiles/build-seed.json").read_text())
        sources = json.loads((self.destination / "profiles/lineage-sources.json").read_text())
        self.assertEqual(set(seeds), {"image_sha256"})
        self.assertEqual(set(sources), {"branch", "heads", "current_kernel_source"})
        self.assertNotIn("private reviewer", json.dumps(sources))
        self.assertNotIn("never export this field", json.dumps(seeds))
        self.assertIn("profiles/build-seed.json", (self.destination / "cold_build_dsu.py").read_text())

    def test_native_and_updater_configuration_is_portable_without_source_edits(self):
        original = {n: (self.source / n).read_bytes() for n in public.ALLOWLIST}
        report = self.run_export()
        self.assertFalse(report["findings"])
        lock = json.loads((self.destination / "components/updater/toolchain.json").read_text())
        self.assertEqual(lock["tools"]["android_jar"]["path"], "build-inputs/android-sdk/platforms/android-37.2/android.jar")
        self.assertEqual(lock["tools"]["android_jar"]["sha256"], "b" * 64)
        tools = json.loads((self.destination / "native_install/tools.example.json").read_text())
        self.assertEqual(tools["avbtool"]["path"], "/ABSOLUTE/SOURCE/native_install/tools/avbtool.py")
        self.assertEqual(tools["avbtool"]["sha256"], "a" * 64)
        plan = json.loads((self.destination / "native_install/plan.example.json").read_text())
        self.assertEqual(plan["repository"], public.PUBLIC_REPOSITORY)
        self.assertEqual(plan["capture"]["hardware"]["boot"]["sha256"], "REPLACE_WITH_SHA256")
        self.assertIn("GOOGLEBOOK_MANAGER_CHECKER", (self.destination / "build_native_rom.py").read_text())
        namespace = {}
        with patch.dict(os.environ, ANDROID_HOME="/sdk-fixture", JAVA_HOME="/jdk-fixture", GOOGLEBOOK_JADX_JAR="/tool-fixture/jadx.jar"):
            exec((self.destination / "patch_taskmanager.py").read_text(), namespace)
        self.assertEqual(namespace["SDK"], Path("/sdk-fixture"))
        self.assertEqual(namespace["JAVA"], Path("/jdk-fixture"))
        self.assertEqual(namespace["JADX"], Path("/tool-fixture/jadx.jar"))
        self.assertEqual(namespace["JADX_SHA256"], "a" * 64)
        namespace = {}
        exec((self.destination / "native_install/manager/build_checker.py").read_text(), namespace)
        with patch.dict(os.environ, ANDROID_HOME="/sdk-fixture", JAVA_HOME="/jdk-fixture"):
            self.assertEqual(namespace["build"](None), (Path("/sdk-fixture"), Path("/jdk-fixture/bin")))
        namespace = {}
        exec((self.destination / "native_install/bootcontrol/build_probe.py").read_text(), namespace)
        with patch.dict(os.environ, ANDROID_HOME="/sdk-fixture", JAVA_HOME="/jdk-fixture"):
            self.assertEqual(namespace["build"](None), (Path("/sdk-fixture"), Path("/jdk-fixture/bin")))
        namespace = {}
        exec((self.destination / "build_updater.py").read_text(), namespace)
        result = namespace["build"](self.work / "fresh-build")
        self.assertTrue(result["source_candidate"])
        self.assertEqual(result["status"], "APK_BUILT_NOT_DEVICE_VALIDATED")
        self.assertTrue((self.work / "fresh-build/reports").is_dir())
        self.assertIn("JAVA_HOME", (self.destination / "test_build_updater.py").read_text())
        self.assertIn("self.skipTest", (self.destination / "test_build_updater.py").read_text())
        for name, value in original.items():
            self.assertEqual((self.source / name).read_bytes(), value)

    def test_native_source_and_layout_pins_are_enforced(self):
        self.put("native_install/tools/avbtool.py", "# substituted upstream tool\n")
        self.assert_blocked(self.run_export(), "native_source_pin_mismatch")

    def test_feed_contract_cannot_point_at_the_private_repository(self):
        self.put("build_updater.py", (self.source / "build_updater.py").read_text().replace(
            public.PUBLIC_REPOSITORY, "owner/private-repository"))
        self.assert_blocked(self.run_export(), "public_updater_feed_contract_mismatch")

    def test_upcoming_sources_are_pending_and_never_implicitly_allowlisted(self):
        with patch.object(public, "ANNOUNCED_TESTS", (*public.ANNOUNCED_TESTS, "test_future_component.py")):
            report = self.run_export()
            self.assertFalse(report["integration_complete"])
            self.assertIn("test_future_component.py", report["pending_missing_paths"])
            self.put("components/face-preview-overlay/new.xml", "<resources/>\n")
            self.put("test_future_component.py", "# newly authored; review first\n")
            self.put("test_face_future.py", "# newly authored test\n")
            report = self.run_export()
            self.assertIn("components/face-preview-overlay/new.xml", report["pending_review_paths"])
            self.assertIn("test_future_component.py", report["pending_review_paths"])
            self.assertIn("test_face_future.py", report["pending_review_paths"])
            self.assertFalse((self.destination / "test_future_component.py").exists())
            self.assertFalse((self.destination / "components/face-preview-overlay/new.xml").exists())

    def test_only_the_exact_nonmaterial_updater_url_assertion_is_exempt(self):
        fixture = "https://owner:" + "token" + "@github.com/ota"
        line = 'fails(() -> UpdateCore.httpsUrl("' + fixture + '"));\n'
        name = "components/updater/tests/UpdateCoreTest.java"
        self.assertFalse(self.scanner.scan(line.encode(), name))
        self.assertTrue(self.scanner.scan(line.replace("token", "private-person").encode(), name))
        self.assertTrue(self.scanner.scan(line.encode(), "another.java"))
        self.scanner.add_secret(b"token", "known_secret")
        self.assertIn("known_secret", {f["classification"] for f in self.scanner.scan(line.encode(), name)})

    def test_unknown_private_metadata_cannot_replace_a_pin(self):
        name = "reports/dsu-staging-report.json"
        value = json.loads((self.source / name).read_text())
        value["image_sha256"]["system"] = self.personal
        self.put(name, json.dumps(value))
        self.assert_blocked(self.run_export(), "invalid_public_metadata_pin")

    def test_only_exact_nonmaterial_header_fixture_is_exempt(self):
        header = b"-" * 5 + b"BEGIN " + b"PRIVATE KEY" + b"-" * 5
        code = b"def test_only_one_android_public_key_is_accepted():\n    value = " + repr(header + b"\n").encode() + b"\n"
        self.assertFalse(self.scanner.scan(code, "test_port_changes.py"))
        material = code.replace(repr(header + b"\n").encode(), repr(header + b"\nnot-placeholder-material").encode())
        self.assertTrue(self.scanner.scan(material, "test_port_changes.py"))
        self.assertTrue(self.scanner.scan(code, "another_test.py"))

    def test_repeat_is_deterministic_and_updates_only_owned_files(self):
        first = self.run_export()
        inode = (self.destination / "android_disk.py").stat().st_ino
        second = self.run_export()
        self.assertEqual(first, second)
        self.assertEqual(inode, (self.destination / "android_disk.py").stat().st_ino)
        self.put("android_disk.py", "# reviewed source change\n")
        third = self.run_export()
        self.assertFalse(third["findings"])
        self.assertEqual((self.destination / "android_disk.py").read_text(), "# reviewed source change\n")

    def test_unknown_existing_directory_is_preserved(self):
        self.destination.mkdir()
        path = self.destination / "user.txt"
        path.write_text("user data")
        with self.assertRaisesRegex(public.ExportError, "destination_has_no_valid_manifest"):
            self.run_export()
        self.assertEqual(path.read_text(), "user data")

    def test_unknown_files_and_empty_directories_block_rerun(self):
        self.run_export()
        path = self.destination / "unknown"
        path.write_text("user data")
        with self.assertRaises(public.ExportError):
            self.run_export()
        self.assertEqual(path.read_text(), "user data")
        path.unlink()
        path.mkdir()
        with self.assertRaisesRegex(public.ExportError, "unknown_directory"):
            self.run_export()

    def test_git_directory_blocks_any_rerun(self):
        self.run_export()
        (self.destination / ".git").mkdir()
        with self.assertRaisesRegex(public.ExportError, "unknown_directory"):
            self.run_export()

    def test_edited_or_missing_managed_file_blocks_rerun(self):
        self.run_export()
        path = self.destination / "android_disk.py"
        path.write_text("# user edit\n")
        with self.assertRaisesRegex(public.ExportError, "modified_file"):
            self.run_export()
        self.assertEqual(path.read_text(), "# user edit\n")

    def test_source_and_destination_symlinks_are_refused(self):
        outside = self.work / "outside"
        outside.write_text("private")
        path = self.source / "android_disk.py"
        path.unlink()
        path.symlink_to(outside)
        report = self.run_export()
        self.assert_blocked(report, "symlink_refused")
        self.destination.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(public.ExportError):
            self.run_export()

    def test_destination_hardlink_is_not_overwritten(self):
        self.run_export()
        path = self.destination / "android_disk.py"
        outside = self.work / "outside"
        os.link(path, outside)
        with self.assertRaisesRegex(public.ExportError, "linked_file"):
            self.run_export()
        self.assertEqual(path.read_bytes(), outside.read_bytes())

    def test_manifest_traversal_is_refused(self):
        self.destination.mkdir()
        marker = {"exporter": public.OWNER, "schema": 1,
                  "files": {"../outside": {"sha256": "0" * 64}}}
        (self.destination / public.MANIFEST).write_text(json.dumps(marker))
        with self.assertRaisesRegex(public.ExportError, "valid_manifest"):
            self.run_export()

    def test_missing_and_binary_selected_sources_fail_closed(self):
        self.put("android_disk.py", bytes([255, 0, 1]))
        self.assert_blocked(self.run_export(), "invalid_selected_source")
        (self.source / "android_disk.py").unlink()
        self.assert_blocked(self.run_export(), "file_unreadable")

    def test_unsettled_python_syntax_is_rejected_before_candidate_writes(self):
        self.put("android_disk.py", "def incomplete(\n")
        self.assert_blocked(self.run_export(), "invalid_selected_source")

    def test_unknown_personal_paths_are_rejected_without_redaction(self):
        self.put("android_disk.py", "location = " + repr(self.personal) + "\n")
        report = self.run_export()
        self.assert_blocked(report, "personal_path")
        self.assertNotIn(self.personal, json.dumps(report))

    def test_unreviewed_private_capture_paths_in_native_examples_are_rejected(self):
        name = "native_install/plan.example.json"
        value = json.loads((self.source / name).read_text())
        value["capture"]["hardware"]["boot"]["path"] = self.personal + "/boot_b.img"
        self.put(name, json.dumps(value))
        report = self.run_export()
        self.assert_blocked(report, "personal_path")
        self.assertNotIn(self.personal, json.dumps(report))

    def test_provisioned_adb_shape_cannot_enter_public_source(self):
        key = base64.b64encode(struct.pack("<I", 64) + bytes(520))
        self.put("android_disk.py", b"key = " + repr(key).encode() + b"\n")
        report = self.run_export()
        self.assert_blocked(report, "adb_authorization_key")
        self.assertNotIn(key.decode(), json.dumps(report))

    def test_pin_matching_uses_boundaries_and_checks_utf16(self):
        pin = ("73" + "1486").encode()
        self.scanner.add_secret(pin, "known_pin")
        for data in (b"'" + pin + b"'", pin.decode().encode("utf-16le"), pin.decode().encode("utf-16be")):
            self.assertIn("known_pin", {f["classification"] for f in self.scanner.scan(data, "fixture")})
        self.assertFalse(self.scanner.scan(b"a" * 20 + pin + b"f" * 38, "hash"))
        self.assertFalse(self.scanner.scan(b"9" + pin + b"1", "different-number"))

    def test_secret_file_json_does_not_persist_values_or_paths(self):
        pin = "73" + "1486"
        secret = self.work / "private-patterns.json"
        secret.write_text(json.dumps({"pin": pin, "serial": "synthetic-device"}))
        self.scanner.load_secrets(secret)
        self.put("android_disk.py", "value = '" + pin + "'\n")
        report = self.run_export()
        self.assert_blocked(report, "known_pin")
        self.assertNotIn(pin, json.dumps(report))
        self.assertNotIn(str(secret), json.dumps(report))

    def test_no_secret_can_be_hidden_in_a_rewritten_json_path(self):
        pin = "73" + "1486"
        self.scanner.add_secret(pin.encode(), "known_pin")
        name = public.COMPONENT + "toolchain.json"
        lock = json.loads((self.source / name).read_text())
        lock["java_home"] = self.personal + "/" + pin + "/jdk"
        self.put(name, json.dumps(lock))
        self.assert_blocked(self.run_export(), "secret_in_portability_field")

    def test_upstream_or_license_drift_blocks_export(self):
        self.put(public.COMPONENT + "LICENSE", "changed license")
        self.assert_blocked(self.run_export(), "upstream_pin_mismatch")

    def test_portability_shape_changes_fail_closed(self):
        self.put("build_dsu_diagnostic.py", "PUBLIC_KEY = None\n")
        self.assert_blocked(self.run_export(), "portability_precondition_changed")

    def test_concurrent_source_change_is_rejected(self):
        original = self.scanner.scan

        def change(data, path, **kwargs):
            if path == "README.md":
                self.put("android_disk.py", "# concurrent change\n")
            return original(data, path, **kwargs)

        self.scanner.scan = change
        self.assert_blocked(self.run_export(), "source_changed_during_export")

    def test_pem_tokens_and_adb_keys_are_detected(self):
        pem = b"-" * 5 + b"BEGIN " + b"RSA PRIVATE KEY" + b"-" * 5
        token = b"gh" + b"p_" + b"X" * 36
        adb = base64.b64encode(struct.pack("<I", 64) + bytes(520))
        for data, expected in ((pem, "private_key"), (token, "token"), (adb, "adb_authorization_key")):
            findings = self.scanner.scan(data, "fixture")
            self.assertIn(expected, {f["classification"] for f in findings})
            self.assertNotIn(data.decode(), json.dumps(findings))

    def test_placeholders_are_nonmaterial_only(self):
        self.assertFalse(self.scanner.scan(b"password = 'not-a-secret'", "fixture"))
        value = b"client_secret = '" + b"material-value-" + b"x" * 20 + b"'"
        self.assertIn("credential_literal", {f["classification"] for f in self.scanner.scan(value, "fixture")})

    def make_zip(self, members):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return stream.getvalue()

    def test_nested_apk_payload_is_scanned(self):
        pin = ("73" + "1486").encode()
        self.scanner.add_secret(pin, "known_pin")
        apk = self.make_zip({"classes.dex": b"dex\n'" + pin + b"'"})
        path = self.work / "release.zip"
        path.write_bytes(self.make_zip({"app.apk": apk}))
        findings = self.scanner.scan_artifact(path)
        self.assertIn("known_pin", {f["classification"] for f in findings})
        self.assertNotIn(pin.decode(), json.dumps(findings))

    def test_tokens_in_compressed_nested_members_are_detected(self):
        token = b"gh" + b"p_" + b"Z" * 36
        path = self.work / "release.apk"
        path.write_bytes(self.make_zip({"asset.zip": self.make_zip({"config.txt": token})}))
        self.assertIn("token", {f["classification"] for f in self.scanner.scan_artifact(path)})

    def test_unscannable_images_and_malformed_zip_block_artifact_approval(self):
        path = self.work / "release.zip"
        path.write_bytes(self.make_zip({"system.img": b"opaque filesystem image"}))
        self.assertIn("unscanned_container", {f["classification"] for f in self.scanner.scan_artifact(path)})
        path.write_bytes(b"PK" + bytes([3, 4]) + b"broken")
        self.assertTrue(self.scanner.scan_artifact(path))
        path.write_bytes(self.make_zip({"../outside": b"text"}))
        self.assertIn("artifact_not_fully_scanned", {f["classification"] for f in self.scanner.scan_artifact(path)})

    def test_archive_limits_and_encryption_fail_closed(self):
        path = self.work / "release.apk"
        data = bytearray(self.make_zip({"asset.txt": b"text"}))
        local, central = data.find(b"PK" + bytes([3, 4])), data.find(b"PK" + bytes([1, 2]))
        struct.pack_into("<H", data, local + 6, 1)
        struct.pack_into("<H", data, central + 8, 1)
        path.write_bytes(data)
        self.assertTrue(self.scanner.scan_artifact(path))
        path.write_bytes(self.make_zip({"asset.txt": b"text"}))
        with patch.object(public, "MAX_ENTRIES", 0):
            self.assertTrue(self.scanner.scan_artifact(path))

    def test_public_verification_cert_is_not_a_private_key(self):
        cert = bytes([48, 130, 3, 0]) + b"synthetic-certificate-fixture" + bytes([10])
        path = self.work / "component-certificate.der"
        path.write_bytes(cert)
        self.scanner.load_secrets(path)
        self.assertIn("owner_certificate", {f["classification"] for f in self.scanner.scan(cert, "source")})
        self.assertFalse(self.scanner.scan(cert, "apk", artifact=True))
        path = self.work / "release.apk"
        path.write_bytes(self.make_zip({"META-INF/CERT.RSA": cert, "classes.dex": b"synthetic"}))
        self.assertFalse(self.scanner.scan_artifact(path))

    def test_cli_does_not_echo_private_exception_text_or_overwrite_unknown_audit(self):
        audit = self.work / "public-export-review.json"
        audit.write_text("private existing data")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = public.main(["--source", str(self.source), "--output", str(self.destination), "--audit", str(audit)])
        self.assertEqual(code, 2)
        self.assertNotIn("private existing data", stream.getvalue())
        self.assertEqual(audit.read_text(), "private existing data")
        self.assertFalse(self.destination.exists())

    def test_cli_updates_audit_to_blocked_without_touching_unknown_candidate_file(self):
        audit = self.work / "public-export-review.json"
        args = ["--source", str(self.source), "--output", str(self.destination), "--audit", str(audit)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(public.main(args), 0)
        private = self.destination / "unknown.txt"
        private.write_text("keep this private user file")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(public.main(args), 2)
        self.assertEqual(json.loads(audit.read_text())["status"], "blocked")
        self.assertEqual(private.read_text(), "keep this private user file")
        self.assertNotIn("keep this private user file", stream.getvalue() + audit.read_text())


if __name__ == "__main__":
    unittest.main()
