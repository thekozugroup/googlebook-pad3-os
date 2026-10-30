import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from unittest.mock import patch

import build_native_userspace as userspace
import patch_taskmanager as taskmanager
from erofs_overlay import content, tar_info
from erofs_sanitize import inventory, rewrite
from port_changes import DIAGNOSTIC_WAITS, diagnostic_init
from test_port_changes import INIT


def pin(path):
    return {"path": str(path), "sha256": userspace.sha256(path)}


def apk_fixture(code):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("classes.dex", code)
    return stream.getvalue()


class TextTests(unittest.TestCase):
    def test_pinned_product_followup_uses_physical_cleanup_without_property_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "base.img"
            base.write_bytes(b"reviewed product")
            recipe = {"images": {"product": pin(base)}}
            proof = {"removed_paths": sorted(userspace.product_cleanup.REMOVALS)}
            with patch.object(userspace.product_cleanup, "SOURCE_SHA", userspace.sha256(base)), \
                 patch.object(userspace.native, "scratch_output", side_effect=lambda p: p), \
                 patch.object(userspace.product_cleanup, "build", return_value=proof) as clean, \
                 patch.object(userspace, "partition_plan", side_effect=AssertionError("must preserve other files")):
                result = userspace.assemble_partition("product", recipe, {}, Path(directory), Path(directory))
                clean.assert_called_once_with(base, Path(directory) / "product.img", Path(directory))
                self.assertEqual(result, proof | {"path": str(Path(directory) / "product.img"),
                                                  "base_sha256": recipe["images"]["product"]["sha256"],
                                                  "changed_paths": [], "added_paths": []})

    def test_cleanup_dispatch_requires_product_and_the_reviewed_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.img"
            base.write_bytes(b"other image")
            for partition, source_sha in (("product", "0" * 64), ("system", userspace.sha256(base))):
                recipe = {"images": {partition: pin(base)}}
                with self.subTest(partition=partition), \
                     patch.object(userspace.product_cleanup, "SOURCE_SHA", source_sha), \
                     patch.object(userspace.native, "scratch_output", side_effect=lambda p: p), \
                     patch.object(userspace.product_cleanup, "build") as clean, \
                     patch.object(userspace, "partition_plan", side_effect=ValueError("ordinary plan")) as plan:
                    with self.assertRaisesRegex(ValueError, "ordinary plan"):
                        userspace.assemble_partition(partition, recipe, {}, root, root)
                    plan.assert_called_once_with(base, partition, recipe, {})
                    clean.assert_not_called()

    def test_pinned_product_cleanup_rejects_a_changed_recipe_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.img"
            base.write_bytes(b"reviewed product")
            recipe = {"images": {"product": pin(base)}}
            with patch.object(userspace.product_cleanup, "SOURCE_SHA", userspace.sha256(base)), \
                 patch.object(userspace.product_cleanup, "build") as clean:
                base.write_bytes(b"changed product")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    userspace.assemble_partition("product", recipe, {}, root, root)
                clean.assert_not_called()

    def test_metrics_receipt_rejects_stale_sources_and_changed_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "native"
            sources.mkdir()
            for name in ("main.c", "metrics.c", "metrics.h"):
                (sources / name).write_bytes(name.encode())
            binary, receipt = root / "metrics", root / "receipt.json"
            binary.write_bytes(b"compiled binary")
            proof = {"ndk_version": "30.0.16248370", "abi": "arm64-v8a", "api": 35,
                     "needed": ["libc.so"], "source_sha256": {
                         "native/" + name: userspace.sha256(sources / name)
                         for name in ("main.c", "metrics.c", "metrics.h")},
                     "binary": {"sha256": userspace.sha256(binary), "bytes": binary.stat().st_size}}
            receipt.write_text(json.dumps(proof))
            with patch.object(userspace, "METRICS_SOURCE", sources), patch.object(userspace.native, "ROOT", root):
                self.assertEqual(userspace.verify_metrics(binary, receipt), proof)
                binary.write_bytes(b"changed binary")
                with self.assertRaisesRegex(ValueError, "source/binary"):
                    userspace.verify_metrics(binary, receipt)
                binary.write_bytes(b"compiled binary")
                (sources / "main.c").write_bytes(b"changed source")
                with self.assertRaisesRegex(ValueError, "source/binary"):
                    userspace.verify_metrics(binary, receipt)

    def test_pen_code_identity_ignores_resigning_and_resources(self):
        original = apk_fixture(b"old code")
        repack = io.BytesIO(original)
        with zipfile.ZipFile(repack, "a") as archive:
            archive.writestr("resources.arsc", b"changed packaging only")
        self.assertEqual(userspace.dex_hashes(original), userspace.dex_hashes(repack.getvalue()))
        self.assertNotEqual(userspace.apk_payload_hashes(original), userspace.apk_payload_hashes(repack.getvalue()))
        self.assertNotEqual(userspace.dex_hashes(original), userspace.dex_hashes(apk_fixture(b"fixed guards")))

    def test_v3_only_component_is_accepted_but_wrong_signer_is_rejected(self):
        signature = ("Verified using v2 scheme (APK Signature Scheme v2): false\n"
                     "Verified using v3 scheme (APK Signature Scheme v3): true\n"
                     "Signer #1 certificate SHA-256 digest: " + userspace.COMPONENT_CERT_SHA + "\n")
        tools = {name: Path("/" + name) for name in ("aapt2", "apksigner")}
        results = [subprocess.CompletedProcess([], 0, signature, ""),
                   subprocess.CompletedProcess([], 0, "package: name='com.googlebook.pad3.facepreview' versionCode='1'\n", "")]
        with patch.object(userspace.subprocess, "run", side_effect=results):
            userspace.verify_component(Path("/face.apk"), userspace.FACE_ENTRY["package"], tools)
        with patch.object(userspace.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, signature.replace(userspace.COMPONENT_CERT_SHA, "0" * 64), "")):
            with self.assertRaisesRegex(ValueError, "signed component"):
                userspace.verify_component(Path("/face.apk"), userspace.FACE_ENTRY["package"], tools)

    def test_taskmanager_proof_binds_candidate_sources_dex_and_method_contract(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("EROFS_TEST_SCRATCH")) as directory:
            root = Path(directory)
            source, jar, receipt = root / "patch_taskmanager.py", root / "candidate.jar", root / "verification.json"
            source.write_bytes(b"pinned source")
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("classes.dex", b"synthetic DEX")
                archive.writestr("META-INF/MANIFEST.MF", b"manifest")
            dex = {"sha256": hashlib.sha256(b"synthetic DEX").hexdigest()}
            proof = {"candidate_sha256": userspace.sha256(jar), "candidate_bytes": jar.stat().st_size,
                     "original_jar_sha256": userspace.TASKMANAGER_BASE_SHA,
                     "original_dex_sha256": taskmanager.ORIGINAL_DEX_SHA256,
                     "sources": {source.name: userspace.sha256(source)}, "dex": dex,
                     "transform": {"grafted_methods": 7}, "preservation": {
                         "changed_methods": list(taskmanager.TARGET_COUNTS), "manager_methods": 89,
                         "untouched_manager_methods": 82,
                         "original_target_instructions_branches_try_debug_preserved": True,
                         "original_fields_dtos_annotations_parameters_preserved": True,
                         "compile_only_classes_in_candidate": False}}
            def save(value):
                receipt.write_text(json.dumps(value))
            with patch.object(userspace.native, "ROOT", root), \
                 patch.object(userspace, "TASKMANAGER_SOURCES", {source.name}), \
                 patch.object(taskmanager, "verify_dex", return_value=dex):
                save(proof)
                self.assertEqual(userspace.verify_taskmanager(jar, receipt), proof)
                for key, value in (("candidate_sha256", "0" * 64), ("dex", {"sha256": "0" * 64}),
                                   ("sources", {"../private.key": "0" * 64}),
                                   ("preservation", dict(proof["preservation"], compile_only_classes_in_candidate=True))):
                    save(dict(proof, **{key: value}))
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        userspace.verify_taskmanager(jar, receipt)
                save(proof)
                source.write_bytes(b"source changed after proof")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    userspace.verify_taskmanager(jar, receipt)

    def test_strip_exact_v10_diagnostics_preserves_normal_init_and_waits(self):
        original = diagnostic_init(INIT)
        cleaned = userspace.strip_diagnostics(original)
        usb = b"    setprop vendor.usb.use_gadget_hal 0\n"
        self.assertEqual(cleaned.count(usb), 1)
        self.assertEqual(cleaned.replace(usb, b"").rstrip(), INIT.rstrip())
        for wait in DIAGNOSTIC_WAITS.values():
            self.assertEqual(cleaned.count(wait.encode()), 1)
        for token in (b"googlebook-dsu", b"boot_stage", b"boot-watchdog", b"persist.adb", b"persist.sys.usb.config"):
            self.assertNotIn(token, cleaned)
        for bad in (original.replace(b"casefold-before", b"unknown-before", 1).replace(b"googlebook-dsu-v4: unknown-before", b"other: unknown-before", 1),
                    original.replace(b"    load_persist_props\n", b"    load_persist_props\n    setprop persist.adb.tradeinmode 0\n"), INIT):
            with self.subTest(bad=hashlib.sha256(bad).hexdigest()), self.assertRaises(ValueError):
                userspace.strip_diagnostics(bad)

    def test_native_properties_preserve_heap_display_and_disable_private_adb(self):
        source = (b"dalvik.vm.heapsize=512m\ndebug.sf.ignore_hwc_physical_display_orientation=true\n"
                  b"ro.product.system.device=desktop\nro.debuggable=1\nro.adb.secure=0\n"
                  b"bluetooth.power.suspend.hid_wake_up.enabled=true\n"
                  b"persist.adb.tls_server.enable=0\nservice.adb.listen_addrs=tcp:localhost:5555\n"
                  b"persist.sys.usb.config=adb\nro.boot.apex.early_adbd=1\nro.build.user=PRIVATE_OWNER\n")
        source += b"ro.audio.ihaladaptervendorextension_enabled=true\nro.audio.ihaladaptervendorextension_enabled=true\n"
        result = userspace.native_properties(source, "system", 3, 1793220000)
        for line in (b"dalvik.vm.heapsize=512m", b"debug.sf.ignore_hwc_physical_display_orientation=true",
                     b"ro.product.system.device=erhai", b"ro.googlebook.pad3.release_sequence=3",
                     b"ro.build.ab_update=true", b"ro.virtual_ab.enabled=true", b"ro.debuggable=0", b"ro.adb.secure=1"):
            self.assertIn(line + b"\n", result)
        self.assertIn(b"bluetooth.power.suspend.hid_wake_up.enabled=false\n", result)
        for token in (b"PRIVATE_OWNER", b"persist.adb.", b"service.adb.", b"persist.sys.usb.config", b"early_adbd"):
            self.assertNotIn(token, result)
        self.assertIn(b"Googlebook/erhai/erhai:17/GBOS/3:user/release-keys", result)
        self.assertIn(b"ro.build.description=erhai-user 17 GBOS 3 release-keys\n", result)
        self.assertEqual(result.count(b"ro.audio.ihaladaptervendorextension_enabled=true\n"), 2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            userspace.native_properties(b"ro.debuggable=0\nro.debuggable=1\n", "system", 1, 1793220000)
        product = userspace.native_properties(b"keep=yes\n", "product", 3, 1793220000)
        self.assertIn(b"ro.product.product.device=erhai\n", product)
        self.assertIn(b"ro.product.build.fingerprint=Googlebook/erhai/erhai:", product)

    def test_overlay_config_preserves_order_comments_and_rejects_conflict(self):
        original = b'<config>\n<!-- retain -->\n<merge path="other.xml" />\n</config>\n'
        result = userspace.overlay_config(original)
        self.assertIn(b'<!-- retain -->\n<merge path="other.xml" />', result)
        self.assertEqual(userspace.ET.fromstring(result)[0].attrib, userspace.FACE_ENTRY)
        self.assertEqual(userspace.overlay_config(result), result)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            userspace.overlay_config(result.replace(b'mutable="false"', b'mutable="true"'))

    def test_immutable_face_overlay_precedes_mutable_and_merged_entries(self):
        original = (b'<config>\n<overlay package="fixed" mutable="false" />\n'
                    b'<overlay package="default.mutable" enabled="true" />\n'
                    b'<overlay package="mutable" mutable="true" />\n'
                    b'<merge path="more.xml" />\n</config>\n')
        result = userspace.overlay_config(original)
        entries = list(userspace.ET.fromstring(result))
        self.assertEqual(entries[0].attrib, userspace.FACE_ENTRY)
        self.assertEqual([e.get("package") for e in entries[1:-1]],
                         ["fixed", "default.mutable", "mutable"])
        self.assertEqual(userspace.overlay_config(result), result)
        old_append = original.replace(b'</config>',
            b'    <overlay package="com.googlebook.pad3.facepreview" mutable="false" enabled="true" />\n</config>')
        self.assertEqual(userspace.overlay_config(old_append), result)

    def test_new_directories_have_explicit_metadata_and_cannot_cross_symlinks(self):
        entries = {"/": {"mode": stat.S_IFDIR}, "/etc": {"mode": stat.S_IFDIR}}
        changes, additions = userspace.additions_and_changes(entries, {"/etc/googlebook/new/data": b"payload"})
        self.assertEqual(changes, {})
        for path in ("/etc/googlebook", "/etc/googlebook/new"):
            self.assertEqual(additions[path]["data"], b"")
            self.assertEqual(additions[path]["metadata"]["mode"], stat.S_IFDIR | 0o755)
            self.assertEqual(additions[path]["metadata"]["xattrs"]["security.selinux"], b"u:object_r:system_file:s0\0")
        entries["/etc"] = {"mode": stat.S_IFLNK}
        with self.assertRaisesRegex(ValueError, "non-directory"):
            userspace.additions_and_changes(entries, {"/etc/googlebook/data": b"payload"})

    def test_native_policy_preserves_existing_rules_and_binds_mapping(self):
        cil, mapping = b"(type pen_app)\n", b";; mapping fixture\n"
        digest = (hashlib.sha256(cil + mapping).hexdigest() + "\n").encode()
        candidate, updated = userspace.native_policy(cil, mapping, digest)
        self.assertEqual(candidate, cil + userspace.NATIVE_POLICY)
        self.assertEqual(updated, (hashlib.sha256(candidate + mapping).hexdigest() + "\n").encode())
        for old, mapped, proof in [(cil, mapping + b"changed", digest),
                                   (candidate, mapping, updated)]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                userspace.native_policy(old, mapped, proof)

    def test_recipe_requires_every_pin_and_rejects_unknown_inputs(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("EROFS_TEST_SCRATCH")) as directory:
            root = Path(directory)
            file = root / "input"
            file.write_bytes(b"input")
            recipe = {"schema": 1, "sequence": 1, "timestamp": 1793220000,
                      "images": {name: pin(file) for name in userspace.PARTITIONS},
                      "files": {name: pin(file) for name in userspace.FILE_INPUTS},
                      "trust": {name: pin(file) for name in userspace.TRUST_PATHS}}
            path = root / "recipe.json"
            path.write_text(json.dumps(recipe))
            with patch.object(userspace.native, "image_kind", return_value="erofs"):
                self.assertEqual(userspace.load_recipe(path)[0], recipe)
                file.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    userspace.load_recipe(path)
            recipe["private_key"] = pin(file)
            path.write_text(json.dumps(recipe))
            with self.assertRaisesRegex(ValueError, "unexpected"):
                userspace.load_recipe(path)

    def test_unverified_component_stops_before_trust_processing(self):
        inputs = {"files": {name: Path("/no-file") for name in userspace.FILE_INPUTS}, "trust": {}}
        with patch.object(userspace, "sha256", return_value=userspace.COMPONENT_CERT_SHA), \
             patch.object(userspace.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "")):
            with self.assertRaisesRegex(ValueError, "signed component"):
                userspace.verify_inputs(inputs)


class PhotosTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("EROFS_TEST_SCRATCH"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.component = self.root / "components/photos-native"
        shutil.copytree(userspace.PHOTOS_COMPONENT, self.component)
        for name in ("build_photos_native.py", "test_build_photos_native.py"):
            shutil.copyfile(userspace.native.ROOT / name, self.root / name)
        self.addCleanup(patch.stopall)
        patch.object(userspace.native, "ROOT", self.root).start()
        patch.object(userspace, "PHOTOS_COMPONENT", self.component).start()
        self.framework, self.receipt = self.root / "framework.jar", self.root / "framework.json"
        with zipfile.ZipFile(self.framework, "w") as archive:
            for i in range(1, 8):
                archive.writestr("classes" + (str(i) if i > 1 else "") + ".dex", b"synthetic DEX")
        self.dex = {"sha256": hashlib.sha256(b"synthetic DEX").hexdigest()}
        patch.object(taskmanager, "verify_dex", return_value=self.dex).start()
        self.proof = {
            "source_framework_sha256": userspace.PHOTOS_BASE_SHA,
            "candidate_sha256": userspace.sha256(self.framework), "candidate_bytes": self.framework.stat().st_size,
            "scope": ["com.google.android.apps.photos"],
            "sources": {str(p.relative_to(self.root)): userspace.sha256(p)
                        for p in [*self.component.rglob("*"), self.root / "build_photos_native.py",
                                  self.root / "test_build_photos_native.py"] if p.is_file()},
            "transform": {"changed_signatures": userspace.PHOTOS_TARGETS,
                          "changed_classes": [p.split("->")[0] for p in userspace.PHOTOS_TARGETS], "changed_count": 2},
            "preservation": {"original_classes": 6969, "unchanged_classes": 6967,
                             "unchanged_methods_in_changed_classes": 684,
                             "changed_methods": [p.split("->")[1] for p in userspace.PHOTOS_TARGETS],
                             "original_bodies_and_metadata_preserved": True},
            "dex": [self.dex, self.dex], "unchanged_original_dex": [f"classes{i}.dex" for i in range(2, 7)]}
        self.receipt.write_text(json.dumps(self.proof))
        self.bundle, self.boot_receipt = self.root / "boot.zip", self.root / "boot.json"
        self.boot_data = {name: (b"art\n119\0payload" if name.endswith(".art") else
                               b"\x7fELF\x02\x01" + b"\0" * 12 + b"\xb7\0oat\n279\0payload" if name.endswith(".oat") else
                               b"vdexpayload") for name in userspace.PHOTOS_BOOT_ENTRIES}
        self.boot_proof = {"schema": 1, "framework_sha256": userspace.sha256(self.framework),
                           "art_version": "119", "oat_version": "279", "private_namespace_verified": True,
                           "namespace_cases": [{"isolated_process_mode": mode,
                               "direct_model": "Pixel XL" if mode == "photos" else "OPD2415",
                               "helper_from_boot_classloader": True, "coherent_boot_images_mapped": True,
                               "scope_and_profile_pass": True, "version_fields_preserved": True,
                               "real_package_manager_hook": mode == "photos"} for mode in ("other", "forged", "photos")]}
        self.save_boot()
        self.files = {"photos_framework": self.framework, "photos_framework_verification": self.receipt,
                      "photos_boot_bundle": self.bundle, "photos_boot_verification": self.boot_receipt}
        self.paths = json.loads((self.component / "boot-paths.json").read_text())

    def save_boot(self, data=None):
        with zipfile.ZipFile(self.bundle, "w") as archive:
            for name, payload in (self.boot_data if data is None else data).items():
                archive.writestr(name, payload)
        self.boot_proof["bundle_sha256"] = userspace.sha256(self.bundle)
        self.boot_proof["files"] = {name: {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
                                    for name, payload in (self.boot_data if data is None else data).items()}
        self.boot_receipt.write_text(json.dumps(self.boot_proof))

    def test_framework_receipt_binds_candidate_scope_targets_and_every_current_source(self):
        self.assertIn("components/photos-native/boot-paths.json", self.proof["sources"])
        self.assertEqual(userspace.verify_photos(self.framework, self.receipt), self.proof)
        for key, value in (("candidate_sha256", "0" * 64), ("source_framework_sha256", "0" * 64),
                           ("candidate_bytes", 1), ("scope", ["other.package"]), ("sources", {}),
                           ("transform", dict(self.proof["transform"], changed_signatures=userspace.PHOTOS_TARGETS[:1])),
                           ("preservation", dict(self.proof["preservation"], unchanged_methods_in_changed_classes=683)),
                           ("dex", [])):
            self.receipt.write_text(json.dumps(dict(self.proof, **{key: value})))
            with self.subTest(key=key), self.assertRaises(ValueError):
                userspace.verify_photos(self.framework, self.receipt)
        self.receipt.write_text(json.dumps(self.proof))
        (self.component / "boot-paths.json").write_text("changed after receipt")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            userspace.verify_photos(self.framework, self.receipt)

    def test_boot_receipt_binds_exact_candidates_versions_and_all_namespace_cases(self):
        self.assertEqual(userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt), self.boot_data)
        for key, value in (("schema", True), ("framework_sha256", "0" * 64), ("bundle_sha256", "0" * 64),
                           ("art_version", "118"), ("oat_version", "278"), ("private_namespace_verified", 1),
                           ("files", {}), ("namespace_cases", self.boot_proof["namespace_cases"][:2])):
            self.boot_receipt.write_text(json.dumps(dict(self.boot_proof, **{key: value})))
            with self.subTest(key=key), self.assertRaises(ValueError):
                userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt)
        for i in range(3):
            for key, value in (("helper_from_boot_classloader", False), ("coherent_boot_images_mapped", False),
                               ("scope_and_profile_pass", 1), ("version_fields_preserved", False),
                               ("direct_model", "wrong"), ("isolated_process_mode", "photos" if i != 2 else "other")):
                proof = json.loads(json.dumps(self.boot_proof))
                proof["namespace_cases"][i][key] = value
                self.boot_receipt.write_text(json.dumps(proof))
                with self.subTest(case=i, key=key), self.assertRaises(ValueError):
                    userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt)
        proof = json.loads(json.dumps(self.boot_proof))
        proof["namespace_cases"][2]["real_package_manager_hook"] = False
        self.boot_receipt.write_text(json.dumps(proof))
        with self.assertRaisesRegex(ValueError, "scope/profile"):
            userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt)

    def test_boot_zip_rejects_entries_hashes_magic_duplicates_crc_and_limits(self):
        for name in userspace.PHOTOS_BOOT_ENTRIES:
            self.save_boot(dict(self.boot_data, **{name: b"wrong magic"}))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "magic"):
                userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt)
        self.save_boot(dict(self.boot_data, **{"../outside": b"escape"}))
        with self.assertRaises(ValueError):
            userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt)
        self.save_boot()
        self.boot_proof["files"]["arm64/boot.art"]["sha256"] = "0" * 64
        self.boot_receipt.write_text(json.dumps(self.boot_proof))
        with self.assertRaisesRegex(ValueError, "hash/size"):
            userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt)
        self.save_boot()
        # Change stored payload bytes while retaining the entry's original CRC.
        data = self.bundle.read_bytes().replace(self.boot_data["arm64/boot.art"], b"art\n119\0PAYLOAD", 1)
        self.bundle.write_bytes(data)
        self.boot_proof["bundle_sha256"] = userspace.sha256(self.bundle)
        self.boot_receipt.write_text(json.dumps(self.boot_proof))
        with self.assertRaises(zipfile.BadZipFile):
            userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt)
        self.save_boot()
        original = zipfile.ZipFile.infolist
        def oversized(archive):
            infos = original(archive)
            infos[0].file_size = 129 * 1024**2
            return infos
        with patch.object(zipfile.ZipFile, "infolist", oversized), self.assertRaisesRegex(ValueError, "limit"):
            userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt)
        self.save_boot()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.bundle, "a") as archive:
                archive.writestr("arm64/boot.art", self.boot_data["arm64/boot.art"])
        self.boot_proof["bundle_sha256"] = userspace.sha256(self.bundle)
        self.boot_receipt.write_text(json.dumps(self.boot_proof))
        with self.assertRaisesRegex(ValueError, "ZIP entries"):
            userspace.photos_boot_payloads(self.framework, self.bundle, self.boot_receipt)

    def test_image_plan_requires_all_original_paths_regular_payloads_and_preserved_links(self):
        original = b"original framework"
        base_sha = hashlib.sha256(original).hexdigest()
        self.paths["source_framework_sha256"] = base_sha
        manifest = self.component / "boot-paths.json"
        manifest.write_text(json.dumps(self.paths))
        (self.component / "source-lock.json").write_text(json.dumps({"source_framework_sha256": base_sha}))
        entries = {path: {"mode": stat.S_IFREG | 0o644}
                   for path in self.paths["remove_paths"] + list(self.paths["replacement_paths"].values())}
        entries |= {path: {"mode": stat.S_IFLNK | 0o777} for path in self.paths["preserved_symlinks"]}
        def contents(image, path):
            return self.paths["preserved_symlinks"][path].encode() if path in self.paths["preserved_symlinks"] else original
        with patch.object(userspace, "sha256", return_value=userspace.r5_userspace.IMAGE_SHAS["system"]), \
             patch.object(userspace, "PHOTOS_BASE_SHA", base_sha), patch.object(userspace, "content", side_effect=contents), \
             patch.object(userspace, "photos_boot_payloads", return_value=self.boot_data):
            payloads, removals = userspace.photos_image_plan(Path("/source.img"), entries, self.files)
            self.assertEqual(removals, set(self.paths["remove_paths"]))
            self.assertEqual(set(payloads), set(self.paths["replacement_paths"].values()))
            self.assertEqual(payloads["/system/framework/boot.vdex"], self.boot_data["arm64/boot.vdex"])
            dangling = "/system/framework/arm64/obsolete.vdex"
            with patch.object(userspace, "content", side_effect=lambda image, path:
                              self.paths["remove_paths"][0].encode() if path == dangling else contents(image, path)), \
                 self.assertRaisesRegex(ValueError, "retained compiled symlink is dangling"):
                userspace.photos_image_plan(Path("/source.img"), dict(entries, **{dangling: {"mode": stat.S_IFLNK}}), self.files)
            for path in entries:
                with self.subTest(missing=path), self.assertRaisesRegex(ValueError, "original path missing"):
                    userspace.photos_image_plan(Path("/source.img"), {p: e for p, e in entries.items() if p != path}, self.files)
            path = self.paths["replacement_paths"]["arm64/boot.vdex"]
            with self.assertRaisesRegex(ValueError, "regular file"):
                userspace.photos_image_plan(Path("/source.img"), dict(entries, **{path: {"mode": stat.S_IFLNK}}), self.files)
            with patch.object(userspace, "content", return_value=b"wrong"), self.assertRaisesRegex(ValueError, "symlink drift"):
                userspace.photos_image_plan(Path("/source.img"), entries, self.files)
            with patch.object(userspace, "content", side_effect=lambda image, path:
                              contents(image, path) if path in self.paths["preserved_symlinks"] else b"wrong framework"), \
                 self.assertRaisesRegex(ValueError, "original framework JAR drift"):
                userspace.photos_image_plan(Path("/source.img"), entries, self.files)
            for path in ("/system/framework/framework.jar", "/system/framework/arm64/boot.vdex", "/data/cache/file"):
                manifest.write_text(json.dumps(dict(self.paths, remove_paths=self.paths["remove_paths"] + [path])))
                with self.subTest(overlap=path), self.assertRaises(ValueError):
                    userspace.photos_image_plan(Path("/source.img"), dict(entries, **{path: {"mode": stat.S_IFREG}}), self.files)
            manifest.write_text(json.dumps(self.paths))
            with patch.object(userspace, "sha256", return_value="0" * 64), self.assertRaisesRegex(ValueError, "pinned original R5"):
                userspace.photos_image_plan(Path("/source.img"), entries, self.files)

    def test_recipe_keeps_old_inputs_closed_and_requires_all_four_photos_pins_from_eight(self):
        recipe = {"schema": 1, "sequence": 1, "timestamp": 1793220000,
                  "images": {name: pin(self.framework) for name in userspace.PARTITIONS},
                  "trust": {name: pin(self.framework) for name in userspace.TRUST_PATHS}}
        path = self.root / "recipe.json"
        with patch.object(userspace.native, "image_kind", return_value="erofs"):
            for sequence in range(1, 10):
                recipe["sequence"] = sequence
                names = userspace.FILE_INPUTS | (userspace.DIAGNOSTICS_INPUTS if sequence >= 7 else set())
                names |= userspace.PHOTOS_INPUTS if sequence >= 8 else set()
                recipe["files"] = {name: pin(self.framework) for name in names}
                path.write_text(json.dumps(recipe))
                self.assertEqual(userspace.load_recipe(path)[0], recipe)
                for name in userspace.PHOTOS_INPUTS:
                    changed = dict(recipe, files=dict(recipe["files"]))
                    if sequence >= 8:
                        changed["files"].pop(name)
                    else:
                        changed["files"][name] = pin(self.framework)
                    path.write_text(json.dumps(changed))
                    with self.subTest(sequence=sequence, pin=name), self.assertRaisesRegex(ValueError, "pinned inputs"):
                        userspace.load_recipe(path)


@unittest.skipUnless(os.environ.get("EROFS_TEST_SCRATCH") and all(shutil.which(tool) for tool in ("mkfs.erofs", "dump.erofs", "fsck.erofs")), "supply owned CleanOS scratch and installed EROFS tools")
class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ["EROFS_TEST_SCRATCH"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.secret = b"SYNTHETIC_PRIVATE_AUTHORIZATION_REMOVAL_CHECK"
        self.keep = b"SIGNED_APK_APEX_BYTES_PRESERVED_WITHOUT_RESIGNING"
        self.jar = b"original client JAR fixture"
        self.meta = {"mode": stat.S_IFREG | 0o644, "uid": 123, "gid": 456, "mtime": 1230768002,
                     "mtime_nsec": 123456789, "xattrs": {"security.selinux": b"u:object_r:system_file:s0\0", "user.binary": b"\0\xff"}}
        images = {}
        for part in userspace.PARTITIONS:
            prefix = "/system" if part == "system" else ""
            files = {prefix + ("/build.prop" if part == "system" else "/etc/build.prop"): b"keep=1\n",
                     prefix + "/etc/init/keep.rc": b"on boot\n    setprop keep.normal 1\n",
                     prefix + "/bin/keep": b"keep executable bytes",
                     prefix + "/app/Signed.apk": self.keep, prefix + "/apex/Signed.apex": self.keep}
            links = {}
            if part == "system":
                files |= {userspace.INIT: diagnostic_init(INIT), userspace.TASKMANAGER: self.jar,
                          userspace.TASKMANAGER + ".fsv_meta": b"metadata for the original JAR only",
                          "/system/lib64/libprotobuf-cpp-lite.so": b"original donor DSO",
                          "/system/bin/update_engine": b"disabled donor binary",
                          "/system/etc/init/update_engine.rc": b"# intentionally disabled donor updater\n",
                          userspace.WATCHDOG_PATH: b"private watchdog",
                          "/system/etc/init/googlebook-private-logger.rc": b"private logger"}
                links["/adb_keys"] = "/product/etc/security/adb_keys"
            if part == "product":
                files["/etc/security/adb_keys"] = self.secret
            if part == "system_ext":
                files[userspace.PEN] = apk_fixture(b"old crashing pen fixture")
                files[userspace.POLICY] = b"(type existing_pen_app)\n"
                files[userspace.POLICY_MAPPING] = b";; retained mapping\n"
                files[userspace.POLICY_HASH] = (hashlib.sha256(
                    files[userspace.POLICY] + files[userspace.POLICY_MAPPING]).hexdigest() + "\n").encode()
            image = self.root / (part + "-source.img")
            self.make_image(image, files, links)
            images[part] = pin(image)
        files = {}
        for name in userspace.FILE_INPUTS:
            p = self.root / name
            p.write_bytes(apk_fixture(b"new headless/permission guards") if name == "pen_apk" else (name + " component fixture").encode())
            files[name] = pin(p)
        self.engine_meta = {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0, "mtime": 1230768000,
                              "mtime_nsec": 0, "xattrs": {"security.selinux": b"u:object_r:system_lib_file:s0\0"}}
        private = userspace.engine_libraries.DESTINATION
        self.engine_dso = private + "/liblp.so"
        self.engine_data = b"native private library fixture"
        self.engine_additions = {
            private: {"data": b"", "metadata": dict(self.engine_meta, mode=stat.S_IFDIR | 0o755)},
            self.engine_dso: {"data": self.engine_data, "metadata": self.engine_meta}}
        trust = {}
        for i, name in enumerate(userspace.TRUST_PATHS):
            p = self.root / ("trust-" + str(i))
            p.write_bytes((name + " trust fixture").encode())
            trust[name] = pin(p)
        self.recipe = {"schema": 1, "sequence": 1, "timestamp": 1793220000, "images": images, "files": files, "trust": trust}
        self.path = self.root / "recipe.json"
        self.path.write_text(json.dumps(self.recipe))

    def make_image(self, image, files, links):
        directories = {"/"}
        for path in files.keys() | links.keys():
            directories.update(map(str, Path(path).parents))
        archive = image.with_suffix(".tar")
        with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tar:
            for directory in sorted(directories, key=lambda p: (p.count("/"), p)):
                directory_meta = dict(self.meta, mode=stat.S_IFDIR | 0o755)
                if directory == "/":
                    directory_meta["xattrs"] = {}
                tar.addfile(tar_info(directory.lstrip("/") or ".", directory_meta, True))
            for path, data in files.items():
                info = tar_info(path.lstrip("/"), self.meta)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            for path, target in links.items():
                info = tar_info(path.lstrip("/"), dict(self.meta, mode=stat.S_IFLNK | 0o777))
                info.type, info.linkname = tarfile.SYMTYPE, target
                tar.addfile(info)
        subprocess.run(["mkfs.erofs", "--tar=f", "--preserve-mtime", "-x0", "-b4096", "-T1230768000", "--mkfs-time", "--quiet", str(image), str(archive)], check=True)

    def run_build(self, output):
        with patch.object(userspace, "TASKMANAGER_BASE_SHA", hashlib.sha256(self.jar).hexdigest()), \
             patch.object(userspace, "verify_inputs"), \
             patch.object(userspace.engine_libraries, "integration_inputs", return_value=(
                 self.engine_additions, Path(self.recipe["files"]["update_engine_rc"]["path"]).read_bytes())):
            return userspace.build(self.path, output, self.root)

    def test_real_three_image_assembly_preserves_signed_bytes_metadata_and_sanitizes(self):
        output = self.root / "native"
        before = {part: inventory(Path(pin["path"])) for part, pin in self.recipe["images"].items()}
        report = self.run_build(output)
        self.assertTrue(report["public_image"]["adb_key_paths_absent"])
        for part in userspace.PARTITIONS:
            image = output / (part + ".img")
            prefix = "/system" if part == "system" else ""
            after = inventory(image)
            for key in ("mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs"):
                self.assertEqual(after["/"][key], before[part]["/"][key])
            for path in (prefix + "/app/Signed.apk", prefix + "/apex/Signed.apex"):
                self.assertEqual(content(image, path), self.keep)
                for key in ("mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs"):
                    self.assertEqual(after[path][key], before[part][path][key])
            self.assertNotIn("/adb_keys", after)
            self.assertNotIn(prefix + "/etc/security/adb_keys", after)
            self.assertNotIn(self.secret, image.read_bytes())
            self.assertTrue(report["images"][part]["full_rewrite"])
            self.assertEqual(userspace.sha256(Path(self.recipe["images"][part]["path"])), self.recipe["images"][part]["sha256"])
        self.assertEqual(content(output / "system_ext.img", userspace.UPDATER), Path(self.recipe["files"]["updater"]["path"]).read_bytes())
        self.assertEqual(content(output / "system_ext.img", userspace.PEN), Path(self.recipe["files"]["pen_apk"]["path"]).read_bytes())
        self.assertEqual(content(output / "system_ext.img", userspace.POLICY),
                         b"(type existing_pen_app)\n" + userspace.NATIVE_POLICY)
        self.assertEqual(content(output / "system.img", userspace.TASKMANAGER), Path(self.recipe["files"]["taskmanager_jar"]["path"]).read_bytes())
        self.assertNotIn(userspace.TASKMANAGER + ".fsv_meta", inventory(output / "system.img"))
        self.assertNotIn(userspace.WATCHDOG_PATH, inventory(output / "system.img"))
        self.assertEqual(content(output / "system.img", "/system/lib64/libprotobuf-cpp-lite.so"), b"original donor DSO")
        added = inventory(output / "system.img")[self.engine_dso]
        self.assertEqual({k: added[k] for k in self.engine_meta}, self.engine_meta)
        self.assertEqual(content(output / "system.img", self.engine_dso), self.engine_data)
        self.assertEqual(list(self.root.glob("userspace-overlay-*")), [])

    def test_failed_rewrite_removes_only_new_outputs_and_preserves_existing(self):
        output = self.root / "failed"
        def fail(source, target, removals, scratch):
            target.write_bytes(b"partial")
            raise ValueError("synthetic rewrite failure")
        with patch.object(userspace, "rewrite", side_effect=fail), self.assertRaisesRegex(ValueError, "rewrite failure"):
            self.run_build(output)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob("userspace-overlay-*")), [])
        output.mkdir()
        sentinel = output / "preserve"
        sentinel.write_bytes(b"existing")
        with self.assertRaises(ValueError):
            self.run_build(output)
        self.assertEqual(sentinel.read_bytes(), b"existing")

    def test_native8_system_replaces_coherent_boot_files_removes_manifest_and_keeps_vdex_links(self):
        image = Path(self.recipe["images"]["system"]["path"])
        entries = inventory(image)
        files = {p: content(image, p) for p, e in entries.items() if stat.S_ISREG(e["mode"])}
        links = {p: content(image, p).decode() for p, e in entries.items() if stat.S_ISLNK(e["mode"])}
        paths = json.loads((userspace.PHOTOS_COMPONENT / "boot-paths.json").read_text())
        original = b"original framework fixture"
        source_sha = hashlib.sha256(original).hexdigest()
        paths["source_framework_sha256"] = source_sha
        component = self.root / "photos-component"
        component.mkdir()
        (component / "boot-paths.json").write_text(json.dumps(paths))
        (component / "source-lock.json").write_text(json.dumps({"source_framework_sha256": source_sha}))
        files |= {p: b"obsolete generated artifact" for p in paths["remove_paths"]}
        files |= {p: b"original boot file" for p in paths["replacement_paths"].values()}
        files["/system/framework/framework.jar"] = original
        files[userspace.TABLET_STATE_JAR] = b"original tablet state"
        links |= paths["preserved_symlinks"]
        self.make_image(image, files, links)
        self.recipe["images"]["system"] = pin(image)
        self.recipe["sequence"] = 8
        framework = self.root / "photos.jar"
        framework.write_bytes(b"Photos candidate")
        inputs = {group: {name: Path(record["path"]) for name, record in self.recipe[group].items()}
                  for group in ("images", "files", "trust")}
        inputs["files"] |= {name: framework for name in userspace.PHOTOS_INPUTS}
        boot = {name: (name + " coherent replacement").encode() for name in userspace.PHOTOS_BOOT_ENTRIES}
        output = self.root / "native8-system"
        output.mkdir()
        with patch.object(userspace, "PHOTOS_COMPONENT", component), patch.object(userspace, "PHOTOS_BASE_SHA", source_sha), \
             patch.dict(userspace.r5_userspace.IMAGE_SHAS, system=userspace.sha256(image)), \
             patch.object(userspace, "TASKMANAGER_BASE_SHA", hashlib.sha256(self.jar).hexdigest()), \
             patch.object(userspace, "patch_tablet_state", return_value=b"patched tablet state"), \
             patch.object(userspace, "photos_boot_payloads", return_value=boot), \
             patch.object(userspace.engine_libraries, "integration_inputs", return_value=(
                 self.engine_additions, inputs["files"]["update_engine_rc"].read_bytes())):
            userspace.assemble_partition("system", self.recipe, inputs, output, self.root)
        final = output / "system.img"
        after = inventory(final)
        self.assertFalse(set(paths["remove_paths"]) & after.keys())
        for name, path in paths["replacement_paths"].items():
            self.assertTrue(stat.S_ISREG(after[path]["mode"]))
            self.assertEqual(content(final, path), framework.read_bytes() if name == "framework.jar" else boot[name])
        for path, target in paths["preserved_symlinks"].items():
            self.assertTrue(stat.S_ISLNK(after[path]["mode"]))
            self.assertEqual(content(final, path), target.encode())
        self.assertEqual(content(final, "/system/app/Signed.apk"), self.keep)

    def test_standalone_partition_cleans_failed_verification_and_preserves_existing(self):
        output = self.root / "partition"
        output.mkdir()
        final = output / "product.img"
        def rewritten(source, target, removals, scratch):
            target.write_bytes(b"x" * 4096)
            return {}
        with patch.object(userspace, "partition_plan", return_value=({}, {}, set(), {"/expected": b"expected"})), \
             patch.object(userspace, "apply"), patch.object(userspace, "rewrite", side_effect=rewritten), \
             patch.object(userspace, "content", return_value=b"wrong"):
            with self.assertRaisesRegex(ValueError, "assembled file differs"):
                userspace.assemble_partition("product", self.recipe, {}, output, self.root)
        self.assertFalse(final.exists())
        self.assertEqual(list(self.root.glob("userspace-overlay-*")), [])
        final.write_bytes(b"existing image")
        with self.assertRaisesRegex(ValueError, "new absolute path"):
            userspace.assemble_partition("product", self.recipe, {}, output, self.root)
        self.assertEqual(final.read_bytes(), b"existing image")


if __name__ == "__main__":
    unittest.main()
