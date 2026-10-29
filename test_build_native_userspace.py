import base64
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
    def test_native_protobuf_binds_bytes_source_and_original_metadata(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("EROFS_TEST_SCRATCH")) as directory:
            root = Path(directory)
            source, dso, manifest = root / "system_b.img", root / "protobuf.so", root / "metadata.json"
            source.write_bytes(b"source image")
            dso.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\xb7\0native protobuf")
            meta = {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0, "mtime": 1230768000,
                    "mtime_nsec": 123, "xattrs": {"security.selinux": b"u:object_r:system_lib_file:s0\0", "user.binary": b"\0\xff"}}
            proof = {"source_image": pin(source), "image_path": userspace.PROTOBUF, "bytes": dso.stat().st_size,
                     "sha256": userspace.sha256(dso), "metadata": dict(meta, xattrs={k: base64.b64encode(v).decode() for k, v in meta["xattrs"].items()})}
            manifest.write_text(json.dumps(proof))
            files = {"update_engine_protobuf": dso, "update_engine_protobuf_metadata": manifest}
            self.assertEqual(userspace.protobuf_addition(files), {"data": dso.read_bytes(), "metadata": meta})
            dso.write_bytes(dso.read_bytes() + b"tampered")
            with self.assertRaisesRegex(ValueError, "source proof mismatch"):
                userspace.protobuf_addition(files)
            source.write_bytes(b"changed source image")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                userspace.protobuf_addition(files)

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
                     "transform": {"grafted_methods": 5}, "preservation": {
                         "changed_methods": list(taskmanager.TARGET_COUNTS), "manager_methods": 89,
                         "untouched_manager_methods": 84,
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
                  b"persist.adb.tls_server.enable=0\nservice.adb.listen_addrs=tcp:localhost:5555\n"
                  b"persist.sys.usb.config=adb\nro.boot.apex.early_adbd=1\nro.build.user=PRIVATE_OWNER\n")
        source += b"ro.audio.ihaladaptervendorextension_enabled=true\nro.audio.ihaladaptervendorextension_enabled=true\n"
        result = userspace.native_properties(source, "system", 3, 1793220000)
        for line in (b"dalvik.vm.heapsize=512m", b"debug.sf.ignore_hwc_physical_display_orientation=true",
                     b"ro.product.system.device=erhai", b"ro.googlebook.pad3.release_sequence=3",
                     b"ro.build.ab_update=true", b"ro.virtual_ab.enabled=true", b"ro.debuggable=0", b"ro.adb.secure=1"):
            self.assertIn(line + b"\n", result)
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
        self.assertTrue(result.startswith(original.split(b"</config>")[0]))
        self.assertEqual(userspace.overlay_config(result), result)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            userspace.overlay_config(result.replace(b'mutable="false"', b'mutable="true"'))

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
            image = self.root / (part + "-source.img")
            self.make_image(image, files, links)
            images[part] = pin(image)
        files = {}
        for name in userspace.FILE_INPUTS:
            p = self.root / name
            p.write_bytes(apk_fixture(b"new headless/permission guards") if name == "pen_apk" else (name + " component fixture").encode())
            files[name] = pin(p)
        self.protobuf_meta = {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0, "mtime": 1230768000,
                              "mtime_nsec": 0, "xattrs": {"security.selinux": b"u:object_r:system_lib_file:s0\0"}}
        dso = Path(files["update_engine_protobuf"]["path"])
        dso.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\xb7\0native protobuf fixture")
        manifest = Path(files["update_engine_protobuf_metadata"]["path"])
        manifest.write_text(json.dumps({"source_image": images["system"], "image_path": userspace.PROTOBUF,
                                       "bytes": dso.stat().st_size, "sha256": userspace.sha256(dso),
                                       "metadata": dict(self.protobuf_meta, xattrs={k: base64.b64encode(v).decode() for k, v in self.protobuf_meta["xattrs"].items()})}))
        files["update_engine_protobuf"], files["update_engine_protobuf_metadata"] = pin(dso), pin(manifest)
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
             patch.object(userspace, "verify_inputs"):
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
        self.assertEqual(content(output / "system.img", userspace.TASKMANAGER), Path(self.recipe["files"]["taskmanager_jar"]["path"]).read_bytes())
        self.assertNotIn(userspace.WATCHDOG_PATH, inventory(output / "system.img"))
        self.assertEqual(content(output / "system.img", "/system/lib64/libprotobuf-cpp-lite.so"), b"original donor DSO")
        added = inventory(output / "system.img")[userspace.PROTOBUF]
        self.assertEqual({k: added[k] for k in self.protobuf_meta}, self.protobuf_meta)
        self.assertEqual(content(output / "system.img", userspace.PROTOBUF), Path(self.recipe["files"]["update_engine_protobuf"]["path"]).read_bytes())
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
