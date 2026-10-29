import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

import build_native_userspace as userspace
from erofs_overlay import content, metadata
from native_install import r5_userspace as r5
import port_changes as port
from tablet_state import patch_tablet_state
from test_port_changes import INIT


def digest(data):
    return hashlib.sha256(data).hexdigest()


def recipe():
    value = {"schema": 2, "lineage": r5.LINEAGE, "sequence": 5, "timestamp": 1793301598,
             "images": {name: {"path": "/inputs/" + name + ".img", "sha256": sha}
                        for name, sha in r5.IMAGE_SHAS.items()},
             "files": {name: {"path": "/inputs/" + name, "sha256": "0" * 64}
                       for name in userspace.FILE_INPUTS | {"tablet_graft_source"}},
             "trust": {name: {"path": "/inputs/trust/" + name, "sha256": "0" * 64}
                       for name in userspace.TRUST_PATHS}}
    value["files"]["tablet_graft_source"]["sha256"] = r5.GRAFT_SHA
    return value


class LineageTests(unittest.TestCase):
    def load(self, value):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recipe.json"
            path.write_text(json.dumps(value))
            return userspace.load_recipe(path)

    def test_explicit_schema_two_and_graft_are_required(self):
        value = recipe()
        with patch.object(userspace.native, "checked", side_effect=lambda pin: Path(pin["path"])), \
             patch.object(userspace.native, "image_kind", return_value="erofs"):
            loaded, inputs = self.load(value)
        self.assertEqual(loaded, value)
        self.assertEqual(inputs["files"]["tablet_graft_source"], Path("/inputs/tablet_graft_source"))
        for field in ("lineage", "tablet_graft_source"):
            bad = copy.deepcopy(value)
            del (bad if field == "lineage" else bad["files"])[field]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "unexpected|missing"):
                self.load(bad)

    def test_wrong_lineage_image_or_graft_pin_fails_before_file_reads(self):
        values = []
        for field, replacement in (("lineage", "mica-r2-16560795"), ("sequence", 4)):
            bad = recipe()
            bad[field] = replacement
            values.append(bad)
        for part in r5.IMAGE_SHAS:
            bad = recipe()
            bad["images"][part]["sha256"] = "0" * 64
            values.append(bad)
        bad = recipe()
        bad["files"]["tablet_graft_source"]["sha256"] = "0" * 64
        values.append(bad)
        bad = recipe()
        bad["images"]["system"] = "not a file pin"
        values.append(bad)
        with patch.object(userspace.native, "checked", side_effect=AssertionError("must reject before file reads")):
            for bad in values:
                with self.subTest(value=bad), self.assertRaises(ValueError):
                    self.load(bad)

    def test_expected_hash_label_does_not_accept_different_actual_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "not-r5.img"
            image.write_bytes(b"different filesystem bytes")
            value = recipe()
            value["images"]["system"]["path"] = str(image)
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                self.load(value)

    def test_schema_one_keeps_its_original_shape(self):
        value = recipe()
        value["schema"], value["sequence"] = 1, 4
        del value["lineage"]
        del value["files"]["tablet_graft_source"]
        with patch.object(userspace.native, "checked", side_effect=lambda pin: Path(pin["path"])), \
             patch.object(userspace.native, "image_kind", return_value="erofs"):
            self.assertEqual(self.load(value)[0], value)
        value["lineage"] = r5.LINEAGE
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.load(value)

    @unittest.skipUnless(os.environ.get("PAD3_R5_RECEIPT"), "supply the verified R5 receipt")
    def test_constants_match_signed_target_receipt(self):
        receipt = json.loads(Path(os.environ["PAD3_R5_RECEIPT"]).read_text())
        targets = {p["name"]: p["target_sha256"] for p in receipt["partitions"]}
        self.assertEqual(r5.IMAGE_SHAS, {name: targets[name] for name in r5.IMAGE_SHAS})
        self.assertTrue(receipt["metadata_and_payload_RSA_signatures_verified"])


class FunctionalTests(unittest.TestCase):
    def test_clean_init_changes_only_functional_usb_property(self):
        result = r5.production_init(INIT)
        self.assertEqual(result.replace(b"    setprop vendor.usb.use_gadget_hal 0\n", b""), INIT)
        for command in port.DIAGNOSTIC_WAITS.values():
            self.assertEqual(result.count(command.encode()), INIT.count(command.encode()))
        for bad in (INIT.replace(b"on early-init\n", b""), INIT + b"on early-init\n",
                    result, port.diagnostic_init(INIT)):
            with self.subTest(data=bad[:80]), self.assertRaises(ValueError):
                r5.production_init(bad)

    def test_properties_compose_tablet_display_heap_and_native_identity(self):
        props = {"system": b"trusty.security_vm.enabled=0\nro.secure=1\nservice.adb.listen_addrs=tcp:localhost:5555\n",
                 "system_ext": b"ro.sf.lcd_density=420\n", "product": b"other=yes\n"}
        functional = port.display_heap_properties(props)
        result = userspace.native_properties(functional, "system", 5, 1793301598)
        for name, value in (port.DISPLAY_PROPERTIES | port.HEAP_PROPERTIES).items():
            self.assertEqual(result.count((name + "=" + value + "\n").encode()), 1)
        self.assertIn(b"trusty.security_vm.enabled=0\n", result)
        self.assertIn(b"Googlebook/erhai/erhai:17/GBOS/5:user/release-keys", result)
        self.assertNotIn(b"service.adb.listen_addrs", result)
        for part in props:
            bad = dict(props)
            bad[part] += b"dalvik.vm.heapsize=1m\n"
            with self.subTest(part=part), self.assertRaisesRegex(ValueError, "already present"):
                port.display_heap_properties(bad)

    def test_pen_and_production_policy_bind_one_final_mapping_digest(self):
        cil, mapping = b"(type original)\n", b";; retained tablet mapping\n"
        marker = ("\n;; Pad3 pen-only policy from native system_ext " + r5.NATIVE_CIL_SHA256 + "\n").encode()
        module = marker + b"(type pen_app)\n"
        initial = (digest(cil + mapping) + "\n").encode()
        with patch.object(r5, "PEN_MODULE_SHA", digest(module)):
            pen, pen_hash = r5.pen_policy(cil, mapping, initial, b"old donor platform\n" + module)
            final, final_hash = userspace.native_policy(pen, mapping, pen_hash)
            self.assertEqual(final, cil + module + userspace.NATIVE_POLICY)
            self.assertEqual(final_hash, (digest(final + mapping) + "\n").encode())
            self.assertNotIn(b"old donor platform", final)
            for old, mapped, proof, seeded in ((cil, mapping, b"wrong", module),
                                               (pen, mapping, pen_hash, module),
                                               (cil, mapping, initial, module + b"changed")):
                with self.subTest(old=old), self.assertRaises(ValueError):
                    r5.pen_policy(old, mapped, proof, seeded)

    def test_clean_system_plan_uses_repair_output_before_posture(self):
        image = Path("/inputs/system.img")
        functional = {"/system/build.prop": b"trusty.security_vm.enabled=0\n",
                      userspace.INIT: r5.production_init(INIT), userspace.TABLET_STATE_JAR: b"repair-patched"}
        paths = set(functional) | {userspace.TASKMANAGER, "/system/bin/update_engine", "/system/etc/init/update_engine.rc"}
        entries = {path: {"mode": stat.S_IFREG | 0o644} for path in paths}
        for path in paths:
            for parent in PurePosixPath(path).parents:
                entries[str(parent)] = {"mode": stat.S_IFDIR | 0o755}
        source = {"/system/build.prop": b"raw properties\n", userspace.TASKMANAGER: b"original-client",
                  userspace.TABLET_STATE_JAR: b"clean-JAR"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {}
            for name in ("component_certificate", "taskmanager_jar", "update_engine", "update_engine_rc", "tablet_graft_source", "update_engine_bundle"):
                files[name] = root / name
                files[name].write_bytes(name.encode())
            inputs = {"images": {"system": image}, "files": files, "trust": {}}
            with patch.object(userspace, "inventory", return_value=entries), \
                 patch.object(userspace, "content", side_effect=lambda image, path: source[path]), \
                 patch.object(r5, "plan", return_value=(dict(functional), {}, set())), \
                 patch.object(userspace.engine_libraries, "integration_inputs", return_value=({}, files["update_engine_rc"].read_bytes())), \
                 patch.object(userspace, "TASKMANAGER_BASE_SHA", digest(b"original-client")), \
                 patch.object(userspace, "strip_diagnostics", side_effect=AssertionError("no diagnostic intermediate")), \
                 patch.object(userspace, "patch_tablet_state", return_value=b"repair-and-tablet") as posture:
                changes, additions, removals, payloads = userspace.partition_plan(image, "system", recipe(), inputs)
            posture.assert_called_once_with(b"repair-patched")
            self.assertEqual(payloads[userspace.TABLET_STATE_JAR], b"repair-and-tablet")
            self.assertIn(b"trusty.security_vm.enabled=0\n", payloads["/system/build.prop"])
            self.assertEqual(changes[userspace.INIT], r5.production_init(INIT))
            self.assertEqual(additions, {})
            self.assertEqual(removals, set())

    def test_clean_system_ext_composes_policy_contexts_and_graft_metadata(self):
        image = Path("/inputs/system_ext.img")
        original, pen, mapping = b"(type original)\n", b"(type pen_app)\n", b";; mapping\n"
        functional = {"/etc/build.prop": b"ro.sf.lcd_density=420\n", userspace.POLICY: original + pen,
                      userspace.POLICY_HASH: (digest(original + pen + mapping) + "\n").encode(),
                      userspace.FILE_CONTEXTS: b"original contexts\n" + r5.AUDIO_CONTEXT}
        paths = set(functional) | {userspace.POLICY_MAPPING}
        entries = {path: {"mode": stat.S_IFREG | 0o644} for path in paths}
        entries["/"] = {"mode": stat.S_IFDIR | 0o755}
        source = {"/etc/build.prop": b"old properties\n", userspace.POLICY: original,
                  userspace.POLICY_MAPPING: mapping, userspace.FILE_CONTEXTS: b"original contexts\n",
                  userspace.POLICY_HASH: (digest(original + mapping) + "\n").encode()}
        meta = {"mode": stat.S_IFREG | 0o755, "uid": 0, "gid": 1000, "mtime": 1230768000,
                "mtime_nsec": 0, "xattrs": {"security.selinux": b"u:object_r:audio_vendor_parameter_parser_exec:s0\0"}}
        grafts = {"/bin/qtiaudiohalvendorextn": {"data": b"reviewed tablet executable", "metadata": meta}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {}
            for name in ("component_certificate", "tablet_graft_source", "update_engine_bundle", "face_overlay", "updater", "pen_apk", "taskmanager_metrics", "manager_service"):
                files[name] = root / name
                files[name].write_bytes(name.encode())
            with patch.object(userspace, "inventory", return_value=entries), \
                 patch.object(userspace, "content", side_effect=lambda image, path: source[path]), \
                 patch.object(r5, "plan", return_value=(dict(functional), grafts, set())), \
                 patch.object(userspace.engine_libraries, "integration_inputs", return_value=({}, b"unused")):
                _, additions, _, payloads = userspace.partition_plan(image, "system_ext", recipe(),
                    {"images": {"system_ext": image}, "files": files, "trust": {}})
            self.assertEqual(payloads[userspace.POLICY], original + pen + userspace.NATIVE_POLICY)
            self.assertEqual(payloads[userspace.POLICY_HASH], (digest(payloads[userspace.POLICY] + mapping) + "\n").encode())
            self.assertTrue(payloads[userspace.FILE_CONTEXTS].startswith(functional[userspace.FILE_CONTEXTS]))
            self.assertEqual(additions["/bin/qtiaudiohalvendorextn"]["metadata"], meta)
            self.assertEqual(additions[userspace.METRICS_BINARY]["metadata"]["mode"], stat.S_IFREG | 0o755)


@unittest.skipUnless(os.environ.get("PAD3_R2_IMAGES") and os.environ.get("PAD3_V10_IMAGES")
                     and shutil.which("dump.erofs"), "supply verified clean R2 and immutable V10 images")
class RealFunctionalProof(unittest.TestCase):
    def test_direct_functional_transforms_match_retained_seed_without_diagnostics(self):
        root, seed = Path(os.environ["PAD3_R2_IMAGES"]), Path(os.environ["PAD3_V10_IMAGES"])
        images = {part: root / (part + ".img") for part in r5.IMAGE_SHAS}
        pins = json.loads((r5.ROOT / "inputs.json").read_text())["donor"]["partitions"]
        for part, image in images.items():
            self.assertEqual(userspace.sha256(image), pins[part + "_a"])
        graft_source = seed / "system_ext.img"
        self.assertEqual(userspace.sha256(graft_source), r5.GRAFT_SHA)
        certificate = (r5.ROOT / "profiles/pad3-components/certificate.der").read_bytes()
        with patch.object(port, "diagnostic_changes", side_effect=AssertionError("no diagnostic planner")), \
             patch.object(port, "diagnostic_init", side_effect=AssertionError("no diagnostic init")), \
             patch.object(port, "public_adb_key", side_effect=AssertionError("no ADB authorization")):
            for part in r5.IMAGE_SHAS:
                payloads, grafts, removals = r5.plan(images, part, graft_source, certificate)
                for path, data in payloads.items():
                    expected = content(seed / (part + ".img"), path)
                    if path == userspace.INIT:
                        self.assertEqual(data.rstrip(), userspace.strip_diagnostics(expected).rstrip())
                    else:
                        self.assertEqual(data, expected, part + ":" + path)
                if part == "system_ext":
                    self.assertEqual(set(grafts), {"/" + name for name in r5.GRAFT})
                    for path, item in grafts.items():
                        self.assertEqual(item["data"], content(graft_source, path))
                        self.assertEqual(item["metadata"], metadata(graft_source, path))
                self.assertNotIn(port.WATCHDOG_PATH, payloads)
                self.assertNotIn("/etc/security/adb_keys", payloads)
                self.assertNotIn("/system/etc/init/tradeinmode.rc", payloads)
                self.assertEqual(removals, set(userspace.product_cleanup.REMOVALS) if part == "product" else set())

    @unittest.skipUnless(os.environ.get("PAD3_R5_SYSTEM"), "supply the verified R5 System image")
    def test_actual_r5_repair_then_posture_and_clean_init_keep_original_guards(self):
        image = Path(os.environ["PAD3_R5_SYSTEM"])
        self.assertEqual(userspace.sha256(image), r5.IMAGE_SHAS["system"])
        jar = content(image, port.JAR_PATH)
        repaired = port.disable_repair_mode(jar)
        final = patch_tablet_state(repaired)
        self.assertEqual(digest(final), "5336294875792306d4a4f2b57bdb75d33c537f76ffe1e7b637d5f6171399f444")
        init = content(image, userspace.INIT)
        self.assertEqual(r5.production_init(init).replace(b"    setprop vendor.usb.use_gadget_hal 0\n", b""), init)
        receiver = content(image, port.REPAIR_SYSCONFIG_PATH)
        self.assertIn(port.REPAIR_RECEIVER.encode(), port.disable_repair_receiver(receiver))


if __name__ == "__main__":
    unittest.main()
