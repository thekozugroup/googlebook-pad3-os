"""Offline tests; optional installed payload-dumper-go supplies an independent decoder."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
import contextlib
import io
from unittest.mock import patch

import build_native_rom as native
from native_install import fstab, payload
from native_install.avb import verify as verify_avb
from native_install.layout import check_layout, parse_text_layout, check_target_state
from native_install.public_image import audit_text, check as check_public_image


def java_bin():
    home, compiler = os.environ.get("JAVA_HOME"), shutil.which("javac")
    directory = Path(home) / "bin" if home else Path(compiler).parent if compiler else None
    return directory if directory and all((directory / tool).is_file() for tool in ("java", "javac")) else None


FSTAB = """# Native EXT4 entries
system /system ext4 ro,barrier=1,discard wait,slotselect,avb=vbmeta_system,logical,first_stage_mount
system_ext /system_ext ext4 ro,barrier=1,discard wait,slotselect,avb=vbmeta_system,logical,first_stage_mount
product /product ext4 ro,barrier=1,discard wait,slotselect,avb=vbmeta_system,logical,first_stage_mount
vendor /vendor erofs ro wait,slotselect,avb=vbmeta_vendor,logical,first_stage_mount
"""


def cpio(items):
    result = bytearray()
    for ino, (name, data) in enumerate(items + [("TRAILER!!!", b"")], 1):
        values = [ino, 0o100644, 0, 0, 1, 1700000000, len(data), 0, 0, 0, 0, len(name) + 1, 0]
        result += b"070701" + b"".join(f"{v:08x}".encode() for v in values) + name.encode() + b"\0"
        result += bytes(-len(result) % 4)
        result += data + bytes(-len(data) % 4)
    return bytes(result)


def vendor_boot(text=FSTAB, extra=None, compression="raw"):
    items = [("system/etc/fstab.default", text.encode()), ("init.vendor.rc", b"unchanged init\n")]
    if extra:
        items.append(extra)
    raw = cpio(items)
    if compression == "gzip":
        import gzip
        raw = gzip.compress(raw, mtime=0)
    header = bytearray(4096)
    header[:8] = b"VNDRBOOT"
    struct.pack_into("<II", header, 8, 4, 4096)
    struct.pack_into("<I", header, 24, len(raw))
    struct.pack_into("<II", header, 2096, 2128, 7)
    struct.pack_into("<IIII", header, 2112, 108, 1, 108, 8)
    table = struct.pack("<III", len(raw), 0, 1) + bytes(96)
    result = header
    for section in (raw, b"DTBtest", table, b"config=1"):
        result += section + bytes(-len(section) % 4096)
    return bytes(result + bytes(65536 - len(result)))


def recovery_boot(compression="raw"):
    ramdisk = cpio([("system/etc/recovery.fstab", FSTAB.encode()), ("system/bin/recovery", b"recovery bytes erofs\0")])
    if compression == "gzip":
        import gzip
        ramdisk = gzip.compress(ramdisk, mtime=0)
    header = bytearray(4096)
    header[:8] = b"ANDROID!"
    struct.pack_into("<II", header, 8, 4096, len(ramdisk))
    struct.pack_into("<I", header, 20, 1584)
    struct.pack_into("<I", header, 40, 4)
    header[44:61] = b"unchangedcmdline!"
    result = header + b"K" * 4096 + ramdisk
    result += bytes(-len(result) % 4096)
    return bytes(result + bytes(65536 - len(result)))


def read_varint(data, index):
    value, shift = 0, 0
    while True:
        byte = data[index]
        index += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, index
        shift += 7


def signature_from_message(data):
    # Decode the two nested length-delimited fields independently of the writer.
    assert data[0] == 10
    _, start = read_varint(data, 1)
    assert data[start] == 18
    length, start = read_varint(data, start + 1)
    return data[start:start + length]


class FstabTests(unittest.TestCase):
    def test_current_erofs_baselines_are_accepted_only_unchanged(self):
        for original, patcher, decision in [(vendor_boot(), fstab.patch_vendor_boot, fstab.filesystem_decision),
                                            (recovery_boot(), fstab.patch_recovery, fstab.recovery_filesystem_decision)]:
            current = patcher(original)
            self.assertEqual(decision(current, current, "erofs")["filesystem"], "erofs")
            changed = current[:-1] + bytes([current[-1] ^ 1])
            with self.assertRaises(ValueError):
                decision(current, changed, "erofs")

    def test_recovery_patch_preserves_kernel_header_and_every_other_record(self):
        for compression in ("raw", "gzip"):
            with self.subTest(compression=compression):
                stock = recovery_boot(compression)
                before = fstab.unpack_recovery(stock)
                candidate = fstab.patch_recovery(stock)
                after = fstab.unpack_recovery(candidate)
                self.assertEqual(before["kernel"], after["kernel"])
                self.assertEqual(before["records"][1:], after["records"][1:])
                self.assertEqual(stock[:12] + stock[16:4096], candidate[:12] + candidate[16:4096])
                self.assertEqual(len(stock), len(candidate))
                decision = fstab.recovery_filesystem_decision(stock, candidate, "erofs")
                self.assertTrue(decision["kernel_preserved"])

    def test_ext4_recovery_and_unrelated_recovery_drift_cannot_pass_erofs_gate(self):
        stock = recovery_boot()
        with self.assertRaises(ValueError):
            fstab.recovery_filesystem_decision(stock, stock, "erofs")
        candidate = bytearray(fstab.patch_recovery(stock))
        candidate[4096] ^= 1
        with self.assertRaisesRegex(ValueError, "bounded EROFS patch"):
            fstab.recovery_filesystem_decision(stock, candidate, "erofs")
        struct.pack_into("<I", candidate, 1580, 4096)
        with self.assertRaisesRegex(ValueError, "GKI signature"):
            fstab.patch_recovery(candidate)
    def test_erofs_patch_preserves_every_unrelated_entry_and_section(self):
        for compression in ("raw", "gzip"):
            with self.subTest(compression=compression):
                stock = vendor_boot(compression=compression)
                candidate = fstab.patch_vendor_boot(stock)
                before, after = fstab.unpack_vendor_boot(stock), fstab.unpack_vendor_boot(candidate)
                self.assertEqual(len(stock), len(candidate))
                self.assertEqual(before["dtb"], after["dtb"])
                self.assertEqual(before["bootconfig"], after["bootconfig"])
                self.assertEqual(before["records"][1:], after["records"][1:])
                fstab.check_fstab(after["fstab"], "erofs")
                self.assertNotIn("barrier=1", after["fstab"])
                self.assertEqual(fstab.filesystem_decision(stock, candidate, "erofs")["filesystem"], "erofs")

    def test_unpatched_dsu_erofs_does_not_pass_native_fstab(self):
        stock = vendor_boot()
        with self.assertRaisesRegex(ValueError, "filesystem mismatch"):
            fstab.filesystem_decision(stock, stock, "erofs")
        fstab.filesystem_decision(stock, stock, "ext4")

    def test_layout_or_fstab_drift_is_rejected(self):
        for stock in (vendor_boot(extra=("fstab.other", FSTAB.encode())),
                      vendor_boot(FSTAB.replace("slotselect,", "")),
                      vendor_boot(FSTAB.replace("system /system", "system /"))):
            with self.assertRaises(ValueError):
                fstab.patch_vendor_boot(stock)
        stock = bytearray(vendor_boot())
        struct.pack_into("<I", stock, 2116, 2)
        with self.assertRaisesRegex(ValueError, "fragment table"):
            fstab.patch_vendor_boot(stock)

    def test_avb_tail_is_removed_only_in_copy_then_requires_resigning(self):
        stock = vendor_boot()
        end = fstab.unpack_vendor_boot(stock)["end"]
        signed = bytearray(stock)
        signed[end:end + 256] = b"AVB0" + bytes(252)
        signed[-64:] = struct.pack(">4sIIQQQ28s", b"AVBf", 1, 0, end, end, 256, bytes(28))
        self.assertEqual(fstab.patch_vendor_boot(signed), fstab.patch_vendor_boot(stock))
        self.assertEqual(signed[-64:-60], b"AVBf")
        signed[-65] = 1
        with self.assertRaisesRegex(ValueError, "outside AVB"):
            fstab.patch_vendor_boot(signed)

    def test_unknown_tail_and_changed_unrelated_ramdisk_are_rejected(self):
        stock = bytearray(vendor_boot())
        stock[-1] = 1
        with self.assertRaises(ValueError):
            fstab.patch_vendor_boot(stock)
        stock = vendor_boot()
        candidate = bytearray(fstab.patch_vendor_boot(stock))
        index = candidate.index(b"unchanged init")
        candidate[index] ^= 1
        with self.assertRaisesRegex(ValueError, "bounded EROFS patch"):
            fstab.filesystem_decision(stock, candidate, "erofs")


class ValidationTests(unittest.TestCase):
    def test_root_replacement_requires_exact_reviewed_image_and_complete_copy_set(self):
        with tempfile.TemporaryDirectory(prefix="root-image-test-") as temporary:
            directory = Path(temporary)
            hardware = {name: directory / (name + "-source.img") for name in ("boot", "init_boot")}
            hardware["boot"].write_bytes(b"unchanged kernel")
            hardware["init_boot"].write_bytes(bytes(8388608))
            images = {"boot": hardware["boot"], "init_boot": directory / "init_boot-target.img"}
            images["init_boot"].write_bytes(b"6" + bytes(8388607))
            boot_hash, source_hash = payload.sha256(hardware["boot"]), payload.sha256(hardware["init_boot"])
            root = {"version_code": 41100, "uapi": 6, "kernel": native.KERNEL,
                    "boot_sha256": boot_hash, "init_boot_sha256": payload.sha256(images["init_boot"])}
            pins = directory / "native_install/source-pins.json"
            pins.parent.mkdir()
            pins.write_bytes(native.json_bytes({"sukisu_root": root}))
            copies = sorted(payload.SOURCE_COPY_ALLOWED - {"init_boot"})
            with patch.object(native, "ROOT", directory), patch.object(native, "BOOT_SHA", boot_hash), \
                 patch.object(native, "INIT_BOOT_SHA", source_hash):
                self.assertEqual(native.check_root_images(hardware, images, copies)["operation"], "REPLACE")
                self.assertEqual(native.check_root_images(hardware, images, sorted(payload.SOURCE_COPY_ALLOWED))["operation"], "SOURCE_COPY")
                self.assertEqual(native.check_root_images(hardware, images,
                                 [name for name in copies if name != "product"])["operation"], "REPLACE")
                for invalid in ([], copies[:-1], copies + ["system"], copies + ["boot"], set(copies)):
                    with self.subTest(copies=invalid), self.assertRaisesRegex(ValueError, "reviewed Product delta"):
                        native.check_root_images(hardware, images, invalid)
                for pin in (None, "", "f" * 64, source_hash):
                    changed = dict(root, init_boot_sha256=pin)
                    pins.write_bytes(native.json_bytes({"sukisu_root": changed}))
                    with self.subTest(pin=pin), self.assertRaises(ValueError):
                        native.check_root_images(hardware, images, copies)
                pins.write_bytes(native.json_bytes({"sukisu_root": dict(root, uapi=5)}))
                with self.assertRaisesRegex(ValueError, "reviewed stack"):
                    native.check_root_images(hardware, images, copies)
                pins.write_bytes(native.json_bytes({"sukisu_root": root}))
                with self.assertRaisesRegex(ValueError, "exact reviewed UAPI 6 image"):
                    native.check_root_images(hardware, hardware, copies)
                changed_boot = directory / "changed-boot.img"
                changed_boot.write_bytes(b"changed kernel")
                with self.assertRaisesRegex(ValueError, "boot/kernel must remain unchanged"):
                    native.check_root_images(hardware, dict(images, boot=changed_boot), copies)
                # Even a reviewed hash cannot waive the matched physical image size.
                images["init_boot"].write_bytes(b"short image")
                root["init_boot_sha256"] = payload.sha256(images["init_boot"])
                pins.write_bytes(native.json_bytes({"sukisu_root": root}))
                with self.assertRaisesRegex(ValueError, "exact reviewed UAPI 6 image"):
                    native.check_root_images(hardware, images, copies)

    def test_plan_schema_allows_only_reviewed_root_and_product_exceptions(self):
        schema = json.loads((native.ROOT / "native_install/plan.schema.json").read_text())
        self.assertEqual(schema["properties"]["source_copy_partitions"]["enum"],
                         [sorted(payload.SOURCE_COPY_ALLOWED - omitted) for omitted in
                          (set(), {"init_boot"}, {"product"}, {"init_boot", "product"})])

    def test_product_cleanup_rejects_wrong_baseline_and_changed_target(self):
        from native_install import product_cleanup
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "source", Path(directory) / "target"
            source.write_bytes(b"baseline")
            target.write_bytes(b"reviewed target")
            with patch.object(product_cleanup, "SOURCE_SHA", payload.sha256(source)), \
                 patch.object(product_cleanup, "TARGET_SHA", payload.sha256(target)):
                product_cleanup.validate(source, target)
                target.write_bytes(b"changed target")
                with self.assertRaisesRegex(ValueError, "three-APK removal"):
                    product_cleanup.validate(source, target)
                source.write_bytes(b"changed baseline")
                with self.assertRaisesRegex(ValueError, "exact installed"):
                    product_cleanup.validate(source, target)

    def test_product_cleanup_removes_only_its_failed_generated_output(self):
        from native_install import product_cleanup
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "source", Path(directory) / "target"
            source.write_bytes(b"baseline")
            def generate(*args):
                target.write_bytes(b"unexpected rewrite")
                return {}
            with patch.object(product_cleanup, "SOURCE_SHA", payload.sha256(source)), \
                 patch.object(product_cleanup, "rewrite", side_effect=generate):
                with self.assertRaisesRegex(ValueError, "three-APK removal"):
                    product_cleanup.build(source, target, Path(directory))
                self.assertFalse(target.exists())
                self.assertEqual(source.read_bytes(), b"baseline")

    def test_product_release_accepts_only_reviewed_lineages(self):
        from native_install import product_cleanup
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old, current, updated, fixed, metrics, photos = [root / name for name in ("old", "current", "updated", "fixed", "metrics", "photos")]
            for path in (old, current, updated, fixed, metrics, photos):
                path.write_bytes(path.name.encode())
            with patch.object(product_cleanup, "SOURCE_SHA", payload.sha256(old)), \
                 patch.object(product_cleanup, "TARGET_SHA", payload.sha256(current)), \
                 patch.object(product_cleanup, "R5_TARGET_SHA", payload.sha256(updated)), \
                 patch.object(product_cleanup, "R5_DIAGNOSTICS_TARGET_SHA", payload.sha256(fixed)), \
                 patch.object(product_cleanup, "R5_METRICS_TARGET_SHA", payload.sha256(metrics)), \
                 patch.object(product_cleanup, "R5_PHOTOS_TARGET_SHA", payload.sha256(photos)):
                for target, source in ((current, None), (updated, None), (fixed, None), (metrics, None), (photos, None), (current, old), (updated, current), (fixed, updated), (metrics, fixed), (photos, fixed)):
                    product_cleanup.validate_release(target, source)
                for target, source in ((updated, old), (current, updated), (fixed, old), (fixed, current), (updated, fixed), (metrics, old), (metrics, updated), (fixed, metrics), (photos, metrics), (photos, updated)):
                    with self.assertRaises(ValueError):
                        product_cleanup.validate_release(target, source)
                updated.write_bytes(b"unreviewed target")
                with self.assertRaisesRegex(ValueError, "reviewed physical"):
                    product_cleanup.validate_release(updated)

    def test_image_reader_allows_android_sonames_and_rejects_path_escape(self):
        with patch("erofs_overlay.content", return_value=b"pinned library"):
            self.assertEqual(native.image_file(Path("unused"), "erofs", "/lib64/private/android.hardware.boot@1.2.so"), b"pinned library")
            for path in ("/lib64/../secret", "/lib64/a;id.so", "/lib64/a\n"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    native.image_file(Path("unused"), "erofs", path)

    def test_only_clean_references_and_production_recovery_targets_are_approved(self):
        hardware = {name: name + "-source" for name in ("vendor_boot", "recovery")}
        images = {name: name + "-target" for name in hardware}
        pins = {hardware["vendor_boot"]: native.CLEAN_VENDOR_BOOT_SHA, hardware["recovery"]: native.CLEAN_RECOVERY_SHA,
                images["vendor_boot"]: native.NATIVE_VENDOR_BOOT_SHA, images["recovery"]: native.NATIVE_RECOVERY_SHA}
        with patch.object(native, "sha256", side_effect=lambda p: pins[p]):
            native.check_production_boot_chain(hardware, images)
            pins[hardware["vendor_boot"]] = native.NATIVE_VENDOR_BOOT_SHA
            pins[hardware["recovery"]] = native.NATIVE_RECOVERY_SHA
            native.check_production_boot_chain(hardware, images)
            for path in (hardware["recovery"], images["recovery"], hardware["vendor_boot"]):
                saved = pins[path]
                pins[path] = "f" * 64
                with self.subTest(path=path), self.assertRaises(ValueError):
                    native.check_production_boot_chain(hardware, images)
                pins[path] = saved

    def test_target_capacities_firmware_and_snapshot_status_are_evidence_bound(self):
        source = {"boot": 4096, "init_boot": 8192}
        state = {"schema": 1, "source_slot": "b", "target_slot": "a", "slot_count": 2,
                 "source_successful": True, "bootloader_unlocked": True, "hal_snapshot_merge_status": "NONE",
                 "gsi_tool_status": "installed\ndisabled\n", "gsi_tool_exit_code": 0,
                 "libsnapshot_update_state": "none", "cow_reconciliation_reviewed": True,
                 "physical_partition_sizes": {n: {"a": size, "b": size} for n, size in source.items()},
                 "firmware_hashes": {n: {"a": "a" * 64, "b": "a" * 64} for n in ("modem", "dsp", "bluetooth")},
                 "other_firmware_compatibility_reviewed": True}
        check_target_state(state, source, source)
        for key, value in (("hal_snapshot_merge_status", "MERGING"), ("bootloader_unlocked", False)):
            changed = copy.deepcopy(state)
            changed[key] = value
            with self.assertRaises(ValueError):
                check_target_state(changed, source, source)
        changed = copy.deepcopy(state)
        changed["gsi_tool_status"] += "running\n"
        with self.assertRaisesRegex(ValueError, "DSU is running"):
            check_target_state(changed, source, source)
        changed = copy.deepcopy(state)
        changed["gsi_tool_status"] = "installed\nenabled\n"
        with self.assertRaisesRegex(ValueError, "DSU is running/enabled"):
            check_target_state(changed, source, source)
        changed = copy.deepcopy(state)
        changed["physical_partition_sizes"]["boot"]["a"] = 8192
        with self.assertRaises(ValueError):
            check_target_state(changed, source, source)
    def test_full_text_metadata_normalizes_extents_and_rejects_overlap(self):
        names = ["system", "system_ext", "product", "vendor", "odm", "vendor_dlkm", "system_dlkm"]
        text = "Slot 1:\nMetadata version: 10.2\nMetadata max size: 65536 bytes\nMetadata slot count: 3\nHeader flags: virtual_ab_device\nPartition table:\n------------------------\n"
        for number, name in enumerate(names):
            text += f"  Name: {name}_b\n  Group: oneplus_dynamic_partitions_b\n  Attributes: readonly,updated\n  Extents:\n    0 .. 7 linear super {2048 + number * 8}\n------------------------\n"
        text += "Super partition layout:\nBlock device table:\n  Partition name: super\n  First sector: 2048\n  Size: 1073741824 bytes\n  Flags: none\nGroup table:\n  Name: oneplus_dynamic_partitions_b\n  Maximum size: 1069547520 bytes\n  Flags: none\n"
        normalized = parse_text_layout(text)
        self.assertEqual(normalized["metadata_reserved_bytes"], 405504)
        self.assertEqual({p["name"] for p in normalized["partitions"]}, set(names))
        with self.assertRaisesRegex(ValueError, "overlapping"):
            parse_text_layout(text.replace("linear super 2056", "linear super 2048"))
    def test_public_image_rejects_keys_without_reading_their_contents(self):
        for location in (("system", "/adb_keys"), ("system", "/system/etc/security/adb_keys"), ("product", "/etc/security/adb_keys")):
            reads = []
            with patch("native_install.public_image.exists", side_effect=lambda image, path: (image, path) == location):
                with self.assertRaisesRegex(ValueError, "must remove key"):
                    check_public_image({"system": "system", "product": "product", "system_ext": "system_ext"},
                                       lambda image, path: reads.append(path), "/system")
            self.assertEqual(reads, [])

    def test_forced_diagnostic_adb_and_debug_services_are_rejected(self):
        for blob in (b"    setprop persist.sys.usb.config adb\n", b"googlebook-dsu-v11\n",
                     b"ro.adb.secure=0\n", b"ro.boot.apex.early_adbd=true\n", b"service.adb.listen_addrs=tcp:localhost:5555\n"):
            with self.assertRaises(ValueError):
                audit_text(blob)
        audit_text(b"ro.adb.secure=1\nro.debuggable=0\non property:sys.usb.config=adb\n    start adbd\n")
    def test_usage_only_or_changed_allocation_metadata_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "usage alone"):
            check_layout({"enabled": True, "partitions": [{"name": "system", "fs_size": "1000"}]}, [], 1000, "")
        groups = [{"name": "dynamic", "maximum_size": 8192, "partitions": ["system"]}]
        metadata = {"enabled": True, "groups": [{"name": "dynamic", "maximum_size": "8192"}],
                    "block_devices": [{"name": "super"}], "super_device": {"total_size": "16384"},
                    "partitions": [{"name": "system", "group_name": "dynamic", "is_dynamic": True}]}
        check_layout(metadata, groups, 16384, "Block device table:\nGroup table:\ndynamic")
        with self.assertRaises(ValueError):
            check_layout(metadata, groups, 32768, "Block device table:\nGroup table:\ndynamic")
    def test_native_property_rejects_donor_identity_and_duplicates(self):
        native.check_device_property(b"ro.product.system.device=erhai\n", "ro.product.system.device")
        for blob in (b"ro.product.system.device=desktop\n", b"", b"ro.product.system.device=erhai\nro.product.system.device=mica\n"):
            with self.assertRaises(ValueError):
                native.check_device_property(blob, "ro.product.system.device")
    def test_repository_rejects_tokens_redirects_and_placeholders(self):
        for value in ("https://github.com/a/b", "a/b?token=secret", "a/../b", "a/b/c", "OWNER/PUBLIC_REPO"):
            with self.assertRaises(ValueError):
                native.repo_name(value)
        self.assertEqual(native.repo_name(native.PUBLIC_REPO), native.PUBLIC_REPO)

    def test_native_identity_and_forbidden_partition_fail_before_file_reads(self):
        base = {"schema": 1, "capture": {"device": "erhai", "slot": "b", "dsu_running": False,
                "page_size": 4096, "kernel": native.KERNEL, "build_utc": 1792932356,
                "snapshot_state": "none", "virtual_ab": False, "hardware": dict.fromkeys(native.HARDWARE)},
                "source_slot": "b", "target_slot": "a", "system_as_root": True, "images": dict.fromkeys(native.PARTITIONS),
                "source_copy_partitions": []}
        for key, value in (("device", "mica"), ("slot", "a"),
                           ("kernel", "6.6.144-old"), ("page_size", 16384)):
            plan = copy.deepcopy(base)
            plan["capture"][key] = value
            with self.assertRaises(ValueError):
                native.validate_plan(plan, None, {})
        for forbidden in ("persist", "userdata", "modemst1", "fsg", "metadata", "modem"):
            plan = copy.deepcopy(base)
            plan["images"][forbidden] = {}
            with self.assertRaisesRegex(ValueError, "allowed matched-base"):
                native.validate_plan(plan, None, {})

    def test_metadata_comparison_covers_xattrs_owner_mode_hardlinks_and_time(self):
        source = {"/": {"mode": 0o40755, "uid": 0, "gid": 0, "mtime": 1, "mtime_nsec": 2,
                        "xattrs": {"security.selinux": "BASE64", "security.capability": "CAPBASE64"},
                        "content_sha256": None, "symlink": None, "hardlink": None, "rdev": None}}
        native.compare_metadata(source, copy.deepcopy(source))
        for key, value in (("uid", 1), ("mode", 0o40700), ("xattrs", {}), ("mtime_nsec", 0), ("hardlink", "/x")):
            changed = copy.deepcopy(source)
            changed["/"][key] = value
            with self.assertRaisesRegex(ValueError, "changed"):
                native.compare_metadata(source, changed)
        with self.assertRaises(ValueError):
            native.compare_metadata(source, {})

    def test_no_device_controller_in_native_implementation(self):
        for path in [native.ROOT / "build_native_rom.py", *list((native.ROOT / "native_install").glob("*.py"))]:
            source = path.read_text()
            self.assertNotIn('["adb"', source)
            self.assertNotIn('["fastboot"', source)


class ManagerBootstrapTests(unittest.TestCase):
    def test_script_syntax_and_shell_install_skip_refusal_paths(self):
        source = native.manager_bootstrap().decode()
        self.assertEqual(subprocess.run(["/bin/sh", "-n"], input=source, text=True, capture_output=True).returncode, 0)
        for uid, decision, should_install, success in (("2000", "10", True, True), ("0", "10", True, True),
                                                       ("2000", "0", False, True), ("2000", "20", False, False),
                                                       ("10001", "10", False, False)):
            with self.subTest(uid=uid, decision=decision), tempfile.TemporaryDirectory(prefix="manager-shell-test-") as directory:
                directory = Path(directory).resolve()
                script = directory / native.BOOTSTRAP_PATH
                apk = directory / native.MANAGER_PATH
                checker = script.parent / "SukiSUManagerCheck.jar"
                for path in (script, apk, checker):
                    path.parent.mkdir(parents=True, exist_ok=True)
                apk.write_bytes(b"public fake APK for shell flow test")
                checker.write_bytes(b"fake checker for shell flow test")
                body = source.replace("/system_ext/", str(directory / "system_ext") + "/")
                body = body.replace(native.MANAGER_SHA, payload.sha256(apk)).replace(native.MANAGER_CHECKER_SHA, payload.sha256(checker))
                script.write_text(body)
                bin_dir = directory / "bin"
                bin_dir.mkdir()
                mocks = {
                    "id": 'echo "$MOCK_UID"', "getprop": "echo 1",
                    "readlink": 'printf "%s\\n" "$2"',
                    "sha256sum": 'exec /usr/bin/shasum -a 256 "$@"',
                    "app_process": '[ -f "$MOCK_INSTALLED" ] && exit 0; exit "$MOCK_DECISION"',
                    "cmd": '[ "$*" = "package install -r --user all $MOCK_APK" ] || exit 99; : > "$MOCK_INSTALLED"',
                }
                for name, body in mocks.items():
                    executable = bin_dir / name
                    executable.write_text("#!/bin/sh\n" + body + "\n")
                    executable.chmod(0o755)
                installed = directory / "installed"
                env = os.environ.copy()
                env.update(PATH=str(bin_dir) + ":/usr/bin:/bin", MOCK_UID=uid, MOCK_DECISION=decision,
                           MOCK_INSTALLED=str(installed), MOCK_APK=str(apk))
                result = subprocess.run(["/bin/sh", str(script)], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                self.assertEqual(installed.exists(), should_install)

    @unittest.skipUnless(java_bin(), "installed JDK required")
    def test_current_certificate_version_and_path_decisions(self):
        with tempfile.TemporaryDirectory(prefix="manager-java-test-") as directory:
            directory = Path(directory)
            harness = directory / "ManagerDecisionTest.java"
            harness.write_text('''public final class ManagerDecisionTest {
              static void expect(int want, int got) { if (want != got) throw new AssertionError(want + " != " + got); }
              public static void main(String[] args) {
                expect(10, ManagerDecision.decide(false, false, 0, false, false, false));
                expect(0, ManagerDecision.decide(true, true, 41101, true, false, true));
                expect(0, ManagerDecision.decide(true, true, 41100, true, false, true));
                expect(10, ManagerDecision.decide(true, true, 41068, true, false, true));
                expect(10, ManagerDecision.decide(true, true, 40994, true, false, true));
                expect(10, ManagerDecision.decide(true, true, 40900, true, false, true));
                expect(10, ManagerDecision.decide(true, true, 40994, false, true, true));
                expect(20, ManagerDecision.decide(true, true, 41101, false, true, true));
                expect(20, ManagerDecision.decide(true, false, 41101, true, false, true));
                expect(20, ManagerDecision.decide(true, true, 41101, true, false, false));
                expect(20, ManagerDecision.decide(true, true, 41100, false, false, true));
              }
            }''')
            jdk = java_bin()
            result = subprocess.run([str(jdk / "javac"), "--release", "8", "-d", str(directory),
                                     str(native.ROOT / "native_install/manager/ManagerDecision.java"), str(harness)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(jdk / "java"), "-cp", str(directory), "ManagerDecisionTest"], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for real signing tests")
class PayloadTests(unittest.TestCase):
    def test_root_migration_payload_replaces_init_boot_and_copies_all_other_baseline_partitions(self):
        from test_source_copy import decode_message, decode_payload, reconstruct
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            directory = Path(temporary)
            images = {}
            for index, name in enumerate(sorted(native.PARTITIONS)):
                images[name] = directory / (name + ".img")
                images[name].write_bytes(bytes([index + 1]) * 4096)
            copies = payload.SOURCE_COPY_ALLOWED - {"init_boot"}
            output = directory / "root-payload.bin"
            payload.write_payload(images, [], 1793220000, True, self.key, self.cert, output, directory,
                                  source_copy_partitions=copies)
            blob = output.read_bytes()
            manifest, partitions, _, _, _ = decode_payload(blob)
            self.assertEqual(manifest[12], [6])
            for name, part in partitions.items():
                operations = [decode_message(record)[1][0] for record in part[8]]
                self.assertEqual(operations, [4 if name in copies else 0], name)
                self.assertEqual(6 in part, name in copies, name)
            sources = {name: images[name].read_bytes() for name in copies}
            self.assertEqual(reconstruct(blob, sources), {name: image.read_bytes() for name, image in images.items()})
            sources["product"] = b"changed Product".ljust(4096, b"\0")
            with self.assertRaisesRegex(ValueError, "source baseline mismatch"):
                reconstruct(blob, sources)

    def test_trust_overlay_places_official_seed_only_in_unscanned_system_ext(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            directory = Path(temporary)
            apk, checker = directory / "official.apk", directory / "native_install/manager/SukiSUManagerCheck.jar"
            checker.parent.mkdir(parents=True)
            apk.write_bytes(b"synthetic official APK")
            checker.write_bytes(b"synthetic checker")
            bootstrap = native.manager_bootstrap()
            output = directory / "overlay"
            with patch.object(native, "ROOT", directory), \
                 patch.dict(os.environ, {"GOOGLEBOOK_MANAGER_CHECKER": str(checker)}), \
                 patch.object(native, "scratch_output", side_effect=lambda path: Path(path)), \
                 patch.object(native, "MANAGER_CHECKER_SHA", payload.sha256(checker)), \
                 patch.object(native, "manager_bootstrap", return_value=bootstrap), \
                 patch.object(native, "verify_manager") as verify:
                native.trust_overlay(native.PUBLIC_REPO, self.cert, apk, None, None, output)
            verify.assert_called_once_with(apk, None, None)
            self.assertFalse((output / "product").exists())
            self.assertEqual((output / "system_ext/etc/googlebook/SukiSU.apk").read_bytes(), apk.read_bytes())
            self.assertEqual((output / native.BOOTSTRAP_PATH).read_bytes(), bootstrap)
            self.assertEqual((output / native.MANAGER_CHECKER_PATH).read_bytes(), checker.read_bytes())
            self.assertEqual((output / native.BOOTSTRAP_PATH).stat().st_mode & 0o777, 0o755)
            manifest = json.loads((output / "integration.json").read_text())
            self.assertEqual(manifest["files"][native.MANAGER_PATH], payload.sha256(apk))

    def test_public_followup_builder_preserves_userdata_and_binds_source_slot(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            directory = Path(temporary)
            images = dict(self.images)
            for name in native.PARTITIONS - images.keys():
                images[name] = directory / (name + ".img")
                images[name].write_bytes(b"C" * 4096)
            plan = {"repository": native.PUBLIC_REPO, "timestamp": 1793220000, "sequence": 2, "source_slot": "b",
                    "expires_utc": 1795812000, "release_tag": "native-2", "capture": {"build_utc": 1792932356, "virtual_ab": True},
                    "avb_mode": "preserve-native-disabled", "super_bytes": 16384, "partition_sizes": {},
                    "version": "native-test-2", "pre_build_fingerprints": ["synthetic/native/test:17/test/1:user/release-keys"],
                    "dynamic_groups": [], "source_copy_partitions": sorted(payload.SOURCE_COPY_ALLOWED),
                    "images": {n: {"sha256": payload.sha256(p)} for n, p in images.items()}}
            plan_path = directory / "plan.json"
            plan_path.write_bytes(native.json_bytes(plan))
            output = directory / "output"
            with patch.object(native, "scratch_output", side_effect=lambda path: Path(path)), \
                 patch.object(native, "FEED_KEY_SHA", payload.sha256(self.feed_public)), \
                 patch.object(native, "validate_plan", return_value=(images, {"synthetic_test": True})):
                release = native.build(plan_path, None, self.key, self.cert, {"scratch": directory}, output,
                                       self.feed_key, self.feed_public)
            validation = json.loads((output / "validation.json").read_bytes())
            self.assertEqual(release["source_slot"], "_b")
            self.assertIs(validation["requires_factory_reset"], False)
            self.assertIs(validation["userdata_preserved"], True)
            self.assertEqual(validation["wipes"], 0)
            self.assertFalse(any("reset" in gate.lower() or "wipe" in gate.lower()
                                 for gate in validation["pending_execution_gates"]))

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-test-")
        cls.directory = Path(cls.temporary.name)
        cls.key, cls.cert = cls.directory / "ephemeral-test.key", cls.directory / "ephemeral-test.pem"
        result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
                                 "-subj", "/CN=Disposable native builder test/", "-keyout", str(cls.key),
                                 "-out", str(cls.cert)], capture_output=True)
        assert result.returncode == 0
        cls.feed_key, cls.feed_public = cls.directory / "ephemeral-feed.key", cls.directory / "feed.der"
        payload.openssl("genrsa", "-out", cls.feed_key, "3072")
        cls.feed_public.write_bytes(payload.openssl("pkey", "-in", cls.feed_key, "-pubout", "-outform", "DER"))
        cls.images = {"system": cls.directory / "system.img", "boot": cls.directory / "boot.img"}
        cls.images["system"].write_bytes(b"A" * (payload.CHUNK + 4096))
        cls.images["boot"].write_bytes(b"B" * 4096)
        cls.output = cls.directory / "payload.bin"
        cls.properties, cls.hashes = payload.write_payload(cls.images,
            [{"name": "test_dynamic", "maximum_size": 16 * 1024**2, "partitions": ["system"]}],
            1793220000, False, cls.key, cls.cert, cls.output, cls.directory)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_signatures_and_tamper_rejection(self):
        blob = self.output.read_bytes()
        major, manifest_size, signature_size = struct.unpack_from(">QQI", blob, 4)
        self.assertEqual(major, 2)
        end = 24 + manifest_size
        metadata_signature = signature_from_message(blob[end:end + signature_size])
        final_at = end + signature_size + sum(p.stat().st_size for p in self.images.values())
        final_signature = signature_from_message(blob[final_at:])
        public = payload.public_key(self.cert)
        metadata_digest = hashlib.sha256(blob[:end]).digest()
        data_digest = hashlib.sha256(blob[:end] + blob[end + signature_size:final_at]).digest()
        payload.verify_digest(metadata_digest, metadata_signature, public, self.directory)
        payload.verify_digest(data_digest, final_signature, public, self.directory)
        for digest, signature in ((hashlib.sha256(blob[:end] + b"tamper").digest(), metadata_signature),
                                  (hashlib.sha256(blob[:end] + blob[end + signature_size:final_at] + b"tamper").digest(), final_signature)):
            with self.assertRaises(ValueError):
                payload.verify_digest(digest, signature, public, self.directory)
        self.assertEqual(self.properties["METADATA_SIZE"], str(end))
        self.assertEqual(self.hashes, {n: payload.sha256(p) for n, p in self.images.items()})

    @unittest.skipUnless(shutil.which("payload-dumper-go"), "independent payload decoder unavailable")
    def test_independent_decoder_restores_exact_images_and_checks_partition_hashes(self):
        destination = self.directory / "decoded"
        result = subprocess.run(["payload-dumper-go", "-c", "2", "-o", str(destination), str(self.output)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr[-1000:])
        self.assertEqual({n: payload.sha256(destination / (n + ".img")) for n in self.images}, self.hashes)

    def test_existing_output_is_preserved(self):
        original = payload.sha256(self.output)
        with self.assertRaisesRegex(ValueError, "already exists"):
            payload.write_payload(self.images, [], 1, False, self.key, self.cert, self.output, self.directory)
        self.assertEqual(payload.sha256(self.output), original)

    def test_unaligned_partition_is_rejected_without_output(self):
        bad, output = self.directory / "unaligned.img", self.directory / "bad-payload.bin"
        bad.write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "unaligned"):
            payload.write_payload({"system": bad}, [], 1, False, self.key, self.cert, output, self.directory)
        self.assertFalse(output.exists())

    def test_ota_config_has_only_own_repo_public_trust(self):
        config = native.ota_config(native.PUBLIC_REPO, self.cert)
        self.assertEqual(config["feed_url"], native.FEED_URL)
        self.assertNotIn(str(self.key), json.dumps(config))
        self.assertTrue(config["requires_factory_reset_for_initial_install"])

    def test_split_assets_reconstruct_exact_zip_with_pinned_repo_urls(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            directory = Path(directory)
            archive = directory / "native.zip"
            original = b"1234567890" * 1000
            archive.write_bytes(original)
            with patch.object(native, "RELEASE_PART_BYTES", 4096):
                assets = native.release_assets(archive, "owner/public", "native-1")
            self.assertFalse(archive.exists())
            self.assertEqual(len(assets), 3)
            reconstructed = b"".join((directory / a["name"]).read_bytes() for a in assets)
            self.assertEqual(reconstructed, original)
            for asset in assets:
                self.assertLessEqual(asset["bytes"], 4096)
                self.assertEqual(asset["sha256"], payload.sha256(directory / asset["name"]))
                self.assertTrue(asset["url"].startswith("https://github.com/owner/public/releases/download/native-1/"))

    def test_zip_descriptor_offset_signature_and_no_key_packaging(self):
        import zipfile
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            directory = Path(directory)
            plan = {"repository": native.PUBLIC_REPO, "timestamp": 1793220000, "sequence": 1, "source_slot": "b",
                    "expires_utc": 1795812000, "release_tag": "native-1", "capture": {"build_utc": 1792932356, "virtual_ab": False},
                    "avb_mode": "verified", "super_bytes": 16384, "partition_sizes": {},
                    "version": "native-test-1", "pre_build_fingerprints": ["synthetic/native/test:17/test/test:user/release-keys"],
                    "dynamic_groups": [], "source_copy_partitions": [],
                    "images": {n: {"sha256": payload.sha256(p)} for n, p in self.images.items()}}
            plan_path = directory / "plan.json"
            plan_path.write_bytes(native.json_bytes(plan))
            # Candidate construction is allowed before any final installer/reset approval.
            output = directory / "output"
            # Isolate packaging from real-image and CleanOS gates, tested separately.
            with patch.object(native, "scratch_output", side_effect=lambda path: Path(path)), \
                 patch.object(native, "FEED_KEY_SHA", payload.sha256(self.feed_public)), \
                 patch.object(native, "validate_plan", return_value=(self.images, {"synthetic_test": True})):
                descriptor = native.build(plan_path, None, self.key, self.cert, {"scratch": directory}, output,
                                          self.feed_key, self.feed_public)
            validation = json.loads((output / "validation.json").read_bytes())
            self.assertIsNone(validation["parent_review_sha256"])
            self.assertIs(validation["execution_approved"], False)
            self.assertEqual(validation["wipes"], 0)
            archive = output / "GoogleBook-erhai-native.zip"
            with zipfile.ZipFile(archive) as package:
                self.assertEqual(set(package.namelist()), {"payload.bin", "payload_properties.txt", "META-INF/com/android/metadata"})
                self.assertNotIn(b"ota-wipe", package.read("META-INF/com/android/metadata"))
                self.assertIn(b"pre-device=erhai\n", package.read("META-INF/com/android/metadata"))
                self.assertNotIn(b"|", package.read("META-INF/com/android/metadata"))
                self.assertNotIn(b"POWERWASH", package.read("payload_properties.txt"))
            with archive.open("rb") as stream:
                stream.seek(descriptor["payload"]["offset"])
                self.assertEqual(stream.read(4), b"CrAU")
            signed = (output / "stable.json").read_bytes()
            self.assertNotIn(str(self.key).encode(), signed)
            self.assertEqual(json.loads(signed), [descriptor])
            self.assertEqual(set(descriptor), {"schema", "device", "channel", "version", "sequence", "published_at", "expires_at",
                                               "base_profile", "pre_build_fingerprints", "source_slot", "ota", "payload"})
            feed_public = payload.openssl("pkey", "-pubin", "-inform", "DER", "-in", self.feed_public, "-pubout")
            payload.verify_digest(hashlib.sha256(signed).digest(), (output / "stable.json.sig").read_bytes(), feed_public, directory)
            # Compile the actual updater consumer against the actual writer ZIP, including ZIP64.
            jdk = java_bin()
            if jdk is None:
                self.skipTest("set JAVA_HOME or put a JDK on PATH for the writer/consumer contract")
            bridge = directory / "NativeProducerConsumerTest.java"
            bridge.write_text('''package org.googlebook.pad3.updater;
              import java.io.*; import java.util.*;
              public final class NativeProducerConsumerTest {
                public static void main(String[] a) throws Exception {
                  File zip = new File(a[0]); UpdateCore.Release r = new UpdateCore.Release();
                  r.version="actual-writer"; r.sourceSlot="_b"; r.sequence=1; r.published=100; r.expires=200;
                  r.baseProfile="erhai-crdroid-20261025"; r.fingerprints.add("fixture");
                  r.otaSize=Long.parseLong(a[1]); r.otaHash=a[2]; r.offset=Long.parseLong(a[3]);
                  r.payloadSize=Long.parseLong(a[4]); r.payloadHash=a[5]; r.metadataSize=Long.parseLong(a[6]); r.metadataHash=a[7];
                  r.properties=Arrays.copyOfRange(a,8,12);
                  r.parts.add(new UpdateCore.Part("https://github.com/thekozugroup/googlebook-pad3-os/releases/download/test/ota.zip",r.otaSize,r.otaHash));
                  r.validate(150); UpdateCore.verifyZip(zip,r);
                  int prefix=UpdateCore.metadataPrefixSize(zip,r);
                  try (RandomAccessFile input=new RandomAccessFile(zip,"r")) {
                    input.seek(r.offset+20); long signature=Integer.toUnsignedLong(input.readInt());
                    if (signature<=0 || prefix!=r.metadataSize+signature) throw new AssertionError("Missing metadata signature");
                    byte[] full=new byte[prefix]; input.seek(r.offset); input.readFully(full);
                  }
                }
              }''')
            classes = directory / "contract-classes"
            classes.mkdir()
            result = subprocess.run([str(jdk / "javac"), "--release", "17", "-d", str(classes),
                                     str(native.ROOT / "components/updater/src/org/googlebook/pad3/updater/UpdateCore.java"), str(bridge)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            archive64 = directory / "forced-zip64.zip"
            with zipfile.ZipFile(archive) as original, zipfile.ZipFile(archive64, "w", compression=zipfile.ZIP_STORED) as changed:
                with original.open("payload.bin") as original_payload, changed.open("payload.bin", "w", force_zip64=True) as new_payload:
                    shutil.copyfileobj(original_payload, new_payload)
                for name in ("payload_properties.txt", "META-INF/com/android/metadata"):
                    changed.writestr(name, original.read(name))
            for candidate in (archive, archive64):
                with zipfile.ZipFile(candidate) as package:
                    info = package.getinfo("payload.bin")
                    with candidate.open("rb") as stream:
                        stream.seek(info.header_offset + 26)
                        names, extra = struct.unpack("<HH", stream.read(4))
                    offset = info.header_offset + 30 + names + extra
                fields = descriptor["payload"]
                args = [str(candidate), str(candidate.stat().st_size), payload.sha256(candidate), str(offset), str(fields["size"]),
                        fields["sha256"], str(fields["metadata_size"]), fields["metadata_sha256"], *fields["properties"]]
                result = subprocess.run([str(jdk / "java"), "-cp", str(classes), "org.googlebook.pad3.updater.NativeProducerConsumerTest", *args],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_feed_rsa3072_cannot_be_used_as_aosp_rsa_payload_key(self):
        cert = self.directory / "feed-payload-test.pem"
        payload.openssl("req", "-new", "-x509", "-key", self.feed_key, "-days", "1",
                        "-subj", "/CN=Ephemeral unsupported payload key test/", "-out", cert)
        output = self.directory / "unsupported-payload.bin"
        with self.assertRaisesRegex(ValueError, "RSA-2048 or RSA-4096"):
            payload.write_payload(self.images, [], 1, False, self.feed_key, cert, output, self.directory)
        self.assertFalse(output.exists())


@unittest.skipUnless(os.environ.get("NATIVE_AVBTOOL"), "set NATIVE_AVBTOOL to pinned AOSP source for real AVB tests")
class AvbTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="native-avb-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.avbtool = Path(os.environ["NATIVE_AVBTOOL"])
        self.key = self.directory / "ephemeral-test.key"
        payload.openssl("genrsa", "-out", self.key, "2048")
        self.public = self.directory / "public.pem"
        self.public.write_bytes(payload.openssl("pkey", "-in", self.key, "-pubout"))
        self.pubblob = self.directory / "public.avbpubkey"
        self.run_tool("extract_public_key", "--key", self.key, "--output", self.pubblob)
        self.images = {name: self.directory / (name + ".img") for name in native.PARTITIONS}
        for name in native.PARTITIONS - {"vbmeta", "vbmeta_system", "vbmeta_vendor"}:
            self.images[name].write_bytes(bytes(4096))
            self.run_tool("add_hash_footer", "--image", self.images[name], "--partition_name", name,
                          "--partition_size", "131072", "--algorithm", "SHA256_RSA2048", "--key", self.key)
        assignments = {"vbmeta_system": ["system", "system_ext", "product", "system_dlkm"],
                       "vbmeta_vendor": ["vendor", "odm", "vendor_dlkm"],
                       "vbmeta": ["init_boot"]}
        for name, members in assignments.items():
            args = ["make_vbmeta_image", "--output", self.images[name], "--algorithm", "SHA256_RSA2048", "--key", self.key]
            for member in members:
                args += ["--include_descriptors_from_image", self.images[member]]
            if name == "vbmeta":
                args += ["--chain_partition", f"vbmeta_system:1:{self.pubblob}",
                         "--chain_partition", f"vbmeta_vendor:2:{self.pubblob}",
                         "--chain_partition", f"boot:3:{self.pubblob}",
                         "--chain_partition", f"dtbo:4:{self.pubblob}",
                         "--chain_partition", f"recovery:5:{self.pubblob}",
                         "--chain_partition", f"vendor_boot:6:{self.pubblob}"]
            self.run_tool(*args)
        self.originals = {}
        for name in native.PHYSICAL - {"init_boot"}:
            destination = self.directory / ("captured-" + name + ".img")
            shutil.copyfile(self.images[name], destination)
            self.originals[name] = destination
        self.keys = dict.fromkeys(self.originals, self.public)

    def run_tool(self, *args):
        import sys
        result = subprocess.run([sys.executable, "-B", str(self.avbtool), *map(str, args)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr[-1000:])

    def verify(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return verify_avb(self.images, self.originals, self.avbtool, self.keys)

    def test_real_chain_and_all_partition_descriptors_verify(self):
        evidence = self.verify()
        self.assertEqual(set(evidence), set(self.originals))
        self.assertTrue(all(entry["flags"] == 0 for entry in evidence.values()))

    def test_partition_tamper_fails(self):
        with self.images["init_boot"].open("r+b") as stream:
            stream.write(b"tamper")
        with self.assertRaisesRegex(ValueError, "AVB descriptor/signature"):
            self.verify()

    def test_unsigned_and_disabled_verification_flags_fail(self):
        self.run_tool("make_vbmeta_image", "--output", self.images["vbmeta"], "--flags", "2")
        with self.assertRaisesRegex(ValueError, "flags"):
            self.verify()

    def test_substituted_chain_key_fails(self):
        other = self.directory / "other-test.key"
        payload.openssl("genrsa", "-out", other, "2048")
        self.public.write_bytes(payload.openssl("pkey", "-in", other, "-pubout"))
        with self.assertRaises(ValueError):
            self.verify()

    def test_preserve_disabled_requires_exact_signed_native_vbmeta(self):
        args = ["make_vbmeta_image", "--output", self.images["vbmeta"], "--algorithm", "SHA256_RSA2048",
                "--key", self.key, "--flags", "3", "--include_descriptors_from_image", self.images["init_boot"]]
        for number, child in enumerate(("vbmeta_system", "vbmeta_vendor", "boot", "dtbo", "recovery", "vendor_boot"), 1):
            args += ["--chain_partition", f"{child}:{number}:{self.pubblob}"]
        self.run_tool(*args)
        shutil.copyfile(self.images["vbmeta"], self.originals["vbmeta"])
        with contextlib.redirect_stdout(io.StringIO()):
            evidence = verify_avb(self.images, self.originals, self.avbtool, {}, "preserve-native-disabled")
        self.assertEqual(evidence["vbmeta"]["flags"], 3)
        self.assertIn("disabled", evidence["limitation"])
        with self.images["vbmeta_system"].open("r+b") as stream:
            stream.seek(255)
            stream.write(b"X")
        with self.assertRaisesRegex(ValueError, "preserve all captured"):
            verify_avb(self.images, self.originals, self.avbtool, {}, "preserve-native-disabled")


if __name__ == "__main__":
    unittest.main()
