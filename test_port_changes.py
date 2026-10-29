import base64
import hashlib
import os
import re
import stat
import struct
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from desktop_repair_gate import JAR_PATH
from port_changes import (BOOT_STAGE_FILE, BOOT_STAGE_PROPERTY, DESKTOP_SECURITY_HAL_NAMES,
                          DIAGNOSTIC_USB_REFRESH, DIAGNOSTIC_WAITS, DISPLAY_PROPERTIES, HEAP_PROPERTIES,
                          REPAIR_PACKAGE, REPAIR_RECEIVER, REPAIR_SYSCONFIG_PATH,
                          TIPS_SYSCONFIG, TIPS_SYSCONFIG_PATH,
                          DISABLED_SYSTEM_INIT, diagnostic_changes, diagnostic_init,
                          disable_repair_receiver, neutralize_system_init, public_adb_key, remove_desktop_security_hal,
                          replace_property, WATCHDOG_NAME, WATCHDOG_PATH, WATCHDOG_SCRIPT, WATCHDOG_SERVICE)


INIT = ("on early-init\n    exec_start apexd-bootstrap\n    perform_apex_config\n\n"
        "on init\n    mkdir /config 0500 root root\n\n"
        "on late-init\n    trigger post-fs-data\n\n"
        "on post-fs-data\n    load_persist_props\n" + "".join("    " + command + "\n"
            for name, command in DIAGNOSTIC_WAITS.items() if name != "odsign-verification") +
        "\non zygote-start\n    wait_for_prop odsign.verification.done 1\n    start zygote\n").encode()
TPM = b"on early-fs\n    mkdir /metadata/hwsec_metadata 775 root root\non post-fs-data\n    exec_background -- /system/bin/check_tpm_clear\n"
TRADEIN = b"on property:persist.adb.tradeinmode=-1 && property:ro.debuggable=0\n    stop adbd\n"
PROPS = (b"ro.secure=1\nro.adb.secure=1\nro.debuggable=0\nro.force.debuggable=0\n"
         b"service.adb.listen_addrs=tcp:localhost:5555\n")
PRODUCT_PROPS = b"other=1\nro.setupwizard.require_network=any\n"
REPAIR_CONFIG = (b'<?xml version="1.0" encoding="UTF-8"?>\n<!-- original comment -->\n<config>\n'
                 b'    <initial-package-state package="com.google.android.desktop.repairmode" stopped="false"/>\n'
                 b'</config>\n')


def key_fixture():
    key = bytearray(524)
    struct.pack_into("<I", key, 0, 64)
    struct.pack_into("<I", key, 520, 65537)
    return base64.b64encode(key) + b" owner@test\n"


class PortChanges(unittest.TestCase):
    def test_property_edit_is_exact(self):
        data = b"# trusty.security_vm.enabled=1\ntrusty.security_vm.enabled=1\nother=1\n"
        result = replace_property(data, "trusty.security_vm.enabled", "0", "1")
        self.assertEqual(result, b"# trusty.security_vm.enabled=1\ntrusty.security_vm.enabled=0\nother=1\n")

    def test_new_property_and_donor_drift(self):
        self.assertEqual(replace_property(b"other=1\n", "density", "420"), b"other=1\ndensity=420\n")
        with self.assertRaises(ValueError):
            replace_property(b"key=2\n", "key", "0", "1")
        with self.assertRaises(ValueError):
            replace_property(b"key=1\nkey=1\n", "key", "0")

    def test_setup_network_property_exact_delta_and_drift_rejection(self):
        key = "ro.setupwizard.require_network"
        original = b"# ro.setupwizard.require_network=any\nkeep=1\n" + PRODUCT_PROPS + b"last=unchanged"
        expected = original.replace(b"\nro.setupwizard.require_network=any\n", b"\nro.setupwizard.require_network=\n")
        self.assertEqual(replace_property(original, key, "", expected="any"), expected)
        self.assertEqual(len(original) - len(expected), 3)
        for data in [PRODUCT_PROPS + b"ro.setupwizard.require_network=any\n",
                     PRODUCT_PROPS + b"ro.setupwizard.require_network=wifi\n",
                     PRODUCT_PROPS.replace(b"=any", b"=wifi"), PRODUCT_PROPS.replace(b"=any", b"="), b"other=1\n"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                replace_property(data, key, "", expected="any")

    def test_repair_receiver_override_preserves_original_package_state_and_bytes(self):
        with patch("port_changes.REPAIR_SYSCONFIG_SHA256", hashlib.sha256(REPAIR_CONFIG).hexdigest()):
            result = disable_repair_receiver(REPAIR_CONFIG)
            with self.assertRaisesRegex(ValueError, "sysconfig source drift"):
                disable_repair_receiver(result)
        override = (f'    <component-override package="{REPAIR_PACKAGE}">\n'
                    f'        <component class="{REPAIR_RECEIVER}" enabled="false"/>\n'
                    '    </component-override>\n').encode()
        self.assertEqual(result, REPAIR_CONFIG.replace(b"</config>\n", override + b"</config>\n"))
        self.assertEqual(result.replace(override, b""), REPAIR_CONFIG)
        before, after = ET.fromstring(REPAIR_CONFIG), ET.fromstring(result)
        self.assertEqual((after[0].tag, after[0].attrib), (before[0].tag, before[0].attrib))
        self.assertEqual(after[1].tag, "component-override")
        self.assertEqual(after[1].attrib, {"package": REPAIR_PACKAGE})
        self.assertEqual([(node.tag, node.attrib) for node in after[1]],
                         [("component", {"class": REPAIR_RECEIVER, "enabled": "false"})])

    def test_repair_receiver_sysconfig_drift_and_duplicate_config_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "sysconfig source drift"):
            disable_repair_receiver(REPAIR_CONFIG)
        initial = b'    <initial-package-state package="com.google.android.desktop.repairmode" stopped="false"/>\n'
        for data in [REPAIR_CONFIG.replace(b'stopped="false"', b'stopped="true"'),
                     REPAIR_CONFIG.replace(b"<config>", b'<config changed="true">'),
                     REPAIR_CONFIG.replace(b"</config>", initial + b"</config>"),
                     REPAIR_CONFIG.replace(b"</config>", b'<component-override package="other"/></config>'),
                     REPAIR_CONFIG.rstrip(b"\n")]:
            with self.subTest(data=data), patch("port_changes.REPAIR_SYSCONFIG_SHA256", hashlib.sha256(data).hexdigest()):
                with self.assertRaises(ValueError):
                    disable_repair_receiver(data)

    def test_manifest_removes_only_desktop_security(self):
        names = sorted(DESKTOP_SECURITY_HAL_NAMES) + ["android.hardware.security.keymint", "android.hidl.manager"]
        data = ('<manifest type="framework">' + ''.join(
            '<hal><name>' + name + '</name></hal>' for name in names) + '</manifest>').encode()
        result = ET.fromstring(remove_desktop_security_hal(data))
        self.assertEqual([h.findtext("name") for h in result], ["android.hidl.manager"])

    def test_changed_manifest_fails_closed(self):
        with self.assertRaises(ValueError):
            remove_desktop_security_hal(b'<manifest type="framework"/>')

    def test_diagnostic_checkpoints_preserve_commands_in_their_actions(self):
        result = diagnostic_init(INIT).decode()
        for name, command in DIAGNOSTIC_WAITS.items():
            self.assertIn(f'    write /dev/kmsg "googlebook-dsu-v4: {name}-before"\n'
                          f'    {command}\n'
                          f'    setprop {BOOT_STAGE_PROPERTY} {name}-after\n'
                          f'    write {BOOT_STAGE_FILE} "v4:{name}-after"\n'
                          f'    write /dev/kmsg "googlebook-dsu-v4: {name}-after"\n', result)
        self.assertLess(result.index("bootstrap-after"), result.index("on init\n"))
        restored = result.removesuffix("\n" + WATCHDOG_SERVICE)
        restored = restored.removesuffix("\n" + DIAGNOSTIC_USB_REFRESH)
        restored = "\n".join(line for line in restored.split("\n") if
                             not line.startswith((f"    setprop {BOOT_STAGE_PROPERTY} ", f"    write {BOOT_STAGE_FILE} ")))
        restored = "\n".join(line for line in restored.split("\n") if
                             "write /dev/kmsg" not in line and
                             line != f"    start {WATCHDOG_NAME}" and line not in
                             ["    setprop vendor.usb.use_gadget_hal 0", "    setprop persist.sys.usb.config adb",
                              "    setprop persist.adb.tradeinmode 0"])
        self.assertEqual(restored.encode(), INIT)

    def test_watchdog_start_service_and_readable_checkpoints(self):
        result = diagnostic_init(INIT).decode()
        start = result.index(f"    start {WATCHDOG_NAME}\n")
        self.assertLess(result.index("    perform_apex_config\n"), start)
        self.assertLess(start, result.index("on init\n"))
        self.assertLess(start, result.index("wait_for_prop ro.casefolding.adjusted"))
        self.assertIn(WATCHDOG_SERVICE, result)
        self.assertNotRegex(result, rf"(?m)^\s*(stop|restart|kill) {WATCHDOG_NAME}\b")
        self.assertNotIn("on property:sys.boot_completed", result)
        service = result.split(WATCHDOG_SERVICE.splitlines()[0], 1)[1]
        self.assertEqual(service.splitlines()[1:], ["    user shell", "    group shell",
                         "    seclabel u:r:shell:s0", "    disabled", "    oneshot", "    reboot_on_failure reboot"])
        checkpoints = re.findall(r'(?m)^    write /dev/kmsg "googlebook-dsu-v4: ([a-z-]+)[^\n]*$', result)
        self.assertEqual(len(checkpoints), 13)
        self.assertEqual(len(set(checkpoints)), 13)
        for stage in checkpoints:
            self.assertIn(f'    setprop {BOOT_STAGE_PROPERTY} {stage}\n'
                          f'    write {BOOT_STAGE_FILE} "v4:{stage}"\n'
                          f'    write /dev/kmsg "googlebook-dsu-v4: {stage}', result)
        writes = re.findall(r'(?m)^    write (/metadata/\S+) "(v4:[a-z-]+)"$', result)
        self.assertEqual(len(writes), 13)
        self.assertEqual({path for path, value in writes}, {BOOT_STAGE_FILE})

    def test_no_early_adbd_or_inline_usb_setup_is_added(self):
        result = diagnostic_init(INIT).decode()
        self.assertNotRegex(result, r"(?m)^\s*setprop ro\.boot\.apex\.early_adbd\s")
        self.assertNotRegex(result, r"(?m)^\s*(start|restart) adbd\b")
        for command in ["mount configfs", "mount functionfs", "/config/usb_gadget/", "/dev/usb-ffs/",
                        "wait_for_prop sys.usb.ffs.ready", "usb-setup-before", "usb-ffs-after", "usb-requested"]:
            self.assertNotIn(command, result)
        self.assertEqual(result.split("on init\n", 1)[1].split("on late-init\n", 1)[0],
                         "    mkdir /config 0500 root root\n\n")
        self.assertNotIn("wait /dev/usb-ffs/adb/ep", result)
        self.assertNotRegex(result, rf"(?m)^\s*(mkdir|chmod|chown|restorecon).*{re.escape(BOOT_STAGE_FILE)}")

    def test_queued_usb_refresh_uses_handlers_without_changing_stage(self):
        result = diagnostic_init(INIT).decode()
        early = result[result.index("on early-init\n"):result.index("on init\n")]
        self.assertIn("    setprop vendor.usb.use_gadget_hal 0\n", early)
        self.assertIn(f"on boot && property:{BOOT_STAGE_PROPERTY}=odsign-verification-after\n"
                      "    trigger googlebook-pad3-usb-refresh\n", result)
        self.assertIn("on googlebook-pad3-usb-refresh\n    setprop sys.usb.configfs 1\n"
                      "    setprop sys.usb.config none\n", result)
        self.assertIn(f"on property:sys.usb.state=none && property:{BOOT_STAGE_PROPERTY}=odsign-verification-after\n"
                      "    setprop sys.usb.config adb\n", result)
        self.assertNotIn("wait_for_prop sys.usb.state", result)
        self.assertNotIn(f"setprop {BOOT_STAGE_PROPERTY}", DIAGNOSTIC_USB_REFRESH)
        self.assertNotIn("write /config/", DIAGNOSTIC_USB_REFRESH)

    def test_persistent_overrides_follow_original_load_and_reject_drift(self):
        result = diagnostic_init(INIT).decode()
        self.assertIn("    load_persist_props\n    setprop persist.sys.usb.config adb\n"
                      "    setprop persist.adb.tradeinmode 0\n", result)
        for data in [INIT.replace(b"    load_persist_props\n", b""),
                     INIT.replace(b"    load_persist_props\n", b"    load_persist_props\n    load_persist_props\n"),
                     INIT.replace(b"on post-fs-data\n", b"on boot\n")]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                diagnostic_init(data)

    def test_tradein_stop_is_neutralized_only_for_diagnostics(self):
        path = "/system/etc/init/tradeinmode.rc"
        self.assertNotIn(path, DISABLED_SYSTEM_INIT)
        output = neutralize_system_init(path, TRADEIN)
        self.assertTrue(output.startswith(b"# erhai Googlebook test port:"))
        self.assertNotRegex(output.decode(), r"(?m)^\s*(on|stop|service)\s")
        for data in [TRADEIN.replace(b"=-1", b"=1"), TRADEIN.replace(b"stop adbd", b"start adbd")]:
            with self.assertRaises(ValueError):
                neutralize_system_init(path, data)

    def run_watchdog(self, boot_completed, sleep_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "getprop").write_text(
                '#!/bin/sh\n[ "$1" = sys.boot_completed ] || exit 90\n'
                'printf "x\\n" >> "$WATCHDOG_TEST_PROPS"\n'
                f'printf "%s\\n" "{boot_completed}"\n')
            (root / "sleep").write_text(
                '#!/bin/sh\n[ "$#" = 1 ] && [ "$1" = 1 ] || exit 91\n'
                'printf "x\\n" >> "$WATCHDOG_TEST_SLEEPS"\n'
                f'exit {sleep_status}\n')
            for name in ["getprop", "sleep"]:
                (root / name).chmod(0o755)
            environment = dict(os.environ, PATH=str(root), WATCHDOG_TEST_PROPS=str(root / "props"),
                               WATCHDOG_TEST_SLEEPS=str(root / "sleeps"))
            result = subprocess.run(["/bin/sh"], input=WATCHDOG_SCRIPT, env=environment,
                                    capture_output=True, timeout=10)
            counts = [len((root / name).read_text().splitlines()) if (root / name).exists() else 0
                      for name in ["props", "sleeps"]]
            return result, counts

    def test_watchdog_immediate_success_exits_naturally_without_sleep(self):
        result, counts = self.run_watchdog("1")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(counts, [1, 0])
        self.assertEqual(result.stderr, b"")

    def test_watchdog_timeout_keeps_real_180_second_deadline(self):
        result, counts = self.run_watchdog("0")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(counts, [180, 180])
        self.assertIn(b"180 seconds", result.stderr)
        self.assertNotIn(b"setprop", WATCHDOG_SCRIPT)

    def test_watchdog_sleep_failure_is_a_failure(self):
        result, counts = self.run_watchdog("0", sleep_status=1)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(counts, [1, 1])

    def test_diagnostic_init_rejects_missing_duplicate_moved_and_reapplied_anchors(self):
        inputs = [INIT.replace(b"    wait_for_prop apexd.status activated\n", b""),
                  INIT + b"\non post-fs-data\n    wait_for_prop apexd.status activated\n",
                  INIT.replace(b"on post-fs-data\n", b"on boot\n"),
                  INIT.replace(b"    perform_apex_config\n", b""), diagnostic_init(INIT)]
        for data in inputs:
            with self.subTest(data=data), self.assertRaises(ValueError):
                diagnostic_init(data)

    def test_tpm_neutralization_is_guarded_and_in_main_recipe(self):
        path = "/system/etc/init/check_tpm_clear.rc"
        self.assertIn(path, DISABLED_SYSTEM_INIT)
        self.assertTrue(neutralize_system_init(path, TPM).startswith(b"# erhai Googlebook test port:"))
        for marker in [b"mkdir /metadata/hwsec_metadata", b"exec_background -- /system/bin/check_tpm_clear"]:
            with self.assertRaises(ValueError):
                neutralize_system_init(path, TPM.replace(marker, b"changed"))

    def test_only_one_android_public_key_is_accepted(self):
        key = key_fixture()
        self.assertEqual(public_adb_key(key), key)
        for invalid in [b"", key + key, b"-----BEGIN PRIVATE KEY-----\n", b"not-base64\n",
                        b"YWJj\n", key.replace(b"\n", b"\r\n"), b"\xff\n", key + b"\0"]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                public_adb_key(invalid)

    def test_diagnostic_scope_and_key_metadata(self):
        def source(image, path):
            if path == "/etc/build.prop":
                return PRODUCT_PROPS if image.stem == "product" else b"other=1\n"
            if path == "/media/bootanimation.zip":
                self.assertEqual(image, Path("images/product.img"))
                return b"original bootanimation ZIP"
            return {"/system/build.prop": PROPS, "/system/etc/init/hw/init.rc": INIT,
                    "/system/etc/init/check_tpm_clear.rc": TPM,
                    "/system/etc/init/tradeinmode.rc": TRADEIN, JAR_PATH: b"original desktop JAR",
                    REPAIR_SYSCONFIG_PATH: REPAIR_CONFIG}[path]
        with patch("port_changes.content", side_effect=source), patch("port_changes.fix_geometry",
                return_value=b"metadata-only geometry ZIP") as geometry, patch("port_changes.disable_repair_mode",
                return_value=b"repair flag disabled JAR") as repair, patch("port_changes.disable_repair_receiver",
                return_value=b"receiver override sysconfig") as receiver:
            changes, additions = diagnostic_changes(Path("images"), key_fixture())
        geometry.assert_called_once_with(b"original bootanimation ZIP")
        repair.assert_called_once_with(b"original desktop JAR")
        receiver.assert_called_once_with(REPAIR_CONFIG)
        self.assertEqual(set(changes), {"system", "product"})
        self.assertEqual(changes["product"], {"/media/bootanimation.zip": b"metadata-only geometry ZIP",
                                           "/etc/build.prop": PRODUCT_PROPS.replace(b"=any\n", b"=\n")})
        self.assertEqual(set(changes["system"]), {"/system/build.prop", "/system/etc/init/hw/init.rc",
                                                "/system/etc/init/check_tpm_clear.rc", "/system/etc/init/tradeinmode.rc",
                                                JAR_PATH, REPAIR_SYSCONFIG_PATH})
        self.assertEqual(changes["system"][JAR_PATH], b"repair flag disabled JAR")
        self.assertEqual(changes["system"][REPAIR_SYSCONFIG_PATH], b"receiver override sysconfig")
        self.assertEqual(changes["system"]["/system/build.prop"], PROPS + b"".join(
            (key + "=" + value + "\n").encode() for key, value in (DISPLAY_PROPERTIES | HEAP_PROPERTIES).items()))
        self.assertEqual(set(additions), {"system", "product"})
        self.assertEqual(set(additions["system"]), {WATCHDOG_PATH, TIPS_SYSCONFIG_PATH})
        tips = additions["system"][TIPS_SYSCONFIG_PATH]
        self.assertEqual(tips["data"], TIPS_SYSCONFIG)
        config = ET.fromstring(tips["data"])
        self.assertEqual(config.tag, "config")
        self.assertEqual(len(config), 1)
        self.assertEqual(config[0].attrib, {"package": "com.google.android.desktop.tips"})
        self.assertEqual([node.attrib for node in config[0]], [
            {"class": "com.google.android.desktop.tips.fortnite.main.MainActivity", "enabled": "false"},
            {"class": "com.google.android.desktop.tips.fortnite.deeplink.DeepLinkGateway", "enabled": "false"},
            {"class": "com.google.android.desktop.tips.fortnite.main.tab.perks.PerksDeepLink", "enabled": "false"},
        ])
        self.assertEqual(tips["metadata"], additions["system"][WATCHDOG_PATH]["metadata"])
        watchdog = additions["system"][WATCHDOG_PATH]
        self.assertEqual(watchdog["data"], WATCHDOG_SCRIPT)
        self.assertEqual((watchdog["metadata"]["uid"], watchdog["metadata"]["gid"],
                          watchdog["metadata"]["mode"]), (0, 0, stat.S_IFREG | 0o644))
        self.assertEqual(watchdog["metadata"]["xattrs"], {"security.selinux": b"u:object_r:system_file:s0\0"})
        self.assertEqual(set(additions["product"]), {"/etc/security/adb_keys"})
        meta = additions["product"]["/etc/security/adb_keys"]["metadata"]
        self.assertEqual((meta["uid"], meta["gid"], meta["mode"]), (0, 0, stat.S_IFREG | 0o644))
        self.assertEqual(meta["xattrs"], {"security.selinux": b"u:object_r:adb_keys_file:s0\0"})

    def test_display_properties_must_be_absent_from_all_original_partitions(self):
        for part in ["system", "system_ext", "product"]:
            for name, value in DISPLAY_PROPERTIES.items():
                def source(image, path):
                    data = PROPS if image.stem == "system" else b"other=1\n"
                    if image.stem == part:
                        data += (name + "=" + value + "\n").encode()
                    return data
                with self.subTest(part=part, name=name), patch("port_changes.content", side_effect=source):
                    with self.assertRaisesRegex(ValueError, "display property already present"):
                        diagnostic_changes(Path("images"), key_fixture())

    def test_only_five_missing_native_heap_fields_are_added(self):
        self.assertEqual(HEAP_PROPERTIES, {"dalvik.vm.heapstartsize": "16m", "dalvik.vm.heapsize": "512m",
                         "dalvik.vm.heaptargetutilization": "0.5", "dalvik.vm.heapminfree": "8m",
                         "dalvik.vm.heapmaxfree": "32m"})
        for growth in [b"", b"dalvik.vm.heapgrowthlimit=512m\n"]:
            def source(image, path):
                if path == "/etc/build.prop":
                    return PRODUCT_PROPS if image.stem == "product" else b"other=1\n"
                if path == "/media/bootanimation.zip":
                    return b"original bootanimation ZIP"
                return {"/system/build.prop": PROPS + growth, "/system/etc/init/hw/init.rc": INIT,
                        "/system/etc/init/check_tpm_clear.rc": TPM,
                        "/system/etc/init/tradeinmode.rc": TRADEIN, JAR_PATH: b"original desktop JAR",
                        REPAIR_SYSCONFIG_PATH: REPAIR_CONFIG}[path]
            with patch("port_changes.content", side_effect=source), patch("port_changes.fix_geometry",
                    return_value=b"metadata-only geometry ZIP"), patch("port_changes.disable_repair_mode",
                    return_value=b"repair flag disabled JAR"), patch("port_changes.disable_repair_receiver",
                    return_value=b"receiver override sysconfig"):
                changes, _ = diagnostic_changes(Path("images"), key_fixture())
            result = changes["system"]["/system/build.prop"]
            self.assertTrue(result.startswith(PROPS + growth))
            self.assertEqual(result.count(b"dalvik.vm.heapgrowthlimit="), int(bool(growth)))
            self.assertNotIn(b"sys.boot_completed", result)

    def test_diagnostic_bootanimation_drift_fails_before_overlay(self):
        def source(image, path):
            if path == "/etc/build.prop":
                return PRODUCT_PROPS if image.stem == "product" else b"other=1\n"
            return {"/system/build.prop": PROPS, "/system/etc/init/hw/init.rc": INIT,
                    "/system/etc/init/check_tpm_clear.rc": TPM,
                    "/system/etc/init/tradeinmode.rc": TRADEIN,
                    "/media/bootanimation.zip": b"unreviewed animation", JAR_PATH: b"original desktop JAR",
                    REPAIR_SYSCONFIG_PATH: REPAIR_CONFIG}[path]
        with patch("port_changes.content", side_effect=source), patch("port_changes.disable_repair_mode",
                return_value=b"repair flag disabled JAR"), patch("port_changes.disable_repair_receiver",
                return_value=b"receiver override sysconfig"), self.assertRaisesRegex(ValueError, "source ZIP drift"):
            diagnostic_changes(Path("images"), key_fixture())

    def test_diagnostic_repair_jar_drift_fails_before_overlay(self):
        def source(image, path):
            if path == "/etc/build.prop":
                return b"other=1\n"
            return {"/system/build.prop": PROPS, "/system/etc/init/hw/init.rc": INIT,
                    "/system/etc/init/check_tpm_clear.rc": TPM,
                    JAR_PATH: b"unreviewed desktop JAR"}[path]
        with patch("port_changes.content", side_effect=source), self.assertRaisesRegex(ValueError, "JAR source drift"):
            diagnostic_changes(Path("images"), key_fixture())

    def test_heap_fields_reject_donor_drift_and_conflicting_growth_limits(self):
        for part in ["system", "system_ext", "product"]:
            for extra in [(key + "=" + value + "\n").encode() for key, value in HEAP_PROPERTIES.items()] + [
                b"dalvik.vm.heapgrowthlimit=256m\n", b"dalvik.vm.heapgrowthlimit=\n",
                b"dalvik.vm.heapgrowthlimit=512m\ndalvik.vm.heapgrowthlimit=512m\n"]:
                def source(image, path):
                    data = PROPS if image.stem == "system" else b"other=1\n"
                    return data + extra if image.stem == part else data
                with self.subTest(part=part, extra=extra), patch("port_changes.content", side_effect=source):
                    with self.assertRaisesRegex(ValueError, "heap property already present|heap growth limit"):
                        diagnostic_changes(Path("images"), key_fixture())

    def test_diagnostic_security_property_drift_fails_closed(self):
        for data in [PROPS.replace(b"ro.adb.secure=1", b"ro.adb.secure=0"),
                     PROPS + b"ro.secure=1\n", PROPS + b"ro.boot.apex.early_adbd=false\n",
                     PROPS.replace(b"tcp:localhost:5555", b"tcp:5555")]:
            with patch("port_changes.content", return_value=data), self.assertRaises(ValueError):
                diagnostic_changes(Path("images"), key_fixture())


if __name__ == "__main__":
    unittest.main()
