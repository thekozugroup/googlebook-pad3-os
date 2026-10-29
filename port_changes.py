"""Small, guarded adaptations of the pinned Googlebook donor for erhai."""
import base64
import binascii
import hashlib
import re
import stat
import struct
import xml.etree.ElementTree as ET

from android_disk import require
from bootanimation_geometry import fix_geometry
from desktop_repair_gate import JAR_PATH, disable_repair_mode
from erofs_overlay import content


DISABLED_SYSTEM_INIT = {
    "/system/etc/init/check_tpm_clear.rc": "Do not create laptop TPM ownership metadata on shared tablet metadata.",
    "/system/etc/init/gscd.rc": "Laptop Google Security Chip is absent on this tablet.",
    "/system/etc/init/gscutil.rc": "Do not wait for or update a laptop TPM/security chip.",
    "/system/etc/init/gscutil-executor.rc": "Disable AIDL-triggered laptop security-chip operations.",
    "/system/etc/init/pinweaver_storaged.rc": "Keep tablet Gatekeeper/KeyMint; no laptop PinWeaver VM.",
    "/system/etc/init/update_engine.rc": "Never apply laptop OTA payloads to tablet firmware.",
}
DISABLED_EXTENSION_INIT = {
    "/etc/init/desktop-trusty_security_vm_launcher.rc": "Keep the tablet's hardware security providers.",
    "/etc/init/android.hardware.security.keymint-service.desktop_trusty_system_vm.rc": "Avoid a second default KeyMint provider.",
    "/etc/init/rpmb_dev.desktop.system.rc": "Laptop virtual RPMB is not a tablet storage device.",
    "/etc/init/super-partition-utils.rc": "Do not expose laptop partition-writing or writable-mount services.",
    "/etc/init/android.hardware.audio.parameter_parser.android-desktop.rc": "Use the tablet adapter as the sole provider of this Binder instance.",
}
DESKTOP_SECURITY_HAL_NAMES = {
    "android.desktop.security.finger_guard",
    "android.hardware.security.keymint",
    "android.hardware.security.secureclock",
    "android.hardware.security.sharedsecret",
    "com.android.trusty.rust.KeyMintProvisioningService",
}

DIAGNOSTIC_ID = "googlebook-dsu-v4"
REPAIR_PACKAGE = "com.google.android.desktop.repairmode"
REPAIR_RECEIVER = REPAIR_PACKAGE + ".receiver.BootCompletedReceiver"
REPAIR_SYSCONFIG_PATH = "/system/etc/sysconfig/sysconfig_com.google.android.desktop.repairmode.xml"
REPAIR_SYSCONFIG_SHA256 = "26e427ae5c608d9c0539ad44777a9bbc947cea5b68e71d3e0fddedbc82b7fc03"
TIPS_SYSCONFIG_PATH = "/system/etc/sysconfig/googlebook-pad3-tips.xml"
# Tips requires the absent laptop serviceability/VPD service.
TIPS_SYSCONFIG = b'''<?xml version="1.0" encoding="utf-8"?>
<config>
    <component-override package="com.google.android.desktop.tips">
        <component class="com.google.android.desktop.tips.fortnite.main.MainActivity" enabled="false"/>
        <component class="com.google.android.desktop.tips.fortnite.deeplink.DeepLinkGateway" enabled="false"/>
        <component class="com.google.android.desktop.tips.fortnite.main.tab.perks.PerksDeepLink" enabled="false"/>
    </component-override>
</config>
'''
DISABLED_DIAGNOSTIC_INIT = {
    "/system/etc/init/tradeinmode.rc": "Prevent a queued trade-in failure action from stopping diagnostic adbd.",
}
BOOT_STAGE_PROPERTY = "sys.googlebook.pad3.boot_stage"
BOOT_STAGE_FILE = "/metadata/gsi/dsu/googlebook-pad3/googlebook-pad3-boot-stage"
DISPLAY_PROPERTIES = {
    "debug.sf.ignore_hwc_physical_display_orientation": "true",
    "ro.bootanim.set_orientation_4630946983774026899": "ORIENTATION_90",
}
HEAP_PROPERTIES = {
    "dalvik.vm.heapstartsize": "16m",
    "dalvik.vm.heapsize": "512m",
    "dalvik.vm.heaptargetutilization": "0.5",
    "dalvik.vm.heapminfree": "8m",
    "dalvik.vm.heapmaxfree": "32m",
}
WATCHDOG_NAME = "googlebook-pad3-boot-watchdog"
WATCHDOG_PATH = "/system/bin/googlebook-pad3-boot-watchdog.sh"
WATCHDOG_SCRIPT = b"""#!/system/bin/sh
remaining=180
while [ "$remaining" -gt 0 ]; do
    if [ "$(getprop sys.boot_completed)" = 1 ]; then
        exit 0
    fi
    sleep 1 || exit 1
    remaining=$((remaining - 1))
done
echo 'googlebook-pad3: boot did not complete within 180 seconds' >&2
exit 1
"""
WATCHDOG_SERVICE = f"""service {WATCHDOG_NAME} /system/bin/sh {WATCHDOG_PATH}
    user shell
    group shell
    seclabel u:r:shell:s0
    disabled
    oneshot
    reboot_on_failure reboot
"""
DIAGNOSTIC_WAITS = {
    "casefold": "wait_for_prop ro.casefolding.adjusted 1",
    "apex": "wait_for_prop apexd.status activated",
    "module-hash": "wait_for_prop keystore.module_hash.sent true",
    "odsign-key": "wait_for_prop odsign.key.done 1",
    "odsign-verification": "wait_for_prop odsign.verification.done 1",
}

DIAGNOSTIC_USB_REFRESH = f"""on boot && property:{BOOT_STAGE_PROPERTY}=odsign-verification-after
    trigger googlebook-pad3-usb-refresh

on googlebook-pad3-usb-refresh
    setprop sys.usb.configfs 1
    setprop sys.usb.config none

on property:sys.usb.state=none && property:{BOOT_STAGE_PROPERTY}=odsign-verification-after
    setprop sys.usb.config adb
"""


def neutralize_system_init(path, data):
    if path.endswith("/tradeinmode.rc"):
        require(data.count(b"on property:persist.adb.tradeinmode=-1 && property:ro.debuggable=0\n"
                           b"    stop adbd\n") == 1, "unexpected trade-in failure action")
    elif path.endswith("/check_tpm_clear.rc"):
        require(b"    mkdir /metadata/hwsec_metadata 775 root root\n" in data and
                b"    exec_background -- /system/bin/check_tpm_clear\n" in data,
                "unexpected TPM metadata action")
    else:
        marker = b"exec - hsm hsm" if path.endswith("/gscutil.rc") else b"service "
        require(marker in data, "unexpected init input: " + path)
    reason = (DISABLED_SYSTEM_INIT | DISABLED_DIAGNOSTIC_INIT)[path]
    return ("# erhai Googlebook test port: " + reason + "\n").encode()


def diagnostic_init(data):
    text = data.decode()
    require(all(marker not in text for marker in (DIAGNOSTIC_ID, BOOT_STAGE_PROPERTY, WATCHDOG_NAME)),
            "diagnostic init already patched")
    edits = {
        "on early-init\n": 'on early-init\n    write /dev/kmsg "googlebook-dsu-v4: second-stage-entry"\n'
                            '    setprop vendor.usb.use_gadget_hal 0\n',
        "    exec_start apexd-bootstrap\n    perform_apex_config\n":
            '    write /dev/kmsg "googlebook-dsu-v4: bootstrap-before early-adbd=${ro.boot.apex.early_adbd:-unset}"\n'
            '    exec_start apexd-bootstrap\n    perform_apex_config\n'
            '    write /dev/kmsg "googlebook-dsu-v4: bootstrap-after"\n'
            f'    start {WATCHDOG_NAME}\n',
        "    load_persist_props\n": "    load_persist_props\n"
            "    setprop persist.sys.usb.config adb\n"
            "    setprop persist.adb.tradeinmode 0\n",
    }
    persist_position = text.find("    load_persist_props\n")
    persist_headers = re.findall(r"^on (.*)$", text[:persist_position], re.MULTILINE)
    require(persist_headers and persist_headers[-1] == "post-fs-data",
            "persistent-property load moved outside expected action")
    for name, command in DIAGNOSTIC_WAITS.items():
        old = "    " + command + "\n"
        action = "zygote-start" if name == "odsign-verification" else "post-fs-data"
        location = text.find(old)
        headers = re.findall(r"^on (.*)$", text[:location], re.MULTILINE)
        require(headers and headers[-1] == action, "wait moved outside expected action: " + name)
        edits[old] = (f'    write /dev/kmsg "{DIAGNOSTIC_ID}: {name}-before"\n' + old +
                      f'    write /dev/kmsg "{DIAGNOSTIC_ID}: {name}-after"\n')
    for old, new in edits.items():
        require(text.count(old) == 1, "unexpected diagnostic init anchor: " + old.strip())
        text = text.replace(old, new)
    pattern = r'^(    write /dev/kmsg "' + re.escape(DIAGNOSTIC_ID) + r': ([a-z-]+)[^\n]*\n)'
    require(len(re.findall(pattern, text, re.MULTILINE)) == 13, "unexpected diagnostic checkpoint count")
    text = re.sub(pattern, lambda match: (f"    setprop {BOOT_STAGE_PROPERTY} {match[2]}\n" +
                  f'    write {BOOT_STAGE_FILE} "v4:{match[2]}"\n' + match[1]),
                  text, flags=re.MULTILINE)
    return (text + "\n" + DIAGNOSTIC_USB_REFRESH + "\n" + WATCHDOG_SERVICE).encode()


def public_adb_key(data):
    require(isinstance(data, bytes) and 0 < len(data) <= 8192 and
            b"\r" not in data and b"\0" not in data and len(data.strip().splitlines()) == 1,
            "expected one public ADB key")
    try:
        fields = data.decode("ascii").strip().split()
        key = base64.b64decode(fields[0], validate=True)
    except (UnicodeError, binascii.Error, IndexError) as error:
        raise ValueError("invalid public ADB key") from error
    require(len(key) == 524 and struct.unpack_from("<I", key)[0] == 64 and
            struct.unpack_from("<I", key, 520)[0] in (3, 65537), "invalid Android RSA public key")
    return data.strip() + b"\n"


def disable_repair_receiver(data):
    require(hashlib.sha256(data).hexdigest() == REPAIR_SYSCONFIG_SHA256,
            "repair receiver sysconfig source drift")
    root = ET.fromstring(data)
    require(root.tag == "config" and not root.attrib and len(root) == 1 and
            root[0].tag == "initial-package-state" and
            root[0].attrib == {"package": REPAIR_PACKAGE, "stopped": "false"},
            "unexpected initial repair package state")
    require(data.count(b"</config>\n") == 1, "unexpected repair sysconfig closing tag")
    override = (f'    <component-override package="{REPAIR_PACKAGE}">\n'
                f'        <component class="{REPAIR_RECEIVER}" enabled="false"/>\n'
                '    </component-override>\n').encode()
    return data.replace(b"</config>\n", override + b"</config>\n")


def display_heap_properties(properties):
    """Add the tablet display/heap values after checking all donor partitions."""
    for part in ("system", "system_ext", "product"):
        data = properties[part]
        for name in DISPLAY_PROPERTIES:
            require(not re.search(rb"^[ \t]*" + re.escape(name.encode()) + rb"[ \t]*=", data, re.MULTILINE),
                    "native display property already present: " + part + ":" + name)
        for name in HEAP_PROPERTIES:
            require(not re.search(rb"^[ \t]*" + re.escape(name.encode()) + rb"[ \t]*=", data, re.MULTILINE),
                    "native heap property already present: " + part + ":" + name)
        growth = re.findall(rb"^[ \t]*dalvik\.vm\.heapgrowthlimit[ \t]*=([^\n]*)$", data, re.MULTILINE)
        require(not growth or (len(growth) == 1 and growth[0].strip() == b"512m"),
                "unexpected existing heap growth limit: " + part)
    prop = properties["system"]
    return prop + (b"" if prop.endswith(b"\n") else b"\n") + b"".join(
        (name + "=" + value + "\n").encode() for name, value in (DISPLAY_PROPERTIES | HEAP_PROPERTIES).items())


def diagnostic_changes(images, key):
    prop = content(images / "system.img", "/system/build.prop")
    for name, value in [("ro.secure", "1"), ("ro.adb.secure", "1"),
                        ("ro.debuggable", "0"), ("ro.force.debuggable", "0"),
                        ("service.adb.listen_addrs", "tcp:localhost:5555")]:
        require(re.findall(rb"^" + re.escape(name.encode()) + rb"=(.*)$", prop, re.MULTILINE) ==
                [value.encode()], "unexpected diagnostic security property: " + name)
    require(not re.search(rb"^ro.boot.apex.early_adbd=", prop, re.MULTILINE),
            "early ADB boot property requires review")
    display_prop = display_heap_properties({
        "system": prop,
        "system_ext": content(images / "system_ext.img", "/etc/build.prop"),
        "product": content(images / "product.img", "/etc/build.prop"),
    })
    tpm = "/system/etc/init/check_tpm_clear.rc"
    changes = {"system": {
        "/system/build.prop": display_prop,
        "/system/etc/init/hw/init.rc": diagnostic_init(content(images / "system.img", "/system/etc/init/hw/init.rc")),
        tpm: neutralize_system_init(tpm, content(images / "system.img", tpm)),
        JAR_PATH: disable_repair_mode(content(images / "system.img", JAR_PATH)),
        REPAIR_SYSCONFIG_PATH: disable_repair_receiver(content(images / "system.img", REPAIR_SYSCONFIG_PATH)),
    }, "product": {
        "/etc/build.prop": replace_property(content(images / "product.img", "/etc/build.prop"),
                                             "ro.setupwizard.require_network", "", expected="any"),
        "/media/bootanimation.zip": fix_geometry(content(images / "product.img", "/media/bootanimation.zip")),
    }}
    for path in DISABLED_DIAGNOSTIC_INIT:
        changes["system"][path] = neutralize_system_init(path, content(images / "system.img", path))
    additions = {"system": {WATCHDOG_PATH: {
        "data": WATCHDOG_SCRIPT,
        "metadata": {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0,
                     "mtime": 1230768000, "mtime_nsec": 0,
                     "xattrs": {"security.selinux": b"u:object_r:system_file:s0\0"}},
    }}, "product": {"/etc/security/adb_keys": {
        "data": public_adb_key(key),
        "metadata": {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0,
                     "mtime": 1230768000, "mtime_nsec": 0,
                     "xattrs": {"security.selinux": b"u:object_r:adb_keys_file:s0\0"}},
    }}}
    additions["system"][TIPS_SYSCONFIG_PATH] = {
        "data": TIPS_SYSCONFIG,
        "metadata": dict(additions["system"][WATCHDOG_PATH]["metadata"]),
    }
    return changes, additions


def replace_property(data, key, value, expected=None):
    text = data.decode()
    pattern = re.compile(r"^" + re.escape(key) + r"=(.*)$", re.MULTILINE)
    matches = pattern.findall(text)
    require(len(matches) <= 1, "duplicate property: " + key)
    if expected is not None:
        require(matches == [expected], "unexpected donor property: " + key)
    if matches:
        text = pattern.sub(lambda _: key + "=" + value, text)
    else:
        text = text.rstrip() + "\n" + key + "=" + value + "\n"
    return text.encode()


def remove_desktop_security_hal(data):
    root = ET.fromstring(data)
    require(root.tag == "manifest" and root.get("type") == "framework",
            "unexpected system_ext manifest")
    removed = []
    for node in list(root):
        name = node.findtext("name")
        if node.tag == "hal" and name in DESKTOP_SECURITY_HAL_NAMES:
            removed.append(name)
            root.remove(node)
    require(set(removed) == DESKTOP_SECURITY_HAL_NAMES and len(removed) == 6,
            "desktop security manifest changed; review the new donor")
    ET.indent(root, space="    ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def create(images):
    return tablet_changes({part: images / (part + "_a.img") for part in ("system", "system_ext", "product")})


def tablet_changes(images):
    """Functional tablet changes shared by the legacy and clean native planners."""
    system, extension, product = {}, {}, {}
    for path in DISABLED_SYSTEM_INIT:
        system[path] = neutralize_system_init(path, content(images["system"], path))
    for path, reason in DISABLED_EXTENSION_INIT.items():
        require(b"service " in content(images["system_ext"], path), "unexpected init input: " + path)
        extension[path] = ("# erhai Googlebook test port: " + reason + "\n").encode()
    system["/system/build.prop"] = replace_property(
        content(images["system"], "/system/build.prop"),
        "trusty.security_vm.enabled", "0", expected="1")
    # Retain the desktop UI and headless-user design. Match the tablet's native DPI.
    extension["/etc/build.prop"] = replace_property(
        content(images["system_ext"], "/etc/build.prop"), "ro.sf.lcd_density", "420")
    extension["/etc/vintf/manifest.xml"] = remove_desktop_security_hal(
        content(images["system_ext"], "/etc/vintf/manifest.xml"))
    for partition, path, name in [
        ("system", "/system/etc/vintf/manifest/manifest_gscd.xml", "android.system.desktop.security.gsc"),
        ("system_ext", "/etc/vintf/manifest/com.google.android.desktop.super-partition-utils.xml", "com.google.android.desktop"),
    ]:
        image = images[partition]
        root = ET.fromstring(content(image, path))
        nodes = root.findall("hal")
        require(len(nodes) == 1 and nodes[0].findtext("name") == name,
                "unreviewed laptop writer manifest: " + path)
        root.remove(nodes[0])
        {"system": system, "system_ext": extension}[partition][path] = (
            ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n")
    prop = content(images["product"], "/etc/build.prop")
    for key, old, new in [
        ("ro.product.product.brand", "Dell", "OnePlus"),
        ("ro.product.product.device", "mica", "OP6190L1"),
        ("ro.product.product.manufacturer", "Dell", "OnePlus"),
        ("ro.product.product.model", "XPS Googlebook", "OnePlus Pad 3 Googlebook Test"),
        ("ro.product.product.name", "mica", "googlebook_erhai"),
    ]:
        prop = replace_property(prop, key, new, expected=old)
    product["/etc/build.prop"] = prop
    return {"system": system, "system_ext": extension, "product": product}
