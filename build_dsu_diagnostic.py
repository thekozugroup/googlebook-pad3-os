#!/usr/bin/env python3
"""Build a private, offline DSU diagnostic ZIP from the verified first candidate."""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

from android_disk import require
from check_policy import check
from bootanimation_geometry import SOURCE_SHA256 as ANIMATION_SOURCE_SHA256
from desktop_repair_gate import (CODE_OFFSET, DEX_SHA256, INSTRUCTION_OFFSET, JAR_PATH, JAR_SHA256,
                                 METHOD, METHOD_ID, NEW_INSTRUCTIONS, OLD_INSTRUCTIONS, valid_checksums)
from erofs_overlay import apply, content, metadata
from validate_candidate import extract_tree
from port_changes import (BOOT_STAGE_FILE, BOOT_STAGE_PROPERTY, DISPLAY_PROPERTIES, HEAP_PROPERTIES, WATCHDOG_NAME, WATCHDOG_PATH,
                          REPAIR_PACKAGE, REPAIR_RECEIVER, REPAIR_SYSCONFIG_PATH, TIPS_SYSCONFIG_PATH, diagnostic_changes)


SOURCE = Path(__file__).resolve().parent
PARTITIONS = ("system", "system_ext", "product")
PUBLIC_KEY = Path(os.environ.get("GOOGLEBOOK_ADB_PUBLIC_KEY", "build-inputs/adb-public-key")).absolute()
# Keep the assigned scratch pathname; validated atomic replacement preserves the published hardlink.
ZIP_NAME = "Googlebook-erhai-dsu-diagnostic-v2.zip"
NATIVE_BASE_SUPPLIED_BY_OWNER = {
    "build_utc": "1792932356", "kernel": "6.6.144-4k-gacb4c5815254", "update_already_activated": True,
}
USB_SOURCE_SHA256 = "8f36f18ece29d70608e4d5da73d69a88e2d59f988d1bd4b9d239b3aad3986fdc"
TIPS_APK_PATH = "/priv-app/DesktopTips/DesktopTips.apk"
TIPS_APK_SHA256 = "6cf85909745a863cc1014dc3908da967a41dd76ec8191b119f9958f7a80bcaa4"
README = """# Private Googlebook DSU diagnostic v9

Unbooted diagnostic candidate for independent review. Do not flash directly.
This is not a recovery-sideload package. No device was contacted by this build.

The product image contains the owner's public ADB key. Strip that key and rebuild
before redistribution. Authentication, production shell privileges, enforcing
SELinux, original signed APEX bytes and the loopback-only listener are retained.

The native USB commands were inspected in the pinned local October 17 crDroid
vendor image. Current slot B's USB rc was not independently obtained offline.
V7 removes the early-adbd boot-property override and the inline on-init USB
setup/start/FFS-wait/UDC-binding block. Normal USB handlers start adbd after APEX
activation; the bootstrap namespace is no longer deliberately selected.
Each kmsg checkpoint records command progress, not proof that commands succeeded.
Diagnostic early-init selects vendor.usb.use_gadget_hal=0. After other boot
actions, a queued refresh selects configfs=1 and config=none; a stage-guarded
sys.usb.state=none handler then requests adb through the standard handlers.
There is no synchronous state-none wait or boot-stage change during refresh.
Immediately after the original load_persist_props, the guest sets
persist.sys.usb.config=adb and persist.adb.tradeinmode=0. The donor tradeinmode.rc
stop action is neutralized to avoid a previously queued failure stopping adbd.
This targets logging access and does not establish the framework failure cause.

Each of the 13 remaining checkpoints sets sys.googlebook.pad3.boot_stage and attempts
one best-effort write of v4:<stage> to only
/metadata/gsi/dsu/googlebook-pad3/googlebook-pad3-boot-stage.
The parent manages the root-only file; failures remain visible in init logs.
There is no fsync or durability guarantee. No policy changes are made.
A guest-only
shell watchdog starts after bootstrap APEX configuration. It exits naturally
with status 0 when sys.boot_completed=1, or status 1 after 180 one-second polls.
Init requests reboot on failure; no action explicitly stops the service.
Returning to native depends on using a non-sticky, one-shot DSU trial. Failures
before watchdog launch, kernel hangs and blocked property/sleep calls are not
covered, and real watchdog-triggered reboot behavior remains untested.

Only system/build.prop gains the two missing native display properties:
debug.sf.ignore_hwc_physical_display_orientation=true and
ro.bootanim.set_orientation_4630946983774026899=ORIENTATION_90.
The retained vendor ORIENTATION_270 and all animation frames are preserved.

V5 adds only the five missing native dalvik heap profile fields to system/build.prop:
heapstartsize=16m, heapsize=512m, heaptargetutilization=0.5, heapminfree=8m,
heapmaxfree=32m. Existing heapgrowthlimit=512m is preserved without adding a new
definition. Conflicting values or unexpected existing profile fields are rejected.
Heap/display/watchdog settings and the late USB handoff remain unchanged.
The remaining checkpoints retain v4 stage markers. There is no artificial
boot-completed property change.

V6 disables only the pinned enableDesktopRepairModeService()Z flag in
desktop-services.jar by returning false, retaining the disabled partition writer.
This is a private variant change, not a runtime DSU condition. Future full-install
tablet partition management needs a separate implementation. The original base
image remains the reproduction input. DEX SHA1/Adler32 and JAR CRCs are updated.
Bootanimation metadata uses canvas 2544x1800 at 60 FPS and trim offset +571+0;
all 145 PNG payloads, repetition, ZIP metadata and compression are retained.

V8 changes only ro.setupwizard.require_network=any to an empty value in product
build.prop, exposing the normal offline Skip while retaining independent FRP
checks. The existing repairmode sysconfig retains initial-package-state and adds
a default-disabled BootCompletedReceiver component override. The signed APK is
unchanged. Existing users in DEFAULT inherit this state; explicit per-user
ENABLED takes precedence. No userdata or setup-completion flags are changed.

V9 adds only googlebook-pad3-tips.xml to default-disable Tips MainActivity,
DeepLinkGateway (welcome) and PerksDeepLink. The signed DesktopTips APK remains
unchanged. V8 offline setup, receiver override, namespace fix and security remain.

Full checkvintf, actual boot, USB enumeration and untrusted-key rejection remain
untested. All original casefold/APEX/keystore/odsign waits remain in place.
Do not stage, activate or reboot without the owner's reviewed next procedure.
"""


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_images(images, expected):
    require(set(expected) == set(PARTITIONS), "unexpected source partition set")
    for part in PARTITIONS:
        path = images / (part + ".img")
        require(not path.is_symlink() and path.is_file() and sha256(path) == expected[part],
                "unverified source image: " + part)


def verify_policy_profile(root):
    profile = json.loads((root / "profile.json").read_text())
    require(set(profile["files"]) == {"vendor/plat_pub_versioned.cil", "vendor/vendor_sepolicy.cil",
            "odm/odm_sepolicy.cil", "vendor/plat_sepolicy_vers.txt", "vendor/genfs_labels_version.txt"},
            "unexpected native policy profile file set")
    for name, expected in profile["files"].items():
        path = root / "policy" / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == expected["bytes"] and
                sha256(path) == expected["sha256"], "native policy profile drift: " + name)
    return profile


def compile_policy(images, compiler, policy_root, output):
    profile_root = SOURCE / "profiles/erhai-crdroid-20261025"
    profile = verify_policy_profile(profile_root)
    policy_root.mkdir()
    for part in PARTITIONS:
        extract_tree(images[part], ("/system" if part == "system" else "") + "/etc/selinux", policy_root / part)
    policy = check(compiler, policy_root / "system", policy_root / "system_ext", policy_root / "product",
                   profile_root / "policy/vendor", profile_root / "policy/odm", output)
    require(policy["strict_neverallow_pass"] and policy["strict_neverallow_failures"] == 0 and
            policy["compiled_sha256"] == profile["compiled_policy_sha256"], "current-base policy regression")
    policy["native_profile"] = {"path": str(profile_root), "sha256": sha256(profile_root / "profile.json")}
    return policy


def read_public_key(path=PUBLIC_KEY):
    require(path == PUBLIC_KEY and path.resolve() == PUBLIC_KEY and not path.is_symlink(),
            "only the owner's regular public-key file is allowed")
    require(stat.S_ISREG(path.stat().st_mode) and path.stat().st_size <= 8192,
            "invalid public-key file")
    return path.read_bytes()


def product_overlay_unchanged(changes, additions, previous_report):
    if previous_report is None:
        return False
    payloads = changes.get("product", {}) | {path: entry["data"] for path, entry in additions.get("product", {}).items()}
    return (set(previous_report["images"]["product"]["changed_paths"]) == set(payloads) and
            all(previous_report["metadata"].get("product:" + path, {}).get("sha256") == hashlib.sha256(data).hexdigest()
                for path, data in payloads.items()))


def preserved_system_payloads(changes, additions, previous_report):
    require(TIPS_SYSCONFIG_PATH in additions.get("system", {}), "V9 requires an explicit Tips sysconfig addition")
    payloads = changes.get("system", {}) | {path: entry["data"] for path, entry in additions.get("system", {}).items()}
    previous_paths = set(previous_report["images"]["system"]["changed_paths"])
    require(set(payloads) == previous_paths | {TIPS_SYSCONFIG_PATH}, "unexpected V9 system overlay file set")
    preserved = {}
    for path, data in payloads.items():
        if path == TIPS_SYSCONFIG_PATH and path not in previous_paths:
            continue
        digest = hashlib.sha256(data).hexdigest()
        require(previous_report["metadata"]["system:" + path]["sha256"] == digest,
                "preserved V8 system payload changed: " + path)
        preserved[path] = digest
    return preserved


def compressed_sha256(path, info):
    with path.open("rb") as stream:
        stream.seek(info.header_offset)
        header = stream.read(30)
        require(len(header) == 30 and header[:4] == b"PK\x03\x04", "invalid ZIP local header")
        name_size, extra_size = struct.unpack_from("<HH", header, 26)
        stream.seek(name_size + extra_size, os.SEEK_CUR)
        remaining, digest = info.compress_size, hashlib.sha256()
        while remaining:
            chunk = stream.read(min(8 * 1024 * 1024, remaining))
            require(bool(chunk), "truncated compressed ZIP member")
            digest.update(chunk)
            remaining -= len(chunk)
        return digest.hexdigest()


def package(images, report, work, *, reuse_existing_payloads=False, readme=README):
    require(bool(images) and set(images) <= set(PARTITIONS) and
            (reuse_existing_payloads or set(images) == set(PARTITIONS)), "unexpected packaged image set")
    rebuilt = tuple(part for part in PARTITIONS if part in images)
    target = work / ZIP_NAME
    temporary = work / (ZIP_NAME + ".part.zip")
    require((target.is_file() if reuse_existing_payloads else not target.exists()) and not target.is_symlink() and
            not temporary.exists() and not temporary.is_symlink(), "diagnostic bundle already exists")
    reused = {}
    previous_hash = None
    if reuse_existing_payloads:
        previous_hash = sha256(target)
        with zipfile.ZipFile(target) as previous:
            previous_report = json.loads(previous.read("diagnostic-report.json"))
            for part in PARTITIONS:
                if part in rebuilt:
                    continue
                require(previous_report["images"][part]["sha256"] == report["images"][part]["sha256"],
                        "reused payload hash changed: " + part)
                reused[part] = compressed_sha256(target, previous.getinfo(part + ".img"))
        report["reused_payload_compressed_sha256"] = reused
        report["previous_bundle_sha256"] = previous_hash
    try:
        if reused:
            subprocess.run(["zip", "-q", "-U", str(target), "--out", str(temporary), "-x",
                            *(part + ".img" for part in rebuilt),
                            "diagnostic-report.json", "README.md", "-b", str(work)],
                           check=True, cwd=work)
        with zipfile.ZipFile(temporary, "a" if reused else "x",
                             compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
            for part in rebuilt:
                require(sha256(images[part]) == report["images"][part]["sha256"], "image changed before packaging")
                archive.write(images[part], part + ".img")
            archive.writestr("diagnostic-report.json", json.dumps(report, indent=2) + "\n")
            archive.writestr("README.md", readme)
        with zipfile.ZipFile(temporary) as archive:
            require(len(archive.namelist()) == 5 and set(archive.namelist()) == {p + ".img" for p in PARTITIONS} |
                    {"diagnostic-report.json", "README.md"}, "unexpected diagnostic ZIP member")
            require(archive.testzip() is None, "diagnostic ZIP CRC failure")
            for part in PARTITIONS:
                with archive.open(part + ".img") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                require(digest == report["images"][part]["sha256"], "packaged image hash mismatch")
            for part, digest in reused.items():
                require(compressed_sha256(temporary, archive.getinfo(part + ".img")) == digest,
                        "reused compressed payload changed: " + part)
        require(previous_hash is None or sha256(target) == previous_hash, "source ZIP changed during packaging")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    digest = sha256(target)
    checksum = work / (ZIP_NAME + ".sha256")
    staged_checksum = checksum.with_name(checksum.name + ".part")
    require(not staged_checksum.exists() and not staged_checksum.is_symlink(), "unfinished checksum already exists")
    staged_checksum.write_text(digest + "  " + ZIP_NAME + "\n")
    staged_checksum.replace(checksum)
    return {"path": str(target), "bytes": target.stat().st_size, "sha256": digest}


def build(work, *, reuse_existing_payloads=False, compiler=None):
    require(work == work.resolve() and work.is_relative_to(Path("/private/tmp/ai-development")) and
            (work.parent / ".cleanos-task.json").is_file(), "use a diagnostic directory inside a tracked CleanOS task")
    owner = json.loads((work.parent / ".cleanos-task.json").read_text())
    require(owner["owner"] == os.getuid() and owner["id"] == work.parent.name and
            owner["project"] == str(SOURCE) and not owner["finished"], "invalid parent task ownership")
    work.mkdir(exist_ok=True)
    policy_output = work / ("watchdog-policy-check" if reuse_existing_payloads else "policy-check")
    require((work / ZIP_NAME).is_file() == reuse_existing_payloads and not (work / "images").exists() and
            not (work / "policy-inputs").exists() and not policy_output.exists(),
            "diagnostic outputs already exist; review them before rebuilding")
    previous_report = None
    if reuse_existing_payloads:
        previous_report = json.loads((work / "diagnostic-report.json").read_text())
        require(sha256(work / ZIP_NAME) == previous_report["bundle"]["sha256"], "existing candidate ZIP changed")
        with zipfile.ZipFile(work / ZIP_NAME) as archive:
            require(json.loads(archive.read("diagnostic-report.json")) ==
                    {k: v for k, v in previous_report.items() if k != "bundle"}, "existing ZIP metadata differs")
    original = work.parent / "candidate-images"
    expected = json.loads((SOURCE / 'profiles/build-seed.json').read_text())["image_sha256"]
    verify_images(original, expected)
    require(previous_report is None or previous_report["source_image_sha256"] == expected,
            "previous candidate used different base images")
    vendor_image = work.parent / "pad3-base-images/vendor.img"
    pinned_vendor = json.loads((SOURCE / "inputs.json").read_text())["tablet"]["partitions"]["vendor"]
    require(not vendor_image.is_symlink() and sha256(vendor_image) == pinned_vendor, "unverified native USB source image")
    usb_source = str(vendor_image) + ":/etc/init/hw/init.qcom.usb.rc"
    require(hashlib.sha256(content(vendor_image, "/etc/init/hw/init.qcom.usb.rc")).hexdigest() == USB_SOURCE_SHA256,
            "unreviewed native USB source")
    require(content(original / "system.img", "/adb_keys") == b"/product/etc/security/adb_keys",
            "unexpected root adb_keys symlink")
    require(stat.S_ISLNK(metadata(original / "system.img", "/adb_keys")["mode"]), "adb_keys is not a symlink")
    contexts = content(original / "system.img", "/system/etc/selinux/plat_file_contexts")
    require(re.search(rb"^/\(product\|system/product\)/etc/security/adb_keys[ \t]+u:object_r:adb_keys_file:s0$",
                      contexts, re.MULTILINE),
            "missing existing key label")
    changes, additions = diagnostic_changes(original, read_public_key())
    preserved_system = {}
    if previous_report is not None:
        require(hashlib.sha256(additions["product"]["/etc/security/adb_keys"]["data"]).hexdigest() ==
                previous_report["metadata"]["product:/etc/security/adb_keys"]["sha256"], "owner public key changed")
        preserved_system = preserved_system_payloads(changes, additions, previous_report)
    with zipfile.ZipFile(io.BytesIO(changes["system"][JAR_PATH])) as jar:
        patched_dex = jar.read("classes.dex")
    require(valid_checksums(patched_dex) and
            patched_dex[INSTRUCTION_OFFSET:INSTRUCTION_OFFSET + 4] == NEW_INSTRUCTIONS,
            "repair flag output validation failed")
    output = work / "images"
    output.mkdir()
    images = {p: original / (p + ".img") for p in PARTITIONS}
    report = {"status": "UNBOOTED_PRIVATE_DSU_DIAGNOSTIC_V9", "source_image_sha256": expected,
              "hardware_partitions_included": [], "device_commands_run": False,
              "boot_tested": False, "untrusted_key_rejection_tested": False,
              "full_checkvintf": {"performed": False, "tool_available": bool(shutil.which("checkvintf")),
                                 "gap": "No complete current vendor/ODM/APEX/kernel dirmaps; no compatibility pass claimed."},
              "native_usb_source": {"sha256": USB_SOURCE_SHA256, "file": str(usb_source),
                                    "base": "pinned local crDroid 20261017 vendor; current B rc unverified"},
              "native_base_supplied_by_owner": NATIVE_BASE_SUPPLIED_BY_OWNER,
              "boot_stage_property": BOOT_STAGE_PROPERTY,
              "boot_stage_file": {"path": BOOT_STAGE_FILE, "value_prefix": "v4:",
                                  "best_effort": True, "parent_manages_ownership": True,
                                  "durability_guaranteed": False, "checkpoint_count": 13},
              "native_display_properties": DISPLAY_PROPERTIES,
              "native_heap_properties_added": HEAP_PROPERTIES,
              "heapgrowthlimit_preserved": "512m; no new framework definition",
              "revision_scope": "Add only default-disabled Tips entrypoints; retain every V8 payload",
              "preserved_v8_system_payload_sha256": preserved_system,
              "tips_component_defaults": {"path": TIPS_SYSCONFIG_PATH, "package": "com.google.android.desktop.tips",
                    "disabled": ["MainActivity", "DeepLinkGateway(welcome)", "PerksDeepLink"],
                    "signed_apk_sha256": TIPS_APK_SHA256, "apk_modified": False, "userdata_modified": False},
              "setup_network_requirement": {"path": "product:/etc/build.prop",
                    "property": "ro.setupwizard.require_network", "before": "any", "after": "",
                    "frp_checks_modified": False, "setup_completion_flags_modified": False},
              "repair_receiver_default": {"path": REPAIR_SYSCONFIG_PATH, "package": REPAIR_PACKAGE,
                    "component": REPAIR_RECEIVER, "enabled": False, "initial_package_state_preserved": True,
                    "apk_modified": False, "userdata_modified": False,
                    "existing_DEFAULT_inherits": True, "explicit_user_ENABLED_takes_precedence": True},
              "desktop_repair_gate": {"path": JAR_PATH, "source_jar_sha256": JAR_SHA256,
                    "source_dex_sha256": DEX_SHA256, "method": METHOD, "method_id": METHOD_ID,
                    "code_item_offset": CODE_OFFSET, "instruction_offset": INSTRUCTION_OFFSET,
                    "before": OLD_INSTRUCTIONS.hex(), "after": NEW_INSTRUCTIONS.hex(),
                    "output_dex_sha256": hashlib.sha256(patched_dex).hexdigest(), "checksums_verified": True,
                    "private_variant_only": True, "runtime_dsu_conditional": False, "partition_writer_restored": False},
              "bootanimation_geometry": {"path": "/media/bootanimation.zip", "source_sha256": ANIMATION_SOURCE_SHA256,
                    "canvas": "2544 1800 60", "trim": "1402x1800+571+0", "pngs_unchanged": 145,
                    "parts_repetition_zip_metadata_preserved": True},
              "diagnostic_usb_handoff": {"vendor.usb.use_gadget_hal": "0",
                    "boot_stage_guard": "odsign-verification-after",
                    "queued_boot_event": "googlebook-pad3-usb-refresh",
                    "refresh_configfs": "1", "refresh_config": "none",
                    "state_none_handler_config": "adb", "synchronous_state_none_wait": False,
                    "refresh_changes_boot_stage": False,
                    "persist_after_load": {"persist.sys.usb.config": "adb", "persist.adb.tradeinmode": "0"},
                    "donor_tradein_stop_neutralized": True, "framework_root_cause_claimed": False},
              "early_adbd_boot_property_set": False, "inline_early_usb_setup": False,
              "ffs_readiness_wait": None,
              "boot_watchdog": {"service": WATCHDOG_NAME, "script": WATCHDOG_PATH,
                                "timeout_seconds": 180, "user": "shell", "group": "shell",
                                "seclabel": "u:r:shell:s0", "reboot_on_failure": "reboot",
                                "success_property": "sys.boot_completed=1", "natural_success_exit_status": 0,
                                "timeout_exit_status": 1, "explicit_stop_action": False,
                                "start": "early-init after perform_apex_config, before post-fs-data waits",
                                "native_return_requires_one_shot_dsu": True, "runtime_tested": False},
              "redistribution_requires_key_removal": True, "images": {}, "metadata": {},
              "unchanged_content_sha256": {}}
    reuse_product = product_overlay_unchanged(changes, additions, previous_report)
    if reuse_product:
        images["product"] = output / "product.img"
        with zipfile.ZipFile(work / ZIP_NAME) as previous:
            with previous.open("product.img") as source, images["product"].open("xb") as destination:
                shutil.copyfileobj(source, destination, 8 * 1024 * 1024)
        require(sha256(images["product"]) == previous_report["images"]["product"]["sha256"],
                "reused product extraction hash mismatch")
    rebuilt = tuple(part for part in PARTITIONS if (changes.get(part) or additions.get(part)) and
                    not (part == "product" and reuse_product))
    for part in rebuilt:
        print("Overlay", part, flush=True)
        images[part] = output / (part + ".img")
        with tempfile.TemporaryDirectory(prefix="overlay-", dir=work) as overlay_scratch:
            report["images"][part] = apply(original / (part + ".img"), images[part],
                                          changes.get(part, {}), overlay_scratch, additions=additions.get(part))
        for path in report["images"][part]["changed_paths"]:
            data = content(images[part], path)
            expected_data = changes.get(part, {}).get(path)
            if expected_data is None:
                expected_data = additions[part][path]["data"]
            require(data == expected_data, "re-extracted bytes differ: " + path)
            meta = metadata(images[part], path)
            report["metadata"][part + ":" + path] = {
                "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "extracted_bytes_match": True,
                "uid": meta["uid"], "gid": meta["gid"], "mode": oct(stat.S_IMODE(meta["mode"])),
                "selinux": meta["xattrs"]["security.selinux"].rstrip(b"\0").decode(),
                "mtime": meta["mtime"], "mtime_nsec": meta["mtime_nsec"],
                "metadata_verified_by_overlay": True}
    for part in PARTITIONS:
        if part not in rebuilt:
            if part == "product" and reuse_product:
                report["images"][part] = dict(previous_report["images"][part], reused_unchanged=True)
                report["metadata"].update({key: dict(value, reused_from_previous_bundle=True)
                    for key, value in previous_report["metadata"].items() if key.startswith("product:")})
            else:
                report["images"][part] = {"sha256": expected[part], "bytes": images[part].stat().st_size,
                                          "changed_paths": [], "reused_unchanged": True}
    for part, paths in {
        "system": ["/system/build.prop", "/adb_keys", "/system/etc/selinux/plat_file_contexts",
                   "/system/etc/selinux/plat_property_contexts", "/system/bin/sh", "/system/bin/getprop",
                   "/system/bin/sleep", "/system/bin/toolbox", "/system/bin/toybox",
                   "/system/etc/init/hw/init.usb.rc", "/system/etc/init/hw/init.usb.configfs.rc",
                   "/system/apex/com.google.android.adbd.apex", "/system/framework/services.jar"],
        "system_ext": ["/priv-app/RepairMode-Desktop/RepairMode-Desktop.apk"],
        "product": ["/etc/build.prop", "/etc/vintf/compatibility_matrix.xml", TIPS_APK_PATH],
    }.items():
        for path in paths:
            before, after = content(original / (part + ".img"), path), content(images[part], path)
            if (part, path) in [("system", "/system/build.prop"), ("product", "/etc/build.prop")]:
                require(after == changes[part][path], "unexpected " + part + " property delta")
                continue
            require(before == after, "protected content changed: " + path)
            report["unchanged_content_sha256"][part + ":" + path] = hashlib.sha256(after).hexdigest()
            if part == "product" and path == TIPS_APK_PATH:
                require(report["unchanged_content_sha256"][part + ":" + path] == TIPS_APK_SHA256,
                        "unreviewed signed Tips APK")
    policy_root = work / "policy-inputs"
    report["policy"] = compile_policy(images, compiler or work.parent / "secilc-tools/bin/secilc", policy_root, policy_output)
    packaged_images = {part: images[part] for part in rebuilt} if reuse_existing_payloads else images
    report["bundle"] = package(packaged_images, report, work, reuse_existing_payloads=reuse_existing_payloads)
    staged_report = work / "diagnostic-report.json.part"
    require(not staged_report.exists() and not staged_report.is_symlink(), "unfinished diagnostic report already exists")
    staged_report.write_text(json.dumps(report, indent=2) + "\n")
    staged_report.replace(work / "diagnostic-report.json")
    shutil.rmtree(output)
    shutil.rmtree(policy_root)
    for name in ("runtime-policy", "strict-policy", "runtime-contexts", "strict-contexts"):
        (policy_output / name).unlink()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--reuse-existing-payloads", action="store_true",
                        help="Rebuild diagnostic overlays, reuse other compressed images and atomically replace the scratch ZIP")
    args = parser.parse_args()
    result = build(args.work, reuse_existing_payloads=args.reuse_existing_payloads)
    print(json.dumps(result["bundle"], indent=2))
