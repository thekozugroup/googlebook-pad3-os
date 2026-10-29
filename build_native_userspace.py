#!/usr/bin/env python3
"""Assemble three native EROFS images offline; never sign, install or publish.

Recipe schema 1: sequence, timestamp, images {system,system_ext,product},
files {face_overlay,updater,pen_apk,pen_unsigned,taskmanager_jar,taskmanager_verification,component_certificate,payload_certificate,
trust_manifest,update_engine,update_engine_rc,update_engine_protobuf,
update_engine_protobuf_metadata,manager_service,apksigner,aapt2},
and trust {each relative path emitted by build_native_rom.trust_overlay: file pin}.
Every file pin is exactly {path: absolute path, sha256: lowercase SHA-256}.
Supply JAVA_HOME for the installed apksigner. Trust files come from the parent's
trust_overlay call; components and the one-shot shell service are reviewed inputs.
"""
import argparse
import base64
import hashlib
import io
import json
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True

import build_native_rom as native
from erofs_overlay import apply, content
from erofs_sanitize import inventory, rewrite
from native_install import public_image
from native_install.payload import require, sha256
from port_changes import (BOOT_STAGE_FILE, BOOT_STAGE_PROPERTY, DIAGNOSTIC_ID,
                          DIAGNOSTIC_USB_REFRESH, DIAGNOSTIC_WAITS, WATCHDOG_NAME,
                          WATCHDOG_PATH, WATCHDOG_SERVICE)

PARTITIONS = ("system", "system_ext", "product")
INIT = "/system/etc/init/hw/init.rc"
TASKMANAGER = "/system/framework/vendor.google.libraries.desktop.serviceability.jar"
TASKMANAGER_BASE_SHA = "5e4d4c6336e18a3228b4ac4960ea5ecddcc556865d530db7a7094903f62695ba"
FACE = "/overlay/GooglebookPad3FacePreview/GooglebookPad3FacePreview.apk"
UPDATER = "/priv-app/Pad3Updater/Pad3Updater.apk"
PEN = "/priv-app/OplusPen.apk"
OVERLAY_CONFIG = "/overlay/config/config.xml"
MANAGER_RC = "/etc/init/googlebook-pad3-sukisu-manager.rc"
PROTOBUF = "/system/lib64/libprotobuf-cpp-lite-6.33.5.so"
COMPONENT_CERT_SHA = "3625a00c6244e94e3150604c4903800c3928e958e77a5b2d2814be1864f82eb4"
TRUST_PATHS = (native.CERT_PATH, native.KEY_PATH, native.CONFIG_PATH,
               native.MANAGER_PATH, native.BOOTSTRAP_PATH, native.MANAGER_CHECKER_PATH)
FILE_INPUTS = {"face_overlay", "updater", "pen_apk", "pen_unsigned", "taskmanager_jar", "taskmanager_verification", "component_certificate",
               "payload_certificate", "trust_manifest", "update_engine", "update_engine_rc",
               "update_engine_protobuf", "update_engine_protobuf_metadata",
               "manager_service", "apksigner", "aapt2"}
FACE_ENTRY = {"package": "com.googlebook.pad3.facepreview", "mutable": "false", "enabled": "true"}
TASKMANAGER_SOURCES = {
    "patch_taskmanager.py", "components/taskmanager-compat/build-support/GraftClient.java",
    "components/taskmanager-compat/compile-api/vendor/google/libraries/desktop/serviceability/ServiceabilityManager.java",
    "components/taskmanager-compat/src/vendor/google/libraries/desktop/serviceability/TaskManagerCompat.java",
    "components/taskmanager-compat/tests/vendor/google/libraries/desktop/serviceability/MetricsSelfTest.java",
}
PRIVATE_FILE = re.compile(r"googlebook.*(?:logger|logcat|watchdog|diagnostic|debug|probe|crash)|(?:gb[-_])?dsu[-_](?:log|boot|adb)", re.I)


def strip_diagnostics(data):
    text = data.decode()
    for block in (WATCHDOG_SERVICE, DIAGNOSTIC_USB_REFRESH):
        require(text.count(block) == 1, "not the pure V10 init: diagnostic block drift")
        text = text.replace(block, "")
    stages = re.findall(r'^    write /dev/kmsg "' + re.escape(DIAGNOSTIC_ID) + r': ([a-z-]+)', text, re.M)
    properties = re.findall(r"^    setprop " + re.escape(BOOT_STAGE_PROPERTY) + r" ([a-z-]+)$", text, re.M)
    markers = re.findall(r'^    write ' + re.escape(BOOT_STAGE_FILE) + r' "v4:([a-z-]+)"$', text, re.M)
    require(len(stages) == len(set(stages)) == 13 and stages == properties == markers,
            "not the pure V10 init: diagnostic stage mismatch")
    for pattern in (r'    write /dev/kmsg "' + re.escape(DIAGNOSTIC_ID) + r': [^\n]*\n',
                    r"    setprop " + re.escape(BOOT_STAGE_PROPERTY) + r" [^\n]*\n",
                    r"    write " + re.escape(BOOT_STAGE_FILE) + r" [^\n]*\n"):
        text, count = re.subn("^" + pattern, "", text, flags=re.M)
        require(count == 13, "not the pure V10 init: expected thirteen diagnostic lines")
    for line in ("    start " + WATCHDOG_NAME + "\n",
                 "    setprop persist.sys.usb.config adb\n", "    setprop persist.adb.tradeinmode 0\n"):
        require(text.count(line) == 1, "not the pure V10 init: diagnostic override drift")
        text = text.replace(line, "")
    for wait in DIAGNOSTIC_WAITS.values():
        require(data.decode().count(wait) == text.count(wait) == 1, "normal init wait changed")
    public_image.audit_text(text.encode())
    return text.encode()


def native_properties(data, partition, sequence, timestamp):
    prefix = "ro." + partition + ".build."
    fingerprint = f"Googlebook/erhai/erhai:17/GBOS/{sequence}:user/release-keys"
    updates = {"ro.product." + partition + ".device": "erhai", prefix + "fingerprint": fingerprint,
               prefix + "type": "user", prefix + "tags": "release-keys",
               prefix + "version.incremental": str(sequence), prefix + "date.utc": str(timestamp),
               "ro.secure": "1", "ro.adb.secure": "1", "ro.debuggable": "0", "ro.force.debuggable": "0"}
    if partition == "system":
        updates |= {"ro.product.device": "erhai", "ro.build.fingerprint": fingerprint,
                    "ro.build.description": f"erhai-user 17 GBOS {sequence} release-keys",
                    "ro.build.user": "android", "ro.build.host": "buildhost",
                    "ro.build.type": "user", "ro.build.tags": "release-keys",
                    "ro.build.version.incremental": str(sequence),
                    "ro.build.date.utc": str(timestamp), "ro.system.build.date.utc": str(timestamp),
                    "ro.googlebook.pad3.native": "1", "ro.googlebook.pad3.device": "erhai",
                    "ro.googlebook.pad3.base_profile": "erhai-crdroid-20261025",
                    "ro.googlebook.pad3.release_sequence": str(sequence),
                    "ro.build.ab_update": "true", "ro.virtual_ab.enabled": "true"}
    controlled = set(updates)
    lines, seen = [], set()
    for line in data.decode().splitlines():
        key, sep, value = line.partition("=")
        if sep and not key.lstrip().startswith("#"):
            require(key == key.strip() and (key not in controlled or key not in seen),
                    "duplicate/ambiguous build property: " + key)
            seen.add(key)
            if (key.startswith("persist.adb.") or key in {"persist.sys.usb.config", "service.adb.listen_addrs",
                    "service.adb.tcp.port", "ro.boot.apex.early_adbd"}):
                continue
            if re.fullmatch(r"ro\.(?:[a-z_]+\.)?build\.(?:user|host)", key):
                value = "android" if key.endswith("user") else "buildhost"
            line = key + "=" + updates.pop(key, value)
        lines.append(line)
    lines.extend(key + "=" + value for key, value in updates.items())
    result = ("\n".join(lines) + "\n").encode()
    public_image.audit_text(result)
    return result


def overlay_config(data):
    root = ET.fromstring(data)
    require(root.tag == "config", "unexpected OverlayConfig root")
    entries = [e for e in root.iter("overlay") if e.get("package") == FACE_ENTRY["package"]]
    require(len(entries) <= 1 and all(e.attrib == FACE_ENTRY and len(e) == 0 for e in entries),
            "conflicting face OverlayConfig entry")
    if entries:
        return data
    require(data.count(b"</config>") == 1, "expected explicit OverlayConfig closing tag")
    return data.replace(b"</config>", b'    <overlay package="com.googlebook.pad3.facepreview" mutable="false" enabled="true" />\n</config>')


def load_recipe(path):
    recipe = json.loads(native.regular(path).read_text())
    require(set(recipe) == {"schema", "sequence", "timestamp", "images", "files", "trust"}
            and recipe["schema"] == 1, "unexpected native userspace recipe")
    require(type(recipe["sequence"]) is int and recipe["sequence"] > 0
            and type(recipe["timestamp"]) is int and 1792932356 <= recipe["timestamp"] < 2**63,
            "invalid release sequence/timestamp")
    require(set(recipe["images"]) == set(PARTITIONS) and set(recipe["files"]) == FILE_INPUTS
            and set(recipe["trust"]) == set(TRUST_PATHS), "missing or unexpected pinned inputs")
    checked = {group: {name: native.checked(pin) for name, pin in recipe[group].items()}
               for group in ("images", "files", "trust")}
    require(all(native.image_kind(image) == "erofs" for image in checked["images"].values()), "EROFS inputs required")
    return recipe, checked


def apk_payload_hashes(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and archive.testzip() is None, "invalid APK ZIP")
        return {name: hashlib.sha256(archive.read(name)).hexdigest() for name in names}


def dex_hashes(data):
    hashes = {name: digest for name, digest in apk_payload_hashes(data).items()
              if re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex", name)}
    require("classes.dex" in hashes, "pen APK has no classes.dex")
    return hashes


def verify_component(apk, package, tools):
    result = subprocess.run([str(tools["apksigner"]), "verify", "--verbose", "--print-certs", str(apk)], capture_output=True, text=True)
    require(result.returncode == 0 and re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)", result.stdout) == [COMPONENT_CERT_SHA]
            and re.search(r"Verified using v[23](?:\.\d+)? scheme[^\n]*: true", result.stdout), "signed component verification failed: " + package)
    result = subprocess.run([str(tools["aapt2"]), "dump", "badging", str(apk)], capture_output=True, text=True)
    require(result.returncode == 0 and re.findall(r"^package: name='([^']+)'", result.stdout, re.M) == [package], "component package mismatch: " + package)


def verify_taskmanager(jar, receipt):
    proof = json.loads(receipt.read_text())
    require(proof["candidate_sha256"] == sha256(jar) and proof["candidate_bytes"] == jar.stat().st_size
            and proof["original_jar_sha256"] == TASKMANAGER_BASE_SHA,
            "TaskManager verification does not bind this candidate/base")
    require(set(proof["sources"]) == TASKMANAGER_SOURCES, "unexpected TaskManager source proof")
    for name, digest in proof["sources"].items():
        native.checked({"path": str(native.ROOT / name), "sha256": digest})
    from patch_taskmanager import ORIGINAL_DEX_SHA256, TARGET_COUNTS, verify_dex
    with zipfile.ZipFile(jar) as archive:
        require(archive.namelist() == ["classes.dex", "META-INF/MANIFEST.MF"] and archive.testzip() is None,
                "invalid patched TaskManager JAR")
        require(verify_dex(archive.read("classes.dex")) == proof["dex"], "TaskManager DEX proof mismatch")
    preserved = proof["preservation"]
    require(proof["original_dex_sha256"] == ORIGINAL_DEX_SHA256
            and set(preserved["changed_methods"]) == set(TARGET_COUNTS)
            and len(preserved["changed_methods"]) == len(TARGET_COUNTS)
            and proof["transform"]["grafted_methods"] == len(TARGET_COUNTS)
            and preserved["untouched_manager_methods"] == preserved["manager_methods"] - len(TARGET_COUNTS)
            and preserved["original_target_instructions_branches_try_debug_preserved"] is True
            and preserved["original_fields_dtos_annotations_parameters_preserved"] is True
            and preserved["compile_only_classes_in_candidate"] is False, "TaskManager ABI preservation proof mismatch")
    return proof


def protobuf_addition(files):
    proof = json.loads(files["update_engine_protobuf_metadata"].read_text())
    native.checked(proof["source_image"])
    data = files["update_engine_protobuf"].read_bytes()
    require(proof["image_path"] == PROTOBUF and proof["bytes"] == len(data)
            and proof["sha256"] == hashlib.sha256(data).hexdigest(), "native protobuf source proof mismatch")
    require(data[:6] == b"\x7fELF\x02\x01" and data[18:20] == b"\xb7\x00", "native protobuf must be an AArch64 ELF")
    meta = dict(proof["metadata"])
    meta["xattrs"] = {k: base64.b64decode(v, validate=True) for k, v in meta["xattrs"].items()}
    require(set(meta) == {"mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs"}
            and meta["mode"] == stat.S_IFREG | 0o644 and meta["uid"] == meta["gid"] == 0
            and type(meta["mtime"]) is int and type(meta["mtime_nsec"]) is int
            and 0 <= meta["mtime_nsec"] < 10**9
            and meta["xattrs"].get("security.selinux") == b"u:object_r:system_lib_file:s0\0",
            "native protobuf metadata mismatch")
    return {"data": data, "metadata": meta}


def verify_inputs(inputs):
    files, trust = inputs["files"], inputs["trust"]
    require(sha256(files["component_certificate"]) == COMPONENT_CERT_SHA, "component certificate differs from public profile")
    for name, package in (("face_overlay", FACE_ENTRY["package"]), ("updater", "org.googlebook.pad3.updater"),
                          ("pen_apk", "org.lineageos.pen")):
        verify_component(files[name], package, files)
    require(apk_payload_hashes(files["pen_apk"].read_bytes()) == apk_payload_hashes(files["pen_unsigned"].read_bytes()),
            "signed pen payload differs from the approved pinned unsigned build")
    verify_taskmanager(files["taskmanager_jar"], files["taskmanager_verification"])
    manifest = json.loads(files["trust_manifest"].read_text())
    require(manifest.get("status") == "PUBLIC_TRUST_OVERLAY_ONLY_NOT_ROM_OR_FLASHABLE"
            and manifest["files"] == {name: sha256(path) for name, path in trust.items()}, "trust_overlay manifest differs from pinned files")
    require(sha256(files["taskmanager_jar"]) != TASKMANAGER_BASE_SHA, "TaskManager input is still the unpatched JAR")
    require(trust[native.CONFIG_PATH].read_bytes() == native.json_bytes(native.ota_config(native.PUBLIC_REPO, files["payload_certificate"])), "own OTA configuration mismatch")
    require(trust[native.KEY_PATH].read_bytes() == native.public_key(files["payload_certificate"]), "own payload public key mismatch")
    with zipfile.ZipFile(trust[native.CERT_PATH]) as archive:
        require(archive.namelist() == ["googlebook-native.x509.pem"]
                and archive.read(archive.namelist()[0]) == files["payload_certificate"].read_bytes(), "own OTA certificate mismatch")
    require(sha256(trust[native.MANAGER_PATH]) == native.MANAGER_SHA
            and trust[native.BOOTSTRAP_PATH].read_bytes() == native.manager_bootstrap()
            and sha256(trust[native.MANAGER_CHECKER_PATH]) == native.MANAGER_CHECKER_SHA, "official manager/bootstrap/checker mismatch")
    engine_rc = files["update_engine_rc"].read_bytes()
    with files["update_engine"].open("rb") as stream:
        elf = stream.read(20)
    require(elf[:6] == b"\x7fELF\x02\x01" and elf[18:20] == b"\xb7\x00", "native engine must be an AArch64 ELF")
    protobuf_addition(files)
    require(re.search(rb"^service update_engine /system/bin/update_engine(?:\s|$)", engine_rc, re.M), "captured native engine service missing")
    public_image.audit_text(engine_rc)
    service = files["manager_service"].read_bytes()
    command = re.search(rb"^service ([a-zA-Z0-9_-]+) /system/bin/sh /product/etc/googlebook/install-sukisu-manager.sh\n", service, re.M)
    require(len(re.findall(rb"^service ", service, re.M)) == 1 and
            command is not None
            and all(line in service.splitlines() for line in (b"    user shell", b"    group shell", b"    seclabel u:r:shell:s0", b"    disabled", b"    oneshot"))
            and b"on property:sys.boot_completed=1\n" in service
            and b"    start " + command[1] in service.splitlines(), "reviewed one-shot shell manager service required")
    public_image.audit_text(service)


def additions_and_changes(entries, payloads):
    changes, additions = {}, {}
    meta = {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0, "mtime": 1230768000,
            "mtime_nsec": 0, "xattrs": {"security.selinux": b"u:object_r:system_file:s0\0"}}
    for path, data in payloads.items():
        if path in entries:
            require(stat.S_ISREG(entries[path]["mode"]), "replacement is not a regular file: " + path)
            changes[path] = data
        else:
            for parent in reversed(PurePosixPath(path).parents):
                parent = str(parent)
                if parent in entries:
                    require(stat.S_ISDIR(entries[parent]["mode"]), "addition crosses a non-directory: " + parent)
                elif parent not in additions:
                    additions[parent] = {"data": b"", "metadata": dict(meta, mode=stat.S_IFDIR | 0o755)}
            mode = 0o755 if path.endswith("install-sukisu-manager.sh") else 0o644
            additions[path] = {"data": data, "metadata": dict(meta, mode=stat.S_IFREG | mode)}
    return changes, additions


def partition_plan(image, partition, recipe, inputs):
    entries = inventory(image)
    prefix = "/system" if partition == "system" else ""
    prop = prefix + ("/build.prop" if partition == "system" else "/etc/build.prop")
    payloads = {prop: native_properties(content(image, prop), partition, recipe["sequence"], recipe["timestamp"])}
    removals = {p for p in ("/adb_keys", prefix + "/etc/security/adb_keys", "/product/etc/security/adb_keys") if p in entries}
    for path, item in entries.items():
        if path == INIT:
            continue
        if (path.startswith(prefix + "/etc/init/") or path.startswith(prefix + "/bin/")) and PRIVATE_FILE.search(PurePosixPath(path).name):
            require(not stat.S_ISDIR(item["mode"]), "diagnostic directory needs explicit review: " + path)
            removals.add(path)
    if partition == "system":
        require(PROTOBUF not in entries, "native protobuf addition would replace an existing DSO")
        protobuf = protobuf_addition(inputs["files"])
        require(WATCHDOG_PATH in removals, "not pure V10: watchdog input missing")
        require(hashlib.sha256(content(image, TASKMANAGER)).hexdigest() == TASKMANAGER_BASE_SHA, "TaskManager source JAR drift")
        payloads |= {INIT: strip_diagnostics(content(image, INIT)), TASKMANAGER: inputs["files"]["taskmanager_jar"].read_bytes(),
                     PROTOBUF: protobuf["data"],
                     "/system/bin/update_engine": inputs["files"]["update_engine"].read_bytes(),
                     "/system/etc/init/update_engine.rc": inputs["files"]["update_engine_rc"].read_bytes()}
    elif partition == "system_ext":
        pen = inputs["files"]["pen_apk"].read_bytes()
        require(dex_hashes(pen) != dex_hashes(content(image, PEN)),
                "pen code is unchanged from V10; headless-user and permission fix required")
        payloads |= {FACE: inputs["files"]["face_overlay"].read_bytes(), UPDATER: inputs["files"]["updater"].read_bytes(),
                     PEN: pen,
                     OVERLAY_CONFIG: overlay_config(content(image, OVERLAY_CONFIG)) if OVERLAY_CONFIG in entries else overlay_config(b"<config>\n</config>\n"),
                     MANAGER_RC: inputs["files"]["manager_service"].read_bytes()}
    for relative, path in inputs["trust"].items():
        part, _, name = relative.partition("/")
        if part == partition:
            payloads["/" + relative if partition == "system" else "/" + name] = path.read_bytes()
    require(not payloads.keys() & removals, "replacement overlaps a removal")
    changes, additions = additions_and_changes(entries, payloads)
    if partition == "system":
        additions[PROTOBUF] = protobuf
    return changes, additions, removals, payloads


def assemble_partition(partition, recipe, inputs, output, scratch):
    image = native.checked(recipe["images"][partition])
    final = native.scratch_output(Path(output) / (partition + ".img"))
    changes, additions, removals, expected = partition_plan(image, partition, recipe, inputs)
    try:
        with tempfile.TemporaryDirectory(prefix="userspace-overlay-", dir=scratch) as directory:
            staged = Path(directory) / (partition + ".img")
            apply(image, staged, changes, scratch, additions=additions)
            # Only a fresh rewrite removes obsolete authorization/debug bytes.
            result = rewrite(staged, final, removals, scratch)
        require(final.stat().st_size % 4096 == 0, "unaligned EROFS output")
        for path, data in expected.items():
            require(content(final, path) == data, "assembled file differs: " + path)
        native.checked(recipe["images"][partition])
        return result | {"path": str(final), "base_sha256": recipe["images"][partition]["sha256"],
                         "changed_paths": sorted(changes), "added_paths": sorted(additions)}
    except BaseException:
        final.unlink(missing_ok=True)
        raise


def build(recipe_path, output, scratch):
    output = native.scratch_output(output)
    scratch = Path(scratch).resolve()
    native.scratch_output(scratch / "userspace-ownership-check")
    require(scratch.is_dir() and output.is_relative_to(scratch), "output must be under the active scratch directory")
    recipe, inputs = load_recipe(recipe_path)
    verify_inputs(inputs)
    require(shutil.disk_usage(scratch).free >= 2 * sum(p.stat().st_size for p in inputs["images"].values()) + 30 * 1024**3, "insufficient rewrite scratch space")
    output.mkdir()
    try:
        results = {}
        for partition in PARTITIONS:
            results[partition] = assemble_partition(partition, recipe, inputs, output, scratch)
        images = {part: output / (part + ".img") for part in PARTITIONS}
        public = public_image.check(images, content, "/system")
        for group in ("images", "files", "trust"):
            for pin in recipe[group].values():
                native.checked(pin)
        report = {"status": "NATIVE_USERSPACE_ASSEMBLED_UNBOOTED", "recipe_sha256": sha256(Path(recipe_path)),
                  "sequence": recipe["sequence"], "images": results, "public_image": public,
                  "limitations": ["Native update_engine library ABI requires a later device check.",
                                  "TaskManager JAR .fsv_meta/dexpreopt integrity remains a separate parent integration gate; ABI proof does not clear it.",
                                  "Parent must verify replacement pen headless/permission guards and protected updater DSU/mount guards; native properties do not prove DSU absence.",
                                  "EROFS requires reviewed vendor_boot AND recovery fstab patches.",
                                  "No AVB signing, payload generation, device actions or runtime pass."]}
        (output / "userspace-build.json").write_bytes(native.json_bytes(report))
        return report
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("recipe", "output", "scratch"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    build(args.recipe, args.output, args.scratch)
    print("NATIVE_USERSPACE_ASSEMBLED_UNBOOTED")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, zipfile.BadZipFile, ET.ParseError) as error:
        raise SystemExit("Native userspace stopped: " + str(error))
