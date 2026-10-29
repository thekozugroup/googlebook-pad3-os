#!/usr/bin/env python3
"""Build one unbooted V10 system_ext pen layer over the pinned private V9 ZIP."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import zipfile

from android_disk import require
from build_dsu_diagnostic import ZIP_NAME, package, sha256
from cold_build_dsu import EXPECTED_IMAGES
from erofs_overlay import apply, content, metadata
from ext4_source import command as ext4_command
from pen_policy import prepare_pen_policy

ROOT = Path(__file__).resolve().parent
CACHE = Path(os.environ.get("GOOGLEBOOK_INPUTS", "build-inputs"))
BASE_ZIP_SHA256 = "3e1f899e7894b968e370212fb6f769865449dc464c693bd469cf42d907a1c8c4"
APK_SHA256 = "2bce85ea227389012be66419f468100bd15b6172824bd8b288b489553bd4e37d"
APK_BYTES = 807260
CERT_SHA256 = "3625a00c6244e94e3150604c4903800c3928e958e77a5b2d2814be1864f82eb4"
GRANT_SHA256 = "b47d73b9b47c0bf77c99170ec9b4cb4c417ebdffe2a24eddec965c90030023ce"
OUTPUT_NAME = "Googlebook-erhai-dsu-pen-v10.zip"
APK_PATH = "/priv-app/OplusPen.apk"
GRANT_PATH = "/etc/default-permissions/default-permissions_org.lineageos.pen.xml"
USER_PATH = "/etc/sysconfig/googlebook-pad3-pen.xml"
USER_XML = b'''<?xml version="1.0" encoding="utf-8"?>
<config>
    <install-in-user-type package="org.lineageos.pen">
        <install-in user-type="FULL"/>
        <do-not-install-in user-type="SYSTEM"/>
    </install-in-user-type>
</config>
'''
README = """# Private GoogleBook Pad3 pen candidate V10

UNBOOTED_PEN_V10. Offline validation only; no functional pen or standby claim.
This adds only a system_ext layer to the pinned private V9 DSU bundle. The
compressed system/product payloads, native boot/vendor/ODM partitions, camera
orientation, and existing Google signed APK/APEX payloads are preserved.

Select a display mode at or below 120 Hz manually before the first pen trial.
Automatic refresh limiting is not implemented; the APK withholds the active
pencil ACK above its limit. Verify pairing, pressure relay, charging, reconnect,
and sleep/wake on hardware before treating the pen as functional.

The locally signed org.lineageos.pen app uses its own UID and package-scoped
pad3_pen SELinux mapping. Sysconfig requests installation in FULL users and
excludes SYSTEM users. Confirm effective installation and runtime grants for
the active full user, and absence from headless user 0, before starting tests.
The donor default allowlist mode is enforced; runtime overrides or existing
userdata state still require checking. No platform trust or shared UID is added.

V9 security and private diagnostic ADB configuration remain unchanged. This
private bundle retains the owner's public ADB authorization material; do not
redistribute without the existing review/removal procedure. Do not flash this
as a recovery package, activate DSU, or reboot without the parent's procedure.
"""


def verify_file(path, expected, size=None):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and (size is None or path.stat().st_size == size)
            and sha256(path) == expected, "input hash/size mismatch: " + str(path))


def verify_base(base_zip):
    require(base_zip.is_file() and not base_zip.is_symlink(), "V9 base must be a regular ZIP file")
    actual_sha256 = sha256(base_zip)
    with zipfile.ZipFile(base_zip) as archive:
        require(len(archive.namelist()) == 5 and set(archive.namelist()) ==
                {p + ".img" for p in EXPECTED_IMAGES} | {"diagnostic-report.json", "README.md"}, "unexpected V9 members")
        require(archive.getinfo("diagnostic-report.json").file_size <= 1024 * 1024 and
                archive.getinfo("README.md").file_size <= 128 * 1024, "oversized V9 report/readme")
        report = json.loads(archive.read("diagnostic-report.json"))
        require(report["status"] == "UNBOOTED_PRIVATE_DSU_DIAGNOSTIC_V9" and
                {p: report["images"][p]["sha256"] for p in EXPECTED_IMAGES} ==
                {p: item["sha256"] for p, item in EXPECTED_IMAGES.items()},
                "protected V9 image hashes changed")
        for part, expected in EXPECTED_IMAGES.items():
            require(archive.getinfo(part + ".img").file_size == expected["bytes"], "unexpected V9 image size: " + part)
            if actual_sha256 != BASE_ZIP_SHA256:
                with archive.open(part + ".img") as stream:
                    require(hashlib.file_digest(stream, "sha256").hexdigest() == expected["sha256"],
                            "V9 decompressed image hash mismatch: " + part)
    return report, {"sha256": actual_sha256, "canonical_zip_fast_path": actual_sha256 == BASE_ZIP_SHA256,
                    "image_integrity_method": "pinned whole ZIP" if actual_sha256 == BASE_ZIP_SHA256 else "all three decompressed image hashes"}


def android_tools():
    lock = json.loads((ROOT / "components/oplus-pen/toolchain.json").read_text())
    tools = {}
    for name in ("aapt2", "apksigner"):
        item = lock["tools"][name]
        verify_file(Path(item["path"]), item["sha256"])
        tools[name] = item["path"]
    return tools, dict(os.environ, JAVA_HOME=lock["java_home"])


def tool_output(argv, env):
    result = subprocess.run(list(map(str, argv)), env=env, capture_output=True, text=True)
    require(result.returncode == 0, "Android validation tool failed: " + (result.stdout + result.stderr)[-1500:])
    return result.stdout


def verify_apk(apk, certificate, tools, env):
    verify_file(apk, APK_SHA256, APK_BYTES)
    require(hashlib.sha256(certificate).hexdigest() == CERT_SHA256, "public pen certificate changed")
    signature = tool_output([tools["apksigner"], "verify", "--verbose", "--print-certs-pem", apk], env)
    certs = re.findall(r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----", signature)
    require(len(certs) == 1 and base64.b64decode(certs[0]) == certificate, "APK signer differs from exact public certificate")
    permissions = tool_output([tools["aapt2"], "dump", "permissions", apk], env)
    requested = set(re.findall(r"^uses-permission: name='([^']+)'", permissions, re.M))
    require(re.search(r"^package: org\.lineageos\.pen$", permissions, re.M) and requested == {
        "android.permission.BLUETOOTH", "android.permission.BLUETOOTH_CONNECT", "android.permission.BLUETOOTH_SCAN",
        "android.permission.POST_NOTIFICATIONS", "android.permission.RECEIVE_BOOT_COMPLETED"}, "unexpected pen package/permissions")
    manifest = tool_output([tools["aapt2"], "dump", "xmltree", apk, "--file", "AndroidManifest.xml"], env)
    require("sharedUserId" not in manifest and "RESTRICT_DISPLAY_MODES" not in manifest, "shared UID/restricted display permission forbidden")
    verify_file(apk, APK_SHA256, APK_BYTES)
    return {"package": "org.lineageos.pen", "sha256": APK_SHA256, "bytes": APK_BYTES,
            "certificate_sha256": CERT_SHA256, "signature_verified": True, "exact_der_match": True,
            "requested_permissions": sorted(requested), "shared_uid": None, "restrict_display_modes": False,
            "signature_schemes": [line for line in signature.splitlines() if line.startswith("Verified using")]}


def verify_user_schema(system, extension, work, tools, env):
    services = content(system, "/system/framework/services.jar")
    require(hashlib.sha256(services).hexdigest() == "ae809d471e48995b4fb09bad7329f9b50208b88277e1699f5d4c5bef368bef4c",
            "donor user-install implementation changed")
    schema = content(system, "/system/etc/sysconfig/preinstalled-packages-platform.xml")
    require(hashlib.sha256(schema).hexdigest() == "e19753b54d55e1274d1457642a514bab1e5e3041f344ffc4ee11f9213eeaa7bf",
            "donor user-type schema changed")
    example = content(extension, "/etc/sysconfig/preinstalled-packages-merged-system_ext.xml")
    require(hashlib.sha256(example).hexdigest() == "08119bbdc23900917577760d86f4722dbd1d9da9c17841fb007ab29f9999a94f",
            "donor system_ext user-type example changed")
    resources = content(system, "/system/framework/framework-res.apk")
    require(hashlib.sha256(resources).hexdigest() == "947a06de1244e753cdc1ab34ea0f36aca83d7ec2b882b5b73beb587ef263acbe",
            "donor user-type resource changed")
    temporary = work / "schema-framework-res.apk"
    temporary.write_bytes(resources)
    try:
        text = tool_output([tools["aapt2"], "dump", "resources", temporary], env)
    finally:
        temporary.unlink()
    require(re.search(r"resource 0x010e0182 integer/config_userTypePackageWhitelistMode\s+\(\) 13\b", text),
            "donor allowlist enforcement default changed")
    return {"reviewed_services_jar_sha256": hashlib.sha256(services).hexdigest(), "default_mode": 13,
            "resource_id": "0x010e0182", "schema_verified": True,
            "reviewed_logic": "SystemConfig.readInstallInUserType parses both tags; UserSystemPackageInstaller expands FULL/SYSTEM base-type masks, subtracts denied types, and bypasses implicit inclusion for explicitly listed packages.",
            "runtime_override_property": "persist.debug.user.package_whitelist_mode",
            "effective_user_installation_tested": False}


def snapshot(image):
    """Read every path's content and security metadata for protected-base comparison."""
    paths, directories = {"/"}, ["/"]
    while directories:
        directory = directories.pop()
        listing = subprocess.check_output(["dump.erofs", "--ls", "--path=" + directory, str(image)], text=True)
        for kind, name in re.findall(r"^\s*\d+\s+(\d+)  (.+)$", listing, re.M):
            if name in (".", ".."):
                continue
            require("/" not in name and name not in ("", ".", ".."), "invalid image directory entry")
            path = directory.rstrip("/") + "/" + name
            paths.add(path)
            if kind == "2":
                directories.append(path)
    result = {}
    for path in sorted(paths):
        meta = metadata(image, path)
        entry = {key: meta[key] for key in ("mode", "uid", "gid", "mtime", "mtime_nsec")}
        entry["xattrs"] = {key: value.hex() for key, value in sorted(meta["xattrs"].items())}
        if not stat.S_ISDIR(meta["mode"]):
            entry["sha256"] = hashlib.sha256(content(image, path)).hexdigest()
        result[path] = entry
    return result


def verify_preserved(before, after, changes, additions):
    require(set(after) == set(before) | set(additions), "unexpected image path added/removed")
    for path, old in before.items():
        expected = dict(old)
        if path in changes:
            expected["sha256"] = hashlib.sha256(changes[path]).hexdigest()
        require(after[path] == expected, "protected V9 content/metadata changed: " + path)
    return {"existing_paths_verified": len(before), "all_existing_metadata_preserved": True,
            "all_other_content_preserved": True,
            "signed_payload_sha256": {path: item["sha256"] for path, item in before.items() if path.endswith((".apk", ".apex"))}}


def build(work, base_zip, pen_apk, compiler):
    work, base_zip, pen_apk, compiler = map(Path, (work, base_zip, pen_apk, compiler))
    require(work == work.resolve() and work.parent == Path("/private/tmp/ai-development"), "use a resolved CleanOS task root")
    marker = work / ".cleanos-task.json"
    require(marker.is_file() and not marker.is_symlink(), "CleanOS task manifest missing")
    owner = json.loads(marker.read_text())
    require(owner["id"] == work.name and owner["owner"] == os.getuid() and owner["project"] == str(ROOT)
            and not owner["finished"], "inactive/foreign CleanOS task")
    output = work / "pen-v10"
    require(not output.exists() and not output.is_symlink(), "refusing to overwrite V10 output")
    require("[Excluded]" in subprocess.check_output(["tmutil", "isexcluded", str(work)], text=True), "scratch backup exclusion missing")
    base, base_validation = verify_base(base_zip)
    certificate = (Path(os.environ.get("GOOGLEBOOK_CERTIFICATE", "build-inputs/component-certificate.der"))).read_bytes()
    tools, env = android_tools()
    apk = verify_apk(pen_apk, certificate, tools, env)
    grant = ROOT / "components/oplus-pen/integration/default-permissions_org.lineageos.pen.xml"
    verify_file(grant, GRANT_SHA256, 490)
    inputs = json.loads((ROOT / "inputs.json").read_text())
    images = {part: CACHE / "donor-images" / (part + "_a.img") for part in ("system", "product")}
    for part, image in images.items():
        verify_file(image, inputs["donor"]["partitions"][part + "_a"])
    native = CACHE / "pad3-base-images/system_ext.img"
    verify_file(native, inputs["tablet"]["partitions"]["system_ext"])
    require(compiler.is_file() and not compiler.is_symlink() and os.access(compiler, os.X_OK), "existing compiler unavailable")
    output.mkdir()
    original = output / "v9-system_ext.img"
    with zipfile.ZipFile(base_zip) as archive, archive.open("system_ext.img") as source, original.open("xb") as target:
        shutil.copyfileobj(source, target, 8 * 1024 * 1024)
    verify_file(original, EXPECTED_IMAGES["system_ext"]["sha256"], EXPECTED_IMAGES["system_ext"]["bytes"])
    images["system_ext"] = original
    schema = verify_user_schema(images["system"], original, output, tools, env)
    policy = prepare_pen_policy(images, ext4_command(native, "cat /etc/selinux/system_ext_sepolicy.cil"),
                                certificate, compiler, output / "policy")
    changes = {}
    for path, entry in policy["files"].items():
        require(hashlib.sha256(content(original, path)).hexdigest() == entry["base_sha256"], "policy replacement base hash mismatch: " + path)
        changes[path] = Path(entry["path"]).read_bytes()
    meta = {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0, "mtime": 1230768000,
            "mtime_nsec": 0, "xattrs": {"security.selinux": b"u:object_r:system_file:s0"}}
    additions = {path: {"data": data, "metadata": meta} for path, data in
                 [(APK_PATH, pen_apk.read_bytes()), (GRANT_PATH, grant.read_bytes()), (USER_PATH, USER_XML)]}
    require(hashlib.sha256(additions[APK_PATH]["data"]).hexdigest() == APK_SHA256, "APK changed after validation")
    require(hashlib.sha256(additions[GRANT_PATH]["data"]).hexdigest() == GRANT_SHA256, "grant changed after validation")
    before = snapshot(original)
    changed_image = output / "system_ext.img"
    overlay = apply(original, changed_image, changes, output, additions=additions)
    preservation = verify_preserved(before, snapshot(changed_image), changes, additions)
    report = copy.deepcopy(base)
    report.update({"status": "UNBOOTED_PEN_V10", "boot_tested": False, "device_commands_run": False,
                   "hardware_partitions_included": [], "camera_orientation_changed": False,
                   "revision_scope": "V9 to V10: system_ext pen-only overlay; system/product compressed streams reused",
                   "manual_refresh_limit_hz": 120, "automatic_refresh_limit": False, "pen_function_tested": False,
                   "base_zip_sha256": base_validation["sha256"], "base_validation": base_validation, "pen_apk": apk, "pen_policy": policy,
                   "user_install_schema": schema, "protected_system_ext": preservation,
                   "policy": policy["candidate"]})
    report["images"]["system_ext"] = overlay
    for path in changes | additions:
        item = metadata(changed_image, path)
        report["metadata"]["system_ext:" + path] = {"sha256": hashlib.sha256(content(changed_image, path)).hexdigest(),
            "uid": item["uid"], "gid": item["gid"], "mode": oct(item["mode"] & 0o7777), "mtime": item["mtime"],
            "selinux": item["xattrs"]["security.selinux"].rstrip(b"\0").decode(), "metadata_verified_by_overlay": True}
    seed = output / ZIP_NAME
    os.link(base_zip, seed)
    bundle = package({"system_ext": changed_image}, report, output, reuse_existing_payloads=True, readme=README)
    final = output / OUTPUT_NAME
    Path(bundle["path"]).rename(final)
    (output / (ZIP_NAME + ".sha256")).unlink()
    bundle["path"] = str(final)
    (output / (OUTPUT_NAME + ".sha256")).write_text(bundle["sha256"] + "  " + OUTPUT_NAME + "\n")
    report["bundle"] = bundle
    require(sha256(base_zip) == base_validation["sha256"], "original V9 ZIP changed")
    (output / "pen-dsu-report.json").write_text(json.dumps(report, indent=2) + "\n")
    # The ZIP is the canonical deliverable; raw images and policy build intermediates are reproducible.
    original.unlink()
    changed_image.unlink()
    shutil.rmtree(output / "policy")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("work", "base-zip", "pen-apk", "compiler"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    result = build(args.work, args.base_zip, args.pen_apk, args.compiler)
    print(json.dumps({"status": result["status"], "bundle": result["bundle"]}, indent=2))
