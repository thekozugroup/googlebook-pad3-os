#!/usr/bin/env python3
"""Offline native OTA preparation. Never calls ADB, fastboot, a device or the network."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import gzip
import stat
import subprocess
import sys
import tempfile
import zipfile

from check_sukisu_layout import check as check_sukisu_layout
from native_install.avb import verify as verify_avb
from native_install.layout import check_layout, parse_text_layout, check_target_state
from native_install.public_image import check as check_public_image
from native_install.fstab import (filesystem_decision, patch_vendor_boot, unpack_vendor_boot,
                                  patch_recovery, recovery_filesystem_decision)
from native_install.payload import (SOURCE_COPY_ALLOWED, openssl, public_key, require, sha256, sign_digest,
                                    verify_digest, write_payload)

ROOT = Path(__file__).resolve().parent
BOOT_SHA = "15e43ca52b939d9780438d32d302f1575c3e99c2df4836d500fe2940cab64448"
INIT_BOOT_SHA = "bdc61ad17b24711bca838e51fbdc4fbbed5c7a2bc4ab1bffa043551645764f16"
MODULE_SHA = "6e9e1abff6ca15da92fe2cb8a51868b99049320aa65d613c826611eb377d4947"
MANAGER_SHA = "a928eb57ad34b105233f92dcd55e54dd883482e417970276329a7d0f0979e212"
MANAGER_CERT = "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef"
KERNEL = "6.6.144-4k-gacb4c5815254"
CLEAN_VENDOR_BOOT_SHA = "07cc553918749eea357d775251043321d44db9839b357f01af1b981beba284c2"
NATIVE_VENDOR_BOOT_SHA = "21266e40b3a292b0bcb489439a8a02e607e63fe9fc9d2a6cc967c192aa8e21e4"
CLEAN_RECOVERY_SHA = "27ac21553b3a532bbb7dc49058a2c3c3e97e866809b560bfafa259e0d4535bd8"
NATIVE_RECOVERY_SHA = "163100ce0eaa18c9f83fe0dd85a33a17ebe25799533714888b16d9824bde1ddc"
DEVICES = {"erhai", "OP6190L1", "OPD2415"}
LOGICAL = {"system", "system_ext", "product", "vendor", "odm", "vendor_dlkm", "system_dlkm"}
PHYSICAL = {"boot", "init_boot", "vendor_boot", "dtbo", "recovery", "vbmeta", "vbmeta_system", "vbmeta_vendor"}
PARTITIONS = LOGICAL | PHYSICAL
HARDWARE = PARTITIONS - {"system", "system_ext", "product"}
CERT_PATH = "system/etc/security/otacerts.zip"
KEY_PATH = "system/etc/update_engine/update-payload-key.pub.pem"
CONFIG_PATH = "system/etc/googlebook/native-ota.json"
MANAGER_PATH = "system_ext/etc/googlebook/SukiSU.apk"
BOOTSTRAP_PATH = "system_ext/etc/googlebook/install-sukisu-manager.sh"
MANAGER_CHECKER_PATH = "system_ext/etc/googlebook/SukiSUManagerCheck.jar"
MANAGER_CHECKER_SHA = "e46d45f8eeeb444c33a58573475049e7dfbe6b0340945399de1e5114b8f7816e"
RELEASE_PART_BYTES = 1024**3
PUBLIC_REPO = "thekozugroup/googlebook-pad3-os"
FEED_URL = "https://raw.githubusercontent.com/thekozugroup/googlebook-pad3-os/refs/heads/main/updates/erhai/stable.json"
FEED_KEY_SHA = "db616de57f6658b13c1828d92c0e956346a9e5a785fa696e6fda7e992262dec8"


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def regular(path):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), "expected absolute regular file")
    return path


def checked(entry):
    require(set(entry) == {"path", "sha256"}, "file record requires path and sha256")
    require(re.fullmatch("[0-9a-f]{64}", entry["sha256"]), "invalid SHA-256 pin")
    path = regular(entry["path"])
    require(sha256(path) == entry["sha256"], "input SHA-256 mismatch: " + path.name)
    return path


def scratch_output(path):
    path = Path(path)
    require(path.is_absolute() and not path.exists() and not path.is_symlink(), "output must be a new absolute path")
    resolved = path.resolve()
    require(resolved.is_relative_to(Path("/private/tmp/ai-development")), "output must be in CleanOS scratch")
    owners = [p for p in resolved.parents if (p / ".cleanos-task.json").is_file()]
    require(len(owners) == 1, "output needs one existing CleanOS task owner")
    owner = json.loads((owners[0] / ".cleanos-task.json").read_text())
    require(owner.get("owner") == os.getuid() and not owner.get("finished")
            and Path(owner.get("project", "")).resolve() == ROOT, "wrong or finished CleanOS task")
    return resolved


def repo_name(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", value),
            "repo must be explicit public GitHub owner/name without URL credentials")
    require(value.split("/")[1] not in (".", "..") and "PUBLIC_REPO" not in value,
            "replace the repository placeholder")
    require(value == PUBLIC_REPO, "repository differs from the pinned parent updater repository")
    return value


def certificate_der(certificate):
    return openssl("x509", "-in", regular(certificate), "-outform", "DER")


def ota_config(repo, certificate):
    repo = repo_name(repo)
    key_text = openssl("pkey", "-pubin", "-text", "-noout", data=public_key(certificate))
    require(b"Modulus:" in key_text and re.search(rb"Public-Key: \((?:2048|4096) bit\)", key_text),
            "AOSP payload certificate requires RSA-2048 or RSA-4096; RSA-3072 feed trust is separate")
    return {"schema": 1, "device": "erhai", "allowed_devices": sorted(DEVICES),
            "repository": repo,
            "feed_url": FEED_URL, "manifest_public_key_der_sha256": FEED_KEY_SHA,
            "certificate_sha256": hashlib.sha256(certificate_der(certificate)).hexdigest(),
            "public_key_sha256": hashlib.sha256(public_key(certificate)).hexdigest(),
            "payload_type": "AB", "reject_donor_otas": True,
            "requires_factory_reset_for_initial_install": True}


def verify_manager(apk, apksigner, aapt2):
    require(sha256(regular(apk)) == MANAGER_SHA, "not the pinned official SukiSU 4.3.0 normal manager")
    result = subprocess.run([str(regular(apksigner)), "verify", "--verbose", "--print-certs", str(apk)],
                            capture_output=True, text=True)
    require(result.returncode == 0 and "Verified using v2 scheme (APK Signature Scheme v2): true" in result.stdout
            and "Signer #1 certificate SHA-256 digest: " + MANAGER_CERT in result.stdout,
            "SukiSU manager v2 signature/certificate mismatch")
    result = subprocess.run([str(regular(aapt2)), "dump", "badging", str(apk)], capture_output=True, text=True)
    require(result.returncode == 0 and
            "package: name='com.sukisu.ultra' versionCode='41100' versionName='v4.3.0'" in result.stdout,
            "SukiSU manager package/version mismatch")


def manager_bootstrap():
    # Kept separate from init/SELinux integration, which the parent must review.
    return (ROOT / "native_install/install-sukisu-manager.sh").read_bytes()


def trust_overlay(repo, certificate, apk, apksigner, aapt2, output):
    output = scratch_output(output)
    verify_manager(apk, apksigner, aapt2)
    require(sha256(Path(os.environ.get("GOOGLEBOOK_MANAGER_CHECKER", "build-inputs/SukiSUManagerCheck.jar"))) == MANAGER_CHECKER_SHA,
            "fixed manager checker artifact drift")
    config = ota_config(repo, certificate)
    output.mkdir()
    try:
        for relative, content in {
            KEY_PATH: public_key(certificate), CONFIG_PATH: json_bytes(config),
            BOOTSTRAP_PATH: manager_bootstrap(),
            MANAGER_CHECKER_PATH: (Path(os.environ.get("GOOGLEBOOK_MANAGER_CHECKER", "build-inputs/SukiSUManagerCheck.jar"))).read_bytes(),
        }.items():
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o755 if relative == BOOTSTRAP_PATH else 0o644)
        target = output / CERT_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("googlebook-native.x509.pem", Path(certificate).read_bytes())
        target = output / MANAGER_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(apk, target)
        target.chmod(0o644)
        (output / "integration.json").write_bytes(json_bytes({
            "status": "PUBLIC_TRUST_OVERLAY_ONLY_NOT_ROM_OR_FLASHABLE",
            "files": {p: sha256(output / p) for p in [CERT_PATH, KEY_PATH, CONFIG_PATH, MANAGER_PATH, BOOTSTRAP_PATH, MANAGER_CHECKER_PATH]},
            "metadata_required": "uid=0 gid=0; directories 0755; APK/config/key/cert 0644; bootstrap 0755; explicit Android SELinux labels",
            "manager_recognition": "41100 normal seed outside APK scanning; shell UID/domain one-shot installs /data/app, current-certificate/version guard, no downgrade; UAPI 6 init_boot required; parent runtime verification required",
        }))
    except BaseException:
        shutil.rmtree(output)
        raise
    return config


def image_kind(path):
    with path.open("rb") as stream:
        require(stream.read(4) != bytes.fromhex("3aff26ed"), "Android sparse images are not accepted")
        stream.seek(1024)
        if stream.read(4) == bytes.fromhex("e2e1f5e0"):
            return "erofs"
        stream.seek(1080)
        if stream.read(2) == b"\x53\xef":
            return "ext4"
    raise ValueError("unknown native userspace filesystem")


def image_file(image, filesystem, path):
    require(re.fullmatch(r"/[A-Za-z0-9_./+@-]+", path) and ".." not in path.split("/"), "unsafe image path")
    if filesystem == "erofs":
        from erofs_overlay import content
        return content(image, path)
    from ext4_source import command
    return command(image, "cat " + path)


def check_native_properties(blob, sequence):
    expected = {"ro.googlebook.pad3.native": "1", "ro.googlebook.pad3.device": "erhai",
                "ro.googlebook.pad3.base_profile": "erhai-crdroid-20261025",
                "ro.googlebook.pad3.release_sequence": str(sequence), "ro.build.ab_update": "true",
                "ro.virtual_ab.enabled": "true"}
    lines = blob.decode().splitlines()
    for key, value in expected.items():
        values = [line.partition("=")[2].strip() for line in lines if line.partition("=")[0].strip() == key]
        require(values == [value], "native updater property missing/wrong: " + key)


def check_device_property(blob, key):
    values = [line.partition("=")[2].strip() for line in blob.decode().splitlines()
              if line.partition("=")[0].strip() == key]
    require(len(values) == 1 and values[0] in DEVICES, "native device property missing/wrong: " + key)


def release_assets(archive, repository, tag):
    """Keep every GitHub asset below 2 GiB without retaining a duplicate full ZIP."""
    prefix = f"https://github.com/{repository}/releases/download/{tag}/"
    if archive.stat().st_size <= RELEASE_PART_BYTES:
        return [{"name": archive.name, "url": prefix + archive.name,
                 "bytes": archive.stat().st_size, "sha256": sha256(archive)}]
    assets = []
    with archive.open("rb") as source:
        while source.tell() < archive.stat().st_size:
            target = archive.with_name(archive.name + f".part{len(assets) + 1:03d}")
            digest, size = hashlib.sha256(), 0
            with target.open("xb") as destination:
                while size < RELEASE_PART_BYTES:
                    data = source.read(min(4 * 1024**2, RELEASE_PART_BYTES - size))
                    if not data:
                        break
                    destination.write(data)
                    digest.update(data)
                    size += len(data)
            assets.append({"name": target.name, "url": prefix + target.name,
                           "bytes": size, "sha256": digest.hexdigest()})
    archive.unlink()
    return assets


def compare_metadata(source, converted):
    """Compare complete externally enumerated inode inventories, not extracted host trees."""
    required = {"mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs", "content_sha256", "symlink", "hardlink", "rdev"}
    require(isinstance(source, dict) and "/" in source and source.keys() == converted.keys(),
            "metadata inventory must include root and exactly the same paths")
    for path, original in source.items():
        require(path.startswith("/") and ".." not in path.split("/") and set(original) == required,
                "incomplete inode inventory: " + path)
        require(original == converted[path], "EXT4 metadata/content changed: " + path)
    return hashlib.sha256(json_bytes(source)).hexdigest()


def check_production_boot_chain(hardware, images):
    for name, clean, production in (("vendor_boot", CLEAN_VENDOR_BOOT_SHA, NATIVE_VENDOR_BOOT_SHA),
                                    ("recovery", CLEAN_RECOVERY_SHA, NATIVE_RECOVERY_SHA)):
        require(sha256(hardware[name]) in (clean, production), "unapproved clean boot-chain reference: " + name)
        require(sha256(images[name]) == production, "approved production boot-chain image required: " + name)


def check_root_images(hardware, images, copies):
    """Accept only the reviewed UAPI 6 image; a plan cannot supply its own approval pin."""
    require(type(copies) is list and copies in
            [sorted(SOURCE_COPY_ALLOWED - omitted) for omitted in
             (set(), {"init_boot"}, {"product"}, {"init_boot", "product"})],
            "only init_boot REPLACE and the reviewed Product delta may omit SOURCE_COPY partitions")
    require(sha256(hardware["boot"]) == BOOT_SHA and sha256(hardware["init_boot"]) == INIT_BOOT_SHA,
            "current native B boot/root image pins mismatch")
    require(sha256(images["boot"]) == BOOT_SHA, "boot/kernel must remain unchanged")
    root = json.loads((ROOT / "native_install/source-pins.json").read_text())["sukisu_root"]
    target = root["init_boot_sha256"]
    require(isinstance(target, str) and re.fullmatch("[0-9a-f]{64}", target)
            and target != INIT_BOOT_SHA, "parent-reviewed UAPI 6 init_boot pin is pending")
    require(root["uapi"] == 6 and root["version_code"] == 41100 and root["boot_sha256"] == BOOT_SHA
            and root["kernel"] == KERNEL, "UAPI 6 root profile differs from the reviewed stack")
    require(images["init_boot"].stat().st_size == hardware["init_boot"].stat().st_size == 8388608
            and sha256(images["init_boot"]) == target, "init_boot must match the exact reviewed UAPI 6 image")
    return {"uapi": 6, "version_code": 41100, "init_boot_sha256": target,
            "boot_sha256": BOOT_SHA, "kernel": KERNEL,
            "operation": "SOURCE_COPY" if "init_boot" in copies else "REPLACE"}


def validate_plan(plan, certificate, tools):
    require(plan.get("schema") == 1, "unknown native plan schema")
    require(plan["system_as_root"] is True, "pinned GoogleBook system-as-root layout required")
    capture = plan["capture"]
    require(capture["device"] in DEVICES and capture["slot"] == "b"
            and capture["page_size"] == 4096 and capture["kernel"] == KERNEL
            and capture["build_utc"] == 1792932356, "not the pinned native October 25 slot B base")
    require(type(capture["virtual_ab"]) is bool, "virtual_ab must be observed boolean")
    require(plan["source_slot"] in ("a", "b") and plan["target_slot"] in ("a", "b")
            and plan["source_slot"] != plan["target_slot"], "source/target must be opposite A/B slots")
    require(set(plan["images"]) == PARTITIONS and set(capture["hardware"]) == HARDWARE,
            "native payload must contain only the complete allowed matched-base image set")
    copies = plan["source_copy_partitions"]
    images = {name: checked(plan["images"][name]) for name in sorted(PARTITIONS)}
    hardware = {name: checked(capture["hardware"][name]) for name in sorted(HARDWARE)}
    root_image = check_root_images(hardware, images, copies)
    from native_install import product_cleanup
    require(sha256(images["product"]) == product_cleanup.TARGET_SHA,
            "Product must contain the reviewed physical Dell APK removal")
    if "product" not in copies:
        product_cleanup.validate(checked(tools["product_source"]), images["product"])
    for name in HARDWARE - {"init_boot", "vendor_boot", "recovery", "vbmeta", "vbmeta_system", "vbmeta_vendor"}:
        require(sha256(images[name]) == sha256(hardware[name]), "mismatched hardware base: " + name)
    for name, image in images.items():
        size = image.stat().st_size
        require(size > 0 and size % 4096 == 0 and size <= plan["partition_sizes"][name],
                "image exceeds captured target capacity or is unaligned: " + name)
    filesystems = {image_kind(images[name]) for name in ("system", "system_ext", "product")}
    require(len(filesystems) == 1, "mixed native userspace filesystems need separate review")
    filesystem = filesystems.pop()
    check_production_boot_chain(hardware, images)
    fstab = filesystem_decision(hardware["vendor_boot"].read_bytes(), images["vendor_boot"].read_bytes(), filesystem)
    recovery = recovery_filesystem_decision(hardware["recovery"].read_bytes(), images["recovery"].read_bytes(), filesystem)
    # Raw metadata captures are mandatory and bound into the parent review.
    for name in ("lpdump_text_0", "lpdump_text_1", "kernel_config"):
        checked(capture[name])
    text_0, text_1 = checked(capture["lpdump_text_0"]).read_text(), checked(capture["lpdump_text_1"]).read_text()
    require(text_0.startswith("Slot 0:") and "Block device table:" in text_0 and "Group table:" in text_0,
            "full inactive metadata slot 0 text required")
    allocation = parse_text_layout(text_1)
    check_layout(allocation, plan["dynamic_groups"], plan["super_bytes"], text_1)
    require(allocation["metadata_reserved_bytes"] == plan["metadata_reserved_bytes"], "LP metadata reservation differs from capture")
    require(capture["virtual_ab"] is allocation["virtual_ab"], "Virtual A/B flag differs from LP header")
    for partition in allocation["partitions"]:
        if partition["name"] in hardware:
            require(hardware[partition["name"]].stat().st_size == partition["size"], "captured logical size differs from extents")
    kernel_config = checked(capture["kernel_config"]).read_bytes()
    if kernel_config.startswith(b"\x1f\x8b"):
        kernel_config = gzip.decompress(kernel_config)
    if filesystem == "erofs":
        require(all(line in kernel_config.splitlines() for line in
                    (b"CONFIG_EROFS_FS=y", b"CONFIG_EROFS_FS_SECURITY=y", b"CONFIG_EROFS_FS_ZIP=y")),
                "captured kernel lacks required EROFS/LZ4/security support")
    groups, seen = plan["dynamic_groups"], set()
    for group in groups:
        require(re.fullmatch(r"[A-Za-z0-9_]+", group["name"]) and not group["name"].endswith(("_a", "_b")),
                "payload dynamic group names must be unsuffixed")
        members = set(group["partitions"])
        require(members and not seen & members and members <= LOGICAL
                and len(members) == len(group["partitions"]), "invalid dynamic group membership")
        seen |= members
        require(sum(images[n].stat().st_size for n in members) <= group["maximum_size"], "dynamic group overflow")
    require(seen == LOGICAL and len({g["name"] for g in groups}) == len(groups), "incomplete dynamic layout")
    require(sum(g["maximum_size"] for g in groups) * (1 if capture["virtual_ab"] else 2)
            + plan["metadata_reserved_bytes"] <= plan["super_bytes"], "super capacity cannot preserve required slot layout")
    if filesystem == "ext4":
        for name in ("system", "system_ext", "product"):
            record = plan["ext4_metadata"][name]
            require(sha256(checked(record["source_image"])) == record["source_image_sha256"]
                    and record["output_image_sha256"] == sha256(images[name]),
                    "EXT4 inventory not bound to candidate image")
            source, target = checked(record["source_inventory"]), checked(record["output_inventory"])
            compare_metadata(json.loads(source.read_text()), json.loads(target.read_text()))
        raise ValueError("EXT4 conversion producer is not validated; exact inode/xattr inventories alone do not prove complete enumeration")
    config = ota_config(plan["repository"], certificate)
    system = images["system"]
    # system-as-root stores files under /system in the EROFS root.
    prefix = "/system" if plan["system_as_root"] is True else ""
    for name in ("system", "system_ext", "product"):
        result = subprocess.run(["fsck.erofs", "--extract", str(images[name])], capture_output=True)
        require(result.returncode == 0, "native EROFS integrity/decompression check failed: " + name)
    sanitization = check_public_image(images, lambda image, path: image_file(image, filesystem, path), prefix)
    check_device_property(image_file(system, filesystem, prefix + "/build.prop"), "ro.product.system.device")
    check_native_properties(image_file(system, filesystem, prefix + "/build.prop"), plan["sequence"])
    check_device_property(image_file(images["product"], filesystem, "/etc/build.prop"), "ro.product.product.device")
    engine, engine_rc = checked(capture["update_engine"]), checked(capture["update_engine_rc"])
    require(hashlib.sha256(image_file(system, filesystem, prefix + "/bin/update_engine")).hexdigest() == sha256(engine),
            "candidate must contain the captured Android native update_engine, not the laptop updater")
    require(image_file(system, filesystem, prefix + "/etc/init/update_engine.rc") == engine_rc.read_bytes(),
            "candidate Android update_engine init service differs from reviewed native source")
    from native_install.engine_libraries import integration_inputs
    engine_files, bundled_rc = integration_inputs(capture["update_engine_bundle"])
    require(engine_rc.read_bytes() == bundled_rc, "native engine RC differs from private bundle")
    for path, item in engine_files.items():
        if stat.S_ISREG(item["metadata"]["mode"]):
            require(path.startswith("/system_ext/"), "private engine library escaped system_ext")
            require(image_file(images["system_ext"], filesystem, path.removeprefix("/system_ext")) == item["data"],
                    "candidate private update_engine library differs: " + path)
    require(image_file(system, filesystem, prefix + "/etc/googlebook/native-ota.json") == json_bytes(config),
            "own-repository native OTA config missing from system image")
    require(image_file(system, filesystem, prefix + "/etc/update_engine/update-payload-key.pub.pem") == public_key(certificate),
            "payload public key not integrated in system image")
    with tempfile.TemporaryDirectory(prefix="native-validate-", dir=tools["scratch"]) as directory:
        directory = Path(directory)
        cert_zip = directory / "otacerts.zip"
        cert_zip.write_bytes(image_file(system, filesystem, prefix + "/etc/security/otacerts.zip"))
        with zipfile.ZipFile(cert_zip) as archive:
            require(archive.namelist() == ["googlebook-native.x509.pem"], "unexpected OTA trust certificates")
            require(archive.read(archive.namelist()[0]) == Path(certificate).read_bytes(), "OTA certificate mismatch")
        apk = directory / "manager.apk"
        apk.write_bytes(image_file(images["system_ext"], filesystem, "/etc/googlebook/SukiSU.apk"))
        verify_manager(apk, tools["apksigner"], tools["aapt2"])
        require(image_file(images["system_ext"], filesystem, "/etc/googlebook/install-sukisu-manager.sh") == manager_bootstrap(),
                "reviewed manager bootstrap missing")
        require(hashlib.sha256(image_file(images["system_ext"], filesystem, "/etc/googlebook/SukiSUManagerCheck.jar")).hexdigest() == MANAGER_CHECKER_SHA,
                "reviewed current-certificate/version manager checker missing")
        staged = {}
        for name, image in images.items():
            (directory / (name + ".img")).symlink_to(image)
            staged[name] = directory / (name + ".img")
        avb = checked(tools["avbtool"])
        keys = {name: checked(entry) for name, entry in tools["avb_public_keys"].items()}
        avb_evidence = verify_avb(staged, hardware, avb, keys, plan["avb_mode"])
    module = checked(tools["sukisu_module"])
    require(sha256(module) == MODULE_SHA, "wrong SukiSU UAPI 6 repaired module")
    baseline_path = ROOT / "native_install/sukisu-layout-baseline.json"
    require(sha256(baseline_path) == json.loads((ROOT / "native_install/source-pins.json").read_text())["filtered_layout_baseline_sha256"],
            "reviewed SukiSU layout baseline drift")
    baseline = json.loads(baseline_path.read_text())
    layout = check_sukisu_layout(hardware["boot"], BOOT_SHA, KERNEL, module, baseline)
    require(layout["module_sha256"] == MODULE_SHA, "wrong SukiSU repaired module")
    return images, {"fstab": fstab, "recovery": recovery, "avb": avb_evidence, "public_image": sanitization,
                    "root_layout": layout, "root_image": root_image, "config": config,
                    "snapshot_rollback": "No rollback guarantee after virtual A/B merge" if capture["virtual_ab"] else "Native B retained; shared data still requires separate backup"}


def build(plan_path, review_path, key, certificate, tools, output, feed_key, feed_public_der):
    output = scratch_output(output)
    task_scratch = Path(tools["scratch"]).resolve()
    # Validate scratch ownership before tempfile can create anything.
    scratch_output(task_scratch / "native-scratch-ownership-check")
    require(task_scratch.is_dir(), "tools scratch directory is missing")
    plan_path, key = regular(plan_path), regular(key)
    review_path = regular(review_path) if review_path is not None else None
    feed_key, feed_public_der = regular(feed_key), regular(feed_public_der)
    require(stat.S_IMODE(key.stat().st_mode) & 0o077 == 0, "private key must not be group/world accessible")
    require(stat.S_IMODE(feed_key.stat().st_mode) & 0o077 == 0, "feed private key must not be group/world accessible")
    require(sha256(feed_public_der) == FEED_KEY_SHA, "feed SPKI key differs from the parent updater pin")
    require(openssl("pkey", "-in", feed_key, "-pubout", "-outform", "DER") == feed_public_der.read_bytes(),
            "feed private signer differs from pinned public SPKI")
    plan = json.loads(plan_path.read_text())
    review = json.loads(review_path.read_text()) if review_path is not None else {}
    if review_path is not None:
        require(review["plan_sha256"] == sha256(plan_path), "parent review does not match exact plan")
    # Offline artifacts must exist before installer/reset approval. This CLI never executes them.
    require(type(plan["timestamp"]) is int and plan["timestamp"] >= plan["capture"]["build_utc"]
            and type(plan["sequence"]) is int and plan["sequence"] > 0
            and type(plan["expires_utc"]) is int and plan["expires_utc"] > plan["timestamp"], "invalid release sequence/timestamps")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", plan["release_tag"]), "unsafe release tag")
    require(isinstance(plan["version"], str) and 0 < len(plan["version"]) <= 128, "release label required")
    require(isinstance(plan["pre_build_fingerprints"], list) and 0 < len(plan["pre_build_fingerprints"]) <= 16
            and all(isinstance(f, str) and 0 < len(f) <= 1024 and "REPLACE" not in f for f in plan["pre_build_fingerprints"]),
            "explicit allowed installed port fingerprints required")
    images, evidence = validate_plan(plan, certificate, tools)
    # Full payload + stored ZIP + transient release parts; do not approach the disk floor.
    required_space = 3 * sum(image.stat().st_size for image in images.values()) + 30 * 1024**3
    require(shutil.disk_usage(task_scratch).free >= required_space, "insufficient scratch space for full native payload/ZIP")
    output.mkdir()
    try:
        with tempfile.TemporaryDirectory(prefix="native-payload-", dir=tools["scratch"]) as temporary:
            temporary = Path(temporary)
            payload = temporary / "payload.bin"
            properties, hashes = write_payload(images, plan["dynamic_groups"], plan["timestamp"],
                                                plan["capture"]["virtual_ab"], key, certificate, payload, temporary,
                                                source_copy_partitions=set(plan["source_copy_partitions"]),
                                                source_images={} if not plan["source_copy_partitions"] or "product" in plan["source_copy_partitions"] else
                                                {"product": checked(tools["product_source"])})
            require(hashes == {n: e["sha256"] for n, e in plan["images"].items()}, "validated inputs changed before payload generation")
            properties_bytes = "".join(f"{name}={value}\n" for name, value in properties.items()).encode()
            filename = "GoogleBook-erhai-native.zip"
            with zipfile.ZipFile(output / filename, "x", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                archive.write(payload, "payload.bin")
                archive.writestr("payload_properties.txt", properties_bytes)
                archive.writestr("META-INF/com/android/metadata", "ota-type=AB\npre-device=erhai\n"
                                 + f"post-timestamp={plan['timestamp']}\n")
            with zipfile.ZipFile(output / filename) as archive:
                info = archive.getinfo("payload.bin")
                with (output / filename).open("rb") as stream:
                    stream.seek(info.header_offset + 26)
                    import struct
                    name_len, extra_len = struct.unpack("<HH", stream.read(4))
                payload_offset = info.header_offset + 30 + name_len + extra_len
            zip_sha, zip_bytes = sha256(output / filename), (output / filename).stat().st_size
            require(zip_bytes <= 16 * 1024**3, "parent updater supports at most a 16 GiB joined ZIP")
            assets = release_assets(output / filename, plan["repository"], plan["release_tag"])
            descriptor = {"schema": 1, "device": "erhai", "channel": "stable", "version": plan["version"],
                          "sequence": plan["sequence"], "published_at": plan["timestamp"], "expires_at": plan["expires_utc"],
                          "base_profile": "erhai-crdroid-20261025", "pre_build_fingerprints": plan["pre_build_fingerprints"],
                          "source_slot": "_" + plan["source_slot"],
                          "ota": {"size": zip_bytes, "sha256": zip_sha,
                                  "parts": [{"url": a["url"], "size": a["bytes"], "sha256": a["sha256"]} for a in assets]},
                          "payload": {"offset": payload_offset, "size": int(properties["FILE_SIZE"]),
                                      "sha256": base64.b64decode(properties["FILE_HASH"]).hex(),
                                      "metadata_size": int(properties["METADATA_SIZE"]),
                                      "metadata_sha256": base64.b64decode(properties["METADATA_HASH"]).hex(),
                                      "properties": [f"{name}={value}" for name, value in properties.items()]}}
            # Parent ManifestCodec requires an array; sign exact complete feed bytes.
            descriptor_bytes = json_bytes([descriptor])
            signature = sign_digest(hashlib.sha256(descriptor_bytes).digest(), feed_key)
            feed_public_pem = openssl("pkey", "-pubin", "-inform", "DER", "-in", feed_public_der, "-pubout")
            verify_digest(hashlib.sha256(descriptor_bytes).digest(), signature, feed_public_pem, temporary)
            (output / "stable.json").write_bytes(descriptor_bytes)
            (output / "stable.json.sig").write_bytes(signature)
            (output / "feed-verification-key.der").write_bytes(feed_public_der.read_bytes())
            (output / "native-public-key.pem").write_bytes(public_key(certificate))
            followup = bool(plan["source_copy_partitions"])
            gates = ["Fresh authoritative native/GSI and snapshot state", "Reviewed inactive target capacity/firmware checks",
                     "Snapshot allocation and merge validation"]
            if not followup:
                gates += ["Prepared initial installer with merge-before-wipe or clean-allocation proof",
                          "Owner reset/data-preservation approval after candidate review"]
            (output / "validation.json").write_bytes(json_bytes({"status": "OFFLINE_NATIVE_OTA_CANDIDATE_UNAPPLIED" if followup else "OFFLINE_NATIVE_CANDIDATE_UNBOOTED",
                "parent_plan_sha256": sha256(plan_path), "parent_review_sha256": sha256(review_path) if review_path else None,
                "evidence": evidence, "device_operations": 0, "wipes": 0, "requires_factory_reset": not followup,
                "userdata_preserved": followup,
                "execution_approved": False,
                "pending_execution_gates": gates,
                "images_sha256": hashes, "avb_mode": plan["avb_mode"], "transport": "UpdateEngine, not recovery whole-ZIP signed",
                "limitations": ["No runtime boot, recovery, manager recognition or update_engine apply was tested.",
                                "No userdata migration or rollback after reset/merge is promised."]}))
    except BaseException:
        shutil.rmtree(output)
        raise
    return descriptor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect-vendor-boot")
    inspect.add_argument("--image", type=Path, required=True)
    patch = commands.add_parser("patch-vendor-boot")
    patch.add_argument("--image", type=Path, required=True)
    patch.add_argument("--output", type=Path, required=True)
    recovery = commands.add_parser("patch-recovery")
    recovery.add_argument("--image", type=Path, required=True)
    recovery.add_argument("--output", type=Path, required=True)
    trust = commands.add_parser("trust-overlay")
    trust.add_argument("--repository", required=True)
    trust.add_argument("--manager-apk", type=Path, required=True)
    for command in (trust, commands.add_parser("build")):
        command.add_argument("--certificate", type=Path, required=True)
        command.add_argument("--apksigner", type=Path, required=True)
        command.add_argument("--aapt2", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    native = commands.choices["build"]
    for name in ("plan", "key", "tools", "feed-key", "feed-public-key"):
        native.add_argument("--" + name, type=Path, required=True)
    native.add_argument("--review", type=Path)
    args = parser.parse_args()
    if args.command == "inspect-vendor-boot":
        parsed = unpack_vendor_boot(regular(args.image).read_bytes())
        print(json.dumps({"fstab": parsed["fstab"], "compression": parsed["compression"],
                          "image_sha256": sha256(args.image)}, indent=2))
    elif args.command in ("patch-vendor-boot", "patch-recovery"):
        output = scratch_output(args.output)
        patcher = patch_recovery if args.command == "patch-recovery" else patch_vendor_boot
        data = patcher(regular(args.image).read_bytes())
        with output.open("xb") as stream:
            stream.write(data)
        print("UNSIGNED_FSTAB_PATCH_ONLY_REQUIRES_AVB_RECOVERY_AND_PARENT_REVIEW")
    elif args.command == "trust-overlay":
        trust_overlay(args.repository, args.certificate, args.manager_apk, args.apksigner, args.aapt2, args.output)
        print("PUBLIC_TRUST_OVERLAY_ONLY_NOT_ROM_OR_FLASHABLE")
    else:
        tools = json.loads(regular(args.tools).read_text())
        tools.update(apksigner=args.apksigner, aapt2=args.aapt2)
        build(args.plan, args.review, args.key, args.certificate, tools, args.output, args.feed_key, args.feed_public_key)
        print("OFFLINE_NATIVE_CANDIDATE_UNBOOTED")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print("Native preparation stopped: " + str(error), file=sys.stderr)
        sys.exit(2)
