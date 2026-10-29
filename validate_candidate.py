#!/usr/bin/env python3
"""Validate actual output filesystems, metadata, policy, and disabled writers."""
import argparse
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from android_disk import require
from check_policy import check
from erofs_overlay import content
from port_changes import DISABLED_EXTENSION_INIT, DISABLED_SYSTEM_INIT


def extract_tree(image, path, destination):
    require(not destination.exists(), "validation extraction already exists: " + str(destination))
    subprocess.run(["fsck.erofs", "--extract=" + str(destination), "--path=" + path,
                    "--no-preserve-owner", str(image)], check=True)


def signatures(text):
    result = set()
    for chunk in text.split("neverallow check failed")[1:]:
        rules = [line.strip() for line in chunk.splitlines() if line.strip().startswith(("(neverallow ", "(allow "))]
        result.add("\n".join(rules))
    return result


def validate(work):
    images = work / "candidate"
    checks = work / "validation"
    require(not checks.exists(), "validation directory already exists")
    checks.mkdir()
    extracted = {}
    for part, path in [("system", "/system/etc"), ("system_ext", "/etc"), ("product", "/etc")]:
        target = checks / part
        extract_tree(images / (part + ".img"), path, target)
        extracted[part] = target
    for part in ("vendor", "odm"):
        target = checks / part
        extract_tree(work / "pad3-base-images" / (part + ".img"), "/etc/selinux", target)
        extracted[part] = target
    # Compare original and grafted extension policies against the same hardware base.
    original = checks / "original-extension"
    extract_tree(work / "donor-images/system_ext_a.img", "/etc/selinux", original)
    compiler = work / "secilc-tools/bin/secilc"
    baseline = check(compiler, extracted["system"] / "selinux", original,
                     extracted["product"] / "selinux", extracted["vendor"], extracted["odm"], checks / "baseline-policy")
    candidate = check(compiler, extracted["system"] / "selinux", extracted["system_ext"] / "selinux",
                      extracted["product"] / "selinux", extracted["vendor"], extracted["odm"], checks / "candidate-policy")
    previous = signatures((checks / "baseline-policy/strict.log").read_text())
    current = signatures((checks / "candidate-policy/strict.log").read_text())
    introduced = current - previous
    require(not introduced, "graft introduces a new neverallow violation; review validation/candidate-policy/strict.log")
    for part, paths in [("system", DISABLED_SYSTEM_INIT), ("system_ext", DISABLED_EXTENSION_INIT)]:
        for path in paths:
            data = content(images / (part + ".img"), path)
            require(not re.search(rb"^\s*(service|on|exec|start|enable)\s", data, re.MULTILINE),
                    "laptop writer/security service still enabled: " + path)
    require(b"trusty.security_vm.enabled=0" in content(images / "system.img", "/system/build.prop"),
            "desktop security VM remains enabled")
    root = ET.fromstring(content(images / "system_ext.img", "/etc/vintf/manifest.xml"))
    require(all("security" not in h.findtext("name", "") and "trusty" not in h.findtext("name", "")
                for h in root.findall("hal")), "unserved desktop security HAL remains declared")
    for part, path in [("system", "/system/etc/vintf/manifest/manifest_gscd.xml"),
                       ("system_ext", "/etc/vintf/manifest/com.google.android.desktop.super-partition-utils.xml")]:
        require(not ET.fromstring(content(images / (part + ".img"), path)).findall("hal"), "writer HAL remains declared")
    report = {"status": "UNBOOTED_EXPERIMENTAL", "runtime_policy": candidate,
              "baseline_strict_neverallow_failures": baseline["strict_neverallow_failures"],
              "introduced_strict_violations": len(introduced), "laptop_writer_init_disabled": True,
              "desktop_security_vm_disabled": True, "hardware_partitions_replaced": False,
              "boot_tested": False, "stylus_tested": False, "refresh_rate_tested": False}
    (images / "validation-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "runtime_policy"}, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    validate(parser.parse_args().work.resolve())
