#!/usr/bin/env python3
"""Compile donor platform plus unchanged tablet vendor/ODM policy offline."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from android_disk import require


def check(compiler, system, extension, product, vendor, odm, output):
    version = (vendor / "plat_sepolicy_vers.txt").read_text().strip()
    require(version == "202604", "unreviewed tablet SELinux API")
    genfs = (vendor / "genfs_labels_version.txt").read_text().strip()
    require(genfs == "202604", "unreviewed tablet genfs label version")
    files = [system / "plat_sepolicy.cil", system / "mapping" / (version + ".cil")]
    compat = system / "mapping" / (version + ".compat.cil")
    if compat.exists():
        files.append(compat)
    files.append(system / ("plat_sepolicy_genfs_" + genfs + ".cil"))
    files.extend([extension / "system_ext_sepolicy.cil", extension / "mapping" / (version + ".cil"),
                  product / "product_sepolicy.cil", product / "mapping" / (version + ".cil"),
                  vendor / "plat_pub_versioned.cil", vendor / "vendor_sepolicy.cil", odm / "odm_sepolicy.cil"])
    require(all(p.is_file() for p in files), "a policy input is missing")
    output.mkdir(parents=True, exist_ok=True)
    base = [str(compiler), "-m", "-M", "true", "-G", "-c", "33"]
    strict = subprocess.run(base + ["-o", str(output / "strict-policy"), "-f", str(output / "strict-contexts")]
                            + list(map(str, files)), capture_output=True, text=True)
    (output / "strict.log").write_text(strict.stdout + strict.stderr)
    # Android init uses -N: neverallow is a source-build assertion, not a runtime
    # enforcement switch. Keep its separate strict result visible in the report.
    binary = output / "runtime-policy"
    runtime = subprocess.run(base + ["-N", "-o", str(binary), "-f", str(output / "runtime-contexts")]
                             + list(map(str, files)), capture_output=True, text=True)
    (output / "runtime.log").write_text(runtime.stdout + runtime.stderr)
    require(runtime.returncode == 0 and binary.is_file(), "Android runtime policy compilation failed: " + runtime.stderr[-1800:])
    report = {
        "runtime_linkage_pass": True,
        "runtime_flags_match_android_init": True,
        "selinux_permissive_requested": False,
        "strict_neverallow_pass": strict.returncode == 0,
        "strict_neverallow_failures": (strict.stdout + strict.stderr).count("neverallow check failed"),
        "compiled_bytes": binary.stat().st_size,
        "compiled_sha256": hashlib.file_digest(binary.open("rb"), "sha256").hexdigest(),
        "input_sha256": {str(p): hashlib.file_digest(p.open("rb"), "sha256").hexdigest() for p in files},
    }
    (output / "policy-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("compiler", "system", "extension", "product", "vendor", "odm", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    print(json.dumps(check(a.compiler, a.system, a.extension, a.product, a.vendor, a.odm, a.output), indent=2))
