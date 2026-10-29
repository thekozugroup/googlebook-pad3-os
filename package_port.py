#!/usr/bin/env python3
"""Publish one validated test bundle and one verified official rollback ROM."""
import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path

from android_disk import require


def package(work, output):
    source = Path(__file__).resolve().parent
    inputs = json.loads((source / "inputs.json").read_text())
    images = json.loads((work / "candidate/image-report.json").read_text())
    validation = json.loads((work / "candidate/validation-report.json").read_text())
    require(validation["runtime_policy"]["runtime_linkage_pass"] and
            validation["introduced_strict_violations"] == 0, "validation gate failed")
    require(set(images) == {"system", "system_ext", "product"}, "unexpected flash partition")
    manifest = {"status": "UNBOOTED_EXPERIMENTAL", "target": inputs["tablet"],
                "donor": inputs["donor"], "images": images,
                "hardware_partitions_included": [], "userdata_erased_by_helper": False,
                "requires_clean_userdata": True, "source_reference_commits": inputs["reference_commits"]}
    output.mkdir(parents=True, exist_ok=True)
    target = output / "Googlebook-erhai-initial-test.zip"
    require(not target.exists(), "canonical test bundle already exists; preserve/review it before replacement")
    temporary = target.with_suffix(".zip.part")
    require(not temporary.exists(), "unfinished bundle already exists")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
        for name, entry in images.items():
            path = work / "candidate" / (name + ".img")
            with path.open("rb") as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == entry["sha256"], "image hash changed before packaging")
            archive.write(path, name + ".img")
        archive.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
        archive.writestr("validation-report.json", json.dumps(validation, indent=2) + "\n")
        archive.write(source / "TESTING.md", "README.md")
        archive.write(source / "flash_test.py", "flash_test.py")
    with zipfile.ZipFile(temporary) as archive:
        require(archive.testzip() is None, "bundle ZIP integrity failure")
        require(set(archive.namelist()) == {"system.img", "system_ext.img", "product.img",
                "manifest.json", "validation-report.json", "README.md", "flash_test.py"}, "unexpected bundle contents")
    temporary.rename(target)
    with target.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    (output / (target.name + ".sha256")).write_text(digest + "  " + target.name + "\n")
    rollback = work / "crDroidAndroid-17.0-20261017-erhai-v13.0.zip"
    destination = output / rollback.name
    with rollback.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == inputs["tablet"]["base_sha256"], "rollback integrity mismatch")
    if destination.exists():
        require(not destination.is_symlink(), "rollback destination is a symlink")
        with destination.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == inputs["tablet"]["base_sha256"],
                    "existing rollback artifact has a different hash")
    else:
        shutil.copyfile(rollback, destination)
    (output / (destination.name + ".sha256")).write_text(inputs["tablet"]["base_sha256"] + "  " + destination.name + "\n")
    print(json.dumps({"test_zip": str(target), "bytes": target.stat().st_size, "sha256": digest,
                      "rollback_zip": str(destination)}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    package(args.work.resolve(), args.output.resolve())
