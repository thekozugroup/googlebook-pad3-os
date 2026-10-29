#!/usr/bin/env python3
"""Reproduce the private V9 images from pinned official inputs in CleanOS scratch."""
import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

from android_disk import require
from assemble_port import build as assemble
from build_dsu_diagnostic import PARTITIONS, SOURCE, build, sha256, verify_images
from prepare_inputs import prepare


# Current target, measured from the independently validated warm V9 build.
EXPECTED_IMAGES = {
    "system": {"sha256": "9f96606d78d69e82fdcef5ef44cf0b0e53ee9236e32d08f03e48e9a3fa14763e", "bytes": 1085116416},
    "product": {"sha256": "63da97f66037961cfc6cc0d42ddfee4213c38de9f70aba6c612e1ffc81004657", "bytes": 1992138752},
    "system_ext": {"sha256": "12af3b88e97fc1e62684574c9ac304932ec8461dcdc1e9e8af3232487df68eee", "bytes": 183074816},
}


def verify_task(work):
    require(work == work.resolve() and work.is_relative_to(Path("/private/tmp/ai-development")) and
            (work / ".cleanos-task.json").is_file() and not (work / ".cleanos-task.json").is_symlink(),
            "use an existing CleanOS task")
    owner = json.loads((work / ".cleanos-task.json").read_text())
    require(owner["owner"] == os.getuid() and owner["id"] == work.name and
            owner["project"] == str(SOURCE) and not owner["finished"], "invalid cold-build task ownership")


def compiler_for(work):
    root = work / "secilc-tools"
    compiler = root / "bin/secilc"
    if not compiler.exists():
        subprocess.run(["bash", str(SOURCE / "build_secilc.sh"), str(root)], check=True)
    provenance = root / "provenance.txt"
    require(compiler == compiler.resolve() and compiler.is_file() and provenance.is_file() and
            not provenance.is_symlink(), "unverified secilc compiler path")
    lines = provenance.read_text().splitlines()
    digest = sha256(compiler)
    require(not compiler.is_symlink() and os.access(compiler, os.X_OK) and
            "source=https://android.googlesource.com/platform/external/selinux" in lines and
            "revision=a8c5e74f85f869bf236a01ba24181b78f5e39a52" in lines and
            any(line.split() and line.split()[0] == digest and
                Path(line.split()[-1]).name == "secilc" for line in lines), "unverified secilc compiler")
    return compiler


def verify_current_images(images):
    require(set(images) == set(PARTITIONS) and all(images[p]["sha256"] == EXPECTED_IMAGES[p]["sha256"] and
            images[p]["bytes"] == EXPECTED_IMAGES[p]["bytes"] for p in PARTITIONS), "cold-build V9 image mismatch")
    return {p: EXPECTED_IMAGES[p]["sha256"] for p in PARTITIONS}


def cold_build(work):
    verify_task(work)
    require(not (work / "candidate-images").exists() and not (work / "diagnostic").exists(),
            "cold-build outputs already exist; review before rebuilding")
    temporary = work / "python-tmp"
    temporary.mkdir(exist_ok=True)
    os.environ["TMPDIR"] = str(temporary)
    prepare(work)
    compiler = compiler_for(work)
    seed = work / "candidate-images"
    assemble(work, seed, diagnostic_seed=True)
    expected_seed = json.loads((SOURCE / 'profiles/build-seed.json').read_text())["image_sha256"]
    verify_images(seed, expected_seed)
    result = build(work / "diagnostic", compiler=compiler)
    report = {"status": "COLD_V9_IMAGES_MATCH", "seed_sha256": expected_seed,
              "images": verify_current_images(result["images"]), "bundle": result["bundle"],
              "compiler_sha256": sha256(compiler), "policy": result["policy"],
              "historical_scratch_or_artifacts_required": False, "zip_bit_identical_claimed": False,
              "device_commands_run": False}
    (work / "cold-build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    shutil.rmtree(seed)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(cold_build(args.work.resolve()), indent=2))
