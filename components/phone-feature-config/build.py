#!/usr/bin/env python3
"""Build the pinned phone feature configuration helper in owned external scratch."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
COMPONENT = Path(__file__).resolve().parent
PROJECT = COMPONENT.parents[1]
sys.path.insert(0, str(PROJECT))
from maintenance_workspace import local_path, require, task_root

GMS_SHA = "8395c70a5e4ffbe2712aea7e1045d700b282f0a67d19b80686c595c991f12112"


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def build(args):
    base = args.gms_base.resolve(strict=True)
    require(digest(base) == GMS_SHA, "unsupported GMS base SHA-256")
    scratch = local_path(args.scratch)
    require(not scratch.exists(), "scratch output directory must not exist")
    task_root(scratch.parent, PROJECT, backup_excluded=True)
    home = args.java_home.resolve(strict=True)
    java, javac = home / "bin/java", home / "bin/javac"
    android, d8 = args.android_jar.resolve(strict=True), args.d8.resolve(strict=True)
    require(all(p.is_file() for p in (java, javac, android, d8)), "missing installed tool")
    scratch.mkdir(mode=0o700)
    for name in ("classes", "dex", "tmp"):
        (scratch / name).mkdir()
    env = dict(os.environ, JAVA_HOME=str(home), TMPDIR=str(scratch / "tmp"),
               PATH=str(home / "bin") + os.pathsep + os.environ.get("PATH", ""))

    def run(command):
        with (scratch / "build.log").open("ab") as log:
            subprocess.run([str(p) for p in command], cwd=scratch, env=env,
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)

    source = COMPONENT / "NativeConfigRepair.java"
    test = COMPONENT / "tests/FeatureConfigBoundaryTest.java"
    run([javac, "-J-Xmx512m", "-J-XX:ActiveProcessorCount=2", "--release", "8",
         "-cp", android, "-d", scratch / "classes", source, test])
    run([java, "-Xmx256m", "-XX:ActiveProcessorCount=2", "-Djava.io.tmpdir=" + str(scratch / "tmp"),
         "-cp", str(scratch / "classes") + os.pathsep + str(android), "FeatureConfigBoundaryTest"])
    run([sys.executable, "-B", COMPONENT / "tests/test_build.py"])
    classes = sorted((scratch / "classes").glob("NativeConfigRepair*.class"))
    require(len(classes) == 2, "unexpected helper class set")
    run([d8, "-JXmx512m", "-JXX:ActiveProcessorCount=2", "-JDjava.io.tmpdir=" + str(scratch / "tmp"),
         "--release", "--min-api", "28", "--lib", android, "--output", scratch / "dex", *classes])
    output = scratch / "classes.dex"
    (scratch / "dex/classes.dex").rename(output)
    require(output.read_bytes()[:8] in (b"dex\n035\0", b"dex\n039\0"), "unexpected DEX header")
    receipt = dict(schema=1, gms_base_sha256=GMS_SHA, gms_version=264330035,
                   phenotype_schema=1036, dex_sha256=digest(output),
                   host_boundary_tests="passed", device_deployed=False,
                   selinux_device_verification="required", source_sha256={
                       str(p.relative_to(COMPONENT)): digest(p) for p in
                       (Path(__file__).resolve(), source, test, COMPONENT / "tests/test_build.py")},
                   tool_sha256={"java": digest(java), "javac": digest(javac),
                                "android_jar": digest(android), "d8_launcher": digest(d8)})
    (scratch / "validation.json").write_text(json.dumps(receipt, indent=2) + "\n")
    for name in ("classes", "dex", "tmp"):
        shutil.rmtree(scratch / name)
    print(json.dumps({"status": "passed", "dex_sha256": receipt["dex_sha256"], "device_deployed": False}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("gms-base", "java-home", "android-jar", "d8", "scratch"):
        parser.add_argument("--" + name, type=Path, required=True)
    try:
        build(parser.parse_args(argv))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("Build refused or failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
