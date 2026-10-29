#!/usr/bin/env python3
"""Build one unsigned native updater APK with existing tools; never sign/install."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
COMPONENT = ROOT / "components/updater"
OUTPUT = ROOT / "artifacts/component-candidates/Pad3Updater-unsigned.apk"
FEED = "https://raw.githubusercontent.com/thekozugroup/googlebook-pad3-os/refs/heads/main/updates/erhai/stable.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_feed(url):
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname == "raw.githubusercontent.com" and
            parsed.port in (None, 443) and parsed.username is None and parsed.password is None and
            parsed.path.startswith("/thekozugroup/googlebook-pad3-os/") and
            not parsed.fragment and not parsed.query and ".." not in parsed.path,
            "use the public owner repository's raw HTTPS JSON feed")
    return url


def verify_scratch(work):
    work = Path(work)
    require(work == work.resolve() and work.is_relative_to(Path("/private/tmp/ai-development")), "use physical CleanOS scratch")
    manifest = work / ".cleanos-task.json"
    require(manifest.is_file() and not manifest.is_symlink(), "missing CleanOS task manifest")
    owner = json.loads(manifest.read_text())
    require(owner["id"] == work.name and owner["owner"] == os.getuid() and
            owner["project"] == str(ROOT) and not owner["finished"], "invalid CleanOS ownership")
    require(ROOT == ROOT.resolve() and ROOT.is_relative_to(Path.home() / "Developer"), "source must stay outside cloud sync")


def public_key(path):
    if path is None:
        return b""
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4096, "supply only a small public SPKI DER key")
    data = path.read_bytes()
    require(data.startswith(b"\x30") and b"PRIVATE" not in data, "require public SPKI DER, never private key/PEM")
    return data


def output_path(work, requested=None):
    target = Path(requested) if requested is not None else OUTPUT
    require(target.is_absolute() and target == target.resolve() and not target.is_symlink(), "output must be a physical local path")
    require(target.is_relative_to(Path(work)) or target == OUTPUT, "output must be task scratch or the canonical component candidate")
    require(target.parent.resolve().is_relative_to(ROOT) or target.is_relative_to(Path(work)), "output parent escaped the local workspace")
    return target


def toolchain():
    lock = json.loads((COMPONENT / "toolchain.json").read_text())
    for name, entry in lock["tools"].items():
        require(Path(entry["path"]).is_file() and sha256(entry["path"]) == entry["sha256"], "tool drift: " + name)
    java = Path(lock["java_home"]) / "bin/java"
    version = subprocess.run([str(java), "-version"], capture_output=True, text=True, check=True).stderr
    require(re.search(r'version "21\.', version), "JDK 21 required")
    lock["java_version"] = version.strip()
    return lock


def run(command, env, work, commands):
    command = [str(value) for value in command]
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    commands.append({"command": command, "exit": result.returncode})
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    require(result.returncode == 0, "command failed: " + command[0] + "\n" + result.stdout[-6000:] + result.stderr[-6000:])
    return result.stdout


def build(work, key_path=None, feed=FEED, output=None):
    verify_scratch(work)
    work = Path(work)
    output = output_path(work, output)
    validate_feed(feed)
    key = public_key(key_path)
    lock = toolchain()
    java_home = Path(lock["java_home"])
    tools = {name: entry["path"] for name, entry in lock["tools"].items()}
    directory = work / "updater-build"
    require(not directory.exists(), "build output already exists; preserve/review before rebuilding")
    directory.mkdir()
    canonical_sources = sorted([p for p in COMPONENT.rglob("*") if p.is_file() and p.suffix in (".java", ".json", ".xml", ".te", ".txt")] +
                               [ROOT / "build_updater.py", ROOT / "test_build_updater.py"])
    source_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in canonical_sources}
    for name in ("tmp", "host-tests", "stubs", "classes", "dex", "assets", "generated/org/googlebook/pad3/updater"):
        (directory / name).mkdir(parents=True)
    env = dict(os.environ, JAVA_HOME=str(java_home), TMPDIR=str(directory / "tmp"), PYTHONDONTWRITEBYTECODE="1",
               JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=" + str(directory / "tmp") + " -XX:-UsePerfData")
    commands = []
    javac, java = java_home / "bin/javac", java_home / "bin/java"
    tests = directory / "host-tests"
    run([javac, "--release", "17", "-d", tests, COMPONENT / "src/org/googlebook/pad3/updater/UpdateCore.java",
         COMPONENT / "tests/UpdateCoreTest.java"], env, directory, commands)
    result = run([java, "-Djava.io.tmpdir=" + str(directory / "tmp"), "-cp", tests,
                  "org.googlebook.pad3.updater.UpdateCoreTest", tests], env, directory, commands)
    require("CORE_CHECKS_PASSED=" in result, "host verification checks did not complete")
    if key:
        key_file = directory / "release-key.der"
        key_file.write_bytes(key)
        check = directory / "CheckPublicKey.java"
        check.write_text('import java.nio.file.*; import java.security.*; import java.security.spec.*; import java.security.interfaces.*; '
                         'class CheckPublicKey { public static void main(String[] a) throws Exception {'
                         'RSAPublicKey k=(RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Path.of(a[0]))));'
                         'if(k.getModulus().bitLength()<2048)throw new Exception("RSA public key too small");}}\n')
        run([javac, "-d", tests, check], env, directory, commands)
        run([java, "-cp", tests, "CheckPublicKey", key_file], env, directory, commands)
    (directory / "assets/release-key.der").write_bytes(key)
    run([javac, "--release", "17", "-cp", str(tests) + os.pathsep + tools["android_jar"], "-d", tests,
         COMPONENT / "src/org/googlebook/pad3/updater/ManifestCodec.java", COMPONENT / "tests/FeedOrderTest.java"], env, directory, commands)
    parser_result = run([java, "-cp", str(tests) + os.pathsep + tools["android_jar"],
                        "org.googlebook.pad3.updater.FeedOrderTest", directory / "assets/release-key.der"], env, directory, commands)
    require("SIGNATURE_BEFORE_JSON_CHECKS_PASSED=2" in parser_result, "signature verification did not precede JSON parsing")
    (directory / "generated/org/googlebook/pad3/updater/BuildConfig.java").write_text(
        "package org.googlebook.pad3.updater; final class BuildConfig { static final String FEED = " + json.dumps(feed) +
        "; static final boolean KEY_PROVISIONED = " + str(bool(key)).lower() + "; }\n")
    # Bind compile-only API declarations to the exact inspected donor, without shipping donor code.
    api = json.loads((COMPONENT / "donor-api.json").read_text())
    image = Path(os.environ.get("GOOGLEBOOK_INPUTS", "build-inputs")) / "donor-images/system_a.img"
    pins = json.loads((ROOT / "inputs.json").read_text())
    require(sha256(image) == pins["donor"]["partitions"]["system_a"], "donor image drift")
    framework = directory / "framework.jar"
    with framework.open("xb") as out:
        extraction = subprocess.run(["dump.erofs", "--cat", "--path=/system/framework/framework.jar", str(image)], stdout=out, stderr=subprocess.PIPE)
    require(extraction.returncode == 0 and sha256(framework) == api["framework_sha256"], "inspected donor API drift")
    stubs = sorted((COMPONENT / "build-support").rglob("*.java"))
    run([javac, "--release", "17", "-cp", tools["android_jar"], "-d", directory / "stubs", *stubs], env, directory, commands)
    sources = sorted((COMPONENT / "src").rglob("*.java")) + sorted((directory / "generated").rglob("*.java"))
    run([javac, "--release", "17", "-cp", str(directory / "stubs") + os.pathsep + tools["android_jar"],
         "-d", directory / "classes", *sources], env, directory, commands)
    for name in ("stubs", "classes"):
        with zipfile.ZipFile(directory / (name + ".jar"), "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted((directory / name).rglob("*.class")):
                archive.write(path, path.relative_to(directory / name).as_posix())
    run([java, "-Xmx768m", "-Djava.io.tmpdir=" + str(directory / "tmp"), "-cp", tools["r8_jar"],
         "com.android.tools.r8.D8", "--release", "--min-api", "35", "--lib", tools["android_jar"],
         "--classpath", directory / "stubs.jar", "--output", directory / "dex", directory / "classes.jar"], env, directory, commands)
    base = directory / "base.apk"
    run([tools["aapt2"], "link", "-o", base, "--manifest", COMPONENT / "AndroidManifest.xml", "-I", tools["android_jar"],
         "-A", directory / "assets", "--min-sdk-version", "35", "--target-sdk-version", "37"], env, directory, commands)
    with zipfile.ZipFile(base, "a", zipfile.ZIP_STORED) as archive:
        for path in sorted((directory / "dex").glob("classes*.dex")):
            info = zipfile.ZipInfo(path.name, (2009, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, path.read_bytes())
    candidate = directory / "Pad3Updater-unsigned.apk"
    run([tools["zipalign"], "-f", "4", base, candidate], env, directory, commands)
    run([tools["zipalign"], "-c", "4", candidate], env, directory, commands)
    badging = run([tools["aapt2"], "dump", "badging", candidate], env, directory, commands)
    require("org.googlebook.pad3.updater" in badging, "wrong package")
    manifest = run([tools["aapt2"], "dump", "xmltree", candidate, "--file", "AndroidManifest.xml"], env, directory, commands)
    require("android.settings.SYSTEM_UPDATE_SETTINGS" in manifest and "sharedUserId" not in manifest, "invalid native Settings/shared UID contract")
    dex = run([tools["dexdump"], directory / "dex/classes.dex"], env, directory, commands)
    declarations = re.findall(r"Class descriptor\s*:\s*'([^']+)'", dex)
    require(declarations and all(not name.startswith("Landroid/") for name in declarations), "compile stubs leaked into APK")
    with zipfile.ZipFile(candidate) as archive:
        require(archive.read("assets/release-key.der") == key and not any(name.upper().endswith((".RSA", ".DSA", ".EC", ".SF")) for name in archive.namelist()), "key/signing mismatch")
    require(all(sha256(ROOT / name) == digest for name, digest in source_hashes.items()), "canonical source changed during build; rebuild the reviewed snapshot")
    # One canonical requested unsigned candidate, replaced only after successful verification.
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".apk.part")
    require(not temporary.is_symlink(), "unsafe temporary APK output")
    shutil.copyfile(candidate, temporary)
    temporary.replace(output)
    report_path = ROOT / "reports/updater-integration.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {"component": "native-updater", "source_candidate": True}
    report.update(status="APK_BUILT_NOT_DEVICE_VALIDATED", verification_key_provisioned=bool(key),
                  verification_key_sha256=hashlib.sha256(key).hexdigest() if key else None,
                  artifact={"path": str(output), "bytes": output.stat().st_size, "sha256": sha256(output), "signed": False},
                  build={"sdk": "37.2", "build_tools": "36.0.0", "jdk": lock["java_version"], "host_tests": result.strip() + "; " + parser_result.strip(),
                         "apk_classes": len(declarations), "compile_stubs_packaged": False, "settings_intent_verified": True,
                         "donor_framework_sha256": api["framework_sha256"], "feed": feed, "no_gradle_androidx_or_new_dependencies": True},
                  source_sha256=source_hashes)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--verification-key", "--public-key", dest="verification_key", type=Path, help="owner's public RSA SPKI DER only; omitted builds fail closed")
    parser.add_argument("--feed-url", default=FEED)
    parser.add_argument("--output", type=Path, help="physical task-scratch path; default is artifacts/component-candidates/Pad3Updater-unsigned.apk")
    args = parser.parse_args()
    try:
        report = build(args.work.resolve(), args.verification_key, args.feed_url, args.output)
        print(json.dumps({"status": report["status"], "artifact": report["artifact"],
                          "verification_key_provisioned": report["verification_key_provisioned"], "tests": report["build"]["host_tests"]}, indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("build_updater: " + str(error), file=sys.stderr)
        sys.exit(1)
