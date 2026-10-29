"""Compile the getter-only probe locally; never contact or operate a device."""
import os
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

from build_native_rom import ROOT, scratch_output


def build(output):
    output = scratch_output(output)
    sdk = Path(os.environ["ANDROID_HOME"])
    tools = sdk / "build-tools/36.0.0"
    jdk = Path(os.environ["JAVA_HOME"]) / "bin"
    source = ROOT / "native_install/bootcontrol"
    with tempfile.TemporaryDirectory(prefix="bootcontrol-build-", dir=output.parent) as temp:
        temp = Path(temp)
        generated = temp / "generated"
        command = [str(tools / "aidl"), "--lang=java", "--structured", "--stability=vintf",
                   "-I" + str(source / "aidl"), "-o" + str(generated),
                   str(source / "aidl/android/hardware/boot/IBootControl.aidl")]
        subprocess.run(command, check=True, capture_output=True)
        binding = (generated / "android/hardware/boot/IBootControl.java").read_text()
        getters = ["getActiveBootSlot", "getCurrentSlot", "getNumberSlots", "getSnapshotMergeStatus",
                   "getSuffix", "isSlotBootable", "isSlotMarkedSuccessful"]
        for offset, name in enumerate(getters):
            assert re.search(r"TRANSACTION_" + name + r" = \(android.os.IBinder.FIRST_CALL_TRANSACTION \+ "
                             + str(offset) + r"\);", binding), "AIDL getter transaction declaration drift"
        classes = temp / "classes"
        classes.mkdir()
        subprocess.run([str(jdk / "javac"), "--release", "8", "-classpath", str(sdk / "platforms/android-37.2/android.jar"),
                        "-d", str(classes), str(source / "NativeBootControlProbe.java")], check=True, capture_output=True)
        jar = temp / "classes.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            for item in classes.glob("*.class"):
                archive.write(item, item.name)
        dex = temp / "dex"
        dex.mkdir()
        subprocess.run([str(jdk / "java"), "-cp", str(tools / "lib/d8.jar"), "com.android.tools.r8.D8",
                        "--min-api", "29", "--output", str(dex), str(jar)], check=True, capture_output=True)
        with zipfile.ZipFile(output, "x") as archive:
            archive.write(dex / "classes.dex", "classes.dex")
    with output.open("rb") as stream:
        print(hashlib.file_digest(stream, "sha256").hexdigest(), output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    build(parser.parse_args().output)
