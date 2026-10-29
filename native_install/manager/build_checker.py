"""Build the fixed read-only PackageManager checker; never contact a device."""
import os
from pathlib import Path
import argparse
import hashlib
import subprocess
import tempfile
import zipfile

from build_native_rom import ROOT, scratch_output


def build(output):
    output = scratch_output(output)
    sdk = Path(os.environ["ANDROID_HOME"])
    jdk = Path(os.environ["JAVA_HOME"]) / "bin"
    source = ROOT / "native_install/manager"
    with tempfile.TemporaryDirectory(prefix="manager-checker-build-", dir=output.parent) as temporary:
        temporary = Path(temporary)
        classes, dex = temporary / "classes", temporary / "dex"
        classes.mkdir()
        dex.mkdir()
        subprocess.run([str(jdk / "javac"), "--release", "8", "-classpath", str(sdk / "platforms/android-37.2/android.jar"),
                        "-d", str(classes), str(source / "ManagerDecision.java"), str(source / "SukiSUManagerCheck.java")],
                       check=True, capture_output=True)
        jar = temporary / "classes.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            for file in sorted(classes.glob("*.class")):
                archive.writestr(zipfile.ZipInfo(file.name, (1980, 1, 1, 0, 0, 0)), file.read_bytes())
        subprocess.run([str(jdk / "java"), "-cp", str(sdk / "build-tools/36.0.0/lib/d8.jar"), "com.android.tools.r8.D8",
                        "--min-api", "29", "--output", str(dex), str(jar)], check=True, capture_output=True)
        with zipfile.ZipFile(output, "x") as archive:
            archive.writestr(zipfile.ZipInfo("classes.dex", (1980, 1, 1, 0, 0, 0)), (dex / "classes.dex").read_bytes())
    with output.open("rb") as stream:
        print(hashlib.file_digest(stream, "sha256").hexdigest(), output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    build(parser.parse_args().output)
