#!/usr/bin/env python3
"""Fetch pinned official inputs and extract only the partitions used by this port."""
import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

from android_disk import extract, inventory, require


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(url, path, expected):
    if not path.exists():
        temporary = path.with_suffix(path.suffix + ".part")
        subprocess.run(["curl", "--fail", "--location", "--retry", "2", "--output", str(temporary), url], check=True)
        require(digest(temporary) == expected, "download integrity mismatch: " + url)
        temporary.rename(path)
    require(digest(path) == expected, "cached input integrity mismatch: " + str(path))


def prepare(work):
    require((work / ".cleanos-task.json").is_file(), "use a tracked CleanOS task scratch directory")
    config = json.loads(Path(__file__).with_name("inputs.json").read_text())
    donor = work / "mica-16560795-recovery.zip"
    base = work / "crDroidAndroid-17.0-20261017-erhai-v13.0.zip"
    root = work / "donor-images"
    root.mkdir(exist_ok=True)
    needed = [name for name, sha in config["donor"]["partitions"].items()
              if not (root / (name + ".img")).exists()]
    if needed:
        download(config["donor"]["url"], donor, config["donor"]["zip_sha256"])
        raw = work / "mica-recovery.raw"
        with zipfile.ZipFile(donor) as archive:
            with archive.open(config["donor"]["raw_member"]) as src, raw.open("wb") as dst:
                shutil.copyfileobj(src, dst, 8 * 1024 * 1024)
        require(raw.stat().st_size == config["donor"]["raw_bytes"] and
                digest(raw) == config["donor"]["raw_sha256"], "donor disk integrity mismatch")
        with raw.open("rb") as stream:
            table = inventory(stream, raw.stat().st_size)
            for name in needed:
                extract(stream, table["logical"][name]["ranges"], root / (name + ".img"))
        raw.unlink()
    root = work / "pad3-base-images"
    root.mkdir(exist_ok=True)
    needed = [name for name in config["tablet"]["partitions"] if not (root / (name + ".img")).exists()]
    if needed:
        download(config["tablet"]["base_url"], base, config["tablet"]["base_sha256"])
        payload = work / "pad3-payload.bin"
        with zipfile.ZipFile(base) as archive:
            with archive.open("payload.bin") as src, payload.open("wb") as dst:
                shutil.copyfileobj(src, dst, 8 * 1024 * 1024)
        subprocess.run(["payload-dumper-go", "-q", "-c", "2", "-p", ",".join(needed),
                        "-o", str(root), str(payload)], check=True)
        payload.unlink()
    for group, root in [("donor", work / "donor-images"), ("tablet", work / "pad3-base-images")]:
        for name, sha in config[group]["partitions"].items():
            require(digest(root / (name + ".img")) == sha, "extracted partition mismatch: " + name)
    print("Pinned official inputs and all required partition hashes verified.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--work", type=Path, required=True)
    a = p.parse_args()
    work = a.work.resolve()
    require(work.is_relative_to(Path("/private/tmp/ai-development")), "scratch must be outside cloud sync")
    prepare(work)
