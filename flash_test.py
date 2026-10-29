#!/usr/bin/env python3
"""Require raw EXT4 for the pinned Pad 3 base. Read-only unless both flash flags are set."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def getvar(serial, name):
    result = subprocess.run(["fastboot", "-s", serial, "getvar", name], capture_output=True, text=True)
    text = result.stdout + result.stderr
    match = re.search(r"(?:\(bootloader\)\s*)?" + re.escape(name) + r":\s*([^\r\n]+)", text)
    if result.returncode or not match:
        raise RuntimeError("Cannot verify fastboot variable " + name + ": " + text.strip())
    return match[1].strip()


def preflight(directory, serial):
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["status"] != "UNBOOTED_EXPERIMENTAL" or set(manifest["images"]) != {"system", "system_ext", "product"}:
        raise RuntimeError("Unexpected test-package manifest")
    for name, entry in manifest["images"].items():
        path = directory / (name + ".img")
        if path.is_symlink() or path.stat().st_size != entry["bytes"]:
            raise RuntimeError("Invalid image file: " + name)
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            stream.seek(1024)
            is_erofs = stream.read(4) == b"\xe2\xe1\xf5\xe0"
            stream.seek(1080)
            is_ext4 = stream.read(2) == b"\x53\xef"
        if digest != entry["sha256"]:
            raise RuntimeError("Image SHA-256 mismatch: " + name)
        if is_erofs or not is_ext4:
            filesystem = "EROFS" if is_erofs else "unknown"
            raise RuntimeError(f"{name}: {filesystem} image rejected; direct flashing on the pinned Pad 3 hardware base requires raw EXT4")
    if getvar(serial, "is-userspace").lower() != "yes":
        raise RuntimeError("Enter fastbootd from the tablet's recovery; bootloader fastboot is insufficient")
    if getvar(serial, "unlocked").lower() != "yes":
        raise RuntimeError("An actually unlocked bootloader is required; Android properties are insufficient")
    product = getvar(serial, "product")
    if product not in {"OP6190L1", "OPD2415", "erhai"}:
        raise RuntimeError("Wrong device: " + product)
    slot = getvar(serial, "current-slot")
    if slot not in {"a", "b"}:
        raise RuntimeError("Unrecognized active slot")
    if getvar(serial, "snapshot-update-status").lower() not in {"none", "cancelled"}:
        raise RuntimeError("A virtual A/B snapshot update is active; resolve it before testing")
    return manifest, slot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--flash", action="store_true")
    parser.add_argument("--acknowledge-unbooted-test-and-formatted-data", action="store_true")
    args = parser.parse_args()
    directory = args.directory.resolve()
    _, slot = preflight(directory, args.serial)
    print("Package hashes, raw EXT4 magic, Pad 3 identity, unlocked fastbootd and snapshot state verified.")
    print("This package requires the pinned 2026-10-17 crDroid hardware base and clean userdata.")
    print("The helper does not verify the installed kernel/vendor/firmware base or that userdata was formatted.")
    if not args.flash:
        print("Read-only preflight complete. Nothing flashed or erased.")
        return
    if not args.acknowledge_unbooted_test_and_formatted_data:
        raise RuntimeError("Back up data, verify the pinned hardware base, and format data in recovery first; then explicitly acknowledge the unbooted test")
    # Never touch bootloaders, firmware, kernel, recovery, vendor, ODM, or userdata.
    for name in ("system", "system_ext", "product"):
        if getvar(args.serial, "current-slot") != slot:
            raise RuntimeError("Slot changed during flashing; stopped")
        subprocess.run(["fastboot", "-s", args.serial, "flash", name + "_" + slot,
                        str(directory / (name + ".img"))], check=True)
    print("Three userspace images flashed. No erase or reboot was performed.")
    print("Reboot manually when ready. Keep the official crDroid rollback ROM available.")


if __name__ == "__main__":
    main()
