#!/usr/bin/env python3
"""Build only system/product/system_ext; never contact or flash a device."""
import argparse
import hashlib
import json
from pathlib import Path

from android_disk import require
from erofs_overlay import apply, content
from ext4_source import regular_file
from port_changes import create

GRAFT = [
    "bin/qccsyshal_aidl-service",
    "etc/init/vendor.qti.qccsyshal_aidl-service.rc",
    "etc/vintf/manifest/vendor.qti.qccsyshal_aidl-service.xml",
    "lib64/libqcc_file_agent_sys.so",
    "lib64/vendor.qti.qccsyshal_aidl-V1-ndk.so",
    "lib64/vendor.qti.qccsyshal_aidl-halimpl.so",
    "bin/qtiaudiohalvendorextn",
    "etc/init/qtiaudiohalvendorextn.rc",
]


def build(work, output, *, diagnostic_seed=False):
    config = json.loads(Path(__file__).with_name("inputs.json").read_text())
    images, base = work / "donor-images", work / "pad3-base-images"
    for group, root in [("donor", images), ("tablet", base)]:
        for name, expected in config[group]["partitions"].items():
            path = root / (name + ".img")
            with path.open("rb") as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == expected,
                        "unverified input partition: " + str(path))
    require(not output.exists() or not any(output.iterdir()), "output directory is not empty")
    output.mkdir(parents=True, exist_ok=True)
    changes = create(images)
    if diagnostic_seed:
        require(changes["system"].pop("/system/etc/init/check_tpm_clear.rc", None) is not None,
                "diagnostic seed requires the normal TPM neutralization")
    fc = content(images / "system_ext_a.img", "/etc/selinux/system_ext_file_contexts")
    require(b"/bin/qtiaudiohalvendorextn" not in fc, "audio extension path already labeled")
    changes["system_ext"]["/etc/selinux/system_ext_file_contexts"] = (
        fc.rstrip() + b"\n/(system_ext|system/system_ext)/bin/qtiaudiohalvendorextn u:object_r:audio_vendor_parameter_parser_exec:s0\n")
    additions = {"/" + path: regular_file(base / "system_ext.img", "/" + path, work) for path in GRAFT}
    # Use the donor's existing domain for the same audio-adapter Binder service.
    additions["/bin/qtiaudiohalvendorextn"]["metadata"]["xattrs"]["security.selinux"] = (
        b"u:object_r:audio_vendor_parameter_parser_exec:s0\0")
    report = {}
    for part in ("system", "system_ext", "product"):
        print("Building", part, flush=True)
        report[part] = apply(images / (part + "_a.img"), output / (part + ".img"), changes[part], work,
                             additions=additions if part == "system_ext" else None)
    require(sum(x["bytes"] for x in report.values()) < 4 * 1024 ** 3,
            "userspace size exceeds reviewed initial-test budget")
    (output / "image-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    build(args.work.resolve(), args.output.resolve())
