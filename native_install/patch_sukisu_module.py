"""Apply the reviewed erhai inode offset correction to official SukiSU 41100 only."""
import argparse
import hashlib
import struct
from pathlib import Path

SOURCE_SHA256 = "0e8f059c89602726dd8180d699b20526c747c58dbc97ebd62893905b56c5e3c6"
TARGET_SHA256 = "6e9e1abff6ca15da92fe2cb8a51868b99049320aa65d613c826611eb377d4947"
ADDENDS = (0x51120, 0x51138)


def patch(data):
    # Exact input identity binds these relocation records to the audited release.
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError("expected official 41100 aarch64 android15-6.6 module")
    result = bytearray(data)
    for offset, instruction, relocation in zip(ADDENDS, (0x3EA8, 0x3EAC), (275, 285)):
        address, info, addend = struct.unpack_from("<QQq", result, offset - 16)
        if (address, info & 0xFFFFFFFF, addend) != (instruction, relocation, 8):
            raise ValueError("reviewed selinux_blob_sizes inode relocation changed")
        struct.pack_into("<q", result, offset, 12)
    if hashlib.sha256(result).hexdigest() != TARGET_SHA256:
        raise ValueError("corrected module checksum mismatch")
    return bytes(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = patch(args.source.read_bytes())
    with args.output.open("xb") as stream:
        stream.write(result)
    print(TARGET_SHA256)
