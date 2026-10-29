#!/usr/bin/env python3
"""Recheck the previously repaired SukiSU module against an updated Pad 3 kernel."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from android_disk import require


def btf_types(blob):
    require(len(blob) >= 24, "truncated BTF header")
    magic, version, flags, header, offset, length, strings_at, strings_length = struct.unpack_from("<HBBIIIII", blob)
    require((magic, version, flags, header, offset, strings_at) == (0xEB9F, 1, 0, 24, 0, length)
            and header + strings_at + strings_length == len(blob), "unsupported BTF layout")
    strings = blob[header + strings_at:]
    require(strings[:1] == b"\0", "invalid BTF strings")

    def name(index):
        require(0 <= index < len(strings), "BTF name outside string table")
        return strings[index:strings.index(0, index)].decode()

    extra = {1: 4, 2: 0, 3: 12, 4: 12, 5: 12, 6: 8, 7: 0, 8: 0, 9: 0,
             10: 0, 11: 0, 12: 0, 13: 8, 14: 4, 15: 12, 16: 0, 17: 4, 18: 0, 19: 12}
    types = [None]
    cursor = header
    while cursor < header + length:
        require(cursor + 12 <= header + length, "truncated BTF type")
        index, info, size = struct.unpack_from("<III", blob, cursor)
        kind, count = info >> 24 & 31, info & 65535
        require(kind in extra, "unsupported BTF type kind")
        step = 12 + extra[kind] * (count if kind in (4, 5, 6, 13, 15, 19) else 1)
        require(cursor + step <= header + length, "truncated BTF type payload")
        record = {"name": name(index), "kind": kind, "size_type": size}
        if kind in (4, 5):
            members = []
            for member in range(count):
                index, type_id, bits = struct.unpack_from("<III", blob, cursor + 12 + member * 12)
                members.append({"name": name(index), "type_id": type_id,
                                "bit_offset": bits & 0xFFFFFF if info >> 31 else bits})
            record["members"] = members
        if kind == 13:
            record["params"] = [struct.unpack_from("<II", blob, cursor + 12 + member * 8)[1]
                                for member in range(count)]
        types.append(record)
        cursor += step
    require(cursor == header + length, "invalid BTF type boundary")
    return types


def field_offsets(types, type_id, name, base=0, seen=()):
    require(type_id not in seen and 0 < type_id < len(types), "invalid recursive BTF member")
    result = []
    for member in types[type_id]["members"]:
        bits = base + member["bit_offset"]
        if member["name"] == name:
            result.append(bits)
        elif not member["name"]:
            child = member["type_id"]
            require(0 < child < len(types), "invalid anonymous BTF member")
            if types[child]["kind"] in (4, 5):
                result.extend(field_offsets(types, child, name, bits, seen + (type_id,)))
    return result


def check(boot, expected_sha256, kernel_release, module, baseline):
    with boot.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == expected_sha256, "stock boot checksum mismatch")
        stream.seek(0)
        header = stream.read(4096)
        require(header[:8] == b"ANDROID!" and struct.unpack_from("<I", header, 40)[0] == 4,
                "expected Android boot header v4")
        kernel = stream.read(struct.unpack_from("<I", header, 8)[0])
    # shortcut: raw ARM64 Image only; review decompression before accepting a compressed future kernel.
    require(kernel[56:60] == b"ARM\x64", "expected uncompressed ARM64 Image")
    require(b"Linux version " + kernel_release.encode() + b" " in kernel, "kernel release mismatch")
    candidates = []
    for match in re.finditer(b"\x9f\xeb\x01\x00\x18\x00\x00\x00", kernel):
        start = match.start()
        if start + 24 > len(kernel):
            continue
        _, _, _, header, offset, length, strings, strings_length = struct.unpack_from("<HBBIIIII", kernel, start)
        end = start + header + strings + strings_length
        if offset == 0 and strings == length and length > 100000 and strings_length > 100000 and end <= len(kernel):
            candidates.append(kernel[start:end])
    require(len(candidates) == 1, "expected exactly one complete kernel BTF table")
    blob = candidates[0]
    types = btf_types(blob)
    layouts, checks = {}, []
    for name, previous in baseline["live_layouts"].items():
        definitions = [(i, t) for i, t in enumerate(types) if t and t["kind"] == 4 and t["name"] == name]
        require(bool(definitions), "missing kernel struct: " + name)
        shape = (previous["size"], [(m["name"], m["bit_offset"]) for m in previous["members"]])
        for _, definition in definitions:
            require((definition["size_type"], [(m["name"], m["bit_offset"]) for m in definition["members"]]) == shape,
                    "kernel struct changed: " + name)
        layouts[name] = definitions[0][0]
        checks.append({"struct": name, "matching_definitions": len(definitions)})
    for name, member, byte in baseline["related_layout_checks"]:
        require(field_offsets(types, layouts[name], member) == [byte * 8], "kernel field changed: " + name + "." + member)
    for function, name in (("security_inode_alloc", "inode"), ("security_file_alloc", "file")):
        functions = [t for t in types[1:] if t["kind"] == 12 and t["name"] == function]
        require(len(functions) == 1, "ambiguous kernel function: " + function)
        pointer = types[types[functions[0]["size_type"]]["params"][0]]
        require(pointer["kind"] == 2 and pointer["size_type"] == layouts[name], "kernel function type mismatch")
    data = module.read_bytes()
    require(hashlib.sha256(data).hexdigest() == baseline["artifact_sha256"], "previously repaired module checksum mismatch")
    for relocation in baseline["references"]:
        expected = 12 if relocation["addend"] == 8 else relocation["addend"]
        require(struct.unpack_from("<q", data, relocation["addend_file_offset"])[0] == expected,
                "previously reviewed relocation changed")
    return {"kernel": kernel_release, "boot_sha256": expected_sha256,
            "module_sha256": baseline["artifact_sha256"], "btf_sha256": hashlib.sha256(blob).hexdigest(),
            "layout_checks": checks, "field_offsets_checked": len(baseline["related_layout_checks"]),
            "module_addends_checked": len(baseline["references"]),
            "status": "BOUNDED_STATIC_CHECK_PASSED_RUNTIME_UNTESTED",
            "limitations": ["Not a full kernel ABI, export/CRC or runtime module-load verification."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("boot", "module", "baseline", "output"):
        parser.add_argument("--" + option, required=True, type=Path)
    parser.add_argument("--boot-sha256", required=True)
    parser.add_argument("--kernel-release", required=True)
    args = parser.parse_args()
    result = check(args.boot, args.boot_sha256, args.kernel_release, args.module, json.loads(args.baseline.read_text()))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(result["status"])
