#!/usr/bin/env python3
"""Read and extract Android GPT/liblp images; never write to a device.

Format reference: AOSP system/core/fs_mgr/liblp/include/liblp/metadata_format.h.
"""
import argparse
import hashlib
import json
import re
import struct
import zlib
from pathlib import Path


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read_at(stream, offset, size):
    require(offset >= 0 and size >= 0, "negative byte range")
    stream.seek(offset)
    data = stream.read(size)
    require(len(data) == size, "truncated image")
    return data


def checked_hash(data, start, end, expected):
    copy = bytearray(data)
    copy[start:end] = bytes(end - start)
    require(hashlib.sha256(copy).digest() == expected, "metadata SHA-256 mismatch")


def inventory(stream, image_size):
    header = read_at(stream, 512, 512)
    require(header[:8] == b"EFI PART", "missing GPT signature")
    size, crc = struct.unpack_from("<II", header, 12)
    require(92 <= size <= 512, "invalid GPT header size")
    copy = bytearray(header[:size])
    copy[16:20] = bytes(4)
    require(zlib.crc32(copy) == crc, "GPT header CRC mismatch")
    lba, count, entry_size = struct.unpack_from("<QII", header, 72)
    require(0 < count <= 4096 and entry_size == 128, "unsupported GPT table")
    require(lba * 512 + count * entry_size <= image_size, "GPT table outside image")
    table = read_at(stream, lba * 512, count * entry_size)
    require(zlib.crc32(table) == struct.unpack_from("<I", header, 88)[0],
            "GPT table CRC mismatch")
    physical = {}
    for offset in range(0, len(table), entry_size):
        entry = table[offset:offset + entry_size]
        if not any(entry[:16]):
            continue
        name = entry[56:128].decode("utf-16le").rstrip("\0")
        first, last = struct.unpack_from("<QQ", entry, 32)
        require(re.fullmatch(r"[A-Za-z0-9_-]+", name) and name not in physical,
                "unsafe or duplicate GPT name")
        require(first <= last and (last + 1) * 512 <= image_size,
                "GPT partition outside image")
        physical[name] = {"offset": first * 512, "bytes": (last - first + 1) * 512}
    require("super" in physical, "missing super partition")
    base = physical["super"]["offset"]
    super_size = physical["super"]["bytes"]
    geometry = read_at(stream, base + 4096, 4096)
    magic, size = struct.unpack_from("<II", geometry)
    require(magic == 0x616C4467 and size == 52, "unsupported LP geometry")
    checked_hash(geometry[:size], 8, 40, geometry[8:40])
    maximum, slots, block_size = struct.unpack_from("<III", geometry, 40)
    require(256 <= maximum <= 1024 * 1024 and 1 <= slots <= 3 and block_size == 4096,
            "unsupported LP geometry limits")
    header = read_at(stream, base + 12288, maximum)
    magic, major, minor, size = struct.unpack_from("<IHHI", header)
    require(magic == 0x414C5030 and major == 10 and minor <= 2 and size in (128, 256),
            "unsupported LP header")
    checked_hash(header[:size], 12, 44, header[12:44])
    table_size = struct.unpack_from("<I", header, 44)[0]
    require(size + table_size <= maximum, "LP tables outside metadata slot")
    tables = header[size:size + table_size]
    require(hashlib.sha256(tables).digest() == header[48:80], "LP table SHA-256 mismatch")
    descriptors = [struct.unpack_from("<III", header, 80 + i * 12) for i in range(4)]
    for offset, count, entry_size in descriptors:
        require(offset + count * entry_size <= len(tables), "LP descriptor outside table")
    (po, pn, ps), (eo, en, es), (go, gn, gs), (bo, bn, bs) = descriptors
    require(ps == 52 and es == 24 and gs == 48 and bs == 64 and bn == 1,
            "unsupported LP entry format or multiple block devices")
    require(struct.unpack_from("<Q", tables, bo + 16)[0] == super_size,
            "LP/GPT super size disagreement")
    groups = {}
    for i in range(gn):
        entry = tables[go + i * gs:go + (i + 1) * gs]
        groups[i] = {"name": entry[:36].split(b"\0")[0].decode(),
                     "maximum_bytes": struct.unpack_from("<Q", entry, 40)[0]}
    logical = {}
    for i in range(pn):
        entry = tables[po + i * ps:po + (i + 1) * ps]
        name = entry[:36].split(b"\0")[0].decode()
        attrs, first, count, group = struct.unpack_from("<IIII", entry, 36)
        require(re.fullmatch(r"[a-z0-9_]+", name) and name not in logical,
                "unsafe or duplicate LP name")
        require(first + count <= en and group in groups, "invalid partition extent/group")
        ranges = []
        for j in range(first, first + count):
            sectors, kind, target, source = struct.unpack_from("<QIQI", tables, eo + j * es)
            length = sectors * 512
            require(kind in (0, 1), "unsupported LP extent type")
            if kind == 0:
                require(source == 0 and target * 512 + length <= super_size,
                        "LP extent outside super")
                ranges.append({"offset": base + target * 512, "bytes": length})
            else:
                ranges.append({"offset": None, "bytes": length})
        logical[name] = {"bytes": sum(r["bytes"] for r in ranges),
                         "attributes": attrs, "group": groups[group]["name"], "ranges": ranges}
    return {"physical": physical, "logical": logical, "groups": groups}


def extract(stream, ranges, path):
    require(not path.exists(), f"refusing to overwrite {path}")
    digest = hashlib.sha256()
    with path.open("xb") as out:
        for region in ranges:
            offset, left = region["offset"], region["bytes"]
            if offset is not None:
                stream.seek(offset)
            while left:
                size = min(left, 8 * 1024 * 1024)
                block = bytes(size) if offset is None else stream.read(size)
                require(len(block) == size, "truncated partition")
                out.write(block)
                digest.update(block)
                left -= size
    return {"bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--partition", action="append", default=[])
    args = parser.parse_args()
    with args.image.open("rb") as stream:
        result = inventory(stream, args.image.stat().st_size)
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            extracted = {}
            for name in args.partition:
                if name in result["logical"]:
                    regions = result["logical"][name]["ranges"]
                else:
                    regions = [result["physical"][name]]
                extracted[name] = extract(stream, regions, args.out / (name + ".img"))
            result["extracted"] = extracted
            (args.out / "partition-manifest.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
