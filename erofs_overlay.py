#!/usr/bin/env python3
"""Apply a small tar overlay while preserving original EROFS inode metadata.

Metadata layout reference: Linux include/uapi/linux/erofs_fs.h. The incremental
workflow was cross-checked against skylartaylor/gbos-vm's pinned ARM port.
"""
import base64
import hashlib
import io
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from android_disk import read_at, require


def content(image, path):
    return subprocess.check_output(["dump.erofs", "--cat", "--path=" + path, str(image)])


def inode_record(stream, nid=None):
    """Read structural fields without interpreting possibly damaged xattrs."""
    sb = read_at(stream, 1024, 128)
    require(sb[:4] == bytes.fromhex("e2e1f5e0"), "invalid EROFS superblock")
    require(9 <= sb[12] <= 16, "invalid EROFS block size")
    # shortcut: 48-bit/metabox formats are unsupported; add their addressing before accepting them.
    require(not struct.unpack_from("<I", sb, 80)[0] & (0x80 | 0x100),
            "unsupported EROFS metadata addressing")
    block_size = 1 << sb[12]
    root_nid = struct.unpack_from("<H", sb, 14)[0]
    nid = root_nid if nid is None else nid
    meta, xbase = struct.unpack_from("<II", sb, 40)
    offset = meta * block_size + nid * 32
    inode = read_at(stream, offset, 32)
    fmt, count, mode = struct.unpack_from("<HHH", inode)
    require(fmt & ~15 == 0 and (fmt >> 1) <= 4, "unsupported EROFS inode format")
    inode_size = 64 if fmt & 1 else 32
    inode = read_at(stream, offset, inode_size)
    uid, gid = struct.unpack_from("<II" if fmt & 1 else "<HH", inode, 24)
    epoch = struct.unpack_from("<Q", sb, 24)[0]
    mtime = struct.unpack_from("<Q", inode, 32)[0] if fmt & 1 else epoch + struct.unpack_from("<I", inode, 12)[0]
    nsec = struct.unpack_from("<I", inode, 40)[0] if fmt & 1 else struct.unpack_from("<I", sb, 32)[0]
    blob = read_at(stream, offset + inode_size, 12 + (count - 1) * 4) if count else b""
    return {"mode": mode, "uid": uid, "gid": gid, "mtime": mtime, "mtime_nsec": nsec,
            "nid": nid, "root_nid": root_nid, "inode_offset": offset, "inode_size": inode_size,
            "format": fmt, "block_size": block_size, "xattr_block": xbase,
            "xattr_count": count, "xattr_blob": blob}


def metadata(image, path):
    text = subprocess.check_output(["dump.erofs", "--path=" + path, str(image)], text=True)
    match = re.search(r"NID: (\d+)", text)
    require(match is not None, "missing EROFS inode ID")
    with Path(image).open("rb") as stream:
        result = inode_record(stream, int(match[1]))
        offset, inode_size = result["inode_offset"], result["inode_size"]
        blob = result["xattr_blob"]
        attrs = {}
        shared_entries = {}

        def entry(position, end=None):
            require(end is None or position + 4 <= end, "truncated EROFS xattr header")
            size, index, length = struct.unpack("<BBH", read_at(stream, position, 4))
            padded = (4 + size + length + 3) & ~3
            require(end is None or position + padded <= end, "truncated EROFS xattr value")
            value = read_at(stream, position + 4, size + length)
            prefix = {1: "user.", 2: "system.posix_acl_access", 3: "system.posix_acl_default",
                      4: "trusted.", 6: "security."}.get(index)
            require(prefix is not None, "unsupported EROFS xattr prefix")
            require(index not in (2, 3) or size == 0, "invalid EROFS ACL name")
            name = prefix + value[:size].decode()
            require("\0" not in name and name not in attrs, "invalid or duplicate EROFS xattr name")
            attrs[name] = value[size:]
            return padded

        if blob:
            start = offset + inode_size
            shared = blob[4]
            require(12 + shared * 4 <= len(blob), "invalid EROFS shared xattr table")
            for i in range(shared):
                pointer = struct.unpack_from("<I", blob, 12 + i * 4)[0]
                position = result["xattr_block"] * result["block_size"] + pointer * 4
                shared_entries[position] = read_at(stream, position, entry(position))
            position = start + 12 + shared * 4
            while position < start + len(blob):
                position += entry(position, start + len(blob))
            require(position == start + len(blob), "misaligned EROFS xattrs")
        return dict(result, xattrs=attrs, shared_xattrs=shared_entries)


def restore_root_xattrs(image, before):
    """Repair the original root body before trying to decode the new root."""
    if not before["xattr_blob"]:
        return
    with Path(image).open("r+b") as stream:
        after = inode_record(stream)
        for key in ("root_nid", "nid", "inode_offset", "inode_size", "xattr_count",
                    "block_size", "xattr_block"):
            require(before[key] == after[key], "cannot safely restore EROFS root xattrs: " + key)
        require(stat.S_ISDIR(after["mode"]), "EROFS root is not a directory")
        for position, value in before["shared_xattrs"].items():
            require(read_at(stream, position, len(value)) == value,
                    "EROFS root shared xattr table changed")
        stream.seek(after["inode_offset"] + after["inode_size"])
        stream.write(before["xattr_blob"])
    update_crc(Path(image))


def tar_info(name, meta, directory=False):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = stat.S_IMODE(meta["mode"])
    info.uid, info.gid, info.mtime = meta["uid"], meta["gid"], meta["mtime"]
    info.pax_headers = {"LIBARCHIVE.xattr." + quote(k, safe=""): base64.b64encode(v).decode("ascii")
                        for k, v in meta["xattrs"].items()}
    if meta.get("mtime_nsec"):
        info.pax_headers["mtime"] = f'{meta["mtime"]}.{meta["mtime_nsec"]:09d}'
    return info


def update_crc(image):
    with image.open("r+b") as stream:
        sb = read_at(stream, 1024, 128)
        if not struct.unpack_from("<I", sb, 8)[0] & 1:
            return
        block = bytearray(read_at(stream, 1024, 3072))
        block[4:8] = bytes(4)
        crc = 0xFFFFFFFF
        for value in block:
            crc ^= value
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
        stream.seek(1028)
        stream.write(struct.pack("<I", crc))


def apply(image, output, changes, scratch, *, additions=None):
    """Replace existing files; additions require {data: bytes, metadata: dict}.

    Addition metadata requires full file/directory mode, uid, gid, mtime, and
    bytes-valued xattrs. New directories need explicit metadata and empty data.
    Optional mtime_nsec defaults to zero. All other parents must exist.
    """
    image, output, scratch = Path(image), Path(output), Path(scratch)
    additions = additions or {}
    require(not output.exists() and not output.is_symlink(), "refusing to overwrite an output image")
    require(bool(changes or additions), "empty overlay")
    require(not changes.keys() & additions.keys(), "addition overlaps an existing-file change")
    for name in list(changes) + list(additions):
        require(isinstance(name, str) and name.startswith("/") and not name.startswith("//") and
                not any(c in name for c in "\0\n\r") and ".." not in PurePosixPath(name).parts and
                str(PurePosixPath(name)) == name, "unsafe overlay path")
    for data in changes.values():
        require(isinstance(data, bytes), "overlay content must be bytes")
    new_metadata = {}
    for name, addition in additions.items():
        require(isinstance(addition, dict) and set(addition) == {"data", "metadata"},
                "addition requires data and explicit metadata")
        require(isinstance(addition["data"], bytes), "overlay content must be bytes")
        meta = addition["metadata"]
        require(isinstance(meta, dict) and {"mode", "uid", "gid", "mtime", "xattrs"} <= meta.keys(),
                "incomplete addition metadata")
        for key, maximum in (("mode", 0o177777), ("uid", 0xFFFFFFFF), ("gid", 0xFFFFFFFF),
                             ("mtime", 0x7FFFFFFFFFFFFFFF)):
            require(type(meta[key]) is int and 0 <= meta[key] <= maximum,
                    "invalid addition metadata: " + key)
        require(stat.S_ISREG(meta["mode"]) or stat.S_ISDIR(meta["mode"]),
                "addition must have a regular-file or directory mode")
        require(not stat.S_ISDIR(meta["mode"]) or (name != "/" and addition["data"] == b""),
                "new directory requires a non-root path and empty data")
        nsec = meta.get("mtime_nsec", 0)
        require(type(nsec) is int and 0 <= nsec < 1000000000, "invalid addition mtime_nsec")
        require(isinstance(meta["xattrs"], dict) and all(
            isinstance(k, str) and k and "\0" not in k and isinstance(v, bytes)
            for k, v in meta["xattrs"].items()), "addition xattrs must map names to bytes")
        new_metadata[name] = dict(meta, mtime_nsec=nsec)
    new_directories = {name: meta for name, meta in new_metadata.items() if stat.S_ISDIR(meta["mode"])}
    directories = {"/"} | new_directories.keys()
    old = {}
    for name, data in changes.items():
        old[name] = metadata(image, name)
        require(stat.S_ISREG(old[name]["mode"]), "overlay target is not a regular file")
    for name in list(changes) + list(additions):
        for parent in PurePosixPath(name).parents:
            directories.add(str(parent))
    originals = {d: new_directories[d] if d in new_directories else metadata(image, d) for d in directories}
    require(all(stat.S_ISDIR(meta["mode"]) for meta in originals.values()),
            "overlay parent is not an existing directory")
    parent_names = {}
    for name in additions:
        parent = str(PurePosixPath(name).parent)
        if parent not in parent_names:
            if parent in new_directories:
                parent_names[parent] = {".", ".."}
            else:
                listing = subprocess.check_output(["dump.erofs", "--ls", "--path=" + parent, str(image)],
                                                  text=True)
                parent_names[parent] = set(re.findall(r"^\s*\d+\s+\d+  (.*)$", listing, re.MULTILINE))
            require({".", ".."} <= parent_names[parent], "cannot verify addition parent entries")
        require(PurePosixPath(name).name not in parent_names[parent],
                "addition target already exists: " + name)
    require(originals["/"]["block_size"] == 4096, "incremental overlay requires 4096-byte blocks")
    payloads = changes | {name: addition["data"] for name, addition in additions.items()
                          if name not in new_directories}
    expected_files = old | {name: meta for name, meta in new_metadata.items() if name not in new_directories}
    created = False
    try:
        with tempfile.NamedTemporaryFile(dir=scratch, suffix="-overlay.tar") as overlay:
            with tarfile.open(fileobj=overlay, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for directory in sorted(directories, key=lambda p: (p.count("/"), p)):
                    name = directory.lstrip("/") or "."
                    info = tar_info(name, originals[directory], directory=True)
                    if directory == "/":
                        info.pax_headers = {k: v for k, v in info.pax_headers.items()
                                            if not k.startswith("LIBARCHIVE.xattr.")}
                    archive.addfile(info)
                for name, data in payloads.items():
                    info = tar_info(name.lstrip("/"), expected_files[name])
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            overlay.flush()
            with image.open("rb") as source, output.open("xb") as destination:
                created = True
                shutil.copyfileobj(source, destination)
            subprocess.run(["mkfs.erofs", "--incremental=data", "--tar=f", "-x0", "-b4096",
                            "-T1230768000", "--mkfs-time", "-zlz4hc", "--workers=2", str(output), overlay.name],
                           check=True, stdout=subprocess.DEVNULL)
        # erofs-utils 1.9.4 clears the root's shared-xattr reference during incremental import.
        restore_root_xattrs(output, originals["/"])
        for path, data in payloads.items():
            require(content(output, path) == data, "overlay content verification failed: " + path)
            actual = metadata(output, path)
            for key in ("mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs"):
                require(actual[key] == expected_files[path][key], "file metadata changed: " + path + ":" + key)
        for path, expected in originals.items():
            actual = metadata(output, path)
            for key in ("mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs"):
                require(actual[key] == expected[key], "directory metadata changed: " + path + ":" + key)
        subprocess.run(["fsck.erofs", "--extract", str(output)], check=True)
        with output.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        return {"bytes": output.stat().st_size, "sha256": digest,
                "changed_paths": sorted(changes.keys() | additions.keys())}
    except BaseException:
        if created:
            output.unlink()
        raise
