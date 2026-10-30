"""Rewrite reachable EROFS files, dropping removed files and obsolete image bytes."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import uuid

from android_disk import read_at, require
from erofs_overlay import content, metadata, tar_info
from maintenance_workspace import task_root

FIELDS = ("mode", "uid", "gid", "mtime", "mtime_nsec", "xattrs")


def inventory(image):
    """Walk directory entries independently of a host filesystem's case rules."""
    result, pending, directory_inodes = {}, ["/"], set()
    while pending:
        path = pending.pop()
        require(path not in result, "duplicate EROFS path")
        item = metadata(image, path)
        require(stat.S_ISDIR(item["mode"]), "directory entry is not a directory: " + path)
        require(item["nid"] not in directory_inodes, "directory hardlink or cycle")
        directory_inodes.add(item["nid"])
        result[path] = item
        text = subprocess.check_output(["dump.erofs", "--ls", "--path=" + path, str(image)], text=True)
        require(text.count("FILENAME\n") == 1, "unknown EROFS listing format")
        names = set()
        for line in text.split("FILENAME\n", 1)[1].splitlines():
            if not line.strip():
                continue
            match = re.fullmatch(r"\s*(\d+)\s+([1-7])\s{2}(.+)", line)
            require(match is not None, "unparsed EROFS directory entry")
            nid, kind, name = int(match[1]), int(match[2]), match[3]
            require(name not in names and not any(c in name for c in "/\0\r\n"), "unsafe directory entry")
            names.add(name)
            if name in (".", ".."):
                if name == ".":
                    require(nid == item["nid"] and kind == 2, "inconsistent directory inode")
                continue
            child = path.rstrip("/") + "/" + name
            require(child not in result and kind in (1, 2, 7), "unsupported or duplicate EROFS entry")
            if kind == 2:
                pending.append(child)
            else:
                child_meta = metadata(image, child)
                expected = stat.S_IFREG if kind == 1 else stat.S_IFLNK
                require(child_meta["nid"] == nid and stat.S_IFMT(child_meta["mode"]) == expected,
                        "inconsistent EROFS entry type or inode")
                result[child] = child_meta
        require({".", ".."} <= names, "directory listing is incomplete")
    return result


def file_size(image, item):
    with Path(image).open("rb") as stream:
        raw = read_at(stream, item["inode_offset"] + 8, 8 if item["format"] & 1 else 4)
    return int.from_bytes(raw, "little")


class HashReader:
    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    def read(self, size=-1):
        data = self.stream.read(size)
        self.digest.update(data)
        return data


def stream_file(image, path, size, archive=None, info=None):
    with subprocess.Popen(["dump.erofs", "--cat", "--path=" + path, str(image)],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            reader = HashReader(process.stdout)
            if archive is not None:
                info.size = size
                archive.addfile(info, reader)
                require(not reader.read(1), "file grew while copying into tar")
            else:
                remaining = size
                while remaining:
                    data = reader.read(min(1024 * 1024, remaining))
                    require(data, "truncated EROFS file")
                    remaining -= len(data)
                require(not reader.read(1), "EROFS size mismatch")
            require(process.wait() == 0, "EROFS content read failed: " + path)
            return reader.digest.hexdigest()
        except BaseException:
            process.kill()
            process.wait()
            raise


def rewrite(image, output, removals, scratch):
    image, output, scratch = map(Path, (image, output, scratch))
    require(image.is_file() and not image.is_symlink(), "expected a regular source image")
    require(not output.exists() and not output.is_symlink() and output.resolve().is_relative_to(scratch.resolve()),
            "output must be a fresh path under task scratch")
    task_root(scratch, Path(__file__).resolve().parent)
    require(isinstance(removals, set) and all(isinstance(p, str) and p.startswith("/")
            and str(PurePosixPath(p)) == p and ".." not in PurePosixPath(p).parts for p in removals),
            "removals must contain canonical absolute image paths")
    with image.open("rb") as stream:
        before_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    before = inventory(image)
    require(removals <= before.keys() and all(not stat.S_ISDIR(before[p]["mode"]) for p in removals),
            "only existing files or symlinks may be removed")
    kept = {p: m for p, m in before.items() if p not in removals}
    expected_hashes, hardlinks = {}, {}
    created = False
    try:
        with tempfile.TemporaryDirectory(prefix="erofs-rewrite-", dir=scratch) as directory:
            tar_path = Path(directory) / "reachable.tar"
            with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(kept, key=lambda p: (p.count("/"), p)):
                    item = kept[path]
                    directory_entry = stat.S_ISDIR(item["mode"])
                    info = tar_info(path.lstrip("/") or ".", item, directory=directory_entry)
                    if directory_entry:
                        archive.addfile(info)
                    elif stat.S_ISLNK(item["mode"]):
                        target = content(image, path)
                        require(len(target) == file_size(image, item) and b"\0" not in target, "invalid symlink")
                        info.type, info.linkname = tarfile.SYMTYPE, target.decode("utf-8")
                        archive.addfile(info)
                        expected_hashes[path] = hashlib.sha256(target).hexdigest()
                    elif item["nid"] in hardlinks:
                        first = hardlinks[item["nid"]]
                        require(all(item[k] == kept[first][k] for k in FIELDS), "inconsistent hardlink metadata")
                        info.type, info.linkname = tarfile.LNKTYPE, first.lstrip("/")
                        archive.addfile(info)
                        expected_hashes[path] = expected_hashes[first]
                    else:
                        expected_hashes[path] = stream_file(image, path, file_size(image, item), archive, info)
                        hardlinks[item["nid"]] = path
            with image.open("rb") as stream:
                filesystem_uuid = str(uuid.UUID(bytes=read_at(stream, 1024 + 48, 16)))
            created = True
            subprocess.run(["mkfs.erofs", "--tar=f", "--preserve-mtime", "-x0", "-b4096", "-T1230768000",
                            "--mkfs-time", "-U" + filesystem_uuid, "-zlz4hc", "--workers=2", "--quiet",
                            str(output), str(tar_path)], check=True)
        subprocess.run(["fsck.erofs", "--extract", str(output)], check=True, stdout=subprocess.DEVNULL)
        after = inventory(output)
        require(after.keys() == kept.keys(), "rewritten EROFS path set changed")
        output_links = {}
        for path, expected in kept.items():
            actual = after[path]
            require(all(actual[k] == expected[k] for k in FIELDS), "rewritten inode metadata changed: " + path)
            if stat.S_ISDIR(actual["mode"]):
                continue
            digest = (hashlib.sha256(content(output, path)).hexdigest() if stat.S_ISLNK(actual["mode"])
                      else stream_file(output, path, file_size(output, actual)))
            require(digest == expected_hashes[path], "rewritten content changed: " + path)
            if stat.S_ISREG(actual["mode"]):
                group = output_links.setdefault(expected["nid"], actual["nid"])
                require(group == actual["nid"], "hardlink group was split")
        with image.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == before_hash, "source image changed")
        with output.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        return {"bytes": output.stat().st_size, "sha256": digest,
                "removed_paths": sorted(removals), "verified_paths": len(kept), "verified_file_hashes": len(expected_hashes),
                "source_sha256": before_hash, "full_rewrite": True, "obsolete_source_bytes_copied": False}
    except BaseException:
        if created:
            output.unlink(missing_ok=True)
        raise
