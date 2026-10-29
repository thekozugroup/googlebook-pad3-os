"""Read regular files and their original metadata from a verified EXT4 image."""
import re
import stat
import subprocess

from android_disk import require

DEBUGFS = "/opt/homebrew/opt/e2fsprogs/sbin/debugfs"


def command(image, text):
    result = subprocess.run([DEBUGFS, "-R", text, str(image)], capture_output=True)
    require(result.returncode == 0, "debugfs read failed: " + result.stderr.decode(errors="replace"))
    return result.stdout


def regular_file(image, path, scratch):
    require(re.fullmatch(r"/[A-Za-z0-9_./@+-]+", path) and ".." not in path.split("/"),
            "unsafe EXT4 input path")
    text = command(image, "stat " + path).decode()
    require("Type: regular" in text, "EXT4 source is not a regular file: " + path)
    mode = re.search(r"Mode:\s+([0-7]+)", text)
    ids = re.search(r"User:\s+(\d+)\s+Group:\s+(\d+)", text)
    size = re.search(r"Size:\s+(\d+)", text)
    timestamp = re.search(r"mtime:\s+0x([0-9a-f]+):([0-9a-f]+)", text)
    require(all((mode, ids, size, timestamp)), "unrecognized debugfs stat output")
    require(int(timestamp[2], 16) == 0, "nonzero EXT4 nanosecond/epoch extension needs review")
    meta = {"mode": stat.S_IFREG | int(mode[1], 8), "uid": int(ids[1]), "gid": int(ids[2]),
            "mtime": int(timestamp[1], 16), "xattrs": {}}
    attrs = command(image, "ea_list " + path).decode()
    for name, length in re.findall(r"^\s+([a-zA-Z0-9_.]+) \((\d+)\)", attrs, re.MULTILINE):
        require(name.startswith(("security.", "trusted.", "user.")), "unknown EXT4 xattr namespace")
        target = scratch / ("ext4-attr-" + name)
        require(not target.exists() and not target.is_symlink(), "temporary xattr target already exists")
        try:
            command(image, "ea_get -f " + str(target) + " " + path + " " + name)
            value = target.read_bytes()
            require(len(value) == int(length), "EXT4 xattr length mismatch")
            meta["xattrs"][name] = value
        finally:
            target.unlink(missing_ok=True)
    require("security.selinux" in meta["xattrs"], "source SELinux label missing")
    data = command(image, "cat " + path)
    require(len(data) == int(size[1]), "EXT4 file content length mismatch")
    return {"data": data, "metadata": meta}
