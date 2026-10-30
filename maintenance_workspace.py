#!/usr/bin/env python3
"""Owned Linux scratch, with the existing CleanOS boundary on macOS."""
import argparse
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import tempfile

CLEANOS_ROOT = Path("/private/tmp/ai-development")
CLEANOS_MARKER = ".cleanos-task.json"
LINUX_MARKER = ".pad3-maintenance-task.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def local_path(path):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(), "use a canonical physical path")
    parts = [part.casefold() for part in path.parts]
    require(not any(part in {"documents", "desktop", "mobile documents", "cloudstorage", "icloud drive", "dropbox", "google drive"}
                    or part.startswith(("onedrive", "googledrive")) for part in parts),
            "workspace must be outside cloud sync")
    return path


def task_root(path, project, *, root_only=False, backup_excluded=False):
    path, project = local_path(path), local_path(project)
    require(project.is_dir(), "project directory is missing")
    host = platform.system()
    require(host in {"Darwin", "Linux"}, "unsupported workspace host")
    markers = [(parent, name) for parent in (path, *path.parents)
               for name in (CLEANOS_MARKER, LINUX_MARKER)
               if (parent / name).exists() or (parent / name).is_symlink()]
    require(len(markers) == 1, "scratch needs exactly one active task owner")
    root, name = markers[0]
    require(not root_only or root == path, "scratch must be a task root")
    require(root.is_dir() and root.stat().st_uid == os.getuid(), "scratch owner mismatch")
    require(not root.is_relative_to(project) and not project.is_relative_to(root), "scratch overlaps source")
    marker = root / name
    require(marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == os.getuid(), "invalid task marker")
    if host == "Darwin":
        require(name == CLEANOS_MARKER and root.parent == CLEANOS_ROOT, "use an existing CleanOS task on macOS")
    else:
        require(name == LINUX_MARKER, "initialize owned Linux scratch explicitly")
        require(stat.S_IMODE(root.stat().st_mode) == 0o700
                and stat.S_IMODE(marker.stat().st_mode) == 0o600, "Linux task must be private")
    require(marker.stat().st_size <= 16384, "task marker is too large")
    owner = json.loads(marker.read_text())
    require(owner.get("schema") == 1 and owner.get("id") == root.name
            and type(owner.get("owner")) is int and owner["owner"] == os.getuid()
            and owner.get("project") == str(project) and owner.get("finished") is False,
            "inactive or foreign task")
    if host == "Darwin" and backup_excluded:
        result = subprocess.run(["tmutil", "isexcluded", str(path)], capture_output=True, text=True, check=True)
        require("[Excluded]" in result.stdout, "scratch backup-copy exclusion not verified")
    return root


def init_linux(parent, project):
    require(platform.system() == "Linux", "macOS uses supported CleanOS task creation")
    parent, project = local_path(parent), local_path(project)
    require(parent.is_dir() and project.is_dir(), "parent and project must exist")
    require(not parent.is_relative_to(project), "scratch overlaps source")
    require(not any((p / name).exists() or (p / name).is_symlink()
                    for p in (parent, *parent.parents) for name in (CLEANOS_MARKER, LINUX_MARKER)),
            "task ownership cannot be nested")
    root = Path(tempfile.mkdtemp(prefix="pad3-maintenance-", dir=parent))
    try:
        root.chmod(0o700)
        marker = root / LINUX_MARKER
        with open(marker, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
            json.dump(dict(schema=1, id=root.name, owner=os.getuid(), project=str(project), finished=False), stream)
        task_root(root, project, root_only=True)
        return root
    except BaseException:
        (root / LINUX_MARKER).unlink(missing_ok=True)
        root.rmdir()
        raise


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError("invalid workspace arguments")
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=["init"])
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        root = init_linux(args.parent, args.project)
        print(json.dumps({"status": "initialized", "task": root.name}))
        return 0
    except (ValueError, OSError, TypeError, subprocess.SubprocessError):
        print(json.dumps({"status": "blocked", "reason": "workspace validation failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
