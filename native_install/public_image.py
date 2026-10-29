"""Read-only EROFS release checks; never read an embedded ADB key's contents."""
import re
import subprocess

from native_install.payload import require

DIAGNOSTIC = re.compile(rb"googlebook[-_](?:dsu|debug|probe|crash|boot[-_]?watchdog)|(?:gb[-_])?dsu[-_](?:boot|watchdog|crash|adb|log)", re.I)


def listing(image, path):
    result = subprocess.run(["dump.erofs", "--ls", "--path=" + path, str(image)], capture_output=True)
    require(result.returncode == 0 and b"NID:" in result.stdout and b"FILENAME" in result.stdout
            and not result.stderr.strip(), "cannot establish complete EROFS directory listing: " + path)
    rows = re.findall(rb"^\s*\d+\s+(\d+)\s+([^\r\n]+)$", result.stdout, re.MULTILINE)
    require(rows and any(name == b"." for _, name in rows), "EROFS directory listing missing dot entry")
    return {name.decode(): int(kind) for kind, name in rows if name not in (b".", b"..")}


def exists(image, path):
    current = ""
    components = path.strip("/").split("/")
    for number, component in enumerate(components):
        entries = listing(image, current or "/")
        if component not in entries:
            return False
        if number < len(components) - 1:
            require(entries[component] == 2, "release path crosses a symlink/non-directory: " + path)
        current += "/" + component
    return True


def audit_text(blob):
    require(not DIAGNOSTIC.search(blob), "private DSU/debug service or checkpoint remains")
    require(not re.search(rb"^\s*setprop\s+(?:persist\.sys\.usb\.config\s+[^\r\n]*adb|ro\.boot\.apex\.early_adbd\s+)",
                          blob, re.MULTILINE), "forced diagnostic ADB startup remains")
    require(not re.search(rb"^(?:ro\.secure|ro\.adb\.secure)=0$|^(?:ro\.debuggable|ro\.force\.debuggable)=1$"
                          rb"|^(?:service\.adb\.listen_addrs|service\.adb\.tcp\.port|persist\.adb\.tcp\.port)=.+$"
                          rb"|^ro\.boot\.apex\.early_adbd=|^persist\.sys\.usb\.config=.*adb",
                          blob, re.MULTILINE), "diagnostic/insecure ADB property remains")


def check(images, read_file, prefix):
    for partition, path in (("system", "/adb_keys"), ("system", prefix + "/etc/security/adb_keys"),
                            ("product", "/etc/security/adb_keys")):
        require(not exists(images[partition], path), "public native image must remove key file/symlink: " + partition + ":" + path)
    for partition, root in (("system", prefix), ("product", ""), ("system_ext", "")):
        for prop in ((root + "/build.prop",) if partition == "system" else ("/etc/build.prop",)):
            audit_text(read_file(images[partition], prop))
        for directory in (root + "/etc/init", root + "/bin"):
            if not exists(images[partition], directory):
                continue
            pending = [directory]
            while pending:
                parent = pending.pop()
                for name, kind in listing(images[partition], parent).items():
                    require(not DIAGNOSTIC.search(name.encode()), "private diagnostic file remains: " + name)
                    path = parent + "/" + name
                    if kind == 2:
                        pending.append(path)
                    elif name.endswith(".rc") and kind == 1:
                        audit_text(read_file(images[partition], path))
    return {"adb_key_paths_absent": True, "diagnostic_init_properties_and_service_paths_rejected": True}
