"""Stage the reviewed OplusPen policy without changing images or pinned profiles."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from android_disk import require
from check_policy import check

PACKAGE = "org.lineageos.pen"
SEINFO = "pad3_pen"
NATIVE_CIL_SHA256 = "f084917951637b823362fdaba923f67729d16d3753cd775036a6663f55ac56f3"
SELECTOR = ("user=_app isPrivApp=true seinfo=pad3_pen name=org.lineageos.pen "
            "domain=pen_app type=app_data_file levelFrom=user\n").encode()
MEMBERSHIPS = ("domain", "appdomain", "bluetoothdomain", "coredomain", "halclientdomain",
               "vendor_hal_oplus_touch_client")
FILENAMES = ("system_ext_sepolicy.cil", "system_ext_mac_permissions.xml", "system_ext_seapp_contexts")
HASH_FILENAME = "system_ext_sepolicy_and_mapping.sha256"


def certificate_hex(certificate):
    """Accept complete canonical X.509 DER bytes or their hexadecimal string."""
    if isinstance(certificate, str):
        require(re.fullmatch(r"(?:[0-9a-fA-F]{2})+", certificate) is not None,
                "certificate must be DER bytes or complete DER hex")
        certificate = bytes.fromhex(certificate)
    require(isinstance(certificate, bytes) and 0 < len(certificate) <= 16384,
            "certificate must be DER bytes or complete DER hex")
    result = subprocess.run(["openssl", "x509", "-inform", "DER", "-outform", "DER"],
                            input=certificate, capture_output=True)
    require(result.returncode == 0 and result.stdout == certificate,
            "certificate is not a complete canonical X.509 DER certificate")
    return certificate.hex()


def native_pen_module(native_cil):
    """Extract only pen_app and its macro restrictions from the pinned native CIL."""
    require(hashlib.sha256(native_cil).hexdigest() == NATIVE_CIL_SHA256,
            "native system_ext policy changed; review pen_app rules")
    lines = native_cil.decode().splitlines()
    selected = []
    for attribute in MEMBERSHIPS:
        require(any(line.startswith("(typeattributeset " + attribute + " ") and
                    re.search(r"\bpen_app\b", line) for line in lines),
                "native pen_app membership missing: " + attribute)
        selected.append("(typeattributeset " + attribute + " (pen_app))")
    for line in lines:
        if (re.match(r"\((type|roletype|typetransition|allow|dontaudit|neverallow) ", line) and
                re.search(r"\bpen_app(?:_[a-z_]+)?\b", line)) or line.startswith(
                    "(neverallow base_typeattr_1347 base_typeattr_1346 ") or re.match(
                    r"\(typeattribute(?:set)? base_typeattr_(134[6-9]|1350)[ )]", line):
            selected.append(line)
    module = "\n".join(selected)
    # Native generated attribute numbers belong to another policy; keep these private.
    module = re.sub(r"\bbase_typeattr_(134[6-9]|1350)\b", r"pad3_pen_native_\1", module)
    require(not re.search(r"\bbase_typeattr_\d+\b", module), "unreviewed native attribute dependency")
    return ("\n;; Pad3 pen-only policy from native system_ext " + NATIVE_CIL_SHA256 + "\n" + module + "\n").encode()


def signer_contexts(mac_permissions, seapp_contexts, certificate, *, other_mac_permissions=(),
                    other_seapp_contexts=()):
    """Append one signer/package binding and selector, preserving donor bytes."""
    signature = certificate_hex(certificate)
    for data in (mac_permissions, *other_mac_permissions):
        require(b"<!DOCTYPE" not in data and b"<!ENTITY" not in data, "unsupported mac_permissions declaration")
        try:
            root = ET.fromstring(data)
        except ET.ParseError as error:
            raise ValueError("invalid mac_permissions XML") from error
        require(root.tag == "policy", "expected mac_permissions policy root")
        for node in root.iter():
            require(node.get("signature", "").lower() != signature,
                    "duplicate or conflicting certificate mapping")
            require(not (node.tag == "package" and node.get("name") == PACKAGE),
                    "duplicate or conflicting pen package mapping")
            require(not (node.tag == "seinfo" and node.get("value") == SEINFO),
                    "duplicate or conflicting pad3_pen mapping")
    for data in (seapp_contexts, *other_seapp_contexts):
        for line in data.decode().splitlines():
            fields = dict(token.split("=", 1) for token in line.split("#", 1)[0].split() if "=" in token)
            name = fields.get("name", "")
            require(not (name == PACKAGE or (name.endswith("*") and PACKAGE.startswith(name[:-1])) or
                         fields.get("seinfo", "").split(":", 1)[0] == SEINFO or fields.get("domain") == "pen_app"),
                    "duplicate or conflicting pen seapp selector")
    require(mac_permissions.count(b"</policy>") == 1, "expected one explicit mac_permissions closing tag")
    entry = (f'\n    <signer signature="{signature}"><package name="{PACKAGE}">'
             f'<seinfo value="{SEINFO}"/></package></signer>\n').encode()
    mac = mac_permissions.replace(b"</policy>", entry + b"</policy>", 1)
    seapp = seapp_contexts + (b"" if not seapp_contexts or seapp_contexts.endswith(b"\n") else b"\n") + SELECTOR
    return mac, seapp


def prepare_pen_policy(images, native_cil, certificate, compiler, work):
    """Return a JSON-safe report and system_ext candidate paths for an image overlay.

    images is the system/system_ext/product path dictionary accepted by compile_policy;
    native_cil is the cached native system_ext CIL bytes. work must be a fresh directory
    inside the caller's active CleanOS task. No APK, key, image or profile is written.
    """
    # The builder may import this helper when selecting its V10 path.
    from build_dsu_diagnostic import SOURCE, PARTITIONS, compile_policy

    work = Path(work)
    require(work == work.resolve() and not work.exists() and
            work.is_relative_to(Path("/private/tmp/ai-development")), "use a fresh local task candidate directory")
    owners = [p / ".cleanos-task.json" for p in work.parents if (p / ".cleanos-task.json").is_file()]
    require(bool(owners), "active CleanOS task ownership required")
    owner = json.loads(owners[0].read_text())
    require(owner["owner"] == os.getuid() and owner["project"] == str(SOURCE) and not owner["finished"],
            "active CleanOS task ownership required")
    require(set(images) == set(PARTITIONS), "expected system/system_ext/product images")
    signature = certificate_hex(certificate)
    module = native_pen_module(native_cil)
    work.mkdir()
    baseline_root = work / "baseline-inputs"
    baseline = compile_policy(images, compiler, baseline_root, work / "baseline-check")
    base_hashes = {str(p.relative_to(baseline_root)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in baseline_root.rglob("*") if p.is_file()}
    for path in baseline_root.rglob("*.cil"):
        require(not re.search(rb"\b(?:pen_app(?:_[a-z_]+)?|pad3_pen_native_\d+)\b", path.read_bytes()),
                "pen policy already present in baseline")
    extension = baseline_root / "system_ext"
    profile = SOURCE / "profiles/erhai-crdroid-20261025"
    cil, mac, seapp = [(extension / name).read_bytes() for name in FILENAMES]
    other_mac = [p.read_bytes() for p in baseline_root.rglob("*_mac_permissions.xml") if p != extension / FILENAMES[1]]
    other_seapp = [p.read_bytes() for p in baseline_root.rglob("*_seapp_contexts") if p != extension / FILENAMES[2]]
    mac, seapp = signer_contexts(mac, seapp, signature, other_mac_permissions=other_mac,
                                 other_seapp_contexts=other_seapp)
    updates = dict(zip(FILENAMES, (cil + module, mac, seapp)))
    if (extension / HASH_FILENAME).is_file():
        version = (profile / "policy/vendor/plat_sepolicy_vers.txt").read_text().strip()
        mapping = extension / "mapping" / (version + ".cil")
        require(mapping.is_file(), "system_ext policy hash mapping input missing")
        mapping_bytes = mapping.read_bytes()
        # Match Android.bp's system_ext_sepolicy_and_mapping.sha256_gen.
        expected = (hashlib.sha256(cil + mapping_bytes).hexdigest() + "\n").encode()
        require((extension / HASH_FILENAME).read_bytes() == expected,
                "system_ext donor policy hash algorithm/input mismatch")
        updates[HASH_FILENAME] = (hashlib.sha256(cil + module + mapping_bytes).hexdigest() + "\n").encode()
    candidate_root = work / "candidate-inputs"
    shutil.copytree(baseline_root, candidate_root)
    files = {}
    for name, data in updates.items():
        path = candidate_root / "system_ext" / name
        path.write_bytes(data)
        files["/etc/selinux/" + name] = {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
                                         "bytes": len(data), "base_sha256": base_hashes["system_ext/" + name]}
    candidate = check(compiler, candidate_root / "system", candidate_root / "system_ext", candidate_root / "product",
                      profile / "policy/vendor", profile / "policy/odm", work / "candidate-check")
    for result, directory in [(baseline, work / "baseline-check"), (candidate, work / "candidate-check")]:
        strict = directory / "strict-policy"
        result["strict_compiled_sha256"] = hashlib.sha256(strict.read_bytes()).hexdigest() if strict.is_file() else None
    require(base_hashes == {str(p.relative_to(baseline_root)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in baseline_root.rglob("*") if p.is_file()}, "baseline files changed")
    report = {"baseline": baseline, "candidate": candidate, "files": files, "package": PACKAGE, "seinfo": SEINFO,
              "certificate_sha256": hashlib.sha256(bytes.fromhex(signature)).hexdigest(),
              "native_system_ext_cil_sha256": NATIVE_CIL_SHA256, "pen_module_sha256": hashlib.sha256(module).hexdigest(),
              "baseline_files_preserved": True, "images_or_profiles_written": False}
    (work / "pen-policy-report.json").write_text(json.dumps(report, indent=2) + "\n")
    require(candidate["strict_neverallow_pass"] and candidate["strict_neverallow_failures"] == 0,
            "pen candidate fails strict policy; inspect candidate-check/strict.log")
    return report
