"""Functional changes for schema 2's exact clean mica R5 image lineage.

Schema 2 adds lineage="mica-r5-16693588" and files.tablet_graft_source to the
schema-1 recipe. The latter is the immutable V10 SystemExt, used only for its
eight reviewed audio/QCC files and extracted pen policy. Binary patch guards
remain independent: a changed R5 JAR or boot animation stops assembly.
"""
import hashlib
import re
import stat
from pathlib import Path

from assemble_port import GRAFT
from erofs_overlay import content, metadata
from native_install import product_cleanup, public_image
from native_install.payload import require
from pen_policy import NATIVE_CIL_SHA256, signer_contexts
import port_changes as port


ROOT = Path(__file__).resolve().parent.parent
LINEAGE = "mica-r5-16693588"
IMAGE_SHAS = {
    "system": "9cfaeb99137407f7a995e91cdac3e0ce27c6ef2891297445e6dbbc2e88d363d3",
    "system_ext": "8001bfe664ab35d2b49056ff9906729cb80c70720f73f240bca085efe3f41a4d",
    "product": "d1b40955110d9f6a92cf9f597d3b6ef370a2476487c2fc47b2e0d3bea9b48297",
}
GRAFT_SHA = "6424a51ccf1fbefa99ba7a24e8f33de02be0b432662b176268c97e59d8e69ff8"
PEN_MODULE_SHA = "aa61904a79d3f1e91369ddacc6bb005d10d4e681c0d7f8a8461eebd9f5970fcb"
POLICY = "/etc/selinux/system_ext_sepolicy.cil"
MAPPING = "/etc/selinux/mapping/202604.cil"
POLICY_HASH = "/etc/selinux/system_ext_sepolicy_and_mapping.sha256"
FILE_CONTEXTS = "/etc/selinux/system_ext_file_contexts"
MAC = "/etc/selinux/system_ext_mac_permissions.xml"
SEAPP = "/etc/selinux/system_ext_seapp_contexts"
PEN_GRANTS = "/etc/default-permissions/default-permissions_org.lineageos.pen.xml"
PEN_GRANTS_SHA = "b47d73b9b47c0bf77c99170ec9b4cb4c417ebdffe2a24eddec965c90030023ce"
PEN_USERS = "/etc/sysconfig/googlebook-pad3-pen.xml"
PEN_USER_XML = b'''<?xml version="1.0" encoding="utf-8"?>
<config>
    <install-in-user-type package="org.lineageos.pen">
        <install-in user-type="FULL"/>
        <do-not-install-in user-type="SYSTEM"/>
    </install-in-user-type>
</config>
'''
AUDIO_CONTEXT = b"/(system_ext|system/system_ext)/bin/qtiaudiohalvendorextn u:object_r:audio_vendor_parameter_parser_exec:s0\n"


def validate_lineage(recipe):
    require(recipe.get("lineage") == LINEAGE and recipe["sequence"] >= 5,
            "schema 2 requires clean mica R5 lineage and native sequence >= 5")
    require(isinstance(recipe["images"], dict) and set(recipe["images"]) == set(IMAGE_SHAS) and all(
        isinstance(recipe["images"][name], dict) and recipe["images"][name].get("sha256") == digest
        for name, digest in IMAGE_SHAS.items()),
        "schema 2 requires the three exact signed R5 target image hashes")
    require(isinstance(recipe["files"]["tablet_graft_source"], dict)
            and recipe["files"]["tablet_graft_source"].get("sha256") == GRAFT_SHA,
            "schema 2 requires the immutable V10 tablet graft source")


def production_init(data):
    public_image.audit_text(data)
    require(data.count(b"on early-init\n") == 1 and b"vendor.usb.use_gadget_hal" not in data,
            "clean init USB anchor drift; review R5")
    return data.replace(b"on early-init\n", b"on early-init\n    setprop vendor.usb.use_gadget_hal 0\n", 1)


def pen_policy(cil, mapping, digest, seeded_cil):
    require(digest == (hashlib.sha256(cil + mapping).hexdigest() + "\n").encode(),
            "clean system_ext policy/mapping hash mismatch")
    require(not re.search(rb"\b(?:pen_app(?:_[a-z_]+)?|pad3_pen_native_\d+)\b", cil),
            "pen policy is already present in clean donor")
    marker = ("\n;; Pad3 pen-only policy from native system_ext " + NATIVE_CIL_SHA256 + "\n").encode()
    require(seeded_cil.count(marker) == 1, "immutable pen policy marker drift")
    module = marker + seeded_cil.split(marker, 1)[1]
    require(hashlib.sha256(module).hexdigest() == PEN_MODULE_SHA, "immutable pen policy module drift")
    candidate = cil + module
    return candidate, (hashlib.sha256(candidate + mapping).hexdigest() + "\n").encode()


def plan(images, partition, graft_source, certificate):
    """Return functional payloads, metadata-bearing grafts and bounded removals.

    The caller validates the entire recipe and actual file hashes before planning.
    No diagnostic image, key, watchdog or boot-stage logging is constructed.
    """
    require(partition in IMAGE_SHAS, "unsupported clean donor partition")
    payloads = port.tablet_changes(images)[partition]
    grafts, removals = {}, set()
    if partition == "system":
        properties = {part: content(image, "/system/build.prop" if part == "system" else "/etc/build.prop")
                      for part, image in images.items()}
        properties["system"] = payloads["/system/build.prop"]
        payloads["/system/build.prop"] = port.display_heap_properties(properties)
        payloads["/system/etc/init/hw/init.rc"] = production_init(content(images[partition], "/system/etc/init/hw/init.rc"))
        payloads[port.JAR_PATH] = port.disable_repair_mode(content(images[partition], port.JAR_PATH))
        payloads[port.REPAIR_SYSCONFIG_PATH] = port.disable_repair_receiver(content(images[partition], port.REPAIR_SYSCONFIG_PATH))
        payloads[port.TIPS_SYSCONFIG_PATH] = port.TIPS_SYSCONFIG
    elif partition == "product":
        payloads["/etc/build.prop"] = port.replace_property(payloads["/etc/build.prop"],
                                                          "ro.setupwizard.require_network", "", expected="any")
        payloads["/media/bootanimation.zip"] = port.fix_geometry(content(images[partition], "/media/bootanimation.zip"))
        removals = set(product_cleanup.REMOVALS)
    else:
        image = images[partition]
        contexts = content(image, FILE_CONTEXTS)
        require(b"/bin/qtiaudiohalvendorextn" not in contexts, "audio extension path already labeled")
        payloads[FILE_CONTEXTS] = contexts.rstrip() + b"\n" + AUDIO_CONTEXT
        for relative in GRAFT:
            path = "/" + relative
            meta = metadata(graft_source, path)
            require(stat.S_ISREG(meta["mode"]), "tablet graft is not a regular file: " + path)
            grafts[path] = {"data": content(graft_source, path), "metadata": meta}
        payloads[POLICY], payloads[POLICY_HASH] = pen_policy(
            content(image, POLICY), content(image, MAPPING), content(image, POLICY_HASH), content(graft_source, POLICY))
        other_mac, other_seapp = [], []
        for part, prefix, stem in (("system", "/system", "plat"), ("product", "", "product")):
            other_mac.append(content(images[part], prefix + "/etc/selinux/" + stem + "_mac_permissions.xml"))
            other_seapp.append(content(images[part], prefix + "/etc/selinux/" + stem + "_seapp_contexts"))
        payloads[MAC], payloads[SEAPP] = signer_contexts(
            content(image, MAC), content(image, SEAPP), certificate,
            other_mac_permissions=other_mac, other_seapp_contexts=other_seapp)
        payloads[PEN_GRANTS] = (ROOT / "components/oplus-pen/integration/default-permissions_org.lineageos.pen.xml").read_bytes()
        require(hashlib.sha256(payloads[PEN_GRANTS]).hexdigest() == PEN_GRANTS_SHA, "pen default grants source drift")
        payloads[PEN_USERS] = PEN_USER_XML
    return payloads, grafts, removals
