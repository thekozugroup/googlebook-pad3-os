"""Use TABLET for the pinned Pad 3 provider's final OPEN fallback."""
import hashlib
import struct
import zlib

from android_disk import require
from desktop_repair_gate import JAR_PATH, replace_stored_dex, valid_checksums
from patch_taskmanager import uleb


JAR_SHA256 = "498011e7fe850a1256cbc549235a5e9e2d9e0746afa8a3f7d346fda24b8a6325"
DEX_SHA256 = "5501cb96a197dbf53d4babe529ba964e01d6bb0b4482a09679210d2bf155a5f6"
METHOD = "Lcom/android/server/desktop/power/DesktopDeviceStateProvider;->getDeviceState()I"
METHOD_ID = 6627
METHOD_ENTRY = bytes.fromhex("6403a200d7770000")
CODE_OFFSET = 1279264
INSTRUCTION_OFFSET = CODE_OFFSET + 16
CODE_HEADER = bytes.fromhex("03000100000000006870330029000000")
CODE_SIZE = 98
METHOD_SHA256 = "b829632730a5733d417184e64daf12a530429a61faf968e6a8e4261137d6049f"
RETURN_OFFSET = INSTRUCTION_OFFSET + 75


def method_signature(dex):
    def string(index):
        table = struct.unpack_from("<I", dex, 60)[0]
        offset = struct.unpack_from("<I", dex, table + index * 4)[0]
        _, offset = uleb(dex, offset)
        return dex[offset:dex.index(b"\0", offset)].decode("utf-8")

    def typename(index):
        table = struct.unpack_from("<I", dex, 68)[0]
        return string(struct.unpack_from("<I", dex, table + index * 4)[0])

    table = struct.unpack_from("<I", dex, 92)[0]
    owner, proto, name = struct.unpack_from("<HHI", dex, table + METHOD_ID * 8)
    table = struct.unpack_from("<I", dex, 76)[0]
    _, result, parameters = struct.unpack_from("<III", dex, table + proto * 12)
    require(parameters == 0, "unexpected tablet method parameters")
    return typename(owner) + "->" + string(name) + "()" + typename(result)


def patch_dex(dex):
    require(hashlib.sha256(dex).hexdigest() == DEX_SHA256, "tablet DEX source drift")
    require(dex[:8] == b"dex\n039\0" and
            struct.unpack_from("<III", dex, 32) == (len(dex), 112, 0x12345678), "unexpected DEX header")
    require(valid_checksums(dex), "invalid source DEX checksums")
    require(struct.unpack_from("<II", dex, 88) == (42117, 390084) and
            dex[390084 + METHOD_ID * 8:390084 + (METHOD_ID + 1) * 8] == METHOD_ENTRY,
            "unexpected tablet method ID")
    require(method_signature(dex) == METHOD, "unexpected tablet method signature")
    require(dex[CODE_OFFSET:INSTRUCTION_OFFSET] == CODE_HEADER, "unexpected tablet code-item header")
    require(hashlib.sha256(dex[CODE_OFFSET:CODE_OFFSET + CODE_SIZE]).hexdigest() == METHOD_SHA256,
            "tablet full method drift")
    require(dex[RETURN_OFFSET - 1:RETURN_OFFSET + 7] == bytes.fromhex("1221280200000f01"),
            "unexpected tablet fallback instructions")
    result = bytearray(dex)
    result[RETURN_OFFSET] = 0x31
    result[12:32] = hashlib.sha1(result[32:]).digest()
    struct.pack_into("<I", result, 8, zlib.adler32(result[12:]) & 0xffffffff)
    require(valid_checksums(result) and result[RETURN_OFFSET] == 0x31, "patched tablet DEX validation failed")
    require(result[:8] == dex[:8] and result[32:RETURN_OFFSET] == dex[32:RETURN_OFFSET] and
            result[RETURN_OFFSET + 1:] == dex[RETURN_OFFSET + 1:], "unexpected tablet DEX byte delta")
    return bytes(result)


def patch_tablet_state(data):
    """Accept only the shipped JAR; preserve CLOSED, DOCKED and all other bytes."""
    require(isinstance(data, bytes) and hashlib.sha256(data).hexdigest() == JAR_SHA256,
            "tablet JAR source drift")
    return replace_stored_dex(data, patch_dex)
