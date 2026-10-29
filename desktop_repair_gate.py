"""Disable the pinned laptop repair service flag in the private DSU variant."""
import hashlib
import io
import struct
import zipfile
import zlib

from android_disk import require


JAR_PATH = "/system/framework/desktop-services.jar"
JAR_SHA256 = "126efcf2e5e717fa168855c4f1a0438ca721106b60972615e138d290063602f4"
DEX_SHA256 = "edf5b52c059cfeb1e5c0a126b44a6bd05c27d3867fa21d30fcba0c4a5733230c"
METHOD = "Lcom/android/desktop/services/flags/Flags;->enableDesktopRepairModeService()Z"
METHOD_ID = 5047
CODE_OFFSET = 1163128
INSTRUCTION_OFFSET = CODE_OFFSET + 16
CODE_HEADER = bytes.fromhex("0100000000000000723a320002000000")
OLD_INSTRUCTIONS = bytes.fromhex("12100f00")
NEW_INSTRUCTIONS = bytes.fromhex("12000f00")


def valid_checksums(dex):
    return (dex[12:32] == hashlib.sha1(dex[32:]).digest() and
            struct.unpack_from("<I", dex, 8)[0] == zlib.adler32(dex[12:]) & 0xffffffff)


def patch_dex(dex):
    require(hashlib.sha256(dex).hexdigest() == DEX_SHA256, "repair DEX source drift")
    require(dex[:8] == b"dex\n039\0" and
            struct.unpack_from("<III", dex, 32) == (len(dex), 112, 0x12345678), "unexpected DEX header")
    require(valid_checksums(dex), "invalid source DEX checksums")
    require(struct.unpack_from("<II", dex, 88) == (42117, 390084) and
            dex[390084 + METHOD_ID * 8:390084 + (METHOD_ID + 1) * 8] == bytes.fromhex("4c02762435720000"),
            "unexpected repair flag method ID")
    require(dex[CODE_OFFSET:INSTRUCTION_OFFSET] == CODE_HEADER, "unexpected repair code-item header")
    require(dex[INSTRUCTION_OFFSET:INSTRUCTION_OFFSET + 4] == OLD_INSTRUCTIONS,
            "unexpected repair flag instructions")
    result = bytearray(dex)
    result[INSTRUCTION_OFFSET:INSTRUCTION_OFFSET + 4] = NEW_INSTRUCTIONS
    result[12:32] = hashlib.sha1(result[32:]).digest()
    struct.pack_into("<I", result, 8, zlib.adler32(result[12:]) & 0xffffffff)
    require(valid_checksums(result) and result[INSTRUCTION_OFFSET:INSTRUCTION_OFFSET + 4] == NEW_INSTRUCTIONS,
            "patched DEX validation failed")
    require(result[:8] == dex[:8] and result[32:INSTRUCTION_OFFSET + 1] == dex[32:INSTRUCTION_OFFSET + 1] and
            result[INSTRUCTION_OFFSET + 2:] == dex[INSTRUCTION_OFFSET + 2:], "unexpected DEX byte delta")
    return bytes(result)


def disable_repair_mode(data):
    """Patch the stored DEX and its two ZIP CRC fields; retain every other byte.

    This is a reversible private-variant patch, not a runtime DSU condition.
    Full-install tablet partition management requires a separate implementation.
    """
    require(isinstance(data, bytes) and hashlib.sha256(data).hexdigest() == JAR_SHA256,
            "repair JAR source drift")
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        infos = source.infolist()
        require(len(source.namelist()) == len(set(source.namelist())), "duplicate repair JAR member")
        info = source.getinfo("classes.dex")
        require(info.compress_type == zipfile.ZIP_STORED and info.flag_bits == 0,
                "repair DEX must remain stored without descriptor or encryption")
        dex = source.read(info)
        patched = patch_dex(dex)
        crc = zlib.crc32(patched) & 0xffffffff
        local = info.header_offset
        require(data[local:local + 4] == b"PK\x03\x04" and
                struct.unpack_from("<H", data, local + 6)[0] == 0 and
                struct.unpack_from("<H", data, local + 8)[0] == zipfile.ZIP_STORED and
                struct.unpack_from("<III", data, local + 14) == (info.CRC, len(dex), len(dex)),
                "unexpected repair DEX local ZIP header")
        name_size, extra_size = struct.unpack_from("<HH", data, local + 26)
        payload = local + 30 + name_size + extra_size
        require(data[payload:payload + len(dex)] == dex, "unexpected stored DEX payload")
        end = len(data) - 22 - len(source.comment)
        require(data[end:end + 4] == b"PK\x05\x06" and
                struct.unpack_from("<4H", data, end + 4) == (0, 0, len(infos), len(infos)),
                "unexpected repair JAR directory")
        directory_size, cursor = struct.unpack_from("<II", data, end + 12)
        require(cursor + directory_size == end, "unexpected repair JAR directory bounds")
        central_crc = None
        for entry in infos:
            require(data[cursor:cursor + 4] == b"PK\x01\x02" and
                    struct.unpack_from("<I", data, cursor + 42)[0] == entry.header_offset,
                    "unexpected repair JAR central entry")
            if entry.filename == "classes.dex":
                central_crc = cursor + 16
                require(struct.unpack_from("<I", data, central_crc)[0] == info.CRC, "unexpected DEX central CRC")
            name_size, extra_size, comment_size = struct.unpack_from("<HHH", data, cursor + 28)
            cursor += 46 + name_size + extra_size + comment_size
        require(cursor == end and central_crc is not None, "missing repair DEX central entry")
        result = bytearray(data)
        edits = [(local + 14, struct.pack("<I", crc)), (payload, patched), (central_crc, struct.pack("<I", crc))]
        position = 0
        for offset, replacement in sorted(edits):
            require(position <= offset, "overlapping repair JAR edits")
            result[offset:offset + len(replacement)] = replacement
            require(result[position:offset] == data[position:offset], "unexpected JAR byte delta")
            position = offset + len(replacement)
        require(len(result) == len(data) and result[position:] == data[position:], "unexpected JAR layout delta")
        with zipfile.ZipFile(io.BytesIO(result)) as verified:
            require(verified.namelist() == source.namelist() and verified.testzip() is None,
                    "patched repair JAR validation failed")
            for entry in infos:
                require(verified.read(entry.filename) == (patched if entry.filename == "classes.dex" else source.read(entry)),
                        "unexpected JAR member delta: " + entry.filename)
    return bytes(result)
