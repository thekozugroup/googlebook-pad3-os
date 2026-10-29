"""Inspect and patch only the previously observed single-fragment vendor_boot v4 layout."""
import gzip
import hashlib
import struct
import subprocess

from native_install.payload import require

TARGETS = {"system", "system_ext", "product"}


def entries(text):
    result = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            parts = line.split()
            require(len(parts) == 5, "unsupported fstab entry")
            result.append(parts)
    return result


def check_fstab(text, filesystem):
    rows = [row for row in entries(text) if row[0] in TARGETS]
    require({row[0] for row in rows} == TARGETS and len(rows) == 3,
            "expected exactly three native userspace fstab entries")
    for source, mount, kind, flags, manager in rows:
        require(mount == "/" + source and kind == filesystem,
                "native fstab filesystem mismatch: " + source)
        require("ro" in flags.split(",") and
                {"wait", "slotselect", "logical", "first_stage_mount", "avb=vbmeta_system"}
                <= set(manager.split(",")), "unsafe first-stage fstab flags")


def erofs_fstab(text):
    check_fstab(text, "ext4")
    result = []
    for line in text.splitlines(keepends=True):
        columns = line.split()
        if columns and columns[0] in TARGETS:
            # ext4-only barrier/discard mount options must not reach EROFS.
            columns[2:4] = ["erofs", "ro"]
            line = " ".join(columns) + "\n"
        result.append(line)
    result = "".join(result)
    check_fstab(result, "erofs")
    return result


def cpio_records(blob):
    records, cursor, names = [], 0, set()
    while True:
        start = cursor
        require(cursor + 110 <= len(blob) and blob[cursor:cursor + 6] == b"070701",
                "expected newc initramfs without CRC")
        header = [int(blob[cursor + i:cursor + i + 8], 16) for i in range(6, 110, 8)]
        size, name_size = header[6], header[11]
        require(0 < name_size < 4096 and cursor + 110 + name_size <= len(blob), "invalid cpio name")
        raw_name = blob[cursor + 110:cursor + 110 + name_size]
        require(raw_name[-1:] == b"\0", "unterminated cpio name")
        name = raw_name[:-1].decode()
        require(name not in names and not name.startswith("/") and ".." not in name.split("/"),
                "duplicate or unsafe cpio path")
        names.add(name)
        data_at = (cursor + 110 + name_size + 3) & ~3
        cursor = (data_at + size + 3) & ~3
        require(cursor <= len(blob), "truncated cpio entry")
        records.append((name, header, blob[data_at:data_at + size], blob[start:cursor]))
        if name == "TRAILER!!!":
            require(not any(blob[cursor:]), "unexpected data after cpio trailer")
            return records


def decode_ramdisk(packed):
    if packed.startswith(b"\x1f\x8b"):
        raw, compression = gzip.decompress(packed), "gzip"
    elif packed.startswith(b"\x02\x21\x4c\x18"):
        process = subprocess.run(["lz4", "-d", "-c"], input=packed, capture_output=True)
        require(process.returncode == 0, "LZ4 ramdisk decoding failed")
        raw, compression = process.stdout, "lz4-legacy"
    else:
        require(packed.startswith(b"070701"), "unreviewed ramdisk compression")
        raw, compression = packed, "raw"
    return cpio_records(raw), compression


def encode_ramdisk(records, name, compression):
    matches = [r for r in records if r[0] in (name, "./" + name)]
    require(len(matches) == 1, "expected exactly one selected fstab")
    replacement = erofs_fstab(matches[0][2].decode()).encode()
    raw = bytearray()
    for path, header, content, original in records:
        if path not in (name, "./" + name):
            raw.extend(original)
            continue
        header = list(header)
        require(header[1] & 0o170000 == 0o100000 and header[4] == 1, "fstab must be a regular non-hardlinked file")
        header[6] = len(replacement)
        raw.extend(b"070701" + b"".join(f"{number:08x}".encode() for number in header))
        raw.extend(path.encode() + b"\0")
        raw.extend(bytes(-len(raw) % 4))
        raw.extend(replacement)
        raw.extend(bytes(-len(raw) % 4))
    if compression == "gzip":
        return gzip.compress(bytes(raw), mtime=0)
    if compression == "lz4-legacy":
        process = subprocess.run(["lz4", "-l", "-c"], input=raw, capture_output=True)
        require(process.returncode == 0, "LZ4 ramdisk encoding failed")
        return process.stdout
    require(compression == "raw", "unreviewed ramdisk encoding")
    return bytes(raw)


def unpack_vendor_boot(data):
    require(len(data) >= 4096 and data[:8] == b"VNDRBOOT", "expected vendor_boot image")
    version, page = struct.unpack_from("<II", data, 8)
    require((version, page) == (4, 4096), "unreviewed vendor_boot header/page size")
    header_size = struct.unpack_from("<I", data, 2096)[0]
    ramdisk_size = struct.unpack_from("<I", data, 24)[0]
    dtb_size = struct.unpack_from("<I", data, 2100)[0]
    table_size, count, entry_size, config_size = struct.unpack_from("<IIII", data, 2112)
    require(header_size == 2128 and count == 1 and entry_size == 108 and table_size == 108,
            "unreviewed vendor ramdisk fragment table")
    align = lambda value: (value + page - 1) // page * page
    dtb_at = page + align(ramdisk_size)
    table_at = dtb_at + align(dtb_size)
    config_at = table_at + align(table_size)
    end = config_at + align(config_size)
    require(end <= len(data), "vendor_boot sections outside image")
    require(struct.unpack_from("<III", data, table_at) == (ramdisk_size, 0, 1),
            "expected one complete platform ramdisk")
    packed = data[page:page + ramdisk_size]
    records, compression = decode_ramdisk(packed)
    matches = [item for item in records if item[0] in ("system/etc/fstab.default", "./system/etc/fstab.default")]
    require(len(matches) == 1, "expected one system/etc/fstab.default")
    # Additional fstab files must be reviewed separately, not silently left ext4-only.
    require(len([r for r in records if "fstab" in r[0].split("/")[-1]]) == 1,
            "multiple first-stage fstab files require review")
    return {"records": records, "fstab": matches[0][2].decode(), "compression": compression,
            "dtb": data[dtb_at:dtb_at + dtb_size],
            "table": data[table_at:table_at + table_size],
            "bootconfig": data[config_at:config_at + config_size], "end": end}


def patch_vendor_boot(data):
    data = unsigned_vendor_boot(data)
    before = unpack_vendor_boot(data)
    require(not any(data[before["end"]:]),
            "vendor_boot has appended AVB/nonzero data; use reviewed AVB tooling first")
    packed = encode_ramdisk(before["records"], "system/etc/fstab.default", before["compression"])
    result = bytearray(data[:4096])
    struct.pack_into("<I", result, 24, len(packed))
    table = bytearray(before["table"])
    struct.pack_into("<I", table, 0, len(packed))
    for section in (packed, before["dtb"], table, before["bootconfig"]):
        result.extend(section)
        result.extend(bytes(-len(result) % 4096))
    require(len(result) <= len(data), "patched vendor_boot exceeds captured partition size")
    result.extend(bytes(len(data) - len(result)))
    after = unpack_vendor_boot(result)
    check_fstab(after["fstab"], "erofs")
    require(after["dtb"] == before["dtb"] and after["bootconfig"] == before["bootconfig"],
            "vendor_boot DTB/bootconfig changed")
    for old, new in zip(before["records"], after["records"], strict=True):
        if "fstab" not in old[0]:
            require(old == new, "unrelated vendor ramdisk entry changed")
    return bytes(result)


def unsigned_vendor_boot(data):
    """Remove only a structurally checked AVB footer region in an in-memory copy."""
    parsed = unpack_vendor_boot(data)
    return strip_avb(data, parsed["end"])


def strip_avb(data, end):
    if data[-64:-60] == b"AVBf":
        magic, major, minor, original, offset, size = struct.unpack_from(">4sIIQQQ", data, len(data) - 64)
        require(major == 1 and minor == 0 and end <= original <= offset
                and offset + size <= len(data) - 64 and data[offset:offset + 4] == b"AVB0",
                "unreviewed vendor_boot AVB footer")
        require(not any(data[end:offset]) and not any(data[offset + size:-64]),
                "unexpected vendor_boot data outside AVB footer")
        return data[:end] + bytes(len(data) - end)
    require(not any(data[end:]), "unreviewed vendor_boot trailing data")
    return data


def unpack_recovery(data):
    require(len(data) >= 4096 and data[:8] == b"ANDROID!", "expected Android recovery boot image")
    require(struct.unpack_from("<I", data, 40)[0] == 4 and struct.unpack_from("<I", data, 20)[0] == 1584,
            "unreviewed recovery boot header")
    require(struct.unpack_from("<I", data, 1580)[0] == 0, "recovery GKI signature needs separate review")
    kernel_size, ramdisk_size = struct.unpack_from("<II", data, 8)
    align = lambda size: (size + 4095) // 4096 * 4096
    at = 4096 + align(kernel_size)
    end = at + align(ramdisk_size)
    require(ramdisk_size > 0 and end <= len(data) and not any(data[at + ramdisk_size:end]),
            "recovery ramdisk outside image or unreviewed nonzero padding")
    records, compression = decode_ramdisk(data[at:at + ramdisk_size])
    matches = [r for r in records if r[0] in ("system/etc/recovery.fstab", "./system/etc/recovery.fstab")]
    require(len(matches) == 1 and len([r for r in records if "fstab" in r[0].split("/")[-1]]) == 1,
            "unreviewed recovery fstab set")
    return {"records": records, "fstab": matches[0][2].decode(), "compression": compression,
            "kernel": data[4096:4096 + kernel_size], "kernel_span": data[4096:at], "end": end}


def patch_recovery(data):
    before = unpack_recovery(data)
    data = strip_avb(data, before["end"])
    packed = encode_ramdisk(before["records"], "system/etc/recovery.fstab", before["compression"])
    result = bytearray(data[:4096])
    struct.pack_into("<I", result, 12, len(packed))
    result.extend(before["kernel_span"])
    result.extend(packed)
    result.extend(bytes(-len(result) % 4096))
    require(len(result) <= len(data), "patched recovery exceeds captured partition size")
    result.extend(bytes(len(data) - len(result)))
    after = unpack_recovery(result)
    check_fstab(after["fstab"], "erofs")
    require(after["kernel"] == before["kernel"], "recovery kernel changed")
    for old, new in zip(before["records"], after["records"], strict=True):
        if "fstab" not in old[0]:
            require(old == new, "unrelated recovery ramdisk entry changed")
    return bytes(result)


def recovery_filesystem_decision(stock, candidate, filesystem):
    before, after = unpack_recovery(stock), unpack_recovery(candidate)
    check_fstab(after["fstab"], filesystem)
    already_erofs = {row[2] for row in entries(before["fstab"]) if row[0] in TARGETS} == {"erofs"}
    if filesystem == "erofs" and already_erofs:
        check_fstab(before["fstab"], "erofs")
        require(candidate == stock, "native EROFS recovery baseline changed")
    elif filesystem == "erofs":
        require(strip_avb(candidate, after["end"]) == patch_recovery(stock), "recovery differs from bounded EROFS patch")
    else:
        require(filesystem == "ext4" and candidate == stock, "EXT4 route must retain captured recovery")
    return {"filesystem": filesystem, "kernel_preserved": before["kernel"] == after["kernel"],
            "stock_fstab_sha256": hashlib.sha256(before["fstab"].encode()).hexdigest(),
            "candidate_fstab_sha256": hashlib.sha256(after["fstab"].encode()).hexdigest(),
            "runtime_mount_verified": False}


def filesystem_decision(stock, candidate, filesystem):
    original, updated = unpack_vendor_boot(stock), unpack_vendor_boot(candidate)
    check_fstab(updated["fstab"], filesystem)
    already_erofs = {row[2] for row in entries(original["fstab"]) if row[0] in TARGETS} == {"erofs"}
    if filesystem == "erofs" and already_erofs:
        check_fstab(original["fstab"], "erofs")
        require(candidate == stock, "native EROFS vendor_boot baseline changed")
    elif filesystem == "erofs":
        require(unsigned_vendor_boot(candidate) == patch_vendor_boot(stock), "vendor_boot differs from bounded EROFS patch")
    else:
        require(filesystem == "ext4" and candidate == stock, "EXT4 route must retain captured vendor_boot")
    return {"filesystem": filesystem, "stock_fstab_sha256": hashlib.sha256(original["fstab"].encode()).hexdigest(),
            "candidate_fstab_sha256": hashlib.sha256(updated["fstab"].encode()).hexdigest()}
