"""Adjust only the pinned bootanimation's canvas and trim metadata in memory."""
import copy
import hashlib
import io
import struct
import zipfile


SOURCE_SHA256 = "c9e7265fd892ddd16898124320dcfee9506b7ff2208bf8fe028419d5efc52911"
SOURCE_DESC = b"2880 1800 60\nc 1 0 part0\nc 120 0 part1\nc 1 0 part2\n"
TARGET_DESC = b"2544 1800 60\n" + SOURCE_DESC.split(b"\n", 1)[1]
SOURCE_TRIM = b"1402x1800+739+0\n"
TARGET_TRIM = b"1402x1800+571+0\n"
PART_FRAME_COUNTS = {"part0": 98, "part1": 1, "part2": 46}
METADATA_FIELDS = (
    "filename", "date_time", "compress_type", "comment", "extra", "create_system",
    "create_version", "extract_version", "reserved", "flag_bits", "volume",
    "internal_attr", "external_attr", "file_size", "compress_size", "header_offset",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fix_geometry(data):
    """Return a ZIP with only desc.txt and trim.txt contents changed.

    The exact source archive is pinned. PNGs are never decoded or rewritten.
    Input/output ZIPs and all verification stay in memory; no files are created.
    """
    require(isinstance(data, bytes), "bootanimation ZIP must be bytes")
    require(hashlib.sha256(data).hexdigest() == SOURCE_SHA256, "bootanimation source ZIP drift")
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        infos = source.infolist()
        names = source.namelist()
        require(len(names) == len(set(names)), "duplicate bootanimation ZIP member")
        require("desc.txt" in names and source.read("desc.txt") == SOURCE_DESC,
                "unexpected canvas, FPS or part/repetition description")
        require(all(info.compress_type == zipfile.ZIP_STORED for info in infos),
                "expected stored bootanimation ZIP members")
        require({name for name in names if name.endswith("/trim.txt")} ==
                {part + "/trim.txt" for part in PART_FRAME_COUNTS}, "unexpected trim file set")
        changes = {"desc.txt": TARGET_DESC}
        pngs = {name for name in names if name.endswith(".png")}
        require(len(pngs) == sum(PART_FRAME_COUNTS.values()), "unexpected PNG count")
        for part, count in PART_FRAME_COUNTS.items():
            frames = [name for name in pngs if name.rpartition("/")[0] == part]
            require(len(frames) == count, "unexpected frame count: " + part)
            trim = part + "/trim.txt"
            require(source.read(trim) == SOURCE_TRIM * count, "unexpected trim entries: " + trim)
            changes[trim] = TARGET_TRIM * count
        for name in pngs:
            header = source.read(name)[:24]
            require(len(header) == 24 and header[:16] == b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" and
                    struct.unpack(">II", header[16:24]) == (1402, 1800), "unexpected PNG dimensions: " + name)
        with zipfile.ZipFile(output, "w") as destination:
            destination.comment = source.comment
            for info in infos:
                payload = changes[info.filename] if info.filename in changes else source.read(info)
                destination.writestr(copy.copy(info), payload)
        result = output.getvalue()
        require(len(result) == len(data), "bootanimation ZIP layout size changed")
        with zipfile.ZipFile(io.BytesIO(result)) as verified:
            require(verified.namelist() == names and verified.comment == source.comment,
                    "bootanimation member order or archive comment changed")
            for before, after in zip(infos, verified.infolist()):
                require(all(getattr(before, field) == getattr(after, field) for field in METADATA_FIELDS),
                        "bootanimation ZIP metadata changed: " + before.filename)
                payload = verified.read(after)
                if before.filename in changes:
                    require(payload == changes[before.filename], "geometry metadata verification failed")
                else:
                    require(before.CRC == after.CRC and hashlib.sha256(payload).digest() ==
                            hashlib.sha256(source.read(before)).digest(),
                            "non-geometry payload changed: " + before.filename)
    return result
