"""Bounded A/B payload v2 writer. No device or network operations.

Wire format: AOSP update_metadata.proto at dc84c2552b2d4cf00d2a843cb1c091d99d0499f1.
Defaults to full REPLACE, minor 0; allowlisted unchanged images may use SOURCE_COPY, minor 6.
Product alone may use a block delta against an explicit installed source image.
Only RSA/SHA-256 signatures are emitted.
"""
import base64
import hashlib
from pathlib import Path
import struct
import subprocess

BLOCK = 4096
CHUNK = 4 * 1024 * 1024
SOURCE_COPY_ALLOWED = frozenset({
    "boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system", "vbmeta_vendor",
    "vendor", "odm", "vendor_dlkm", "system_dlkm", "product",
})


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def varint(number):
    require(isinstance(number, int) and 0 <= number < 2**64, "invalid protobuf integer")
    result = bytearray()
    while number > 127:
        result.append((number & 127) | 128)
        number >>= 7
    return bytes(result + bytes([number]))


def field(number, value):
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return varint(number * 8 + 2) + varint(len(value)) + value
    return varint(number * 8) + varint(value)


def signature_message(signature):
    # fixed32 unpadded_signature_size, as emitted by AOSP PayloadSigner.
    item = field(2, signature) + varint(3 * 8 + 5) + struct.pack("<I", len(signature))
    return field(1, item)


def openssl(*args, data=None):
    result = subprocess.run(["openssl", *map(str, args)], input=data, capture_output=True)
    # Do not echo stderr: it can include private key locations or provider details.
    require(result.returncode == 0, "OpenSSL operation failed: " + args[0])
    return result.stdout


def public_key(certificate):
    return openssl("x509", "-in", certificate, "-pubkey", "-noout")


def sign_digest(digest, key):
    return openssl("pkeyutl", "-sign", "-inkey", key,
                   "-pkeyopt", "digest:sha256", "-pkeyopt", "rsa_padding_mode:pkcs1", data=digest)


def verify_digest(digest, signature, public, scratch):
    signature_path = scratch / "verification.signature"
    public_path = scratch / "verification.public.pem"
    try:
        signature_path.write_bytes(signature)
        public_path.write_bytes(public)
        openssl("pkeyutl", "-verify", "-pubin", "-inkey", public_path,
                "-sigfile", signature_path, "-pkeyopt", "digest:sha256",
                "-pkeyopt", "rsa_padding_mode:pkcs1", data=digest)
    finally:
        signature_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)


def _file_state(path):
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _product_delta(source, target, offset):
    """Index hashes only; compare candidate bytes before selecting a moved extent."""
    source_state, target_state = _file_state(source), _file_state(target)
    require(all(state[2] > 0 and state[2] % BLOCK == 0 for state in (source_state, target_state)),
            "unaligned raw Product delta input")
    index, old_digest = {}, hashlib.sha256()
    with source.open("rb") as stream:
        block = 0
        while data := stream.read(BLOCK):
            old_digest.update(data)
            index.setdefault(hashlib.sha256(data).digest(), []).append(block)
            block += 1
    operations, runs = [], []
    digest, run_digest = hashlib.sha256(), hashlib.sha256()
    run_source, run_target, count = None, 0, 0
    start_offset = offset

    def flush():
        nonlocal offset, count, run_digest
        if not count:
            return
        extent = field(1, run_target) + field(2, count)
        size = count * BLOCK
        if run_source is None:
            operation = (field(1, 0) + field(2, offset) + field(3, size)
                         + field(6, extent) + field(8, run_digest.digest()))
            offset += size
        else:
            operation = (field(1, 4) + field(4, field(1, run_source) + field(2, count))
                         + field(6, extent) + field(9, run_digest.digest()))
        operations.append(field(8, operation))
        runs.append((size, run_source is None))
        count, run_digest = 0, hashlib.sha256()

    with source.open("rb") as old, target.open("rb") as new:
        block = 0
        while data := new.read(BLOCK):
            require(len(data) == BLOCK, "Product target changed while planning")
            digest.update(data)
            source_block = None
            # Prefer continuing a run, including repeated zero blocks, before hash lookup.
            preferred = run_source + count if count and run_source is not None else block
            if preferred * BLOCK < source_state[2]:
                old.seek(preferred * BLOCK)
                if old.read(BLOCK) == data:
                    source_block = preferred
            if source_block is None:
                for candidate in index.get(hashlib.sha256(data).digest(), ()):
                    old.seek(candidate * BLOCK)
                    if old.read(BLOCK) == data:
                        source_block = candidate
                        break
            if count and (count * BLOCK == CHUNK
                          or (source_block is None) != (run_source is None)
                          or (source_block is not None and source_block != run_source + count)):
                flush()
            if not count:
                run_source, run_target = source_block, block
            run_digest.update(data)
            count += 1
            block += 1
        flush()
    require(_file_state(source) == source_state and _file_state(target) == target_state,
            "Product delta input changed while planning")
    return {"operations": b"".join(operations), "runs": runs, "blob_bytes": offset - start_offset,
            "old_info": field(1, source_state[2]) + field(2, old_digest.digest()),
            "new_info": field(1, target_state[2]) + field(2, digest.digest()),
            "source_sha256": old_digest.hexdigest(), "target_sha256": digest.hexdigest(),
            "source_state": source_state, "target_state": target_state}


def write_payload(images, groups, timestamp, virtual_ab, key, certificate, output, scratch,
                  *, source_copy_partitions=frozenset(), source_images=None):
    """images: ordered {name: Path}; raw byte lengths must be 4 KiB aligned.

    Opt-in set/frozenset must be a subset of SOURCE_COPY_ALLOWED. Each installed
    source must equal its target image byte-for-byte; that image pins both.
    source_images may be empty or {'product': Path}; it must not overlap that set.
    Product delta operations cover the entire target and copy byte-identical 4 KiB
    source blocks (including moved blocks); only unmatched target blocks are literal.
    """
    require(isinstance(source_copy_partitions, (set, frozenset))
            and source_copy_partitions <= SOURCE_COPY_ALLOWED, "SOURCE_COPY partition not allowlisted")
    require(source_copy_partitions <= images.keys(), "SOURCE_COPY partition missing from images")
    if source_images is None:
        source_images = {}
    require(isinstance(source_images, dict) and set(source_images) <= {"product"}
            and all(isinstance(path, Path) and path.is_file() and not path.is_symlink()
                    for path in source_images.values()), "source_images accepts only Product regular Path input")
    require(source_images.keys() <= images.keys(), "Product delta target missing from images")
    require(not source_copy_partitions & source_images.keys(), "Product delta overlaps SOURCE_COPY selection")
    public = public_key(certificate)
    probe = sign_digest(hashlib.sha256(b"native-payload-key-check").digest(), key)
    require(len(probe) in (256, 512), "only RSA-2048 or RSA-4096 payload keys are supported")
    verify_digest(hashlib.sha256(b"native-payload-key-check").digest(), probe, public, scratch)
    signature_size = len(signature_message(bytes(len(probe))))
    partitions = []
    blobs_size = 0
    expected = {}
    deltas = {}
    for name, path in images.items():
        if name in source_images:
            delta = _product_delta(source_images[name], path, blobs_size)
            deltas[name] = delta
            expected[name] = delta["target_sha256"]
            blobs_size += delta["blob_bytes"]
            partitions.append(field(13, field(1, name) + field(2, 0)
                                    + field(6, delta["old_info"]) + field(7, delta["new_info"])
                                    + delta["operations"]))
            continue
        source_copy = name in source_copy_partitions
        size = path.stat().st_size
        require(size > 0 and size % BLOCK == 0, "unaligned raw partition: " + name)
        digest = hashlib.sha256()
        operations = []
        with path.open("rb") as stream:
            block = 0
            while data := stream.read(CHUNK):
                digest.update(data)
                if not source_copy:
                    extent = field(1, block) + field(2, len(data) // BLOCK)
                    operations.append(field(8, field(1, 0) + field(2, blobs_size)
                                            + field(3, len(data)) + field(6, extent)
                                            + field(8, hashlib.sha256(data).digest())))
                    blobs_size += len(data)
                block += len(data) // BLOCK
            require(stream.tell() == size, "input size changed while packaging: " + name)
        expected[name] = digest.hexdigest()
        info = field(1, size) + field(2, digest.digest())
        if source_copy:
            extent = field(1, 0) + field(2, size // BLOCK)
            operations = [field(8, field(1, 4) + field(4, extent) + field(6, extent)
                                + field(9, digest.digest()))]
        partitions.append(field(13, field(1, name) + field(2, 0)
                                + (field(6, info) if source_copy else b"") + field(7, info)
                                + b"".join(operations)))
    dynamic = b""
    for group in groups:
        record = field(1, group["name"]) + field(2, group["maximum_size"])
        record += b"".join(field(3, name) for name in group["partitions"])
        dynamic += field(1, record)
    # VABC is deliberately disabled; uncompressed snapshot allocation needs parent review.
    dynamic += field(2, int(virtual_ab)) + field(3, 0)
    # Minor 3 adds source hashes; minor 6 also permits 64-bit REPLACE blob offsets.
    minor = 6 if source_copy_partitions or source_images else 0
    manifest = (field(3, BLOCK) + field(4, blobs_size) + field(5, signature_size)
                + field(12, minor) + b"".join(partitions) + field(14, timestamp)
                + field(15, dynamic) + field(16, 0))
    metadata = b"CrAU" + struct.pack(">QQI", 2, len(manifest), signature_size) + manifest
    metadata_digest = hashlib.sha256(metadata).digest()
    raw_metadata_signature = sign_digest(metadata_digest, key)
    metadata_signature = signature_message(raw_metadata_signature)
    require(len(metadata_signature) == signature_size, "metadata signature size changed")
    payload_digest = hashlib.sha256(metadata)
    require(not output.exists() and not output.is_symlink(), "payload output already exists")
    created = False
    try:
        with output.open("xb") as stream:
            created = True
            stream.write(metadata)
            stream.write(metadata_signature)
            for name, path in images.items():
                digest = hashlib.sha256()
                with path.open("rb") as source:
                    if name in deltas:
                        for size, literal in deltas[name]["runs"]:
                            data = source.read(size)
                            require(len(data) == size, "input changed while packaging: " + name)
                            digest.update(data)
                            if literal:
                                payload_digest.update(data)
                                stream.write(data)
                        require(not source.read(1), "input changed while packaging: " + name)
                        require(_file_state(path) == deltas[name]["target_state"],
                                "input changed while packaging: " + name)
                    else:
                        while data := source.read(CHUNK):
                            digest.update(data)
                            if name not in source_copy_partitions:
                                payload_digest.update(data)
                                stream.write(data)
                require(digest.hexdigest() == expected[name], "input changed while packaging: " + name)
            for name, source in source_images.items():
                require(sha256(source) == deltas[name]["source_sha256"]
                        and _file_state(source) == deltas[name]["source_state"],
                        "source input changed while packaging: " + name)
            signature = sign_digest(payload_digest.digest(), key)
            verify_digest(payload_digest.digest(), signature, public, scratch)
            verify_digest(metadata_digest, raw_metadata_signature, public, scratch)
            for name, delta in deltas.items():
                require(_file_state(images[name]) == delta["target_state"]
                        and _file_state(source_images[name]) == delta["source_state"],
                        "Product delta input changed while signing")
            stream.write(signature_message(signature))
    except BaseException:
        if created:
            output.unlink(missing_ok=True)
        raise
    size = output.stat().st_size
    properties = {
        "FILE_HASH": base64.b64encode(bytes.fromhex(sha256(output))).decode(),
        "FILE_SIZE": str(size),
        "METADATA_HASH": base64.b64encode(metadata_digest).decode(),
        "METADATA_SIZE": str(len(metadata)),
    }
    return properties, expected
