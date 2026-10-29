"""Bounded full A/B payload v2 writer. No device or network operations.

Wire format: AOSP update_metadata.proto at dc84c2552b2d4cf00d2a843cb1c091d99d0499f1.
Only REPLACE operations, full minor version 0, and RSA/SHA-256 are emitted.
"""
import base64
import hashlib
import struct
import subprocess

BLOCK = 4096
CHUNK = 4 * 1024 * 1024


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


def write_payload(images, groups, timestamp, virtual_ab, key, certificate, output, scratch):
    """images: ordered {name: Path}; all raw byte lengths must be 4 KiB aligned."""
    public = public_key(certificate)
    probe = sign_digest(hashlib.sha256(b"native-payload-key-check").digest(), key)
    require(len(probe) in (256, 512), "only RSA-2048 or RSA-4096 payload keys are supported")
    verify_digest(hashlib.sha256(b"native-payload-key-check").digest(), probe, public, scratch)
    signature_size = len(signature_message(bytes(len(probe))))
    partitions = []
    blobs_size = 0
    expected = {}
    for name, path in images.items():
        size = path.stat().st_size
        require(size > 0 and size % BLOCK == 0, "unaligned raw partition: " + name)
        digest = hashlib.sha256()
        operations = []
        with path.open("rb") as stream:
            block = 0
            while data := stream.read(CHUNK):
                digest.update(data)
                extent = field(1, block) + field(2, len(data) // BLOCK)
                operations.append(field(8, field(1, 0) + field(2, blobs_size)
                                        + field(3, len(data)) + field(6, extent)
                                        + field(8, hashlib.sha256(data).digest())))
                block += len(data) // BLOCK
                blobs_size += len(data)
        expected[name] = digest.hexdigest()
        info = field(1, size) + field(2, digest.digest())
        partitions.append(field(13, field(1, name) + field(2, 0) + field(7, info)
                                + b"".join(operations)))
    dynamic = b""
    for group in groups:
        record = field(1, group["name"]) + field(2, group["maximum_size"])
        record += b"".join(field(3, name) for name in group["partitions"])
        dynamic += field(1, record)
    # VABC is deliberately disabled; uncompressed snapshot allocation needs parent review.
    dynamic += field(2, int(virtual_ab)) + field(3, 0)
    manifest = (field(3, BLOCK) + field(4, blobs_size) + field(5, signature_size)
                + field(12, 0) + b"".join(partitions) + field(14, timestamp)
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
                    while data := source.read(CHUNK):
                        digest.update(data)
                        payload_digest.update(data)
                        stream.write(data)
                require(digest.hexdigest() == expected[name], "input changed while packaging: " + name)
            signature = sign_digest(payload_digest.digest(), key)
            verify_digest(payload_digest.digest(), signature, public, scratch)
            verify_digest(metadata_digest, raw_metadata_signature, public, scratch)
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
