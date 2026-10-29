"""Check descriptor coverage, chain keys and rollback indices with pinned avbtool."""
import importlib.util
from contextlib import ExitStack

from native_install.payload import require, sha256

AVBTOOL_SHA = "e5a664a38db623da00f080219bc0ee60a640a9dc4a872803616fae4938ac749b"


def verify(images, captured, avbtool, keys, mode="verified"):
    require(sha256(avbtool) == AVBTOOL_SHA, "avbtool source pin mismatch")
    spec = importlib.util.spec_from_file_location("native_pinned_avbtool", avbtool)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Upstream ImageHandler has no context manager and leaks descriptors in library use.
    image_type = module.ImageHandler
    with ExitStack() as handles:
        class OwnedImage(image_type):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                handles.callback(self._image.close)
        module.ImageHandler = OwnedImage
        if mode == "preserve-native-disabled":
            return _preserve_disabled(module, images, captured)
        require(mode == "verified", "explicit AVB mode required")
        return _verify(module, images, captured, keys)


def _preserve_disabled(module, images, captured):
    """Keep the observed unlocked-native flags, never silently clear AVB flags."""
    engine, evidence = module.Avb(), {}
    for name in ("vbmeta", "vbmeta_system", "vbmeta_vendor"):
        require(sha256(images[name]) == sha256(captured[name]), "disabled-AVB mode must preserve all captured vbmeta bytes")
        image = module.ImageHandler(str(images[name]), read_only=True)
        footer, header, descriptors, _ = engine._parse_image(image)
        require(header.flags == (3 if name == "vbmeta" else 0), "captured native AVB flags differ from reviewed 3/0/0")
        require(header.algorithm_type != 0, "captured vbmeta must still have a valid signature")
        image.seek(footer.vbmeta_offset if footer else 0)
        blob = image.read(header.SIZE + header.authentication_data_block_size + header.auxiliary_data_block_size)
        require(module.verify_vbmeta_signature(header, blob), "captured vbmeta signature is invalid")
        evidence[name] = {"flags": header.flags, "rollback_index": header.rollback_index}
    evidence["mode"] = "preserve-native-disabled"
    evidence["limitation"] = "AVB verification and verity remain disabled as captured; unlocked bootloader required. OTA RSA signatures are separate. No relock support."
    return evidence


def _verify(module, images, captured, keys):
    engine = module.Avb()
    # The actual Pad 3 root chains to boot/dtbo/recovery/vendor_boot as well.
    roots = {"vbmeta", "boot", "dtbo", "recovery", "vendor_boot", "vbmeta_system", "vbmeta_vendor"}
    require(set(keys) <= roots and roots <= set(captured), "invalid/missing AVB chain image inputs")
    parsed, originals, evidence, blobs = {}, {}, {}, {}
    hashed, chained, locations = set(), set(), set()
    for name in sorted(roots):
        image = module.ImageHandler(str(images[name]), read_only=True)
        footer, header, descriptors, _ = engine._parse_image(image)
        original = module.ImageHandler(str(captured[name]), read_only=True)
        old_footer, old_header, old_descriptors, _ = engine._parse_image(original)
        require(header.flags == 0, "candidate AVB verification/verity flags must both remain enabled")
        require(header.algorithm_type != 0, "unsigned vbmeta is not accepted")
        require(header.rollback_index >= old_header.rollback_index,
                "candidate lowers captured rollback index: " + name)
        require(header.rollback_index_location == old_header.rollback_index_location,
                "candidate changes AVB rollback index location")
        parsed[name] = descriptors
        originals[name] = {(d.partition_name, d.rollback_index_location, d.flags) for d in old_descriptors
                           if isinstance(d, module.AvbChainPartitionDescriptor)}
        chain_shape = {(d.partition_name, d.rollback_index_location, d.flags) for d in descriptors
                       if isinstance(d, module.AvbChainPartitionDescriptor)}
        require(chain_shape == originals[name], "candidate changes captured AVB chain topology/rollback locations")
        offset = (footer.vbmeta_offset if footer else 0) + header.SIZE + header.authentication_data_block_size
        image.seek(offset + header.public_key_offset)
        blobs[name] = image.read(header.public_key_size)
        if name in keys:
            require(blobs[name] == module.RSAPublicKey(str(keys[name])).encode(), "AVB public key pin mismatch: " + name)
        else:
            require(sha256(images[name]) == sha256(captured[name]), "changed AVB image requires its own public key pin: " + name)
        evidence[name] = {"flags": header.flags, "rollback_index": header.rollback_index,
                          "rollback_index_location": header.rollback_index_location,
                          "algorithm_type": header.algorithm_type}
    for name, descriptors in parsed.items():
        expected = []
        for descriptor in descriptors:
            if isinstance(descriptor, module.AvbChainPartitionDescriptor):
                child = descriptor.partition_name
                require(name == "vbmeta" and child in roots - {"vbmeta"} and child not in chained,
                        "unreviewed/duplicate AVB chain partition")
                require(descriptor.flags == 0 and descriptor.rollback_index_location > 0
                        and descriptor.rollback_index_location not in locations, "unsafe AVB chain flags/location")
                locations.add(descriptor.rollback_index_location)
                require(descriptor.public_key == blobs[child],
                        "AVB chain key differs from pinned child key")
                # avbtool's bare --follow_chain_partitions skips this expected-key check.
                expected.append(f"{child}:{descriptor.rollback_index_location}:{images[child].parent / (child + '.avbpubkey')}")
                (images[child].parent / (child + ".avbpubkey")).write_bytes(descriptor.public_key)
                chained.add(child)
            elif isinstance(descriptor, (module.AvbHashDescriptor, module.AvbHashtreeDescriptor)):
                require(descriptor.partition_name in images and descriptor.flags == 0,
                        "unexpected or non-A/B AVB image descriptor")
                require(descriptor.partition_name not in hashed, "duplicate AVB partition descriptor")
                hashed.add(descriptor.partition_name)
        try:
            engine.verify_image(str(images[name]), str(keys[name]) if name in keys else None, expected, False, False)
        except module.AvbError:
            raise ValueError("AVB descriptor/signature verification failed: " + name) from None
    require(chained == roots - {"vbmeta"} and hashed | chained == set(images) - {"vbmeta"},
            "AVB descriptors do not cover the complete native payload")
    return evidence
