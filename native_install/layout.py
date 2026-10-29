"""Reject usage-only lpdump JSON and bind group/capacity planning to captured metadata."""
from native_install.payload import require
import re


def parse_text_layout(text):
    """Normalize the captured Pad 3 LP v10.2 text; omit default/COW groups from OTA groups."""
    require(text.startswith("Slot 1:") and "Metadata version: 10.2" in text,
            "expected full source B metadata slot 1 text")
    maximum = int(re.search(r"Metadata max size: (\d+) bytes", text)[1])
    slots = int(re.search(r"Metadata slot count: (\d+)", text)[1])
    require(maximum == 65536 and slots == 3 and "Header flags: virtual_ab_device" in text,
            "unreviewed Pad 3 LP geometry/flags")
    block_table = text.split("Block device table:", 1)[1].split("Group table:", 1)[0]
    match = re.search(r"Partition name: super\s+First sector: (\d+)\s+Size: (\d+) bytes\s+Flags: none", block_table)
    require(match is not None, "expected one ordinary super block device")
    first_sector, total = map(int, match.groups())
    groups = []
    for name, size in re.findall(r"Name: (\S+)\s+Maximum size: (\d+) bytes\s+Flags: none", text.split("Group table:", 1)[1]):
        if name.endswith("_b"):
            groups.append({"name": name[:-2], "maximum_size": int(size)})
    require(len(groups) == 1 and groups[0]["name"] == "oneplus_dynamic_partitions", "unreviewed native update groups")
    table = text.split("Partition table:", 1)[1].split("Super partition layout:", 1)[0]
    partitions, ranges = [], []
    for record in table.split("------------------------"):
        if not record.strip():
            continue
        fields = re.search(r"Name: (\S+)\s+Group: (\S+)\s+Attributes: ([^\n]+)\s+Extents:", record)
        require(fields is not None, "unparsed LP partition record")
        name, group, attributes = fields.groups()
        extents = re.findall(r"(\d+) \.\. (\d+) linear super (\d+)", record)
        require(extents and len(extents) == len(re.findall(r"\.\.", record)), "unsupported LP extent type")
        cursor = 0
        for begin, end, physical in extents:
            begin, end, physical = int(begin), int(end), int(physical)
            count = end - begin + 1
            require(begin == cursor and count > 0 and physical >= first_sector
                    and physical + count <= total // 512, "LP extent outside super or noncontiguous logical image")
            cursor += count
            ranges.append((physical, physical + count))
        if group != "cow":
            require(name.endswith("_b") and group == "oneplus_dynamic_partitions_b"
                    and "readonly" in attributes, "unreviewed source LP partition")
            partitions.append({"name": name[:-2], "group_name": group[:-2], "is_dynamic": True, "size": cursor * 512})
    ranges.sort()
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "overlapping physical LP extents")
    require(len(partitions) == 7 and len({p["name"] for p in partitions}) == 7, "incomplete native logical set")
    return {"enabled": True, "groups": groups, "partitions": partitions,
            "block_devices": [{"name": "super", "size": total}], "super_device": {"total_size": total},
            "metadata_reserved_bytes": 4096 + 2 * (4096 + maximum * slots),
            "virtual_ab": True, "cow_extents_present": "Group: cow" in table}


def check_layout(metadata, groups, super_bytes, raw_dump):
    require(metadata.get("enabled") is True and metadata.get("groups")
            and (metadata.get("block_devices") or metadata.get("blockDevices")),
            "lpdump JSON has no allocation metadata; filesystem usage alone is insufficient")
    super_device = metadata.get("super_device", metadata.get("superDevice", {}))
    total = super_device.get("total_size", super_device.get("totalSize"))
    require(total is not None and int(total) == super_bytes, "super size differs from capture")
    expected = {}
    for group in metadata["groups"]:
        name = group["name"]
        require(name not in expected, "duplicate captured dynamic group")
        maximum = group.get("maximum_size", group.get("maximumSize"))
        expected[name] = {"name": name, "maximum_size": int(maximum), "partitions": []}
    for partition in metadata["partitions"]:
        if partition.get("is_dynamic", partition.get("isDynamic")) is True:
            name = partition.get("group_name", partition.get("groupName"))
            require(name in expected, "logical partition has no captured group")
            expected[name]["partitions"].append(partition["name"])
    actual = {g["name"]: dict(g, partitions=sorted(g["partitions"])) for g in groups}
    expected = {name: dict(g, partitions=sorted(g["partitions"])) for name, g in expected.items()}
    require(actual == expected, "dynamic groups differ from captured allocation metadata")
    require("Block device table:" in raw_dump and "Group table:" in raw_dump
            and all(name in raw_dump for name in expected), "complete raw lpdump evidence is missing")


def check_target_state(state, target_sizes, source_sizes):
    require(state.get("schema") == 1 and state.get("source_slot") == "b" and state.get("target_slot") == "a"
            and state.get("slot_count") == 2 and state.get("source_successful") is True
            and state.get("bootloader_unlocked") is True, "unverified source slot/bootloader state")
    gsi = {line.strip() for line in state.get("gsi_tool_status", "").splitlines() if line.strip()}
    require(state.get("gsi_tool_exit_code") == 0 and gsi <= {"installed", "not installed", "enabled", "disabled", "running"}
            and bool(gsi & {"installed", "not installed"}) and bool(gsi & {"enabled", "disabled"})
            and "running" not in gsi and "enabled" not in gsi, "DSU is running/enabled or authoritative gsi_tool status is unavailable")
    require(state.get("hal_snapshot_merge_status") == "NONE" and state.get("libsnapshot_update_state") == "none"
            and state.get("cow_reconciliation_reviewed") is True, "snapshot/COW state has not been reconciled")
    require(set(state["physical_partition_sizes"]) == set(source_sizes), "incomplete target physical capacity evidence")
    for name, size in source_sizes.items():
        observed = state["physical_partition_sizes"][name]
        require(observed["b"] == size and observed["a"] == target_sizes[name] and observed["a"] == observed["b"],
                "target A capacity differs from matched B capture or plan: " + name)
    require(set(state["firmware_hashes"]) == {"modem", "dsp", "bluetooth"}, "missing firmware parity evidence")
    for name, slots in state["firmware_hashes"].items():
        require(re.fullmatch(r"[0-9a-f]{64}", slots["a"]) and slots["a"] == slots["b"], "target firmware differs: " + name)
    require(state.get("other_firmware_compatibility_reviewed") is True, "remaining firmware compatibility review required")
