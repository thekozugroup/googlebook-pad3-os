#!/usr/bin/env python3
"""Sample GoogleBook DSU or native builds through read-only ADB queries.

Example: python3 -B stability_probe.py --output /tmp/your-cleanos-task/probe \
    --duration 1800 --interval 30
Only bounded crash/system log tails are retained, at most 10 MiB combined.
Sampling can miss events between queries or after log-buffer eviction.
Each query has a 10-second timeout; the final sample can extend the duration.
Sync checks cover standard home-directory provider roots, including symlinks.
"""
import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


FINGERPRINT = "CL3B.260622.276.R2/16560795"
RAW_LIMIT = 10 * 1024 * 1024
LOG_LINES = 1000
CRASH_KINDS = ("fatal_process", "java_crash", "anr")
QUERIES = {
    "boot_id": ("shell", "cat", "/proc/sys/kernel/random/boot_id"),
    "uptime": ("shell", "cat", "/proc/uptime"),
    "system_server_pid": ("shell", "pidof", "system_server"),
    "boot_completed": ("shell", "getprop", "sys.boot_completed"),
    "free": ("shell", "free", "-k"),
    "meminfo": ("shell", "cat", "/proc/meminfo"),
    "battery": ("shell", "dumpsys", "battery"),
    "thermal": ("shell", "dumpsys", "thermalservice"),
    "connectivity": ("shell", "dumpsys", "connectivity"),
    "wifi": ("shell", "cmd", "wifi", "status"),
    "crash": ("logcat", "-b", "crash", "-d", "-t", str(LOG_LINES), "-v", "epoch"),
    "anr": ("logcat", "-b", "system", "-d", "-t", str(LOG_LINES), "-v", "epoch",
            "ActivityManager:I", "*:S"),
}


def adb(serial, *args):
    try:
        result = subprocess.run(["adb", "-s", serial, *args], capture_output=True,
                                text=True, errors="replace", timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("ADB unavailable or query timed out") from None
    if result.returncode:
        raise RuntimeError(f"ADB query exited {result.returncode}")
    return result.stdout


def parse_identity(fingerprint, user, dsu, native=False):
    expected = "00000000" if native else "00000001"
    parcel = re.fullmatch(r"\s*Result:\s*Parcel\(\s*00000000\s+" + expected + r"\s+'[^']*'\s*\)\s*", dsu)
    correct_build = (re.fullmatch(r"Googlebook/erhai/erhai:17/GBOS/[1-9][0-9]*:user/release-keys", fingerprint.strip())
                     if native else FINGERPRINT in fingerprint.strip())
    if not correct_build:
        raise ValueError("Expected GoogleBook fingerprint was not observed")
    if user.strip() != "10":
        raise ValueError("Expected current Android user 10")
    if not parcel:
        raise ValueError("Unexpected dynamic_system Binder transaction 7 result")
    return {"fingerprint": fingerprint.strip(), "current_user": 10, "dsu_running": not native}


def output_directory(path):
    path = path.expanduser().resolve()
    home = Path.home().resolve()
    roots = [home / name for name in ("Documents", "Desktop", "Library/Mobile Documents",
                                      "Library/CloudStorage", "Dropbox", "OneDrive", "Google Drive")]
    roots += list(home.glob("Dropbox*")) + list(home.glob("OneDrive*")) + list(home.glob("Google Drive*"))
    if any(path.is_relative_to(root.resolve()) for root in roots):
        raise ValueError("Output must be outside cloud-sync roots")
    if path.is_relative_to(Path(__file__).resolve().parent) or any(
            (parent / ".git").exists() for parent in (path, *path.parents)):
        raise ValueError("Raw logs must be outside source repositories, including ignored directories")
    if path.exists() and (not path.is_dir() or path.stat().st_uid != os.getuid() or any(path.iterdir())):
        raise ValueError("Output must be a new or empty directory owned by the current user")
    return path


def private_file(path, mode="w"):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    flags |= os.O_EXCL if mode == "w" else os.O_APPEND
    return os.fdopen(os.open(path, flags, 0o600), mode, encoding="utf-8")


def raw_log(directory, text):
    path = directory / "crash-buffer.log"
    data = text.encode("utf-8", errors="replace")[-RAW_LIMIT // 2:]
    if path.exists() and path.stat().st_size + len(data) > RAW_LIMIT // 2:
        path.replace(directory / "crash-buffer.log.1")
    with private_file(path, "a") as stream:
        stream.write(data.decode("utf-8", errors="ignore"))


def crash_counts(text, seen, records=None):
    counts = dict.fromkeys(CRASH_KINDS, 0)
    for line in text.splitlines():
        entry = re.fullmatch(r"\s*(\d+\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^:]+?)\s*:\s?(.*)", line)
        if not entry:
            continue
        timestamp, pid, tid, priority, tag, message = entry.groups()
        kind = None
        if tag == "libc" and priority == "F" and re.match(r"Fatal signal \d+ \([A-Z0-9]+\).*\bin tid \d+", message):
            kind = "fatal_process"
        elif tag == "AndroidRuntime" and priority in "EF" and re.match(r"FATAL EXCEPTION(?: IN SYSTEM PROCESS)?:\s*\S", message):
            kind = "java_crash"
        elif tag == "ActivityManager" and priority in "IWEF" and re.match(r"ANR in \S", message):
            kind = "anr"
        if kind:
            key = hashlib.sha256(line.encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                counts[kind] += 1
                if records is not None:
                    records.append({"timestamp_epoch_seconds": timestamp, "pid": int(pid),
                                    "tid": int(tid), "kind": kind, "entry_key": key})
    return counts


def numeric_fields(text, allowed=None):
    return {key.strip(): int(value) for key, value in
            re.findall(r"^\s*([^:\n]+):\s*(-?\d+)(?:\s+kB)?\s*$", text, re.MULTILINE)
            if allowed is None or key.strip() in allowed}


def parse_free(text):
    lines = [line.split() for line in text.splitlines() if line.strip()]
    allowed = {"total", "used", "free", "shared", "buffers", "cached", "available"}
    if not lines or not set(lines[0]) <= allowed:
        raise ValueError("Unrecognized free header")
    rows = {line[0].rstrip(":").lower(): dict(zip(lines[0], map(int, line[1:])))
            for line in lines[1:] if (line[0] == "Mem:" and len(line) == len(lines[0]) + 1)
            or (line[0] == "Swap:" and len(line) == 4)}
    if "mem" not in rows:
        raise ValueError("Missing free memory row")
    return rows


def parse_connectivity(text):
    active = re.search(r"(?m)^\s*Active default network:\s*(\d+|none)\s*$", text)
    if not active:
        raise ValueError("Default network state unavailable")
    if active[1] == "none":
        return {"default_network_present": False, "default_network_validated": False,
                "default_is_wifi": False, "default_wifi_validated": False}
    current = text.partition("Current Networks:")[2].split("Network Requests:", 1)[0]
    for line in current.splitlines():
        if not line.strip().startswith("NetworkAgentInfo"):
            continue
        if not re.search(r"network\{" + active[1] + r"\}|-\s*" + active[1] + r"\]", line):
            continue
        capabilities = re.search(r"\bCapabilities:\s*([^\]]+)", line)
        transports = re.search(r"\bTransports:\s*(.*?)\s+Capabilities:", line)
        if not capabilities or not transports:
            continue
        validated = bool(re.search(r"\bVALIDATED\b", capabilities[1]))
        wifi = bool(re.search(r"\bWIFI\b", transports[1]))
        return {"default_network_present": True, "default_network_validated": validated,
                "default_is_wifi": wifi, "default_wifi_validated": wifi and validated}
    raise ValueError("Active network capabilities could not be parsed")


def parse_readings(readings):
    boot_id = readings["boot_id"].strip()
    pid = readings["system_server_pid"].strip()
    uptime = float(readings["uptime"].split()[0])
    if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", boot_id):
        raise ValueError("Invalid boot UUID")
    if not pid.isdecimal() or int(pid) <= 0 or not math.isfinite(uptime) or uptime < 0:
        raise ValueError("Invalid uptime or system_server PID")
    if readings["boot_completed"].strip() not in {"0", "1"}:
        raise ValueError("Boot-completed state unavailable")
    return {"boot_id": boot_id, "uptime_seconds": uptime, "system_server_pid": int(pid),
            "boot_completed": int(readings["boot_completed"].strip())}


def collect(serial, directory, seen):
    sample = {"utc": datetime.now(timezone.utc).isoformat(), "errors": []}
    readings = {}
    for name, args in QUERIES.items():
        try:
            readings[name] = adb(serial, *args)
        except RuntimeError as error:
            readings[name] = ""
            sample["errors"].append(f"{name}: {error}")
    parsers = {
        "runtime": lambda: parse_readings(readings),
        "free_kib": lambda: parse_free(readings["free"]),
        "meminfo_kib_or_counts": lambda: numeric_fields(readings["meminfo"]),
        "battery": lambda: numeric_fields(readings["battery"], {
            "status", "health", "level", "scale", "voltage", "temperature", "charge counter"}),
        "thermal_status": lambda: int(re.search(r"Thermal Status:\s*(\d+)", readings["thermal"])[1]),
        "connectivity": lambda: parse_connectivity(readings["connectivity"]),
    }
    for name, parser in parsers.items():
        try:
            value = parser()
            if value == {} or (name == "battery" and "status" not in value) or (
                    name == "meminfo_kib_or_counts" and "MemTotal" not in value):
                raise ValueError("Required numeric fields unavailable")
            if name == "runtime":
                sample.update(value)
            else:
                sample[name] = value
        except (ValueError, TypeError, IndexError):
            sample[name] = None
            sample["errors"].append(f"{name}: unavailable or unrecognized response")
    wifi = re.search(r"(?m)^Wifi is (connected|not connected|disabled)(?:\s|$)", readings["wifi"])
    sample["wifi_connected"] = None if wifi is None else wifi[1] == "connected"
    if wifi is None:
        sample["errors"].append("wifi_connected: unavailable or unrecognized response")
    if sample.get("boot_completed") == 0:
        sample["errors"].append("boot_completed: Android boot is incomplete")
    raw_log(directory, f"\n=== {sample['utc']} crash ===\n{readings['crash']}\n=== system ANR ===\n{readings['anr']}")
    sample["new_crash_evidence"] = crash_counts(readings["crash"] + "\n" + readings["anr"], seen)
    return sample


def probe(serial, output, duration, interval, native=False):
    if not all(math.isfinite(value) and value > 0 for value in (duration, interval)):
        raise ValueError("Duration and interval must be finite positive seconds")
    output = output_directory(output)
    identity = parse_identity(adb(serial, "shell", "getprop", "ro.build.fingerprint"),
                              adb(serial, "shell", "am", "get-current-user"),
                              adb(serial, "shell", "service", "call", "dynamic_system", "7"), native)
    baseline_utc = datetime.now(timezone.utc).isoformat()
    baseline = "\n".join(adb(serial, *QUERIES[name]) for name in ("crash", "anr"))
    seen, baseline_records = set(), []
    baseline_counts = crash_counts(baseline, seen, baseline_records)
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    output.chmod(0o700)
    raw_log(output, f"=== baseline {baseline_utc} ===\n{baseline}")
    summary = {"identity": identity, "requested_seconds": duration, "interval_seconds": interval,
               "baseline_utc": baseline_utc, "baseline_crash_records": baseline_records,
               "baseline_crash_evidence": baseline_counts,
               "samples": 0, "samples_with_errors": 0, "unexpected_changes": [],
               "new_crash_evidence": dict.fromkeys(CRASH_KINDS, 0), "status": "completed",
               "coverage": "Bounded log tails; polling can miss intervening restarts and evicted events. "
                           "WiFi validation describes the default network only; no Internet request is made."}
    previous = {}
    started = time.monotonic()
    next_sample = started
    try:
        with private_file(output / "samples.jsonl") as stream:
            while True:
                sample = collect(serial, output, seen)
                sample["unexpected_changes"] = []
                for name in ("boot_id", "system_server_pid"):
                    if name in sample:
                        if name in previous and sample[name] != previous[name]:
                            change = {"utc": sample["utc"], "field": name,
                                      "previous": previous[name], "current": sample[name]}
                            sample["unexpected_changes"].append(change)
                            summary["unexpected_changes"].append(change)
                        previous[name] = sample[name]
                for kind in CRASH_KINDS:
                    summary["new_crash_evidence"][kind] += sample["new_crash_evidence"][kind]
                stream.write(json.dumps(sample, sort_keys=True) + "\n")
                stream.flush()
                summary["samples"] += 1
                summary["samples_with_errors"] += bool(sample["errors"])
                if time.monotonic() >= started + duration:
                    break
                next_sample = max(next_sample + interval, time.monotonic())
                time.sleep(max(0, min(next_sample, started + duration) - time.monotonic()))
    except KeyboardInterrupt:
        summary["status"] = "interrupted"
    summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
    with private_file(output / "summary.json") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"), required=not os.environ.get("ANDROID_SERIAL"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--duration", type=float, default=1800)
    parser.add_argument("--interval", type=float, default=30)
    parser.add_argument("--native", action="store_true", help="Require a native erhai build with DSU inactive")
    args = parser.parse_args(argv)
    try:
        summary = probe(args.serial, args.output, args.duration, args.interval, args.native)
    except (ValueError, RuntimeError, OSError) as error:
        parser.exit(2, f"stability_probe: {error}\n")
    print(json.dumps(summary, sort_keys=True))
    if summary["status"] == "interrupted":
        return 130
    return 2 if summary["samples_with_errors"] or summary["unexpected_changes"] or any(summary["new_crash_evidence"].values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
