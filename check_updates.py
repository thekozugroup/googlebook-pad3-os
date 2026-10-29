#!/usr/bin/env python3
"""Compare repository pins with small official recovery metadata; never install."""
import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CATALOG_URL = "https://dl.google.com/dl/edgedl/device/recovery/production_recovery.json"
NATIVE_PROFILE = "profiles/erhai-crdroid-20261025/profile.json"
SOURCE_PROFILE = 'profiles/lineage-sources.json'
MAX_CATALOG_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 15


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_catalog():
    request = urllib.request.Request(CATALOG_URL, headers={"Accept": "application/json"})
    # A metadata redirect must never turn this request into an image download.
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=TIMEOUT_SECONDS) as response:
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > MAX_CATALOG_BYTES):
            raise ValueError("invalid or oversized catalog Content-Length")
        body = response.read(MAX_CATALOG_BYTES + 1)
    if len(body) > MAX_CATALOG_BYTES:
        raise ValueError("catalog exceeds 1 MiB")
    return json.loads(body)


def version_suffix(value):
    first, separator, rest = value.partition(".")
    return rest if separator and first.isdecimal() else value


def load_baseline():
    inputs = json.loads((ROOT / "inputs.json").read_text())
    native = json.loads((ROOT / NATIVE_PROFILE).read_text())
    sources = json.loads((ROOT / SOURCE_PROFILE).read_text())
    donor = inputs["donor"]
    keys = ("device", "build", "version", "published", "url", "zip_md5", "zip_sha256")
    if not all(isinstance(donor[k], str) and donor[k] for k in keys):
        raise ValueError("invalid donor pins")
    if donor["catalog"] != CATALOG_URL or not re.fullmatch(r"[0-9]+", donor["build"]):
        raise ValueError("unexpected pinned catalog or build")
    date.fromisoformat(donor["published"])
    if not re.fullmatch(r"[a-z0-9_-]+", donor["device"]):
        raise ValueError("invalid pinned device")
    if not re.fullmatch(r"[0-9a-f]{32}", donor["zip_md5"]) or not re.fullmatch(r"[0-9a-f]{64}", donor["zip_sha256"]):
        raise ValueError("invalid pinned digest")
    return {
        "basis": "repository pins; device not inspected",
        "donor": {k: donor[k] for k in keys},
        "native_base": {"profile": NATIVE_PROFILE, **{k: native[k] for k in
                        ("native_build_utc", "native_slot", "kernel", "compiled_policy_sha256")}},
        "source_review": {"profile": SOURCE_PROFILE, "live_metadata_checked": False,
                          **{k: sources[k] for k in ("branch", "heads", "current_kernel_source")}},
    }


def compare_catalog(catalog, donor):
    if isinstance(catalog, dict):
        envelopes = [k for k in ("images", "recoveries") if k in catalog]
        if len(envelopes) != 1:
            raise ValueError("expected a catalog list or one images/recoveries list")
        catalog = catalog[envelopes[0]]
    if not isinstance(catalog, list):
        raise ValueError("catalog entries must be a list")
    candidates = []
    for row in catalog:
        if not isinstance(row, dict) or not isinstance(row.get("device"), str) or not row["device"]:
            raise ValueError("catalog entry requires a device string")
        if row["device"] != donor["device"]:
            continue
        channel = row.get("channel", "STABLE")
        if not isinstance(channel, str):
            raise ValueError("invalid candidate channel")
        if channel.upper() != "STABLE":
            continue
        if row.get("target", donor["device"] + "-user") != donor["device"] + "-user":
            raise ValueError("candidate target disagrees with pinned device")
        url = row.get("url")
        pattern = r"https://dl\.google\.com/device/recovery/" + re.escape(donor["device"]) + r"-user/([0-9]+)/recovery\.zip"
        match = re.fullmatch(pattern, url) if isinstance(url, str) else None
        if match is None:
            raise ValueError("candidate requires an official device-specific recovery URL")
        build = match[1]
        identifier = row.get("buildidentifier")
        version = None
        if identifier is not None:
            parts = re.fullmatch(r"([0-9]+)_(.+)", identifier) if isinstance(identifier, str) else None
            if parts is None or int(parts[1]) != int(build):
                raise ValueError("candidate buildidentifier disagrees with URL")
            version = parts[2]
        published = row.get("dateupdated")
        if published is not None:
            if not isinstance(published, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", published):
                raise ValueError("invalid candidate dateupdated")
            date.fromisoformat(published)
        md5 = row.get("md5")
        if md5 is not None:
            if not isinstance(md5, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", md5):
                raise ValueError("invalid candidate md5")
            md5 = md5.lower()
        candidate = {"device": row["device"], "build": build, "version": version,
                     "published": published, "url": url, "zip_md5": md5}
        changes = [k for k in ("url", "published", "zip_md5")
                   if candidate[k] is not None and candidate[k] != donor[k]]
        if version is not None and version not in (donor["version"], version_suffix(donor["version"])):
            changes.append("version")
        if int(build) != int(donor["build"]):
            changes.insert(0, "build")
            relation = "newer_build" if int(build) > int(donor["build"]) else "older_build"
        elif changes:
            relation = "different_metadata"
        elif any(candidate[k] is None for k in ("version", "published", "zip_md5")):
            relation = "same_build_incomplete_metadata"
        else:
            relation = "matches_pin"
        candidate.update(relation=relation, changed_fields=changes, compatibility="not_assessed")
        candidates.append(candidate)
    return sorted(candidates, key=lambda c: int(c["build"]), reverse=True)


def main():
    try:
        baseline = load_baseline()
        candidates = compare_catalog(fetch_catalog(), baseline["donor"])
        status = "no_matching_device"
        if candidates:
            status = "pin_matches_catalog" if all(c["relation"] == "matches_pin" for c in candidates) else "review_candidates"
        print(json.dumps({"status": status, "catalog": CATALOG_URL, "baseline": baseline,
                          "candidates": candidates, "ota_implemented": False}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"check_updates: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    sys.exit(main())
