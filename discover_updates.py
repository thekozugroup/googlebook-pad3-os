#!/usr/bin/env python3
"""Discover public upstream changes. Never download firmware, build, sign or install."""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import urllib.error
import urllib.request

import check_updates

ROOT = Path(__file__).resolve().parent
POLICY = ROOT / "maintenance/upstream.json"
INDEX = "https://otachecker.com/list"
OTA = r"https://ota\.googlezip\.net/packages/ota-api/package/[0-9a-f]{40}\.zip"
FINGERPRINT = r"Dell/mica/mica:17/[A-Za-z0-9._-]{1,96}/[0-9]{1,16}:user/release-keys"
MAX_BYTES = 1024 * 1024
COVERAGE = "Google full recovery catalog, latest public OTA index page and pinned source branches; rollout-only or older index records can be missed."


class Links(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.links, self.href, self.text = [], None, []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.href, self.text = dict(attrs).get("href"), []

    def handle_data(self, data):
        if self.href is not None:
            self.text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.href is not None:
            self.links.append((self.href, "".join(self.text).strip()))
            self.href, self.text = None, []


def permitted_url(url):
    return (url in (check_updates.CATALOG_URL, INDEX)
            or re.fullmatch(r"https://otachecker\.com/ota/[1-9][0-9]{0,7}", url)
            or re.fullmatch(r"https://api\.github\.com/repos/(?:LineageOS|crdroidandroid)/[A-Za-z0-9_.-]+/git/ref/heads/[A-Za-z0-9_.-]+", url))


def fetch(url):
    if not permitted_url(url):
        raise ValueError("metadata URL is outside the reviewed sources")
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "User-Agent": "GoogleBook-Pad3-maintenance"})
    try:
        response = urllib.request.build_opener(check_updates.NoRedirect()).open(request, timeout=15)
    except urllib.error.HTTPError as error:
        error.close()
        raise
    with response:
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > MAX_BYTES):
            raise ValueError("metadata size exceeds limit")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("metadata size exceeds limit")
    return data.decode("utf-8")


def load_policy(path=POLICY):
    policy = json.loads(Path(path).read_text())
    if (set(policy) != {"schema", "donor", "reviewed_ota_urls", "sources"}
            or policy["schema"] != 1 or set(policy["donor"]) != {"device", "build", "version", "security_patch"}
            or policy["donor"]["device"] != "mica"
            or not re.fullmatch(r"[0-9]{1,16}", policy["donor"]["build"])
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,96}", policy["donor"]["version"])):
        raise ValueError("invalid reviewed donor policy")
    if not policy["reviewed_ota_urls"] or not all(re.fullmatch(OTA, u) for u in policy["reviewed_ota_urls"]):
        raise ValueError("invalid reviewed OTA URL")
    for source in policy["sources"]:
        if (set(source) != {"repository", "branch", "reviewed_sha"}
                or not re.fullmatch(r"(?:LineageOS|crdroidandroid)/[A-Za-z0-9_.-]+", source["repository"])
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", source["branch"])
                or not re.fullmatch(r"[0-9a-f]{40}", source["reviewed_sha"])):
            raise ValueError("invalid reviewed source pin")
    return policy


def index_records(text):
    records = set()
    for href, label in Links(text).links:
        if re.fullmatch(r"/ota/[1-9][0-9]{0,7}", href) and re.fullmatch(FINGERPRINT, label):
            records.add(("https://otachecker.com" + href, label))
    if len(records) > 8:
        raise ValueError("OTA index exceeds bounded mica lookup")
    return sorted(records)


def ota_urls(text, fingerprint):
    if fingerprint not in text:
        raise ValueError("OTA detail does not match the index fingerprint")
    urls = sorted({href for href, _ in Links(text).links if re.fullmatch(OTA, href)})
    if not urls or len(urls) > 4:
        raise ValueError("OTA detail has no unambiguous Google package links")
    return urls


def discover(policy, donor_pins, request=fetch):
    errors, recoveries, otas, sources = [], [], [], []
    try:
        for candidate in check_updates.compare_catalog(json.loads(request(check_updates.CATALOG_URL)), donor_pins):
            if candidate["version"] is not None and not re.fullmatch(r"[A-Za-z0-9._-]{1,96}", candidate["version"]):
                raise ValueError("unexpected recovery version")
            candidate["newer_than_reviewed_donor"] = int(candidate["build"]) > int(policy["donor"]["build"])
            recoveries.append(candidate)
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors.append({"source": "google_recovery_catalog", "error": type(error).__name__})
    try:
        records = index_records(request(INDEX))
        if not records:
            raise ValueError("bounded OTA index contains no mica records")
    except (OSError, ValueError, KeyError, TypeError) as error:
        records = []
        errors.append({"source": "public_ota_index", "error": type(error).__name__})
    for record, fingerprint in records:
        try:
            for url in ota_urls(request(record), fingerprint):
                otas.append({"record": record, "source_fingerprint": fingerprint, "url": url,
                             "new_url": url not in policy["reviewed_ota_urls"], "trust": "discovery_only_not_signature_verified"})
        except (OSError, ValueError, KeyError, TypeError) as error:
            failure = {"source": "public_ota_record", "record": record, "error": type(error).__name__}
            if isinstance(error, urllib.error.HTTPError):
                failure["http_status"] = error.code
            errors.append(failure)
    for source in policy["sources"]:
        try:
            url = "https://api.github.com/repos/" + source["repository"] + "/git/ref/heads/" + source["branch"]
            sha = json.loads(request(url))["object"]["sha"]
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
                raise ValueError("invalid upstream revision")
            sources.append(dict(source, observed_sha=sha, changed=sha != source["reviewed_sha"]))
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append({"source": source["repository"], "error": type(error).__name__})
    changed = any(c["newer_than_reviewed_donor"] for c in recoveries) or any(c["new_url"] for c in otas) or any(c["changed"] for c in sources)
    return {"schema": 1, "status": "incomplete" if errors else "review_required" if changed else "no_observed_change",
            "reviewed_donor": policy["donor"], "recoveries": recoveries, "incremental_otas": otas,
            "sources": sources, "errors": errors, "automatic_build_or_install": False,
            "coverage": COVERAGE}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=POLICY)
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
        pins = json.loads((ROOT / "inputs.json").read_text())["donor"]
        result = discover(policy, pins)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"status": result["status"], "source_errors": len(result["errors"]),
                          "errors": result["errors"], "automatic_build_or_install": False}))
        return 1 if result["errors"] else 0
    except (OSError, ValueError, KeyError, TypeError):
        print('{"status":"discovery_failed","private_paths_redacted":true}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
