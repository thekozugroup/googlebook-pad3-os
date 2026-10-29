import copy
import io
import json
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import check_updates as checker


PIN = {
    "device": "mica", "build": "16560795", "version": "17.CL3B.260622.276.R2",
    "published": "2026-10-22", "url": "https://dl.google.com/device/recovery/mica-user/16560795/recovery.zip",
    "zip_md5": "be97fb4fe368e50bb6102dcede1b2a80",
}


def entry(build="16560795", **fields):
    return {"device": "mica", "target": "mica-user", "channel": "STABLE",
            "url": f"https://dl.google.com/device/recovery/mica-user/{build}/recovery.zip",
            "buildidentifier": f"{build}_CL3B.260622.276.R2", "dateupdated": "2026-10-22",
            "md5": PIN["zip_md5"], **fields}


class CatalogTest(unittest.TestCase):
    def test_catalog_envelopes_and_release_prefix(self):
        rows = [entry()]
        for catalog in (rows, {"images": rows}, {"recoveries": rows, "timestamp": 1},
                        [entry(buildidentifier="16560795_17.CL3B.260622.276.R2")]):
            with self.subTest(catalog=catalog):
                candidate, = checker.compare_catalog(catalog, PIN)
                self.assertEqual(candidate["relation"], "matches_pin")
                self.assertEqual(candidate["changed_fields"], [])
                self.assertEqual(candidate["compatibility"], "not_assessed")

    def test_numeric_order_newer_and_older_not_date_or_lexical_order(self):
        pin = {**PIN, "build": "99"}
        result = checker.compare_catalog([entry("9"), entry("100", dateupdated="2020-01-01")], pin)
        self.assertEqual([c["build"] for c in result], ["100", "9"])
        self.assertEqual([c["relation"] for c in result], ["newer_build", "older_build"])

    def test_same_build_changed_metadata_is_reported(self):
        for field, value, changed in (("md5", "a" * 32, "zip_md5"),
                                      ("dateupdated", "2026-10-23", "published"),
                                      ("buildidentifier", "16560795_CL3B.260622.276.R4", "version"),
                                      ("buildidentifier", "16560795_18.CL3B.260622.276.R2", "version")):
            with self.subTest(field=field):
                candidate, = checker.compare_catalog([entry(**{field: value})], PIN)
                self.assertEqual(candidate["relation"], "different_metadata")
                self.assertEqual(candidate["changed_fields"], [changed])

    def test_device_and_channel_filtering(self):
        foreign = {"device": "ruby", "url": "unused; never fetched"}
        result = checker.compare_catalog([foreign, entry("99999999", channel="BETA"), entry(channel="stable")], PIN)
        self.assertEqual([c["build"] for c in result], [PIN["build"]])
        self.assertEqual(checker.compare_catalog([foreign], PIN), [])

    def test_missing_optional_metadata_is_not_full_match(self):
        row = entry()
        for key in ("buildidentifier", "dateupdated", "md5"):
            del row[key]
        candidate, = checker.compare_catalog([row], PIN)
        self.assertEqual(candidate["relation"], "same_build_incomplete_metadata")
        self.assertEqual(candidate["compatibility"], "not_assessed")

    def test_placeholder_sizes_are_not_trusted(self):
        candidate, = checker.compare_catalog([entry(zipfilesize=1, filesize=19230966272)], PIN)
        self.assertEqual(candidate["relation"], "matches_pin")
        self.assertNotIn("zipfilesize", candidate)

    def test_malformed_catalog_shapes(self):
        for catalog in (None, "[]", {}, {"devices": []}, {"images": {}},
                        {"images": [], "recoveries": []}, [None], [{}], [{"device": 123}]):
            with self.subTest(catalog=catalog), self.assertRaises(ValueError):
                checker.compare_catalog(catalog, PIN)

    def test_malformed_matching_rows_fail_without_suppressing_error(self):
        variants = [
            {"target": "ruby-user"}, {"channel": 1}, {"url": None},
            {"url": "http://dl.google.com/device/recovery/mica-user/16560795/recovery.zip"},
            {"url": "https://dl.google.com.evil.test/device/recovery/mica-user/16560795/recovery.zip"},
            {"url": "https://dl.google.com/device/recovery/ruby-user/16560795/recovery.zip"},
            {"url": PIN["url"] + "?download=1"},
            {"buildidentifier": "16560796_CL3B.260622.276.R2"}, {"buildidentifier": 16560795},
            {"dateupdated": "2026-02-30"}, {"dateupdated": "20261022"}, {"dateupdated": True},
            {"md5": "corrupt"}, {"md5": 123},
        ]
        for fields in variants:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                checker.compare_catalog([entry(), entry(**fields)], PIN)

    def test_does_not_mutate_inputs(self):
        catalog = {"images": [entry()]}
        before = copy.deepcopy((catalog, PIN))
        checker.compare_catalog(catalog, PIN)
        self.assertEqual((catalog, PIN), before)


class FetchTest(unittest.TestCase):
    def fetch(self, body, headers=None):
        response = io.BytesIO(body)
        response.headers = headers or {}
        with patch.object(checker.urllib.request, "build_opener") as make_opener:
            make_opener.return_value.open.return_value = response
            result = checker.fetch_catalog()
            make_opener.assert_called_once()
            self.assertIsInstance(make_opener.call_args.args[0], checker.NoRedirect)
            request = make_opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, checker.CATALOG_URL)
            self.assertEqual(request.get_method(), "GET")
            make_opener.return_value.open.assert_called_once_with(request, timeout=15)
            return result

    def test_fetches_only_the_fixed_metadata_endpoint(self):
        rows = [entry()]
        self.assertEqual(self.fetch(json.dumps(rows).encode()), rows)

    def test_rejects_redirects_to_metadata_or_images(self):
        for url in (checker.CATALOG_URL, PIN["url"], "https://other.test/catalog.json"):
            with self.subTest(url=url):
                self.assertIsNone(checker.NoRedirect().redirect_request(None, None, 302, "Found", {}, url))

    def test_bounded_body_with_or_without_content_length(self):
        with patch.object(checker, "MAX_CATALOG_BYTES", 16):
            for headers in ({}, {"Content-Length": "2"}):
                with self.subTest(headers=headers), self.assertRaisesRegex(ValueError, "exceeds"):
                    self.fetch(b" " * 17, headers)
            for length in ("17", "-1", "broken"):
                with self.subTest(length=length), self.assertRaisesRegex(ValueError, "Content-Length"):
                    self.fetch(b"[]", {"Content-Length": length})

    def test_invalid_json_and_encoding(self):
        for body in (b"<html>error</html>", b"{", b"\xff"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.fetch(body)


class CommandTest(unittest.TestCase):
    def run_main(self, catalog):
        out, error = io.StringIO(), io.StringIO()
        baseline = {"donor": PIN, "basis": "repository pins; device not inspected"}
        with patch.object(checker, "load_baseline", return_value=baseline), patch.object(checker, "fetch_catalog", return_value=catalog), redirect_stdout(out), redirect_stderr(error):
            code = checker.main()
        return code, out.getvalue(), error.getvalue()

    def test_uses_repository_and_current_native_profiles(self):
        baseline = checker.load_baseline()
        inputs = json.loads((checker.ROOT / "inputs.json").read_text())
        native = json.loads((checker.ROOT / checker.NATIVE_PROFILE).read_text())
        sources = json.loads((checker.ROOT / checker.SOURCE_PROFILE).read_text())
        self.assertEqual(baseline["donor"]["build"], inputs["donor"]["build"])
        self.assertEqual(baseline["native_base"]["kernel"], native["kernel"])
        self.assertEqual(baseline["source_review"]["heads"], sources["heads"])
        self.assertFalse(baseline["source_review"]["live_metadata_checked"])

    def test_command_reports_match_change_and_missing_device(self):
        for catalog, expected in (([entry()], "pin_matches_catalog"),
                                  ([entry("16560796")], "review_candidates"),
                                  ([{"device": "ruby"}], "no_matching_device")):
            with self.subTest(expected=expected):
                code, out, error = self.run_main(catalog)
                self.assertEqual((code, error), (0, ""))
                report = json.loads(out)
                self.assertEqual(report["status"], expected)
                self.assertFalse(report["ota_implemented"])
                self.assertEqual(report["baseline"]["basis"], "repository pins; device not inspected")

    def test_malformed_catalog_has_nonzero_exit_and_no_success_report(self):
        code, out, error = self.run_main({"unexpected": []})
        self.assertEqual((code, out), (1, ""))
        self.assertTrue(error.startswith("check_updates: "))

    def test_network_failure_has_nonzero_exit(self):
        for failure in (urllib.error.URLError("offline"), TimeoutError("timeout")):
            out, error = io.StringIO(), io.StringIO()
            with self.subTest(failure=failure), patch.object(checker, "fetch_catalog", side_effect=failure), redirect_stdout(out), redirect_stderr(error):
                self.assertEqual(checker.main(), 1)
            self.assertEqual(out.getvalue(), "")
            self.assertTrue(error.getvalue().startswith("check_updates: "))

    def test_invalid_pins_fail_before_fetching(self):
        inputs = json.loads((checker.ROOT / "inputs.json").read_text())
        for fields in ({"catalog": "https://other.test/catalog.json"}, {"build": True},
                       {"zip_sha256": "bad"}, {"published": "2026-02-30"}):
            config = copy.deepcopy(inputs)
            config["donor"].update(fields)
            out, error = io.StringIO(), io.StringIO()
            with self.subTest(fields=fields), patch.object(checker.Path, "read_text", side_effect=[json.dumps(config), "{}", "{}"]), patch.object(checker, "fetch_catalog") as fetch, redirect_stdout(out), redirect_stderr(error):
                self.assertEqual(checker.main(), 1)
                fetch.assert_not_called()
            self.assertEqual(out.getvalue(), "")
            self.assertTrue(error.getvalue().startswith("check_updates: "))

    def test_malformed_local_json_fails_before_fetching(self):
        out, error = io.StringIO(), io.StringIO()
        with patch.object(checker.Path, "read_text", return_value="{"), patch.object(checker, "fetch_catalog") as fetch, redirect_stdout(out), redirect_stderr(error):
            self.assertEqual(checker.main(), 1)
            fetch.assert_not_called()
        self.assertEqual(out.getvalue(), "")
        self.assertTrue(error.getvalue().startswith("check_updates: "))


if __name__ == "__main__":
    unittest.main()
