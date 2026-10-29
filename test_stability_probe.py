import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import stability_probe as probe


FINGERPRINT = "google/mica/mica:17/CL3B.260622.276.R2/16560795:user/release-keys"
DSU_TRUE = "Result: Parcel(00000000 00000001   '........')\n"
BOOT_ID = "12345678-1234-1234-1234-123456789abc"
NETWORK = """Active default network: 100
Current Networks:
  NetworkAgentInfo{network{100} nc{[ Transports: WIFI Capabilities: INTERNET&VALIDATED ]}}
Network Requests:
Historical log: VALIDATED WIFI SSID=private-name BSSID=private-address IP=private-ip account=private-account
"""
CRASHES = """1793219000.001  100  100 E AndroidRuntime: FATAL EXCEPTION: main
1793219000.002  100  100 E AndroidRuntime: Process: com.google.android.factory.taskmanager, PID: 100
1793219000.003  101  101 F libc    : Fatal signal 11 (SIGSEGV), code 1, fault addr 0x0 in tid 101 (worker), pid 101 (example)
1793219000.004  102  102 E ActivityManager: ANR in example.app
1793219000.005  103  103 I Diagnostics: saved text FATAL EXCEPTION: main ANR in example.app
1793219000.006  103  103 I AndroidRuntime: FATAL EXCEPTION: example text
1793219000.007  103  103 E ActivityManager: lastANRState: no ANR in example.app
FATAL EXCEPTION: bare untrusted text
"""


def fake_adb(serial, *args):
    identity = {("shell", "getprop", "ro.build.fingerprint"): FINGERPRINT,
                ("shell", "am", "get-current-user"): "10\n",
                ("shell", "service", "call", "dynamic_system", "7"): DSU_TRUE}
    if args in identity:
        return identity[args]
    readings = {
        "boot_id": BOOT_ID, "uptime": "1000.20 1700.30\n", "system_server_pid": "1234\n",
        "boot_completed": "1\n", "free": " total used free shared buffers\nMem: 100 20 80 1 2\nSwap: 10 0 10\n",
        "meminfo": "MemTotal: 100 kB\nMemAvailable: 80 kB\nHugePages_Total: 0\n",
        "battery": "Current Battery Service state:\n  status: 2\n  level: 90\n  temperature: 250\n  account: private-account\n",
        "thermal": "Thermal Status: 0\n", "connectivity": NETWORK,
        "wifi": "Wifi is enabled\nWifi is connected to private-name\n", "crash": CRASHES, "anr": "",
    }
    for name, command in probe.QUERIES.items():
        if args == command:
            return readings[name]
    raise AssertionError(f"Unexpected command: {args}")


class StabilityProbeTests(unittest.TestCase):
    def test_identity_requires_exact_user_build_and_true_binder_result(self):
        self.assertTrue(probe.parse_identity(FINGERPRINT, "10\n", DSU_TRUE)["dsu_running"])
        for fingerprint, user, dsu in [
                ("stock/fingerprint", "10", DSU_TRUE), (FINGERPRINT, "0", DSU_TRUE),
                (FINGERPRINT, "110", DSU_TRUE),
                (FINGERPRINT, "10", "Result: Parcel(00000000 00000000   '........')"),
                (FINGERPRINT, "10", "Result: Parcel(ffffffff 00000001   '........')"),
                (FINGERPRINT, "10", "error: service unavailable; true 00000001")]:
            with self.subTest(fingerprint=fingerprint, user=user, dsu=dsu), self.assertRaises(ValueError):
                probe.parse_identity(fingerprint, user, dsu)

    def test_real_crash_evidence_is_filtered_and_not_counted_twice(self):
        seen = set()
        records = []
        self.assertEqual(probe.crash_counts(CRASHES, seen, records), {"fatal_process": 1, "java_crash": 1, "anr": 1})
        self.assertEqual(records[0]["timestamp_epoch_seconds"], "1793219000.001")
        self.assertEqual(records[0]["pid"], 100)
        self.assertIn(records[0]["entry_key"], seen)
        self.assertEqual(probe.crash_counts(CRASHES, seen), dict.fromkeys(probe.CRASH_KINDS, 0))
        system = "1793219001.001  100  100 E AndroidRuntime: FATAL EXCEPTION IN SYSTEM PROCESS: main\n"
        self.assertEqual(probe.crash_counts(system, seen)["java_crash"], 1)

    def test_failed_preconditions_never_sample_or_emit_verified_identity(self):
        failures = [
            (("shell", "getprop", "ro.build.fingerprint"), "stock/fingerprint"),
            (("shell", "am", "get-current-user"), "0"),
            (("shell", "service", "call", "dynamic_system", "7"),
             "Result: Parcel(00000000 00000000   '........')"),
            (("shell", "service", "call", "dynamic_system", "7"), RuntimeError("ADB query exited 1")),
            (probe.QUERIES["crash"], RuntimeError("ADB query exited 1")),
        ]
        for command, response in failures:
            def read(serial, *args):
                if args == command:
                    if isinstance(response, Exception):
                        raise response
                    return response
                return fake_adb(serial, *args)

            with self.subTest(command=command, response=response), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "probe"
                stdout = io.StringIO()
                with patch.object(probe, "adb", side_effect=read), patch.object(probe, "collect") as collect, \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()), \
                        self.assertRaises(SystemExit) as error:
                    probe.main(["--output", str(output), "--duration", "0.001"])
                self.assertEqual(error.exception.code, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertFalse(output.exists())
                collect.assert_not_called()

    def test_connectivity_uses_active_capabilities_without_identifiers(self):
        self.assertTrue(probe.parse_connectivity(NETWORK)["default_wifi_validated"])
        unvalidated = NETWORK.replace("INTERNET&VALIDATED", "INTERNET&NOT_VALIDATED")
        self.assertFalse(probe.parse_connectivity(unvalidated)["default_network_validated"])
        self.assertFalse(probe.parse_connectivity("Active default network: none\n")["default_network_present"])
        with self.assertRaises(ValueError):
            probe.parse_connectivity("Historical VALIDATED WIFI")
        self.assertEqual(probe.parse_free(fake_adb("test", *probe.QUERIES["free"]))["mem"]["free"], 80)
        self.assertEqual(probe.parse_free(fake_adb("test", *probe.QUERIES["free"]))["swap"]["total"], 10)

    def test_output_refuses_source_cloud_symlinks_and_existing_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = Path(probe.__file__).resolve().parent
            (root / "source-link").symlink_to(source, target_is_directory=True)
            with patch.object(Path, "home", return_value=root):
                for path in (source / "artifacts/probe", root / "source-link/probe", root / "Documents/probe"):
                    with self.subTest(path=path), self.assertRaises(ValueError):
                        probe.output_directory(path)
            (root / "keep.txt").write_text("unique data")
            with self.assertRaises(ValueError):
                probe.output_directory(root)
            self.assertEqual((root / "keep.txt").read_text(), "unique data")

    def test_deliberately_disabled_wifi_is_a_disconnected_reading(self):
        def read(serial, *args):
            if args == probe.QUERIES["wifi"]:
                return "Wifi is disabled\n"
            if args == probe.QUERIES["connectivity"]:
                return "Active default network: none\n"
            return fake_adb(serial, *args)

        with tempfile.TemporaryDirectory() as temporary, patch.object(probe, "adb", side_effect=read):
            sample = probe.collect("test", Path(temporary), set())
        self.assertFalse(sample["wifi_connected"])
        self.assertFalse(sample["connectivity"]["default_network_present"])
        self.assertEqual(sample["errors"], [])

    def test_mocked_cli_and_rotation_keep_output_private_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "probe"
            clock = [0.0]
            with patch.object(probe, "adb", side_effect=fake_adb), \
                    patch.object(probe.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(probe.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = probe.main(["--serial", "test", "--output", str(output), "--duration", "0.001", "--interval", "30"])
            self.assertEqual(result, 0)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["samples"], 2)
            self.assertEqual(summary["samples_with_errors"], 0)
            self.assertEqual(summary["baseline_crash_evidence"]["java_crash"], 1)
            self.assertEqual(summary["baseline_crash_records"][0]["pid"], 100)
            self.assertEqual(summary["new_crash_evidence"]["java_crash"], 0)
            sample = json.loads((output / "samples.jsonl").read_text().splitlines()[0])
            self.assertEqual(sample["boot_id"], BOOT_ID)
            self.assertEqual(sample["system_server_pid"], 1234)
            self.assertEqual(sample["new_crash_evidence"], dict.fromkeys(probe.CRASH_KINDS, 0))
            self.assertTrue(sample["wifi_connected"])
            self.assertNotIn("private-", json.dumps(sample) + json.dumps(summary))
            self.assertNotIn("com.google.android.factory.taskmanager", json.dumps(sample) + json.dumps(summary))
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            for file in output.iterdir():
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            for file in output.glob("crash-buffer.log*"):
                file.unlink()
            with patch.object(probe, "RAW_LIMIT", 1024):
                for _ in range(10):
                    probe.raw_log(output, "x" * 400)
            self.assertLessEqual(sum(file.stat().st_size for file in output.glob("crash-buffer.log*")), 1024)

    def test_mocked_long_run_reports_changes_and_read_failures(self):
        clock = [0.0]

        def read(serial, *args):
            if clock[0] >= 30:
                if args == probe.QUERIES["boot_id"]:
                    return "87654321-1234-1234-1234-123456789abc"
                if args == probe.QUERIES["system_server_pid"]:
                    return "4321"
                if args == probe.QUERIES["thermal"]:
                    raise RuntimeError("ADB unavailable or query timed out")
                if args == probe.QUERIES["crash"]:
                    return CRASHES + "1793219031.001  105  105 E AndroidRuntime: FATAL EXCEPTION: main\n"
            return fake_adb(serial, *args)

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(probe, "adb", side_effect=read), \
                patch.object(probe.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(probe.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            summary = probe.probe("test", Path(temporary) / "probe", 1800, 900)
        self.assertEqual(summary["elapsed_seconds"], 1800)
        self.assertEqual(summary["samples"], 3)
        self.assertEqual(summary["samples_with_errors"], 2)
        self.assertEqual({change["field"] for change in summary["unexpected_changes"]}, {"boot_id", "system_server_pid"})
        self.assertEqual(summary["new_crash_evidence"]["java_crash"], 1)


if __name__ == "__main__":
    unittest.main()
