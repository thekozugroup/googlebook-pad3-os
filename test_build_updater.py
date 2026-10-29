import tempfile
import unittest
from pathlib import Path
import ast
import json
import os
import struct
import subprocess
import zipfile
from unittest.mock import patch

import build_updater as builder


class UpdaterBuildTest(unittest.TestCase):
    def test_public_owner_feed(self):
        self.assertEqual(builder.validate_feed(builder.FEED), builder.FEED)

    def test_feed_rejects_cleartext_credentials_foreign_hosts_and_path_escape(self):
        for url in (builder.FEED.replace("https:", "http:"), builder.FEED.replace("raw.githubusercontent.com", "evil.test"),
                    builder.FEED.replace("https://", "https://token@"), builder.FEED + "#fragment", builder.FEED + "?token=secret",
                    builder.FEED.replace("googlebook-pad3-os/", "googlebook-pad3-os/../other/"),
                    builder.FEED.replace("raw.githubusercontent.com", "raw.githubusercontent.com.evil.test"),
                    builder.FEED.replace("raw.githubusercontent.com", "raw.githubusercontent.com:8443")):
            with self.subTest(url=url), self.assertRaises(ValueError):
                builder.validate_feed(url)

    def test_no_key_is_explicitly_unprovisioned(self):
        self.assertEqual(builder.public_key(None), b"")

    def test_private_pem_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "not-a-key.txt"
            path.write_bytes(b"This is a format-rejection fixture, not key material.\n")
            with self.assertRaisesRegex(ValueError, "public SPKI DER"):
                builder.public_key(path)

    def test_key_size_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized-public.der"
            path.write_bytes(b"x" * 4097)
            with self.assertRaises(ValueError):
                builder.public_key(path)
            link = Path(temporary) / "link.der"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                builder.public_key(link)

    def test_source_cloud_path_cannot_be_build_scratch(self):
        with self.assertRaisesRegex(ValueError, "physical CleanOS scratch"):
            builder.verify_scratch(Path.home() / "Documents/ChatGPT/Oneplus pad 3")

    def test_unowned_tmp_folder_cannot_be_build_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                builder.verify_scratch(Path(temporary))

    def test_output_stays_in_scratch_or_component_candidates(self):
        scratch = Path("/private/tmp/ai-development/output-contract-fixture")
        self.assertEqual(builder.output_path(scratch), builder.OUTPUT)
        self.assertEqual(builder.output_path(scratch, scratch / "Updater.apk"), scratch / "Updater.apk")
        for output in (builder.COMPONENT / "Updater.apk", Path.home() / "Documents/Updater.apk", Path("relative.apk")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                builder.output_path(scratch, output)

    def test_actual_native_writer_zip32_and_zip64_match_consumer(self):
        from native_install import payload
        source = (builder.ROOT / "build_native_rom.py").read_text()
        metadata_prefix = None
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "writestr"
                    and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "META-INF/com/android/metadata"):
                prefix = node.args[1].left if isinstance(node.args[1], ast.BinOp) else node.args[1]
                self.assertIsInstance(prefix, ast.Constant, "review producer metadata API drift")
                metadata_prefix = prefix.value
        self.assertIsNotNone(metadata_prefix)
        lock = json.loads((builder.COMPONENT / "toolchain.json").read_text())
        java = Path(os.environ.get("JAVA_HOME", lock["java_home"])) / "bin"
        if not all((java / tool).is_file() for tool in ("java", "javac")):
            self.skipTest("set JAVA_HOME or configure the portable JDK input")
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            image = work / "system.img"; image.write_bytes(b"\0" * 4096)
            binary = work / "payload.bin"
            # Explicitly keyless format test: these mocks prevent all signing/key access.
            with patch.object(payload, "public_key", return_value=b"keyless"), patch.object(payload, "sign_digest", return_value=b"x" * 256), patch.object(payload, "verify_digest"):
                properties, _ = payload.write_payload({"system": image}, [{"name": "fixture", "maximum_size": 4096, "partitions": ["system"]}],
                                                      100, True, None, None, binary, work)
            signature_size = struct.unpack_from(">I", binary.read_bytes(), 20)[0]
            props = work / "payload_properties.txt"; props.write_text("".join(f"{k}={v}\n" for k, v in properties.items()))
            env = dict(os.environ, JAVA_TOOL_OPTIONS=f"-Djava.io.tmpdir={work} -XX:-UsePerfData")
            subprocess.run([str(java / "javac"), "--release", "17", "-d", str(work),
                            str(builder.COMPONENT / "src/org/googlebook/pad3/updater/UpdateCore.java"),
                            str(builder.COMPONENT / "tests/ProducerConsumerTest.java")], env=env, check=True, capture_output=True)
            for zip64 in (False, True):
                with self.subTest(zip64=zip64):
                    archive = work / ("zip64.zip" if zip64 else "zip32.zip")
                    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as out:
                        with out.open("payload.bin", "w", force_zip64=zip64) as stream: stream.write(binary.read_bytes())
                        out.writestr("payload_properties.txt", props.read_bytes())
                        out.writestr("META-INF/com/android/metadata", metadata_prefix + "post-timestamp=100\n")
                    with zipfile.ZipFile(archive) as result:
                        start = result.getinfo("payload.bin").header_offset
                    with archive.open("rb") as stream:
                        stream.seek(start + 26); name, extra = struct.unpack("<HH", stream.read(4))
                    result = subprocess.run([str(java / "java"), "-cp", str(work), "org.googlebook.pad3.updater.ProducerConsumerTest",
                                             str(archive), str(props), str(start + 30 + name + extra), str(signature_size)],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("PRODUCER_CONSUMER_FORMAT_PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
