import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("identity_build", Path(__file__).resolve().parents[1] / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildBoundaryTest(unittest.TestCase):
    def test_unknown_input_is_rejected_before_output_or_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "wrong.dex", root / "must-not-exist"
            source.write_bytes(b"dex\n039\0unsupported module version")
            args = argparse.Namespace(input_dex=source, scratch=output,
                                      java_home=root / "missing", jadx_jar=root / "missing", d8=root / "missing")
            with self.assertRaisesRegex(ValueError, "unsupported module input SHA-256"):
                build.build(args)
            self.assertFalse(output.exists())
            argv = ["--input-dex", str(source), "--scratch", str(output),
                    "--java-home", str(root / "missing"), "--jadx-jar", str(root / "missing"),
                    "--d8", str(root / "missing")]
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(build.main(argv), 1)
            self.assertFalse(output.exists())

    def test_cloud_and_relative_scratch_are_rejected(self):
        for path in (Path("relative-output"), Path("/tmp/CloudStorage/identity-output")):
            with self.assertRaises(ValueError):
                build.local_path(path)


if __name__ == "__main__":
    unittest.main()
