import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prepare_inputs import prepare


class CachedInputsTest(unittest.TestCase):
    def test_verified_partitions_do_not_need_download_archives(self):
        config = json.loads(Path(__file__).with_name("inputs.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / ".cleanos-task.json").write_text("{}")
            hashes = {}
            for group, folder in [("donor", "donor-images"), ("tablet", "pad3-base-images")]:
                (work / folder).mkdir()
                for name, expected in config[group]["partitions"].items():
                    path = work / folder / (name + ".img")
                    path.touch()
                    hashes[path] = expected
            with patch("prepare_inputs.download") as download, patch("prepare_inputs.digest", side_effect=hashes.__getitem__):
                prepare(work)
                download.assert_not_called()
            hashes[work / "donor-images/system_a.img"] = "corrupt"
            with patch("prepare_inputs.download") as download, patch("prepare_inputs.digest", side_effect=hashes.__getitem__):
                with self.assertRaisesRegex(ValueError, "extracted partition mismatch"):
                    prepare(work)
                download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
