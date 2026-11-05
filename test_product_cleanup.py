from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from native_install import product_cleanup as product
from native_install.payload import sha256


PROPERTIES = (b"ro.product.product.device=erhai\n"
              b"ro.product.build.fingerprint=Googlebook/erhai/erhai:17/GBOS/8:user/release-keys\n"
              b"ro.product.build.version.incremental=8\n")


class Native10ProductTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="product-validation-")
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / "product.img"
        self.original = b"reviewed native8 Product bytes"
        self.target.write_bytes(self.original)
        mocked = patch.object(product, "R5_PHOTOS_TARGET_SHA", sha256(self.target))
        mocked.start()
        self.addCleanup(mocked.stop)

    def test_native10_accepts_only_unchanged_product8_and_its_original_version(self):
        with patch.object(product, "content", return_value=PROPERTIES) as content:
            product.validate_release(self.target, sequence=10)
        content.assert_called_once_with(self.target, "/etc/build.prop")
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_wrong_hash_or_delta_source_is_rejected_before_metadata_read(self):
        with patch.object(product, "content", side_effect=AssertionError("hash/source must reject first")):
            with self.assertRaisesRegex(ValueError, "unchanged reviewed native8"):
                product.validate_release(self.target, sequence=10.0)
            with self.assertRaisesRegex(ValueError, "unchanged reviewed native8"):
                product.validate_release(self.target, self.target, sequence=10)
            self.target.write_bytes(b"arbitrary replacement bytes")
            with self.assertRaisesRegex(ValueError, "unchanged reviewed native8"):
                product.validate_release(self.target, sequence=10)

    def test_native10_rejects_all_other_historical_product_hashes(self):
        with patch.object(product, "content", side_effect=AssertionError("wrong hash")):
            for name in ("TARGET_SHA", "R5_TARGET_SHA", "R5_DIAGNOSTICS_TARGET_SHA", "R5_METRICS_TARGET_SHA"):
                with self.subTest(pin=name), patch.object(product, "R5_PHOTOS_TARGET_SHA", "0" * 64), \
                     patch.object(product, name, sha256(self.target)), self.assertRaises(ValueError):
                    product.validate_release(self.target, sequence=10)

    def test_missing_duplicate_or_relabelled_product_metadata_is_rejected(self):
        for line in PROPERTIES.splitlines(keepends=True):
            cases = (PROPERTIES.replace(line, b""), PROPERTIES + line,
                     PROPERTIES.replace(line, line.partition(b"=")[0] + b"=10\n"))
            for properties in cases:
                with self.subTest(properties=properties), patch.object(product, "content", return_value=properties), \
                     self.assertRaisesRegex(ValueError, "metadata mismatch"):
                    product.validate_release(self.target, sequence=10)

    def test_historical_validation_does_not_relabel_or_require_reuse_metadata(self):
        with patch.object(product, "content", side_effect=AssertionError("historical path unchanged")):
            product.validate_release(self.target)
            product.validate_release(self.target, sequence=8)


if __name__ == "__main__":
    unittest.main()
