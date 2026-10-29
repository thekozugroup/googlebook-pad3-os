import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import assemble_port
import cold_build_dsu as cold


class ColdBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_seed_omits_only_tpm_replacement_and_normal_assembly_keeps_it(self):
        config = {"donor": {"partitions": {}}, "tablet": {"partitions": {}}}
        for group, directory, names in [("donor", "donor-images", ["system_a", "system_ext_a", "product_a"]),
                                         ("tablet", "pad3-base-images", ["system_ext"])]:
            root = self.root / directory
            root.mkdir()
            for name in names:
                data = name.encode()
                (root / (name + ".img")).write_bytes(data)
                config[group]["partitions"][name] = hashlib.sha256(data).hexdigest()
        tpm = "/system/etc/init/check_tpm_clear.rc"
        changes = {"system": {tpm: b"disabled", "/keep": b"unchanged"},
                   "system_ext": {"/keep": b"extension"}, "product": {"/keep": b"product"}}
        observed = {}

        def overlay(image, output, payloads, scratch, **kwargs):
            observed[(output.parent.name, output.stem)] = dict(payloads)
            output.write_bytes(b"fixture")
            return {"bytes": 7, "sha256": hashlib.sha256(b"fixture").hexdigest(), "changed_paths": list(payloads)}

        def graft(*args):
            return {"data": b"graft", "metadata": {"xattrs": {"security.selinux": b"original"}}}

        with patch("assemble_port.json.loads", return_value=config), \
                patch("assemble_port.create", side_effect=lambda images: copy.deepcopy(changes)), \
                patch("assemble_port.content", return_value=b"original contexts\n"), \
                patch("assemble_port.regular_file", side_effect=graft), patch("assemble_port.apply", side_effect=overlay):
            assemble_port.build(self.root, self.root / "normal")
            assemble_port.build(self.root, self.root / "seed", diagnostic_seed=True)
        self.assertEqual(observed[("normal", "system")].pop(tpm), b"disabled")
        self.assertEqual(observed[("normal", "system")], observed[("seed", "system")])
        self.assertNotIn(tpm, observed[("seed", "system")])
        for part in ("product", "system_ext"):
            self.assertEqual(observed[("normal", part)], observed[("seed", part)])
        self.assertIn(tpm, changes["system"])

    def test_bad_seed_hash_stops_before_diagnostic_overlay(self):
        def assemble(work, output, **kwargs):
            self.assertIs(kwargs["diagnostic_seed"], True)
            output.mkdir()
            for part in cold.PARTITIONS:
                (output / (part + ".img")).write_bytes(b"incorrect seed")
        with patch("cold_build_dsu.verify_task"), patch("cold_build_dsu.prepare"), \
                patch("cold_build_dsu.compiler_for", return_value=self.root / "compiler"), \
                patch("cold_build_dsu.assemble", side_effect=assemble), patch("cold_build_dsu.build") as diagnostic, \
                patch.dict(os.environ):
            with self.assertRaisesRegex(ValueError, "unverified source image"):
                cold.cold_build(self.root)
            diagnostic.assert_not_called()

    def test_current_v9_requires_exact_three_image_hashes_and_lengths(self):
        expected = copy.deepcopy(cold.EXPECTED_IMAGES)
        self.assertEqual(cold.verify_current_images(expected), {p: expected[p]["sha256"] for p in cold.PARTITIONS})
        invalid = copy.deepcopy(expected)
        invalid["system"]["sha256"] = "wrong"
        for images in [invalid, {p: value for p, value in expected.items() if p != "product"},
                       dict(expected, vendor=expected["system"])]:
            with self.assertRaisesRegex(ValueError, "V9 image mismatch"):
                cold.verify_current_images(images)
        invalid = copy.deepcopy(expected)
        invalid["product"]["bytes"] += 4096
        with self.assertRaisesRegex(ValueError, "V9 image mismatch"):
            cold.verify_current_images(invalid)

    def test_reused_compiler_requires_pinned_source_and_matching_binary_hash(self):
        compiler = self.root / "secilc-tools/bin/secilc"
        compiler.parent.mkdir(parents=True)
        compiler.write_bytes(b"test compiler")
        compiler.chmod(0o755)
        (self.root / "secilc-tools/provenance.txt").write_text(
            "source=https://android.googlesource.com/platform/external/selinux\n"
            "revision=a8c5e74f85f869bf236a01ba24181b78f5e39a52\n" + cold.sha256(compiler) + "  /cache/bin/secilc\n")
        self.assertEqual(cold.compiler_for(self.root), compiler)
        compiler.write_bytes(b"corrupt compiler")
        with self.assertRaisesRegex(ValueError, "unverified secilc"):
            cold.compiler_for(self.root)
        compiler.unlink()
        target = self.root / "other-file"
        target.write_bytes(b"not a compiler")
        compiler.symlink_to(target)
        with patch("cold_build_dsu.sha256") as digest:
            with self.assertRaisesRegex(ValueError, "compiler path"):
                cold.compiler_for(self.root)
            digest.assert_not_called()

    def test_untracked_task_is_refused(self):
        with self.assertRaises(ValueError):
            cold.verify_task(self.root)


if __name__ == "__main__":
    unittest.main()
