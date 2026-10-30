"""Trust-boundary checks for the Photos framework graft."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_photos_native as build


class PhotosNativeTest(unittest.TestCase):
    def test_exact_package_and_minimum_targets(self):
        lock = json.loads((build.COMPONENT/'source-lock.json').read_text())
        self.assertEqual(lock['scope'], ['com.google.android.apps.photos'])
        self.assertEqual(len(lock['source_targets']), 2)
        self.assertFalse(lock['dependency_on_zygisk_or_xposed'])

    def test_unknown_source_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'framework.jar'; source.write_bytes(b'wrong')
            with patch.object(build, 'verify_scratch', return_value=root), self.assertRaisesRegex(ValueError, 'source drift'):
                build.build(source, root/'out.jar', root, root/'sdk', root/'jdk', root/'tools')
            self.assertFalse((root/'out.jar').exists())

    def test_unrelated_class_change_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); before=root/'a'; after=root/'b'; before.mkdir(); after.mkdir()
            (before/'Other.smali').write_text('.class public LOther;\n')
            (after/'Other.smali').write_text('.class public LDifferent;\n')
            with self.assertRaisesRegex(ValueError, 'unrelated framework class'):
                build.preservation(before, after)

    def test_normalization_preserves_branch_identity(self):
        first='if-eqz v0, :cond_a\n:cond_a\nreturn-void\n'
        renamed='if-eqz v0, :cond_b\n:cond_b\nreturn-void\n'
        self.assertEqual(build.normalize(first), build.normalize(renamed))
        self.assertNotEqual(build.normalize(first), build.normalize(renamed.replace('if-eqz','if-nez')))

    def test_encoded_static_zero_and_default_are_equivalent(self):
        field = '.field private static final FLAG:I'
        self.assertEqual(build.normalize(field+' = 0x0'), build.normalize(field))
        self.assertNotEqual(build.normalize(field+' = 0x1'), build.normalize(field))

    def test_normalization_preserves_string_literals(self):
        for value in ('goto/16 ', 'goto/32 ', 'const-string/jumbo ', ':cond_a'):
            text = 'const-string/jumbo v0, "'+value+'"\n:cond_a\n'
            normalized = build.normalize(text)
            self.assertIn('"'+value+'"', normalized)
            self.assertTrue(normalized.startswith('const-string v0,'))

    def test_target_declarations_annotations_and_parameters_are_preserved(self):
        method = ('.method public hasSystemFeature(Ljava/lang/String;I)Z\n'
                  '    .registers 6\n    .param p1, "feature"\n'
                  '    .annotation runtime LExample;\n        value = "original"\n'
                  '    .end annotation\n    return v0\n.end method\n')
        for before, after in [('public ', 'private '), ('LExample;', 'LChanged;'),
                              ('.registers 6', '.registers 7'), ('p1, "feature"', 'p2, "feature"')]:
            with self.subTest(change=before), tempfile.TemporaryDirectory() as directory:
                a, b = Path(directory)/'a', Path(directory)/'b'
                for path, text in [(a, method), (b, method.replace(before, after))]:
                    file = path/'android/app/ApplicationPackageManager.smali'
                    file.parent.mkdir(parents=True); file.write_text(text)
                with self.assertRaisesRegex(ValueError, 'target (declaration|annotations|register/parameter)'):
                    build.preservation(a, b)

    def test_absent_sdk_flags_match_explicit_zero_only(self):
        method = '.method public test()V'
        self.assertEqual(build.normalize(method), build.normalize(method.replace('public ', 'public whitelist ')))
        self.assertNotEqual(build.normalize(method), build.normalize(method.replace('public ', 'public blacklist ')))
