import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

COMPONENT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('photos_verify', COMPONENT / 'verify.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class SourceContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(os.environ['PHOTOS_SOURCE_ROOT'])

    def changed_source(self, relative, before, after):
        tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(tmp.cleanup)
        target = Path(tmp.name) / 'source'
        # Only contract inputs are needed; do not duplicate dependencies or full source.
        shutil.copytree(self.source / verify.JAVA, target / verify.JAVA)
        metadata = Path('app/src/main/resources/META-INF/xposed')
        shutil.copytree(self.source / metadata, target / metadata)
        path = target / relative
        text = path.read_text()
        self.assertIn(before, text)
        path.write_text(text.replace(before, after, 1))
        return target

    def test_locked_candidate_satisfies_contract(self):
        verify.verify_source(self.source)

    def test_broad_package_eligibility_is_rejected(self):
        source = self.changed_source(verify.JAVA / 'ScopePolicy.kt',
            'return packageName == Constants.PACKAGE_NAME_GOOGLE_PHOTOS', 'return true')
        with self.assertRaisesRegex(ValueError, 'Exact Photos'):
            verify.verify_source(source)

    def test_security_patch_cannot_enter_profile_writes(self):
        source = self.changed_source(verify.JAVA / 'DeviceSpoofer.kt', '"SECURITY_PATCH", ', '')
        with self.assertRaisesRegex(ValueError, 'Real version/security'):
            verify.verify_source(source)

    def test_feature_entry_cannot_skip_package_guard(self):
        source = self.changed_source(verify.JAVA / 'FeatureSpoofer.kt',
            'if (!ScopePolicy.shouldSpoof(packageName)) return', '// guard removed')
        with self.assertRaisesRegex(ValueError, 'fail closed'):
            verify.verify_source(source)

    def test_api101_and_single_package_scope_are_required(self):
        relative = Path('app/src/main/resources/META-INF/xposed/scope.list')
        source = self.changed_source(relative, verify.PACKAGE, verify.PACKAGE + '\ncom.google.android.gms')
        with self.assertRaisesRegex(ValueError, 'Only Photos'):
            verify.verify_source(source)

    def test_publicable_inputs_contain_no_owner_tool_paths(self):
        forbidden = [str(Path.home()) + '/', '/'.join(['', 'Users', '']),
                     '/'.join(['', 'private', 'tmp', ''])]
        for path in COMPONENT.rglob('*'):
            if path.is_file():
                text = path.read_text()
                self.assertFalse(any(value in text for value in forbidden), str(path.relative_to(COMPONENT)))
                self.assertNotIn(path.suffix.lower(), {'.apk', '.zip', '.gz', '.jks', '.keystore', '.p12'})
        lock = json.loads((COMPONENT / 'source-lock.json').read_text())
        self.assertEqual(lock['module']['minimum_modern_libxposed_api'], 101)
        self.assertEqual(lock['module']['scope'], [verify.PACKAGE])
