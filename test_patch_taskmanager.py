"""Offline build/preservation checks. Supply the active owned scratch and original JAR."""
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib

sys.dont_write_bytecode = True
import patch_taskmanager as patch


class TaskManagerPatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get('TASKMANAGER_TEST_SCRATCH') or not os.environ.get('TASKMANAGER_INPUT_JAR'):
            raise unittest.SkipTest('offline integration requires TASKMANAGER_TEST_SCRATCH and TASKMANAGER_INPUT_JAR')
        cls.scratch = patch.verify_scratch(Path(os.environ['TASKMANAGER_TEST_SCRATCH']))
        cls.original = Path(os.environ['TASKMANAGER_INPUT_JAR'])
        cls.temp = tempfile.TemporaryDirectory(prefix='taskmanager-tests-', dir=cls.scratch)
        cls.work = Path(cls.temp.name)
        cls.env = dict(os.environ, JAVA_TOOL_OPTIONS='-Xmx768m -Djava.io.tmpdir=' + str(cls.work),
                       TMPDIR=str(cls.work))
        cls.output = cls.work / 'candidate.jar'
        cls.receipt = patch.build(cls.original, cls.scratch, cls.output)
        for name, jar in [('original', cls.original), ('patched', cls.output)]:
            with zipfile.ZipFile(jar) as archive:
                (cls.work / (name + '.dex')).write_bytes(archive.read('classes.dex'))
            patch.run([patch.JAVA / 'bin/java', '-cp', patch.JADX,
                       'com.android.tools.smali.baksmali.Main', 'd', cls.work / (name + '.dex'),
                       '-o', cls.work / (name + '-smali')], cls.env)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_host_metrics_and_gate_fixtures(self):
        self.assertRegex(self.receipt['host_checks'], r'\d+ metric/gate fixture checks passed')
        self.assertGreaterEqual(int(self.receipt['host_checks'].split()[0]), 40)

    def test_complete_preservation_boundary(self):
        proof = self.receipt['preservation']
        self.assertEqual(proof['original_classes'], 153)
        self.assertEqual(proof['unchanged_classes'], 152)
        self.assertEqual(proof['public_manager_methods'], 79)
        self.assertEqual(proof['public_manager_fields'], 30)
        self.assertEqual(set(proof['changed_methods']), patch.TARGET_COUNTS.keys())
        self.assertEqual(proof['untouched_manager_methods'], 83)
        self.assertTrue(proof['original_target_instructions_branches_try_debug_preserved'])
        self.assertFalse(proof['compile_only_classes_in_candidate'])

    def test_local_cancellation_is_guarded_and_returns_no_fake_token(self):
        methods, _ = patch.split_methods((self.work / 'patched-smali' / patch.MANAGER).read_text())
        _, instructions, _ = patch.code_records(methods['stopLongRunningTest(Ljava/lang/String;)V'])
        self.assertTrue(instructions[1].endswith('->mTaskManagerCompat:Z'))
        self.assertTrue(instructions[2].startswith('if-eqz '))
        self.assertEqual(instructions[3], 'return-void')

    def test_helper_links_to_original_public_dtos(self):
        self.assertGreaterEqual(self.receipt['transform']['validated_client_references'], 9)

    def test_input_sha_guard_before_rewrite(self):
        damaged = self.work / 'wrong-original.jar'
        data = bytearray(self.original.read_bytes())
        data[-1] ^= 1
        damaged.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            patch.guard_original(damaged)
        self.assertEqual(patch.digest(self.original), patch.ORIGINAL_SHA256)

    def test_already_patched_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'original client JAR'):
            patch.guard_original(self.output)

    def test_dex_signature_and_identifier_order(self):
        original = (self.work / 'original.dex').read_bytes()
        self.assertEqual(patch.verify_dex(original)['classes'], 153)
        data = bytearray((self.work / 'patched.dex').read_bytes())
        _, offset = struct.unpack_from('<II', data, 56)
        first, second = struct.unpack_from('<II', data, offset)
        struct.pack_into('<II', data, offset, second, first)
        data[12:32] = hashlib.sha1(data[32:]).digest()
        struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
        with self.assertRaisesRegex(ValueError, 'StringIDs not strictly ordered'):
            patch.verify_dex(data)

    def test_candidate_layout_and_original_manifest(self):
        with zipfile.ZipFile(self.output) as candidate, zipfile.ZipFile(self.original) as original:
            self.assertEqual(candidate.namelist(), original.namelist())
            self.assertEqual(candidate.read('META-INF/MANIFEST.MF'), original.read('META-INF/MANIFEST.MF'))
            self.assertNotEqual(candidate.read('classes.dex'), original.read('classes.dex'))
            self.assertEqual(patch.verify_dex(candidate.read('classes.dex'))['classes'],
                             153 + len(self.receipt['preservation']['helper_classes']))

    def test_unrelated_class_change_is_rejected(self):
        changed = next(p for p in (self.work / 'patched-smali').rglob('*.smali')
                       if not p.name.startswith(('ServiceabilityManager', 'TaskManagerCompat')))
        before = changed.read_text()
        try:
            changed.write_text(before + '\n# deliberate preservation-test tamper\n')
            with self.assertRaisesRegex(ValueError, 'unrelated class changed'):
                patch.preservation(self.work / 'original-smali', self.work / 'patched-smali')
        finally:
            changed.write_text(before)

    def test_new_public_field_is_rejected(self):
        changed = self.work / 'patched-smali' / patch.MANAGER
        before = changed.read_text()
        try:
            changed.write_text(before.replace(patch.MODE_LINE, '.field public mTaskManagerCompat:Z'))
            with self.assertRaisesRegex(ValueError, 'private mode field drift'):
                patch.preservation(self.work / 'original-smali', self.work / 'patched-smali')
        finally:
            changed.write_text(before)

    def test_wrong_guard_continuation_is_rejected(self):
        changed = self.work / 'patched-smali' / patch.MANAGER
        before = changed.read_text()
        methods, _ = patch.split_methods(before)
        signature = next(k for k in patch.TARGET_COUNTS if k.startswith('fetchCpuUsageInfo()'))
        block = methods[signature]
        _, instructions, labels = patch.code_records(block)
        branch = next(line for line in instructions[:6] if line.startswith('if-eqz '))
        wrong = next(label for label, index in labels.items() if index > 6)
        corrupted = block.replace(branch, branch.rsplit(' ', 1)[0] + ' ' + wrong, 1)
        try:
            changed.write_text(before.replace(block, corrupted))
            with self.assertRaisesRegex(ValueError, 'guard does not continue'):
                patch.preservation(self.work / 'original-smali', self.work / 'patched-smali')
        finally:
            changed.write_text(before)

    def test_unrelated_added_class_is_rejected(self):
        unexpected = self.work / 'patched-smali/Unexpected.smali'
        try:
            unexpected.write_text('.class public LUnexpected;\n.super Ljava/lang/Object;\n')
            with self.assertRaisesRegex(ValueError, 'unexpected added class'):
                patch.preservation(self.work / 'original-smali', self.work / 'patched-smali')
        finally:
            unexpected.unlink()

    def test_output_and_scratch_boundaries(self):
        with self.assertRaisesRegex(ValueError, 'canonical candidate or owned scratch'):
            patch.verify_output(patch.ROOT / 'unrequested.jar', self.scratch)
        with self.assertRaisesRegex(ValueError, 'refusing to overwrite'):
            patch.verify_output(self.output, self.scratch)
        with self.assertRaisesRegex(ValueError, 'CleanOS task root'):
            patch.verify_scratch(self.work)

    def test_identical_rebuild(self):
        repeated = self.work / 'repeat.jar'
        receipt = patch.build(self.original, self.scratch, repeated)
        self.assertEqual(receipt['candidate_sha256'], self.receipt['candidate_sha256'])
        self.assertEqual(repeated.read_bytes(), self.output.read_bytes())
        self.assertEqual(receipt['preservation'], self.receipt['preservation'])


if __name__ == '__main__':
    unittest.main()
