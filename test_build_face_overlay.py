"""Focused RRO scope, certificate and scratch/output boundary tests."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

import build_face_overlay as face


class FaceOverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = os.environ.get('FACE_OVERLAY_TEST_SCRATCH')
        if not scratch:
            raise unittest.SkipTest('set FACE_OVERLAY_TEST_SCRATCH to an active CleanOS task root')
        cls.scratch = face.verify_scratch(scratch)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.scratch, prefix='face-overlay-test-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def component(self):
        target = self.work / 'component'
        shutil.copytree(face.COMPONENT, target)
        return target

    def test_source_has_exactly_one_override_and_no_extra_privileges(self):
        hashes = face.verify_sources()
        self.assertEqual(len(hashes), 5)
        self.assertEqual(face.ADMISSION['entry'], {
            'package': face.PACKAGE, 'mutable': 'false', 'enabled': 'true'})
        self.assertIsNone(face.ADMISSION['target_name'])

    def test_wrong_boolean_is_rejected(self):
        component = self.component()
        path = component / 'res/values/bools.xml'
        path.write_text(path.read_text().replace('false', 'true'))
        with self.assertRaisesRegex(ValueError, 'false preview boolean'):
            face.verify_sources(component)

    def test_wrong_target_or_mapping_is_rejected(self):
        component = self.component()
        manifest = component / 'AndroidManifest.xml'
        original = manifest.read_text()
        manifest.write_text(original.replace('com.android.settings', 'other.settings'))
        with self.assertRaisesRegex(ValueError, 'manifest attributes'):
            face.verify_sources(component)
        manifest.write_text(original)
        mapping = component / 'res/xml/overlays.xml'
        mapping.write_text(mapping.read_text().replace('target="bool/', 'target="integer/'))
        with self.assertRaisesRegex(ValueError, 'resource mapping'):
            face.verify_sources(component)

    def test_additional_resource_is_rejected(self):
        component = self.component()
        (component / 'res/values/unrelated.xml').write_text('<resources/>')
        with self.assertRaisesRegex(ValueError, 'file inventory'):
            face.verify_sources(component)

    def test_source_symlinks_are_rejected(self):
        linked = self.work / 'linked'
        linked.symlink_to(face.COMPONENT, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            face.verify_sources(linked)
        component = self.component()
        path = component / 'res/values/bools.xml'
        path.unlink()
        path.symlink_to(face.COMPONENT / 'res/values/bools.xml')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            face.verify_sources(component)

    def test_certificate_rejects_text_and_empty_input_without_openssl(self):
        path = self.work / 'public.der'
        for data in (b'', b'not DER', b'-----BEGIN CERTIFICATE-----\ninvalid\n'):
            path.write_bytes(data)
            with self.subTest(data=data), mock.patch.object(face.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    face.certificate_sha256(path)
                run.assert_not_called()

    def test_certificate_rejects_symlink_and_oversize(self):
        path = self.work / 'public.der'
        path.write_bytes(b'\x30' + bytes(16384))
        with self.assertRaisesRegex(ValueError, 'size invalid'):
            face.certificate_sha256(path)
        link = self.work / 'linked.der'
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, 'without symlinks'):
            face.certificate_sha256(link)

    def test_certificate_requires_openssl_success_and_exact_canonical_der(self):
        path = self.work / 'public.der'
        data = b'\x30test-public-DER-fixture'
        path.write_bytes(data)
        for code, output in ((1, data), (0, data[:-1])):
            result = subprocess.CompletedProcess([], code, output, b'')
            with mock.patch.object(face.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(ValueError, 'complete canonical'):
                    face.certificate_sha256(path)
        result = subprocess.CompletedProcess([], 0, data, b'')
        with mock.patch.object(face.subprocess, 'run', return_value=result) as run:
            self.assertEqual(face.certificate_sha256(path), hashlib.sha256(data).hexdigest())
            self.assertEqual(run.call_args.args[0],
                             ['openssl', 'x509', '-inform', 'DER', '-outform', 'DER'])
            self.assertEqual(run.call_args.kwargs['input'], data)

    def test_nested_or_linked_scratch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'CleanOS task root'):
            face.verify_scratch(self.work)
        link = self.work / 'scratch-link'
        link.symlink_to(self.scratch, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'real path'):
            face.verify_scratch(link)

    def test_finished_or_foreign_task_is_rejected_without_editing_manifest(self):
        task = json.loads((self.scratch / '.cleanos-task.json').read_text())
        for change in ({'finished': True}, {'owner': -1}, {'project': 'different-project'},
                       {'id': 'different-task'}):
            with self.subTest(change=change), mock.patch.object(face.json, 'loads', return_value=task | change):
                with self.assertRaisesRegex(ValueError, 'inactive or foreign'):
                    face.verify_scratch(self.scratch)

    def test_unverified_backup_exclusion_is_rejected(self):
        with mock.patch.object(face, 'run', return_value='[Included] task'):
            with self.assertRaisesRegex(ValueError, 'exclusion not verified'):
                face.verify_scratch(self.scratch)

    def test_existing_output_is_preserved_before_reading_certificate(self):
        output = self.work / 'face-preview-overlay'
        output.mkdir()
        sentinel = output / 'keep.txt'
        sentinel.write_text('existing parent work')
        with mock.patch.object(face, 'verify_scratch', return_value=self.work), \
                mock.patch.object(face, 'certificate_sha256') as certificate:
            with self.assertRaisesRegex(ValueError, 'refusing to overwrite'):
                face.build(self.scratch, self.work / 'absent.der')
            certificate.assert_not_called()
        self.assertEqual(sentinel.read_text(), 'existing parent work')

    def test_unsigned_payload_rejects_code_signatures_and_duplicates(self):
        apk = self.work / 'overlay.apk'
        base = {'AndroidManifest.xml': b'manifest', 'resources.arsc': b'resources',
                'res/xml/overlays.xml': b'mapping'}
        for extra in ({'classes.dex': b'dex'}, {'META-INF/CERT.RSA': b'signature'},
                      {'resources.arsc': b'APK Sig Block 42'}):
            with zipfile.ZipFile(apk, 'w') as archive:
                for name, data in (base | extra).items():
                    archive.writestr(name, data)
            with self.assertRaises(ValueError):
                face.verify_unsigned_payload(apk)
        with zipfile.ZipFile(apk, 'w') as archive:
            for name, data in base.items():
                archive.writestr(name, data)
        face.verify_unsigned_payload(apk)
        with warnings.catch_warnings(), zipfile.ZipFile(apk, 'a') as archive:
            warnings.simplefilter('ignore', UserWarning)
            archive.writestr('resources.arsc', b'duplicate')
        with self.assertRaisesRegex(ValueError, 'resource-only unsigned overlay payload'):
            face.verify_unsigned_payload(apk)


if __name__ == '__main__':
    unittest.main()
