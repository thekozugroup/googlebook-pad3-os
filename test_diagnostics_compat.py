"""Small security-contract checks; runtime hooking remains a device test."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import build_diagnostics_compat as builder


class DiagnosticsContractTest(unittest.TestCase):
    def test_no_permissions_or_exported_components(self):
        manifest = ET.parse(builder.COMPONENT / 'AndroidManifest.xml').getroot()
        self.assertEqual(manifest.attrib['package'], builder.PACKAGE)
        self.assertEqual(manifest.findall('uses-permission'), [])
        self.assertEqual(list(manifest.find('application')), [])

    def test_exact_scope_and_locked_compile_api(self):
        metadata = builder.COMPONENT / 'META-INF/xposed'
        lock = json.loads((builder.COMPONENT / 'source-lock.json').read_text())
        self.assertEqual((metadata / 'scope.list').read_text().strip(), lock['target_package'])
        self.assertEqual(lock['compile_only_api']['classes_jar_sha256'], builder.API_SHA)
        self.assertEqual(lock['target_app_id'], 1000)

    def test_untrusted_compile_input_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); api = root / 'api.jar'; api.write_bytes(b'wrong dependency')
            with patch.object(builder, 'verify_scratch', return_value=root), self.assertRaisesRegex(ValueError, 'API101'):
                builder.build(root, api, root/'key', root/'cert', root/'sdk', root/'jdk', root/'out.apk')
            self.assertFalse((root/'out.apk').exists())

    def test_battery_policy_exposes_only_read_only_leaves(self):
        policy = (builder.ROOT/'components/taskmanager-compat/native/taskmanager_metrics.cil').read_text()
        self.assertEqual(policy.count('(genfscon sysfs '), 3)
        self.assertIn('(allow system_app googlebook_battery_info (file (getattr open read)))', policy)
        self.assertNotIn('googlebook_battery_info (file (write', policy)
