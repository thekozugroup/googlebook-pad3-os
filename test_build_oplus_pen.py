"""Focused source, path and privilege boundaries for the standalone pen builder."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

import build_oplus_pen as pen


@unittest.skipUnless(os.environ.get('OPLUS_PEN_TEST_SCRATCH'), 'active local CleanOS task required')
class PenBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = pen.verify_scratch(os.environ['OPLUS_PEN_TEST_SCRATCH'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.scratch, prefix='pen-test-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def test_pinned_sources_and_patch_are_complete(self):
        self.assertEqual(pen.verify_sources()['commit'], 'c78b87c9efb89049b35a184d60095f26c7cb29aa')

    def run_kotlin_check(self, production_files, test_file, main_class):
        source = self.work / 'source'
        shutil.copytree(pen.COMPONENT / 'upstream/packages/Pen', source)
        config = pen.load(pen.COMPONENT / "toolchain.json")
        inputs = [*config["dependencies"].values(), *config["tools"].values()]
        if not (Path(config["java_home"]) / "bin/java").is_file() or not all(Path(item["path"]).is_file() for item in inputs):
            self.skipTest("configure the pinned local pen toolchain inputs")
        lock = pen.verify_toolchain()
        env = os.environ.copy()
        env['JAVA_HOME'] = lock['java_home']
        env['JAVA_TOOL_OPTIONS'] = '-Djava.io.tmpdir=' + str(self.work)
        commands = []
        pen.run(['git', '-C', source, 'apply', pen.COMPONENT / 'patches/googlebook.patch'], self.work, env, commands)
        java = Path(lock['java_home']) / 'bin/java'
        deps = lock['dependencies']
        target = self.work / 'lifecycle.jar'
        pen.run([java, '-cp', os.pathsep.join(x['path'] for x in deps.values()),
                 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
                 '-jvm-target', '1.8', '-classpath', deps['stdlib']['path'], '-d', target,
                 *(source / 'src/org/lineageos/pen' / name for name in production_files),
                 pen.COMPONENT / 'tests' / test_file], self.work, env, commands)
        output = pen.run([java, '-cp', str(target) + os.pathsep + deps['stdlib']['path'],
                          'org.lineageos.pen.' + main_class], self.work, env, commands)
        self.assertIn('PASS', output)

    def test_kotlin_runtime_lifecycle_and_permission_races(self):
        self.run_kotlin_check(['PenRuntime.kt'], 'PenRuntimeSelfTest.kt', 'PenRuntimeSelfTestKt')

    def test_kotlin_peak_cap_save_restore_owner_and_error_cases(self):
        self.run_kotlin_check(['PeakCap.kt', 'PenProtocol.kt'], 'PeakCapSelfTest.kt', 'PeakCapSelfTestKt')

    def test_source_tampering_is_rejected(self):
        component = self.work / 'component'
        shutil.copytree(pen.COMPONENT, component, ignore=shutil.ignore_patterns('build-result.json'))
        source = component / 'upstream/packages/Pen/src/org/lineageos/pen/PenRelay.kt'
        source.write_text(source.read_text() + '\n// changed\n')
        with self.assertRaisesRegex(ValueError, 'upstream source drift'):
            pen.verify_sources(component)

    def test_unmanifested_code_is_rejected(self):
        component = self.work / 'component'
        shutil.copytree(pen.COMPONENT, component, ignore=shutil.ignore_patterns('build-result.json'))
        (component / 'upstream/injected.kt').write_text('fun injected() = Unit')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            pen.verify_sources(component)

    def test_parent_path_escape_is_rejected(self):
        for name in ['../key', '/private/key', 'a/../key', 'a//key', './key']:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'unsafe'):
                pen.source_path(self.work, name)

    def test_symlink_input_is_rejected(self):
        (self.work / 'link').symlink_to('/private/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            pen.source_path(self.work, 'link')

    def test_component_root_symlink_is_rejected(self):
        component = self.work / 'component'
        component.symlink_to(pen.COMPONENT, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            pen.verify_sources(component)

    def test_output_cannot_overwrite_or_escape(self):
        target = self.work / 'candidate.apk'
        with mock.patch.object(pen, 'ROOT', self.work), mock.patch.object(pen, 'ARTIFACT', target):
            pen.verify_output(target)
            target.write_bytes(b'keep')
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                pen.verify_output(target)
            with self.assertRaisesRegex(ValueError, 'canonical'):
                pen.verify_output(self.work / 'other.apk')
            self.assertEqual(target.read_bytes(), b'keep')

    def test_symlink_output_is_rejected(self):
        target = self.work / 'candidate.apk'
        target.symlink_to(self.work / 'missing')
        with mock.patch.object(pen, 'ROOT', self.work), mock.patch.object(pen, 'ARTIFACT', target):
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                pen.verify_output(target)

    def test_replacement_requires_exact_current_hash(self):
        target = self.work / 'candidate.apk'
        target.write_bytes(b'v38 preserve until tests pass')
        with mock.patch.object(pen, 'ROOT', self.work), mock.patch.object(pen, 'ARTIFACT', target):
            pen.verify_output(target, replace_sha256=pen.sha256(target))
            with self.assertRaisesRegex(ValueError, 'exact expected hash'):
                pen.verify_output(target, replace_sha256='0' * 64)
            self.assertEqual(target.read_bytes(), b'v38 preserve until tests pass')

    def test_foreign_scratch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'CleanOS task root'):
            pen.verify_scratch(self.work)

    def test_dex_parser_rejects_truncated_or_oversized_data(self):
        with self.assertRaisesRegex(ValueError, 'DEX header'):
            pen.DEX.DexApi().add_dex(b'dex\n')
        with self.assertRaisesRegex(ValueError, 'oversized'):
            pen.DEX.uleb(bytes([128] * 6), 0)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            pen.DEX.uleb(b'\x80', 0)

    def test_inherited_methods_resolve_without_accepting_unknown_methods(self):
        api = pen.DEX.DexApi()
        api.classes['Landroid/Child;'] = ['Landroid/Parent;']
        api.definitions.add('Landroid/Parent;->method()V')
        self.assertTrue(api.resolves('Landroid/Child;->method()V'))
        self.assertFalse(api.resolves('Landroid/Child;->missing()V'))
        self.assertFalse(api.resolves('Landroid/Child;-><init>()V'))

    def test_apk_rejects_path_traversal_before_parsing_code(self):
        apk = self.work / 'unsafe.apk'
        with zipfile.ZipFile(apk, 'w') as out:
            out.writestr('../../outside', b'data')
        with self.assertRaisesRegex(ValueError, 'unsafe entry path'):
            pen.check_apk(apk, pen.DEX.DexApi())

    def test_apk_rejects_signatures_jni_and_compile_only_classes(self):
        for name in ['META-INF/SIGNER.RSA', 'lib/arm64-v8a/extra.so', 'android/os/Binder.class']:
            apk = self.work / 'unsafe.apk'
            with zipfile.ZipFile(apk, 'w') as out:
                out.writestr(name, b'data')
            with self.subTest(name=name), self.assertRaises(ValueError):
                pen.check_apk(apk, pen.DEX.DexApi())

    def test_default_grants_are_only_existing_runtime_permissions(self):
        path = pen.COMPONENT / 'upstream/packages/Pen/default-permissions_org.lineageos.pen.xml'
        root = ET.parse(path).getroot()
        entry, = root.findall('exception')
        self.assertEqual(entry.attrib, {'package': 'org.lineageos.pen'})
        self.assertEqual({x.attrib['name'] for x in entry}, {
            'android.permission.BLUETOOTH_CONNECT', 'android.permission.BLUETOOTH_SCAN',
            'android.permission.POST_NOTIFICATIONS'})
        self.assertTrue(all(x.attrib['fixed'] == 'false' for x in entry))

    def test_scoped_signer_template_never_assigns_platform(self):
        root = ET.parse(pen.COMPONENT / 'integration/system_ext_mac_permissions.xml.template').getroot()
        signer, = root.findall('signer')
        package, = signer.findall('package')
        self.assertEqual(package.attrib, {'name': 'org.lineageos.pen'})
        self.assertEqual(list(package)[0].attrib, {'value': 'pad3_pen'})
        self.assertEqual(len(list(signer)), 1)
        self.assertNotIn('platform', ET.tostring(root).decode())

    def test_policy_never_broadens_priv_app_or_uses_permissive(self):
        policy = (pen.COMPONENT / 'integration/pen_app.cil').read_text()
        self.assertNotIn('priv_app', policy)
        self.assertNotIn('(typepermissive', policy)
        self.assertIn('(typeattributeset vendor_hal_oplus_touch_client (pen_app))', policy)


if __name__ == '__main__':
    unittest.main()
