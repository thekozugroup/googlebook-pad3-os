"""Host-only trust-boundary tests; never contact a device or run Android tools."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import build_photos_boot as boot


def bootclasspath():
    # Mainline names are irrelevant to these host tests except for the split boundary.
    return [*boot.PRIMARY, '/apex/com.android.adservices/javalib/framework-adservices.jar',
            *['/apex/com.android.test/javalib/test' + str(i) + '.jar' for i in range(37)]]


def case_output():
    cases = []
    for mode in boot.CASES:
        model = 'Pixel XL' if mode == 'photos' else 'OPD2415'
        cases.append({'isolated_process_mode': mode, 'before_model': 'OPD2415',
                      'direct_model': model, 'reflected_model': model, 'sdk': 37,
                      'release': '17', 'security_patch': '2026-10-01',
                      **{key: True for key in ('version_fields_preserved', 'scope_and_profile_pass',
                         'helper_from_boot_classloader', 'coherent_boot_images_mapped', 'real_package_manager_hook')}})
    return cases


def stdout(cases=None, namespace='mnt:[2]'):
    return 'namespace=' + namespace + '\n' + '\n'.join(map(json.dumps, case_output() if cases is None else cases))


def write_artifacts(root):
    (root / 'arm64').mkdir(parents=True)
    for name in boot.FILES:
        header = (b'art\n119\0' if name.endswith('.art') else
                  b'\x7fELF' + b'\0' * 64 + b'oat\n279\0' if name.endswith('.oat') else b'vdex027\0')
        (root / name).write_bytes(header + b'fixture')


class PhotosBootTests(unittest.TestCase):
    def test_classpath_formats_and_primary_boundary(self):
        paths = bootclasspath()
        for document in ({'BOOTCLASSPATH': ':'.join(paths)}, {'classpaths': {'BOOTCLASSPATH': ':'.join(paths)}}):
            self.assertEqual(boot.classpaths(document), paths)
        for bad in (paths[:-1], paths + [paths[-1]], paths[:15] + [paths[0]] + paths[16:],
                    [paths[1], paths[0], *paths[2:]], paths[:20] + ['/apex/a/javalib/x.jar;id'] + paths[21:]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                boot.classpaths({'BOOTCLASSPATH': ':'.join(bad)})
        with self.assertRaises(ValueError):
            boot.classpaths({'BOOTCLASSPATH': paths})

    def test_receipt_rejects_other_scope_hash_and_donor(self):
        with tempfile.TemporaryDirectory() as temporary:
            framework = Path(temporary) / 'framework.jar'
            framework.write_bytes(b'framework')
            source = json.loads((boot.COMPONENT / 'source-lock.json').read_text())['source_framework_sha256']
            receipt = {'candidate_sha256': boot.digest(framework), 'source_framework_sha256': source,
                       'scope': ['com.google.android.apps.photos']}
            self.assertEqual(boot.verify_framework(framework, receipt), source)
            for changes in ({'candidate_sha256': '0' * 64}, {'source_framework_sha256': '1' * 64},
                            {'source_framework_sha256': None}, {'scope': ['com.google.android.apps.photos', 'other']},
                            {'scope': 'com.google.android.apps.photos'}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    boot.verify_framework(framework, dict(receipt, **changes))

    def test_output_requires_new_owned_zip_and_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / 'out.zip'
            self.assertEqual(boot.verify_output(output, root), output)
            for invalid in (root.parent / 'foreign.zip', root / 'out.jar'):
                with self.assertRaises(ValueError):
                    boot.verify_output(invalid, root)
            (root / 'link').symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                boot.verify_output(root / 'link/out.zip', root)
            output.with_suffix('.verification.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                boot.verify_output(output, root)

    def test_compiler_split_and_runtime_locations(self):
        device = '/data/local/tmp/pad3-photos-boot-test'
        paths = bootclasspath()
        for mainline, count, compiler_filter in ((False, 15, 'speed-profile'), (True, 38, 'verify')):
            args = boot.compiler_args(device, paths, mainline)
            self.assertEqual(args[0], boot.ART + 'dex2oat64')
            self.assertIn('--compiler-filter=' + compiler_filter, args)
            self.assertIn('--single-image', args)
            self.assertIn('-j2', args)
            self.assertIn('-Xmx512m', args)
            files = [a.split('=', 1)[1] for a in args if a.startswith('--dex-file=')]
            locations = [a.split('=', 1)[1] for a in args if a.startswith('--dex-location=')]
            self.assertEqual(len(files), count)
            self.assertEqual(locations, paths[15:] if mainline else paths[:15])
            runtime = next(a for a in args if a.startswith('-Xbootclasspath:')).split(':')[1:]
            self.assertEqual(len(runtime), 53 if mainline else 15)
            self.assertEqual(runtime[5], device + '/framework.jar')
            self.assertIn('-Xbootclasspath-locations:' + ':'.join(paths if mainline else paths[:15]), args)
        primary = boot.compiler_args(device, paths)
        self.assertIn('--base=0x70000000', primary)
        self.assertIn('--profile-file=' + device + '/boot.prof', primary)
        self.assertIn('--preloaded-classes=/system/etc/preloaded-classes', primary)
        self.assertIn('--boot-image=' + device + '/boot.art', boot.compiler_args(device, paths, True))

    def test_profile_uses_current_inputs_for_dump_and_patched_for_create(self):
        device = '/data/local/tmp/pad3-photos-boot-test'
        dump = boot.profman_args(device, bootclasspath())
        create = boot.profman_args(device, bootclasspath(), True)
        self.assertIn('--profile-file=/system/etc/boot-image.prof', dump)
        self.assertIn('--apk=' + boot.FRAMEWORK, dump)
        self.assertNotIn('--apk=' + boot.FRAMEWORK, create)
        self.assertIn('--apk=' + device + '/framework.jar', create)
        self.assertIn('--output-profile-type=boot', create)
        self.assertEqual(len([a for a in dump if a.startswith('--apk=')]), 15)
        self.assertEqual(boot.PROFILE_RULES.splitlines(), [
            'L' + boot.HELPER + ';', 'HSPL' + boot.HELPER + ';->onBind(Ljava/lang/String;)V',
            'HSPL' + boot.HELPER + ';->feature(Ljava/lang/String;I)Ljava/lang/Boolean;'])
        self.assertIn('export LD_LIBRARY_PATH=' + boot.LIBRARIES,
                      boot.pid_command(dump, device + '/profile.pid'))

    def test_probe_d8_input_is_only_probe_class(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); work = root / 'work'; work.mkdir()
            evidence = root / 'evidence'; evidence.mkdir()
            commands = []

            def fake_checked(args, *unused):
                args = list(map(str, args)); commands.append(args)
                if args[0].endswith('/d8'):
                    (work / 'dex/classes.dex').write_bytes(b'dex fixture')
                return ''

            with patch.object(boot, 'checked', side_effect=fake_checked):
                jar = boot.compile_probe(root / 'sdk', root / 'jdk', work, evidence)
            java, d8 = commands
            self.assertIn(str(boot.COMPONENT / 'src' / (boot.HELPER + '.java')), java)
            self.assertEqual([a for a in d8 if a.endswith('.class')], [str(work / 'classes' / (boot.PROBE + '.class'))])
            self.assertFalse(any(boot.HELPER in a for a in d8))
            with zipfile.ZipFile(jar) as archive:
                self.assertEqual(archive.namelist(), ['classes.dex'])

    def test_namespace_protects_both_caches_and_only_runs_three_baked_probes(self):
        device = '/data/local/tmp/pad3-photos-boot-test'
        command = boot.namespace_command(device, [device + '/' + m + '.pid' for m in boot.CASES])
        self.assertEqual(command[:5], ['unshare', '-m', '--', '/system/bin/sh', '-c'])
        script = command[-1]
        self.assertIn('mount -o rprivate none /', script)
        self.assertIn(device + '/cache-art /data/misc/apexdata/com.android.art/dalvik-cache', script)
        self.assertIn(device + '/cache-dalvik /data/dalvik-cache', script)
        self.assertEqual(script.count(' baked '), 3)
        self.assertNotIn('LD_LIBRARY_PATH', script)
        self.assertNotIn('rm ', script)

    def test_namespace_proofs_fail_closed(self):
        self.assertEqual(len(boot.namespace_cases(stdout(), 'mnt:[1]')), 3)
        for key in ('helper_from_boot_classloader', 'coherent_boot_images_mapped', 'real_package_manager_hook',
                    'scope_and_profile_pass', 'version_fields_preserved'):
            cases = case_output(); cases[2][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                boot.namespace_cases(stdout(cases), 'mnt:[1]')
        for key in ('direct_model', 'reflected_model'):
            cases = case_output(); cases[1][key] = 'Pixel XL'
            with self.assertRaises(ValueError):
                boot.namespace_cases(stdout(cases), 'mnt:[1]')
        for cases in (case_output()[:-1], list(reversed(case_output()))):
            with self.assertRaises(ValueError):
                boot.namespace_cases(stdout(cases), 'mnt:[1]')
        with self.assertRaisesRegex(ValueError, 'private mount'):
            boot.namespace_cases(stdout(namespace='mnt:[1]'), 'mnt:[1]')

    def test_artifact_names_and_version_magic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); write_artifacts(root)
            records = boot.artifact_files(root)
            self.assertEqual(set(records), set(boot.FILES))
            for name, record in records.items():
                self.assertEqual(record['bytes'], (root / name).stat().st_size)
                self.assertEqual(record['sha256'], hashlib.sha256((root / name).read_bytes()).hexdigest())
            for name in ('arm64/boot.art', 'arm64/boot.oat'):
                path = root / name; original = path.read_bytes(); path.write_bytes(original.replace(b'119', b'118').replace(b'279', b'278'))
                with self.assertRaises(ValueError):
                    boot.artifact_files(root)
                path.write_bytes(original)
            (root / 'arm64/unexpected.art').write_bytes(b'anything')
            with self.assertRaisesRegex(ValueError, 'exactly six'):
                boot.artifact_files(root)

    def test_root_quoting_and_shell_writable_transfer(self):
        with tempfile.TemporaryDirectory() as temporary:
            donor = boot.Donor('/mock/adb', 'serial', 'owned', Path(temporary))
            with patch.object(donor, 'call', return_value='') as call:
                command = "printf '%s' 'a b; $HOME'"
                donor.root(command)
                self.assertEqual(shlex.split(call.call_args.args[0][1]), ['su', '-c', command])
                donor.push(Path('/mock/local.jar'), 'framework.jar')
                self.assertEqual(call.call_args_list[1].args[0], ['push', '/mock/local.jar', donor.transfer + '/framework.jar'])
                move = shlex.split(call.call_args_list[2].args[0][1])[2]
                self.assertIn('mv ' + donor.transfer + '/framework.jar ' + donor.device + '/framework.jar', move)
                self.assertIn('chown 0:0', move)
                self.assertIn('chmod 0444', move)

    def test_recycled_or_foreign_pid_is_never_signaled(self):
        with tempfile.TemporaryDirectory() as temporary:
            donor = boot.Donor('/mock/adb', 'serial', 'owned', Path(temporary))
            record = donor.register('primary', [boot.ART + 'dex2oat64', '--image=' + donor.device + '/boot.art'])
            for start, command in ((222, '/system/bin/unrelated'), (111, '/system/bin/unrelated')):
                stat = '42 (test) ' + ' '.join(['S'] + ['0'] * 18 + [str(start)] + ['0'] * 5)
                with patch.object(donor, 'root', side_effect=['42 111', stat + '\n' + command + '\n']) as root:
                    if start == 111:
                        with self.assertRaisesRegex(ValueError, 'does not match owned'):
                            donor.stop(record)
                    else:
                        donor.stop(record)
                    self.assertEqual(root.call_count, 2)
                    self.assertFalse(any('kill ' in c.args[0] for c in root.call_args_list))

    def test_timeout_cleanup_stops_verified_pid_before_removing_owned_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            donor = boot.Donor('/mock/adb', 'serial', 'owned', Path(temporary))
            donor.attempted = True
            record = donor.register('primary', [boot.ART + 'dex2oat64', '--image=' + donor.device + '/boot.art'])
            stat = '42 (dex2oat64) ' + ' '.join(['S'] + ['0'] * 18 + ['111'] + ['0'] * 5)
            with patch.object(donor, 'root', side_effect=['42 111', stat + '\n' + '\n'.join(record['argv']) + '\n', '', '', '']) as root:
                donor.cleanup()
                commands = [c.args[0] for c in root.call_args_list]
                self.assertIn('kill -TERM 42', commands[2])
                self.assertIn('kill -KILL 42', commands[2])
                self.assertIn("awk '{print $22}' /proc/42/stat", commands[2])
                self.assertIn('cat ' + donor.device + '/owner', commands[3])
                self.assertIn('test ! -e ' + donor.device, commands[3])
                self.assertNotIn('pkill', '\n'.join(commands))

    def test_failed_pid_verification_preserves_device_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            donor = boot.Donor('/mock/adb', 'serial', 'owned', Path(temporary))
            donor.attempted = True; donor.register('namespace', ['unshare'])
            with patch.object(donor, 'stop', side_effect=ValueError('foreign PID')), patch.object(donor, 'root') as root:
                with self.assertRaisesRegex(ValueError, 'cleanup incomplete'):
                    donor.cleanup()
                root.assert_not_called()

    def test_mocked_pipeline_publishes_exact_bundle_and_cleans_failure_outputs(self):
        for failure in (None, 'profile', 'receipt'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                framework = root / 'framework.jar'; framework.write_bytes(b'framework')
                framework_hash = boot.digest(framework)
                source = json.loads((boot.COMPONENT / 'source-lock.json').read_text())['source_framework_sha256']
                receipt = root / 'framework.json'
                receipt.write_text(json.dumps({'scope': ['com.google.android.apps.photos'],
                    'candidate_sha256': framework_hash, 'source_framework_sha256': source}))
                paths = root / 'classpaths.json'; paths.write_text(json.dumps({'BOOTCLASSPATH': ':'.join(bootclasspath())}))
                for name in ('adb', 'jdk/bin/javac', 'sdk/platforms/android-36/android.jar', 'sdk/build-tools/36.0.0/d8'):
                    path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.touch()
                fixture = root / 'fixture'; write_artifacts(fixture)
                output = root / 'boot.zip'
                dumps = json.dumps

                def publish_json(value, *args, **kwargs):
                    if failure == 'receipt' and isinstance(value, dict) and value.get('schema') == 1:
                        raise OSError('receipt write failed')
                    return dumps(value, *args, **kwargs)

                with patch.object(boot, 'verify_scratch', return_value=root), patch.object(boot, 'compile_probe', return_value=root / 'probe.jar'), \
                        patch.object(boot, 'Donor') as donor_class, patch.object(boot.json, 'dumps', side_effect=publish_json):
                    donor = donor_class.return_value
                    donor.device = '/data/local/tmp/pad3-photos-boot-mock'
                    donor.before = {'namespace': 'mnt:[1]'}
                    donor.register.side_effect = lambda name, argv: {'name': name, 'argv': argv, 'pidfile': donor.device + '/' + name + '.pid'}

                    def remote(command, *args):
                        if command.startswith('sha256sum '):
                            return framework_hash + ' framework.jar\n'
                        if command.startswith('ls -1 '):
                            return '\n'.join(Path(n).name for n in boot.FILES)
                        return stdout()

                    def pull(args, *unused):
                        if args[0] == 'pull':
                            Path(args[2]).write_bytes((fixture / 'arm64' / Path(args[1]).name).read_bytes())

                    donor.root.side_effect = remote; donor.call.side_effect = pull
                    if failure == 'profile':
                        donor.job.side_effect = subprocess.TimeoutExpired('mock compiler', 600)
                    else:
                        donor.job.return_value = 'Landroid/Foo;\n'
                    arguments = (framework, receipt, paths, root / 'adb', 'serial', root / 'sdk', root / 'jdk', root, output)
                    if failure:
                        with self.assertRaises((subprocess.TimeoutExpired, OSError)):
                            boot.build(*arguments)
                        self.assertFalse(output.exists())
                        self.assertFalse(output.with_suffix('.verification.json').exists())
                    else:
                        result = boot.build(*arguments)
                        self.assertEqual(result['bundle_sha256'], boot.digest(output))
                        self.assertEqual(result['framework_sha256'], framework_hash)
                        self.assertEqual(len(result['namespace_cases']), 3)
                        self.assertEqual(json.loads(output.with_suffix('.verification.json').read_text()), result)
                        with zipfile.ZipFile(output) as archive:
                            self.assertEqual(archive.namelist(), list(boot.FILES))
                            for name in archive.namelist():
                                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), result['files'][name]['sha256'])
                    donor.cleanup.assert_called_once()
                    builds = list(root.glob('photos-boot-*'))
                    self.assertEqual(len(builds), 1)
                    self.assertEqual([p.name for p in builds[0].iterdir()], ['evidence'])


if __name__ == '__main__':
    unittest.main()
