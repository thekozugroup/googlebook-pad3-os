#!/usr/bin/env python3
"""Build and privately verify Photos boot images on the supplied rooted donor.

--classpaths accepts the audit's {"classpaths": {"BOOTCLASSPATH": "..."}}
or a simple {"BOOTCLASSPATH": "..."}. --scratch is an active owned CleanOS
task root. The new ZIP and its .verification.json receipt must be inside it.
Commands, stdout, PID records and cleanup proofs remain in a unique evidence
directory there. No installation, real ART cache deletion, or reboot occurs.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import zipfile

from patch_taskmanager import digest, require, verify_scratch

ROOT = Path(__file__).resolve().parent
COMPONENT = ROOT / 'components/photos-native'
FRAMEWORK = '/system/framework/framework.jar'
ART = '/apex/com.android.art@371899999/bin/'
LIBRARIES = ('/apex/com.android.art/lib64:/apex/com.android.os.statsd/lib64:'
             '/apex/com.android.runtime/lib64/bionic:/system/lib64')
HELPER = 'com/android/internal/util/googlebook/PhotosCompat'
PROBE = 'org/googlebook/pad3/probe/PhotosNativeProbe'
PRIMARY = (
    '/apex/com.android.art/javalib/core-oj.jar',
    '/apex/com.android.art/javalib/core-libart.jar',
    '/apex/com.android.art/javalib/okhttp.jar',
    '/apex/com.android.art/javalib/bouncycastle.jar',
    '/apex/com.android.art/javalib/apache-xml.jar', FRAMEWORK,
    '/system/framework/framework-graphics.jar',
    '/system/framework/framework-location.jar', '/system/framework/ext.jar',
    '/system/framework/telephony-common.jar', '/system/framework/voip-common.jar',
    '/system/framework/ims-common.jar',
    '/system/framework/framework-ondeviceintelligence-platform.jar',
    '/system/framework/GameControlsInputProcessorLib.jar',
    '/apex/com.android.i18n/javalib/core-icu4j.jar',
)
FILES = tuple('arm64/' + stem + '.' + ext
              for stem in ('boot', 'boot-framework-adservices')
              for ext in ('art', 'oat', 'vdex'))
PROFILE_RULES = ('L' + HELPER + ';\nHSPL' + HELPER
                 + ';->onBind(Ljava/lang/String;)V\nHSPL' + HELPER
                 + ';->feature(Ljava/lang/String;I)Ljava/lang/Boolean;\n')
CASES = ('other', 'forged', 'photos')


def classpaths(document):
    require(isinstance(document, dict), 'classpaths JSON must be an object')
    mapping = document.get('classpaths', document)
    require(isinstance(mapping, dict), 'classpaths must be an object')
    value = mapping.get('BOOTCLASSPATH')
    require(isinstance(value, str), 'BOOTCLASSPATH must be a colon-separated string')
    paths = value.split(':')
    require(len(paths) == 53 and len(set(paths)) == 53, 'expected 53 unique boot JARs')
    require(all(re.fullmatch(r'/(?:system/framework|apex/[A-Za-z0-9_.@-]+/javalib)/[A-Za-z0-9_.-]+\.jar', p)
                and '..' not in p.split('/') for p in paths), 'unsafe boot JAR path')
    require(tuple(paths[:15]) == PRIMARY and paths[15] ==
            '/apex/com.android.adservices/javalib/framework-adservices.jar',
            'donor primary15/mainline38 layout changed')
    return paths


def verify_framework(framework, receipt):
    require(receipt.get('scope') == ['com.google.android.apps.photos'], 'receipt must scope only Photos')
    require(receipt.get('candidate_sha256') == digest(framework), 'framework hash differs from receipt')
    source = receipt.get('source_framework_sha256')
    require(isinstance(source, str) and re.fullmatch('[0-9a-f]{64}', source), 'invalid source framework hash')
    lock = json.loads((COMPONENT / 'source-lock.json').read_text())
    require(source == lock['source_framework_sha256'], 'source framework differs from pinned donor')
    return source


def verify_output(output, scratch):
    output = Path(output).absolute()
    receipt = output.with_suffix('.verification.json')
    require(output == output.resolve() and output.is_relative_to(scratch)
            and output.suffix == '.zip', 'new ZIP must be inside owned scratch')
    require(not output.exists() and not receipt.exists() and not receipt.is_symlink(),
            'refusing to overwrite output or receipt')
    return output


def compiler_args(device, bcp, mainline=False):
    start, count = (15, 53) if mainline else (0, 15)
    stem = 'boot-framework-adservices' if mainline else 'boot'
    inputs = [device + '/framework.jar' if p == FRAMEWORK else p for p in bcp]
    args = [ART + 'dex2oat64', '--android-root=/system', '--instruction-set=arm64',
            '--instruction-set-variant=oryon', '--instruction-set-features=default',
            '--single-image', '--image-format=lz4',
            '--image=' + device + '/arm64/' + stem + '.art',
            '--oat-file=' + device + '/arm64/' + stem + '.oat',
            '--oat-location=/system/framework/arm64/' + stem + '.oat',
            '--compiler-filter=' + ('verify' if mainline else 'speed-profile'),
            '--force-determinism', '--abort-on-hard-verifier-error',
            '--no-inline-from=core-oj.jar', '-j2', '--runtime-arg', '-Xms64m',
            '--runtime-arg', '-Xmx512m', '--runtime-arg',
            '-Xbootclasspath:' + ':'.join(inputs[:count]), '--runtime-arg',
            '-Xbootclasspath-locations:' + ':'.join(bcp[:count])]
    if mainline:
        args += ['--boot-image=' + device + '/boot.art']
    else:
        args += ['--base=0x70000000', '--profile-file=' + device + '/boot.prof',
                 '--preloaded-classes=/system/etc/preloaded-classes']
    for path, location in zip(inputs[start:count], bcp[start:count]):
        args += ['--dex-file=' + path, '--dex-location=' + location]
    return args


def profman_args(device, bcp, create=False):
    args = [ART + 'profman']
    if create:
        args += ['--create-profile-from=' + device + '/profile.txt',
                 '--reference-profile-file=' + device + '/boot.prof', '--output-profile-type=boot']
    else:
        args += ['--dump-classes-and-methods', '--profile-file=/system/etc/boot-image.prof']
    for path in bcp[:15]:
        args += ['--apk=' + (device + '/framework.jar' if create and path == FRAMEWORK else path),
                 '--dex-location=' + path]
    return args


def checked(args, log, env=None, timeout=60):
    args = list(map(str, args))
    log.with_suffix('.command.json').write_text(json.dumps(args, indent=2) + '\n')
    with log.open('w') as stream, log.with_suffix('.stderr.log').open('w') as errors:
        result = subprocess.run(args, stdout=stream, stderr=errors, env=env, timeout=timeout)
    require(result.returncode == 0, 'command failed; inspect ' + str(log))
    return log.read_text()


def compile_probe(sdk, jdk, work, evidence):
    classes, dex = work / 'classes', work / 'dex'
    classes.mkdir(); dex.mkdir()
    android = sdk / 'platforms/android-36/android.jar'
    env = dict(os.environ, JAVA_HOME=str(jdk), TMPDIR=str(work),
               JAVA_TOOL_OPTIONS='-XX:ActiveProcessorCount=2 -Xmx512m -Djava.io.tmpdir=' + str(work))
    checked([jdk / 'bin/javac', '--release', '8', '-cp', android, '-d', classes,
             COMPONENT / 'src' / (HELPER + '.java'),
             COMPONENT / 'device-test/PhotosNativeProbe.java'], evidence / 'javac.log', env)
    # The helper is only a javac dependency; bundling it would invalidate the boot-classloader test.
    checked([sdk / 'build-tools/36.0.0/d8', '--release', '--min-api', '35', '--lib', android,
             '--output', dex, classes / (PROBE + '.class')], evidence / 'd8.log', env)
    with zipfile.ZipFile(work / 'probe.jar', 'x') as archive:
        archive.write(dex / 'classes.dex', 'classes.dex')
    return work / 'probe.jar'


def pid_command(command, pidfile):
    script = ("set -eu\nprintf '%s %s\\n' \"$$\" \"$(awk '{print $22}' /proc/$$/stat)\" > "
              + shlex.quote(pidfile) + '\n')
    if command[0] in (ART + 'dex2oat64', ART + 'profman'):
        script += 'export LD_LIBRARY_PATH=' + shlex.quote(LIBRARIES) + '\n'
    return script + 'exec ' + shlex.join(command)


def namespace_command(device, pidfiles):
    lines = ['set -eu', 'mount -o rprivate none /']
    for source, target in [(device + '/framework.jar', FRAMEWORK),
                           (device + '/arm64', '/system/framework/arm64'),
                           (device + '/cache-art', '/data/misc/apexdata/com.android.art/dalvik-cache'),
                           (device + '/cache-dalvik', '/data/dalvik-cache')]:
        lines.append(shlex.join(['mount', '-o', 'bind', source, target]))
    lines.append("printf 'namespace='; readlink /proc/self/ns/mnt")
    for mode, pidfile in zip(CASES, pidfiles):
        args = ['/system/bin/app_process', '/system/bin', PROBE.replace('/', '.'), mode, 'baked', device]
        lines.append('CLASSPATH=' + shlex.quote(device + '/probe.jar') + ' '
                     + shlex.join(['/system/bin/sh', '-c', pid_command(args, pidfile)]))
    return ['unshare', '-m', '--', '/system/bin/sh', '-c', '\n'.join(lines)]


def namespace_cases(stdout, parent_namespace):
    namespaces = [line.removeprefix('namespace=') for line in stdout.splitlines() if line.startswith('namespace=')]
    require(len(namespaces) == 1 and re.fullmatch(r'mnt:\[\d+\]', namespaces[0])
            and namespaces[0] != parent_namespace, 'private mount namespace not proved')
    cases = [json.loads(line) for line in stdout.splitlines() if line.startswith('{')]
    require([case.get('isolated_process_mode') for case in cases] == list(CASES), 'expected three namespace cases')
    for case in cases:
        expected = 'Pixel XL' if case['isolated_process_mode'] == 'photos' else 'OPD2415'
        require(case.get('before_model') == 'OPD2415' and case.get('direct_model') == expected
                and case.get('reflected_model') == expected, 'namespace model/scope mismatch')
        require(all(case.get(key) is True for key in (
            'version_fields_preserved', 'scope_and_profile_pass', 'helper_from_boot_classloader',
            'coherent_boot_images_mapped', 'real_package_manager_hook')), 'namespace boot/profile/hook proof failed')
    require(len({(c.get('sdk'), c.get('release'), c.get('security_patch')) for c in cases}) == 1
            and all(type(c.get('sdk')) is int and c['sdk'] > 0
                    and isinstance(c.get('release'), str) and c['release']
                    and isinstance(c.get('security_patch'), str) and c['security_patch'] for c in cases),
            'namespace version evidence missing or inconsistent')
    return cases


def artifact_files(directory):
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    require(actual == set(FILES), 'expected exactly six boot artifacts')
    records = {}
    for name in FILES:
        path = directory / name
        require(not path.is_symlink() and path.stat().st_size > 8, 'invalid artifact: ' + name)
        with path.open('rb') as stream:
            header = stream.read(131072)
        if name.endswith('.art'):
            require(header.startswith(b'art\n119\0'), 'expected ART119: ' + name)
        elif name.endswith('.oat'):
            require(header.startswith(b'\x7fELF') and b'oat\n279\0' in header, 'expected ELF/OAT279: ' + name)
        else:
            require(header.startswith(b'vdex'), 'invalid VDEX: ' + name)
        records[name] = {'sha256': digest(path), 'bytes': path.stat().st_size}
    return records


class Donor:
    """Exact task-owned device paths and foreground jobs, with PID/start-time cleanup."""

    def __init__(self, adb, serial, task, evidence):
        self.adb = [str(adb), '-s', serial]
        self.device = '/data/local/tmp/pad3-photos-boot-' + task
        self.transfer = self.device + '-transfer'
        self.token = task
        self.evidence = evidence
        self.jobs = []
        self.sequence = 0
        self.attempted = False
        self.before = None
        self.namespace_id = None
        self.manifest()

    def manifest(self):
        (self.evidence / 'ownership.json').write_text(json.dumps({
            'device_root': self.device, 'transfer_root': self.transfer, 'token': self.token,
            'jobs': self.jobs, 'bind_targets': [FRAMEWORK, '/system/framework/arm64',
                '/data/misc/apexdata/com.android.art/dalvik-cache', '/data/dalvik-cache'],
            'bind_scope': 'private child mount namespace only',
            'private_namespace': self.namespace_id,
        }, indent=2) + '\n')

    def call(self, args, label='adb', timeout=60):
        self.sequence += 1
        return checked(self.adb + list(args), self.evidence / f'{self.sequence:03d}-{label}.log', timeout=timeout)

    def root(self, command, label='root', timeout=60):
        return self.call(['shell', shlex.join(['su', '-c', command])], label, timeout)

    def global_state(self):
        output = self.call(['shell', 'sha256sum ' + FRAMEWORK + '; readlink /proc/self/ns/mnt'], 'global-proof')
        lines = output.splitlines()
        require(len(lines) == 2 and re.fullmatch('[0-9a-f]{64}', lines[0].split()[0])
                and re.fullmatch(r'mnt:\[\d+\]', lines[1]), 'invalid global framework/namespace proof')
        return {'framework_sha256': lines[0].split()[0], 'namespace': lines[1]}

    def prepare(self, bcp, source_hash):
        self.before = self.global_state()
        require(self.before['framework_sha256'] == source_hash, 'live donor framework differs from source receipt')
        live = self.call(['shell', 'printf \'%s\\n\' "$BOOTCLASSPATH"'], 'live-classpath').strip()
        require(live == ':'.join(bcp), 'live donor BOOTCLASSPATH differs from input')
        self.root('set -eu\n' + '\n'.join('test ! -e ' + p + ' && test ! -L ' + p
                                        for p in (self.device, self.transfer)), 'require-absent')
        self.attempted = True
        # adb shell owns the transfer directory; the compiler tree stays root-owned 0755.
        self.call(['shell', 'set -eu\nmkdir -m 0700 ' + self.transfer
                   + '\nprintf %s ' + shlex.quote(self.token) + ' > ' + self.transfer + '/owner'], 'transfer-create')
        self.root('set -eu\nmkdir -m 0755 ' + self.device + '\nprintf %s ' + shlex.quote(self.token)
                  + ' > ' + self.device + '/owner\nmkdir ' + ' '.join(self.device + '/' + p
                    for p in ('arm64', 'cache-art', 'cache-dalvik')), 'device-create')

    def push(self, source, name):
        require(re.fullmatch('[A-Za-z0-9_.-]+', name) is not None, 'unsafe transfer name')
        transfer, target = self.transfer + '/' + name, self.device + '/' + name
        self.call(['push', str(source), transfer], 'push-' + name)
        self.root('set -eu\nmv ' + shlex.quote(transfer) + ' ' + shlex.quote(target)
                  + '\nchown 0:0 ' + shlex.quote(target) + '\nchmod 0444 ' + shlex.quote(target), 'move-' + name)

    def register(self, name, argv):
        record = {'name': name, 'pidfile': self.device + '/' + name + '.pid', 'argv': argv}
        self.jobs.append(record); self.manifest()
        return record

    def job(self, name, argv, timeout=600):
        record = self.register(name, argv)
        result = self.root(pid_command(argv, record['pidfile']), name, timeout)
        self.stop(record, require_exited=True)
        return result

    def stop(self, record, require_exited=False):
        pidfile = shlex.quote(record['pidfile'])
        text = self.root('if test -f ' + pidfile + '; then cat ' + pidfile + '; fi', 'pid-' + record['name']).strip()
        if not text:
            require(not require_exited, 'owned job PID proof missing')
            return
        require(re.fullmatch(r'[0-9]+ [0-9]+', text) is not None, 'invalid owned PID record')
        pid, start = map(int, text.split())
        require(pid > 1 and start > 0, 'unsafe owned PID')
        record['pid'], record['start_ticks'] = pid, start
        self.manifest()
        proc = '/proc/' + str(pid)
        state = self.root('if test -r ' + proc + '/stat; then cat ' + proc
                          + "/stat; tr '\\000' '\\n' < " + proc + '/cmdline 2>/dev/null || true; fi', 'inspect-' + record['name'])
        if not state:
            return
        lines = state.splitlines()
        current_start = int(lines[0].rsplit(')', 1)[1].split()[19])
        if current_start != start:
            return  # The original PID exited; never signal a recycled PID.
        command = lines[1:]
        owned = command == record['argv'] or any(self.device in arg for arg in command)
        if not owned and record['name'].startswith('probe-'):
            # app_process can rewrite argv; its private CLASSPATH still identifies this probe.
            identity = self.root('readlink ' + proc + '/exe; readlink -f /system/bin/app_process; '
                                 + "tr '\\000' '\\n' < " + proc
                                 + "/environ 2>/dev/null | sed -n '/^CLASSPATH=/p'", 'probe-identity').splitlines()
            owned = len(identity) == 3 and identity[0] == identity[1] and identity[2] == 'CLASSPATH=' + self.device + '/probe.jar'
        require(owned,
                'live PID does not match owned command; cleanup refused')
        require(not require_exited, 'owned job left a running process')
        # Recheck start time immediately before each signal to avoid PID reuse.
        same = 'test -r ' + proc + "/stat && test \"$(awk '{print $22}' " + proc + '/stat)" = ' + str(start)
        self.root('set -eu\nif ' + same + '; then kill -TERM ' + str(pid) + ' || ! (' + same + '); fi\n'
                  + 'for n in 1 2 3 4 5; do if ! (' + same + '); then exit 0; fi; sleep 1; done\n'
                  + 'if ' + same + '; then kill -KILL ' + str(pid) + ' || ! (' + same + '); fi\n'
                  + 'for n in 1 2 3 4 5; do if ! (' + same + '); then exit 0; fi; sleep 1; done\nexit 1',
                  'stop-' + record['name'], 20)

    def cleanup(self):
        errors = []
        if self.attempted:
            for record in reversed(self.jobs):
                try:
                    self.stop(record)
                except Exception as error:
                    errors.append(str(error))
            if not errors:
                for path in (self.device, self.transfer):
                    try:
                        self.root('set -eu\nif test -e ' + path + '; then test ! -L ' + path
                                  + '\ntest "$(cat ' + path + '/owner)" = ' + shlex.quote(self.token)
                                  + '\nrm -rf ' + path + '\nfi\ntest ! -e ' + path + ' && test ! -L ' + path,
                                  'cleanup')
                    except Exception as error:
                        errors.append(str(error))
        if self.before:
            try:
                after = self.global_state()
                require(after == self.before, 'global framework or mount namespace changed')
                (self.evidence / 'cleanup-proof.json').write_text(json.dumps({
                    'before': self.before, 'after': after, 'owned_device_resources_removed': not errors,
                    'owned_pids_exited': not errors, 'errors': errors,
                    'private_namespace': self.namespace_id,
                }, indent=2) + '\n')
            except Exception as error:
                errors.append(str(error))
        require(not errors, 'cleanup incomplete; preserve ownership.json and inspect: ' + '; '.join(errors))


def build(framework, framework_verification, classpaths_file, adb, serial, sdk, jdk, scratch, output):
    scratch = verify_scratch(scratch)
    framework, sdk, jdk, adb = [Path(p).resolve(strict=True) for p in (framework, sdk, jdk, adb)]
    output = verify_output(output, scratch)
    require(bool(serial) and not serial.startswith('-') and not any(c.isspace() for c in serial), 'invalid serial')
    receipt = json.loads(Path(framework_verification).read_text())
    source_hash = verify_framework(framework, receipt)
    bcp = classpaths(json.loads(Path(classpaths_file).read_text()))
    for path in (sdk, jdk):
        require(not any(part in path.parts for part in ('Documents', 'Desktop', 'Mobile Documents', 'CloudStorage')),
                'SDK/JDK must be outside cloud-sync roots')
    for path in (adb, jdk / 'bin/javac', sdk / 'platforms/android-36/android.jar', sdk / 'build-tools/36.0.0/d8'):
        require(path.is_file(), 'existing tool input missing: ' + str(path))
    directory = Path(tempfile.mkdtemp(prefix='photos-boot-', dir=scratch))
    evidence = directory / 'evidence'
    evidence.mkdir()
    with tempfile.TemporaryDirectory(prefix='build-', dir=directory) as temporary:
        work = Path(temporary)
        donor = Donor(adb, serial, directory.name, evidence)
        try:
            probe = compile_probe(sdk, jdk, work, evidence)
            donor.prepare(bcp, source_hash)
            donor.push(framework, 'framework.jar'); donor.push(probe, 'probe.jar')
            staged = donor.root('sha256sum ' + donor.device + '/framework.jar', 'staged-framework').split()[0]
            require(staged == receipt['candidate_sha256'], 'staged framework hash mismatch')
            profile = donor.job('profile-dump', profman_args(donor.device, bcp))
            require('Landroid/' in profile and '\x00' not in profile, 'profman did not dump a text profile')
            profile_file = work / 'profile.txt'
            profile_file.write_text(profile.rstrip() + '\n\n' + PROFILE_RULES)
            donor.push(profile_file, 'profile.txt')
            donor.job('profile-create', profman_args(donor.device, bcp, create=True))
            donor.job('primary', compiler_args(donor.device, bcp))
            donor.job('mainline', compiler_args(donor.device, bcp, mainline=True))
            for ext in ('art', 'oat', 'vdex'):
                old = donor.device + '/arm64/boot-framework-adservices-framework-adservices.' + ext
                new = donor.device + '/arm64/boot-framework-adservices.' + ext
                donor.root('set -eu\ntest -f ' + old + '\ntest ! -e ' + new + '\nmv ' + old + ' ' + new, 'normalize-' + ext)
            names = donor.root('ls -1 ' + donor.device + '/arm64', 'artifact-names').splitlines()
            require(set(names) == {Path(n).name for n in FILES} and len(names) == 6, 'unexpected compiler outputs')
            donor.root('chmod 0755 ' + donor.device + '/arm64\nchmod 0644 ' + donor.device + '/arm64/*', 'artifact-permissions')
            # app_process resolves this base through arm64; retain the validated runtime location.
            namespace = donor.register('namespace', [])
            probes = [donor.register('probe-' + mode, ['/system/bin/app_process', '/system/bin',
                      PROBE.replace('/', '.'), mode, 'baked', donor.device]) for mode in CASES]
            namespace['argv'] = namespace_command(donor.device, [p['pidfile'] for p in probes])
            donor.manifest()
            stdout = donor.root(pid_command(namespace['argv'], namespace['pidfile']), 'namespace', 180)
            for record in [*probes, namespace]:
                donor.stop(record, require_exited=True)
            cases = namespace_cases(stdout, donor.before['namespace'])
            donor.namespace_id = next(line.removeprefix('namespace=') for line in stdout.splitlines()
                                      if line.startswith('namespace='))
            donor.manifest()
            artifacts = work / 'artifacts'
            (artifacts / 'arm64').mkdir(parents=True)
            for name in FILES:
                donor.call(['pull', donor.device + '/' + name, str(artifacts / name)], 'pull-' + Path(name).name)
            files = artifact_files(artifacts)
            require(digest(framework) == receipt['candidate_sha256'], 'framework changed during build')
        finally:
            donor.cleanup()
        created = receipt_created = False
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
                created = True
                for name in FILES:
                    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                    info.external_attr = 0o100644 << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, (artifacts / name).read_bytes())
            result = {'schema': 1, 'framework_sha256': receipt['candidate_sha256'], 'bundle_sha256': digest(output),
                      'art_version': '119', 'oat_version': '279', 'files': files,
                      'private_namespace_verified': True, 'namespace_cases': cases,
                      'system_and_user_caches_modified': False}
            with output.with_suffix('.verification.json').open('x') as stream:
                receipt_created = True
                stream.write(json.dumps(result, indent=2) + '\n')
            return result
        except BaseException:
            if receipt_created:
                output.with_suffix('.verification.json').unlink()
            if created:
                output.unlink()
            raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('framework', 'framework-verification', 'classpaths', 'adb', 'sdk', 'jdk', 'scratch', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--serial', required=True)
    arguments = vars(parser.parse_args())
    arguments['classpaths_file'] = arguments.pop('classpaths')
    print(json.dumps(build(**arguments), indent=2))
