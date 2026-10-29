#!/usr/bin/env python3
"""Build one unsigned OplusPen candidate offline; never sign, install or rebuild an image."""
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
COMPONENT = ROOT / 'components/oplus-pen'
ARTIFACT = ROOT / 'artifacts/component-candidates/oplus-pen-unsigned.apk'
SPEC = importlib.util.spec_from_file_location('pen_dex_api', COMPONENT / 'build-support/dex_api.py')
DEX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEX)
require = DEX.require


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def zip_member(archive, name, data):
    info = zipfile.ZipInfo(name, (2009, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def load(path):
    return json.loads(Path(path).read_text())


def source_path(root, name):
    require(isinstance(name, str) and not name.startswith('/') and
            all(p not in ('', '.', '..') for p in name.split('/')), 'unsafe component path')
    path = root / name
    require(not any(p.is_symlink() for p in [path, *path.parents]),
            'symlink component input: ' + name)
    require(path.resolve().is_relative_to(root.resolve()), 'component input escapes root')
    return path


def verify_sources(component=COMPONENT):
    manifest = load(component / 'upstream-manifest.json')
    expected = {x['path']: x for x in manifest['files']}
    require(len(expected) == len(manifest['files']), 'duplicate source manifest path')
    actual = {str(p.relative_to(component / 'upstream')) for p in (component / 'upstream').rglob('*') if p.is_file()}
    require(actual == set(expected), 'upstream inventory differs from pinned manifest')
    for name, entry in expected.items():
        path = source_path(component / 'upstream', name)
        require(path.is_file() and sha256(path) == entry['sha256'], 'upstream source drift: ' + name)
    for entry in [manifest['patch'], manifest['license_text']]:
        path = source_path(component, entry['path'])
        require(sha256(path) == entry['sha256'], 'patch/license drift: ' + entry['path'])
    patch = source_path(component, manifest['patch']['path'])
    paths = re.findall(r'^\+\+\+ b/(.+)$', patch.read_text(), re.MULTILINE)
    require(set(paths) == {'AndroidManifest.xml', 'res/values/config.xml',
                          'src/org/lineageos/pen/PenService.kt', 'src/org/lineageos/pen/PenProtocol.kt',
                          'src/org/lineageos/pen/BootCompletedReceiver.kt', 'src/org/lineageos/pen/PenAccess.kt',
                          'src/org/lineageos/pen/PenRuntime.kt', 'src/org/lineageos/pen/PenRelay.kt',
                          'src/org/lineageos/pen/PenGattSession.kt', 'src/org/lineageos/pen/PeakCap.kt',
                          'src/org/lineageos/pen/PenRefreshRateCap.kt'},
            'patch changes an unreviewed path')
    return manifest


def verify_scratch(path):
    path = Path(path).absolute()
    require(not path.is_symlink() and path == path.resolve(), 'scratch must use its real path')
    require(path.parent == Path('/private/tmp/ai-development'), 'scratch must be a CleanOS task root')
    require(path.is_dir() and path.stat().st_uid == os.getuid(), 'scratch owner mismatch')
    marker = path / '.cleanos-task.json'
    require(marker.is_file() and not marker.is_symlink(), 'CleanOS task manifest missing')
    task = load(marker)
    require(task.get('schema') == 1 and task.get('id') == path.name and
            task.get('owner') == os.getuid() and task.get('project') == str(ROOT) and
            task.get('finished') is False, 'inactive or foreign CleanOS task')
    result = subprocess.run(['tmutil', 'isexcluded', str(path)], capture_output=True, text=True, check=True)
    require('[Excluded]' in result.stdout, 'scratch backup-copy exclusion not verified')
    return path


def verify_output(path=ARTIFACT, *, replace_sha256=None):
    path = Path(path)
    require(path == ARTIFACT and path.is_absolute(), 'output must be the canonical unsigned candidate')
    require(not path.is_symlink(), 'refusing to overwrite candidate symlink')
    if path.exists():
        require(replace_sha256 is not None and re.fullmatch('[0-9a-f]{64}', replace_sha256) is not None
                and sha256(path) == replace_sha256, 'refusing to overwrite candidate without its exact expected hash')
    else:
        require(replace_sha256 is None, 'expected replacement candidate is missing')
    require(not any(p.is_symlink() for p in path.parents), 'output parent is a symlink')
    require(path.resolve().is_relative_to(ROOT.resolve()), 'output escapes repository')


def verify_toolchain():
    lock = load(COMPONENT / 'toolchain.json')
    for entry in [*lock['dependencies'].values(), *lock['tools'].values()]:
        path = Path(entry['path'])
        require(path.is_file(), 'Missing exact dependency: ' + entry.get('coordinate', str(path)))
        require(sha256(path) == entry['sha256'], 'tool/dependency hash mismatch: ' + str(path))
    java = Path(lock['java_home']) / 'bin/java'
    require(java.is_file(), 'Missing JDK 21: ' + str(java))
    version = subprocess.run([str(java), '-version'], capture_output=True, text=True, check=True).stderr
    require(re.search(r'version "21\.', version) is not None, 'JDK 21 required')
    lock['java_version'] = version.strip()
    return lock


def run(args, work, env, commands):
    args = [str(x) for x in args]
    result = subprocess.run(args, cwd=work, env=env, capture_output=True, text=True, timeout=180)
    commands.append({'argv': args, 'returncode': result.returncode,
                     'output': (result.stdout + result.stderr)[-6000:]})
    (work / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    require(result.returncode == 0, 'command failed: ' + args[0] + '\n' + (result.stdout + result.stderr)[-3500:])
    return result.stdout


def extract_donor(work):
    pins = load(COMPONENT / 'donor-inputs.json')
    for entry in pins['images']:
        require(sha256(entry['path']) == entry['sha256'], 'donor image drift')
    result = {}
    for entry in pins['files']:
        if entry.get('container_chain'):
            continue
        target = work / Path(entry['image_path']).name
        with target.open('xb') as out:
            read = subprocess.run(['dump.erofs', '--cat', '--path=' + entry['image_path'], entry['image']],
                                  stdout=out, stderr=subprocess.PIPE)
        require(read.returncode == 0 and sha256(target) == entry['sha256'], 'donor file drift: ' + entry['image_path'])
        result[target.name] = target
    for entry in pins['files']:
        if not entry.get('container_chain'):
            continue
        apex = result[Path(entry['container_chain'][0]).name]
        payload = work / (apex.stem + '-payload.img')
        with zipfile.ZipFile(apex) as archive:
            with archive.open('apex_payload.img') as source, payload.open('xb') as out:
                shutil.copyfileobj(source, out, 1024 * 1024)
        target = work / Path(entry['image_path']).name
        with target.open('xb') as out:
            read = subprocess.run(['dump.erofs', '--cat', '--path=' + entry['image_path'], str(payload)],
                                  stdout=out, stderr=subprocess.PIPE)
        require(read.returncode == 0 and sha256(target) == entry['sha256'], 'APEX Java file drift')
        result[target.name] = target
    api = DEX.DexApi()
    api.add_archive(result['framework.jar'])
    api.add_archive(result['framework-bluetooth.jar'])
    api.add_archive(result['core-oj.jar'])
    return result, api


def verify_compile_api(api):
    checked = []
    for line in (COMPONENT / 'build-support/compile-api.txt').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        v = line.split()
        if v[1] == 'FIELD':
            name = 'L' + v[0] + ';->' + v[2] + ':' + v[4]
            expected = int(v[5]) if v[4] == 'I' else v[5]
            require(api.fields.get(name) == expected, 'donor constant mismatch: ' + name)
        else:
            name = 'L' + v[0] + ';->' + v[1] + v[2]
            require(name in api.definitions, 'donor hidden method absent: ' + name)
        checked.append(name)
    return checked


def check_apk(apk, donor):
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'APK has duplicate entries')
        require(not any(n.startswith('/') or '..' in n.split('/') for n in names), 'APK has unsafe entry path')
        require(not any(n.startswith('lib/') or n.endswith('.class') for n in names), 'APK contains unexpected JNI/class input')
        require(not any(re.search(r'META-INF/.*\.(RSA|DSA|EC|SF)$', n, re.I) for n in names), 'APK is signed')
        require(b'APK Sig Block 42' not in apk.read_bytes(), 'APK has a signing block')
    app = DEX.DexApi(); app.add_archive(apk)
    require(not any(n.startswith('Landroid/') for n in app.classes), 'compile-only Android classes leaked into APK')
    require(not any('requestMaxRefreshRate(' in n for n in app.references), 'unsupported display method remains')
    references = sorted(x for x in app.references if x.startswith('Landroid/'))
    missing = [x for x in references if not donor.resolves(x)]
    require(not missing, 'actual donor cannot resolve APK methods: ' + str(missing))
    require(any(n.startswith('Lvendor/oplus/hardware/touch/IOplusTouch;') for n in app.classes), 'V2 client missing')
    return {'android_method_references_checked': references, 'unresolved_android_methods': missing,
            'android_classes_packaged': [], 'signed': False, 'class_count': len(app.classes)}


def build(scratch, *, replace_sha256=None):
    scratch = verify_scratch(scratch)
    verify_output(replace_sha256=replace_sha256)
    source_manifest = verify_sources()
    lock = verify_toolchain()
    commands = []
    with tempfile.TemporaryDirectory(prefix='oplus-pen-', dir=scratch) as temp:
        work = Path(temp)
        env = os.environ.copy(); env['JAVA_HOME'] = lock['java_home']
        env['TMPDIR'] = str(work / 'tmp'); (work / 'tmp').mkdir()
        env['JAVA_TOOL_OPTIONS'] = '-Djava.io.tmpdir=' + str(work / 'tmp')
        try:
            source = work / 'source'
            shutil.copytree(COMPONENT / 'upstream/packages/Pen', source)
            run(['git', '-C', source, 'apply', '--check', COMPONENT / source_manifest['patch']['path']], work, env, commands)
            run(['git', '-C', source, 'apply', COMPONENT / source_manifest['patch']['path']], work, env, commands)
            donor_files, donor = extract_donor(work)
            hidden_methods = verify_compile_api(donor)
            java = Path(lock['java_home']) / 'bin'
            deps = {k: v['path'] for k, v in lock['dependencies'].items()}
            tools = {k: v['path'] for k, v in lock['tools'].items()}
            compiler_cp = os.pathsep.join(deps.values())
            helper = work / 'helper'; helper.mkdir()
            run([java / 'javac', '-cp', deps['compiler'], '-d', helper, COMPONENT / 'build-support/CompileApi.java'], work, env, commands)
            shim = work / 'compile-only-api.jar'
            run([java / 'java', '-cp', str(helper) + os.pathsep + deps['compiler'], 'CompileApi', tools['android_jar'],
                 COMPONENT / 'build-support/compile-api.txt', shim], work, env, commands)
            kotlin = [java / 'java', '-Xmx1024m', '-cp', compiler_cp, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
                      '-no-stdlib', '-no-reflect', '-jvm-target', '1.8']
            protocol = source / 'src/org/lineageos/pen/PenProtocol.kt'
            run(kotlin + ['-classpath', deps['stdlib'], '-d', work / 'protocol-test.jar', protocol,
                          source / 'src/org/lineageos/pen/PenRuntime.kt',
                          source / 'src/org/lineageos/pen/PeakCap.kt', COMPONENT / 'tests/PeakCapSelfTest.kt',
                          COMPONENT / 'tests/ProtocolSelfTest.kt', COMPONENT / 'tests/PenRuntimeSelfTest.kt'], work, env, commands)
            protocol_result = run([java / 'java', '-cp', str(work / 'protocol-test.jar') + os.pathsep + deps['stdlib'],
                                   'org.lineageos.pen.ProtocolSelfTestKt'], work, env, commands)
            lifecycle_result = run([java / 'java', '-cp', str(work / 'protocol-test.jar') + os.pathsep + deps['stdlib'],
                                   'org.lineageos.pen.PenRuntimeSelfTestKt'], work, env, commands)
            peak_result = run([java / 'java', '-cp', str(work / 'protocol-test.jar') + os.pathsep + deps['stdlib'],
                              'org.lineageos.pen.PeakCapSelfTestKt'], work, env, commands)
            resources = work / 'resources.zip'
            run([tools['aapt2'], 'compile', '--dir', source / 'res', '-o', resources], work, env, commands)
            generated = work / 'generated'; generated.mkdir()
            package = work / 'resources.apk'
            run([tools['aapt2'], 'link', '-I', tools['android_jar'], '--manifest', source / 'AndroidManifest.xml',
                 '--min-sdk-version', '37', '--target-sdk-version', '37', '--version-code', '39', '--version-name', '17-pen-cap1',
                 '--java', generated, '-o', package, resources], work, env, commands)
            aidlroot = COMPONENT / 'upstream/interfaces/aidl_api/vendor.oplus.hardware.touch/2'
            aidl_hash = (aidlroot / '.hash').read_text().strip()
            for path in sorted(aidlroot.rglob('*.aidl')):
                run([tools['aidl'], '--lang=java', '--structured', '--stability=vintf', '--version=2', '--hash=' + aidl_hash,
                     '-I' + str(aidlroot), '--out=' + str(generated), path], work, env, commands)
            classes = work / 'classes'; classes.mkdir()
            classpath = os.pathsep.join([str(shim), tools['android_jar'], deps['annotations']])
            run([java / 'javac', '--release', '8', '-Xlint:-options', '-cp', classpath, '-d', classes,
                 *sorted(generated.rglob('*.java'))], work, env, commands)
            program = work / 'program.jar'
            run(kotlin + ['-classpath', classpath + os.pathsep + str(classes) + os.pathsep + deps['stdlib'],
                          '-d', work / 'kotlin.jar', *sorted((source / 'src').rglob('*.kt'))], work, env, commands)
            with zipfile.ZipFile(program, 'w', zipfile.ZIP_DEFLATED) as out:
                for path in sorted(classes.rglob('*.class')):
                    zip_member(out, str(path.relative_to(classes)), path.read_bytes())
                with zipfile.ZipFile(work / 'kotlin.jar') as kt:
                    for name in kt.namelist():
                        if name.endswith('.class'):
                            zip_member(out, name, kt.read(name))
            dexdir = work / 'dex'; dexdir.mkdir()
            # Build-tools 36 supports DEX API 36; the manifest still requires Android API 37.
            run([tools['d8'], '--min-api', '36', '--lib', tools['android_jar'], '--classpath', shim,
                 '--output', dexdir, program, deps['stdlib']], work, env, commands)
            raw = work / 'uncompressed.apk'
            shutil.copyfile(package, raw)
            with zipfile.ZipFile(raw, 'a', zipfile.ZIP_DEFLATED) as apk:
                for path in sorted(dexdir.glob('classes*.dex')):
                    zip_member(apk, path.name, path.read_bytes())
                zip_member(apk, 'META-INF/LICENSE-oplus-pen', (COMPONENT / 'LICENSE').read_bytes())
                with zipfile.ZipFile(deps['stdlib']) as stdlib:
                    for name in stdlib.namelist():
                        if name.lower().endswith(('.txt', '.md')) and ('license' in name.lower() or 'notice' in name.lower()):
                            zip_member(apk, 'META-INF/kotlin-' + Path(name).name, stdlib.read(name))
            candidate = work / 'oplus-pen-unsigned.apk'
            run([tools['zipalign'], '-P', '16', '4', raw, candidate], work, env, commands)
            run([tools['zipalign'], '-c', '-P', '16', '4', candidate], work, env, commands)
            checks = check_apk(candidate, donor)
            badging = run([tools['aapt2'], 'dump', 'badging', candidate], work, env, commands)
            require("package: name='org.lineageos.pen'" in badging, 'unexpected APK package')
            require('RESTRICT_DISPLAY_MODES' not in badging and 'sharedUserId' not in badging, 'unexpected APK privilege')
            receipt = {'status': 'UNSIGNED_UNTESTED_COMPONENT_CANDIDATE', 'apk': str(ARTIFACT),
                       'sha256': sha256(candidate), 'bytes': candidate.stat().st_size,
                       'signing_key_generated': False, 'device_commands_run': False, 'image_changes': False,
                       'automatic_refresh_limiting': 'Settings.System.peak_refresh_rate; only when Settings.System.canWrite',
                       'manual_cap_required_if_write_settings_denied_hz': 120,
                       'version_code': 39, 'version_name': '17-pen-cap1',
                       'headless_system_user_blocked': True, 'bluetooth_runtime_permissions_required': True,
                       'd8_min_api': 36, 'manifest_min_sdk': 37,
                       'active_ack_above_120_hz': 'withheld (native 0.5 Hz rounding tolerance)',
                       'source_manifest_sha256': sha256(COMPONENT / 'upstream-manifest.json'),
                       'patch_sha256': source_manifest['patch']['sha256'], 'toolchain': lock,
                       'compile_only_api_verified': hidden_methods, 'donor_abi_check': checks,
                       'protocol_tests': protocol_result.strip(), 'apk_badging': badging,
                       'lifecycle_tests': lifecycle_result.strip(),
                       'peak_cap_tests': peak_result.strip(), 'superseded_unsigned_sha256': replace_sha256,
                       'commands': commands}
            verify_output(replace_sha256=replace_sha256)
            ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            require(ARTIFACT.parent.stat().st_dev == candidate.stat().st_dev,
                    'atomic candidate publication requires the same filesystem')
            os.replace(candidate, ARTIFACT)
            require(sha256(ARTIFACT) == receipt['sha256'], 'published candidate mismatch')
            (COMPONENT / 'build-result.json').write_text(json.dumps(receipt, indent=2) + '\n')
            return receipt
        finally:
            (scratch / 'last-build-commands.json').write_text(json.dumps(commands, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True, help='active CleanOS task root under /private/tmp/ai-development')
    parser.add_argument('--replace-sha256', help='replace only this exact existing unsigned candidate, after all build checks pass')
    args = parser.parse_args()
    try:
        result = build(args.scratch, replace_sha256=args.replace_sha256)
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps({k: result[k] for k in ['status', 'apk', 'sha256', 'bytes', 'protocol_tests']}, indent=2))
