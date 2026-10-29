#!/usr/bin/env python3
"""Build the face preview RRO unsigned in an active, owned CleanOS task."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent
COMPONENT = ROOT / 'components/face-preview-overlay'
PACKAGE = 'com.googlebook.pad3.facepreview'
TARGET = 'com.android.settings'
RESOURCE = 'config_face_settings_should_manage_preview'
OUTPUT = 'GooglebookPad3FacePreview-unsigned.apk'
ANDROID = '{http://schemas.android.com/apk/res/android}'
ADMISSION = {
    'image_path': 'system_ext/overlay/GooglebookPad3FacePreview/GooglebookPad3FacePreview.apk',
    'merge_into': 'system_ext/overlay/config/config.xml',
    'entry': {'package': PACKAGE, 'mutable': 'false', 'enabled': 'true'},
    'target_package': TARGET,
    'target_resource': 'bool/' + RESOURCE,
    'value': False,
    'target_name': None,
    'requires_external_signing': True,
    'requires_preinstalled_overlay_admission': True,
    'device_validation_performed': False,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(args, *, env=None):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, env=env)
    require(result.returncode == 0, f'{Path(args[0]).name} failed: {result.stderr[-3000:]}')
    return result.stdout or result.stderr


def verify_scratch(path):
    path = Path(path).absolute()
    require(path == path.resolve() and not path.is_symlink(), 'scratch must use its real path')
    require(path.parent == Path('/tmp/ai-development').resolve(), 'scratch must be a CleanOS task root')
    require(path.is_dir() and path.stat().st_uid == os.getuid(), 'scratch owner mismatch')
    marker = path / '.cleanos-task.json'
    require(marker.is_file() and not marker.is_symlink(), 'CleanOS task manifest missing')
    task = json.loads(marker.read_text())
    require(task.get('schema') == 1 and task.get('id') == path.name and
            task.get('owner') == os.getuid() and task.get('project') == str(ROOT) and
            task.get('finished') is False, 'inactive or foreign CleanOS task')
    require('[Excluded]' in run(['tmutil', 'isexcluded', path]),
            'scratch backup-copy exclusion not verified')
    return path


def certificate_sha256(path):
    path = Path(path).absolute()
    require(path == path.resolve() and not path.is_symlink() and path.is_file(),
            'certificate must be a regular public DER file, without symlinks')
    require(0 < path.stat().st_size <= 16384, 'public certificate size invalid')
    data = path.read_bytes()
    require(data.startswith(b'\x30') and b'-----BEGIN' not in data, 'expected public X.509 DER certificate')
    result = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-outform', 'DER'],
                            input=data, capture_output=True)
    require(result.returncode == 0 and result.stdout == data,
            'not a complete canonical X.509 DER public certificate')
    return hashlib.sha256(data).hexdigest()


def verify_sources(component=COMPONENT):
    component = Path(component).absolute()
    require(component == component.resolve(), 'component contains a symlink')
    expected = {'AndroidManifest.xml', 'res/values/bools.xml', 'res/xml/overlays.xml',
                'overlay-config-entry.xml', 'README.md'}
    paths = list(component.rglob('*'))
    require(not any(p.is_symlink() for p in paths), 'component contains a symlink')
    require({p.relative_to(component).as_posix() for p in paths if p.is_file()} == expected,
            'unexpected component file inventory')
    manifest = ET.parse(component / 'AndroidManifest.xml').getroot()
    require(manifest.tag == 'manifest' and manifest.attrib == {
        'package': PACKAGE, ANDROID + 'versionCode': '1', ANDROID + 'versionName': '1'},
        'unexpected manifest identity')
    require([e.tag for e in manifest] == ['uses-sdk', 'application', 'overlay'] and
            all(len(e) == 0 for e in manifest), 'unexpected manifest component')
    require(manifest[0].attrib == {ANDROID + 'minSdkVersion': '35', ANDROID + 'targetSdkVersion': '37'} and
            manifest[1].attrib == {ANDROID + 'hasCode': 'false'} and
            manifest[2].attrib == {ANDROID + 'targetPackage': TARGET,
                                   ANDROID + 'resourcesMap': '@xml/overlays'},
            'unexpected manifest attributes')
    values = ET.parse(component / 'res/values/bools.xml').getroot()
    require(values.tag == 'resources' and not values.attrib and len(values) == 1 and
            values[0].tag == 'bool' and values[0].attrib == {'name': RESOURCE} and
            len(values[0]) == 0 and (values[0].text or '').strip() == 'false',
            'expected only the false preview boolean')
    mapping = ET.parse(component / 'res/xml/overlays.xml').getroot()
    require(mapping.tag == 'overlay' and not mapping.attrib and len(mapping) == 1 and
            mapping[0].tag == 'item' and len(mapping[0]) == 0 and
            mapping[0].attrib == {'target': 'bool/' + RESOURCE, 'value': '@bool/' + RESOURCE},
            'unexpected resource mapping')
    entry = ET.parse(component / 'overlay-config-entry.xml').getroot()
    require(entry.tag == 'overlay' and len(entry) == 0 and entry.attrib == ADMISSION['entry'],
            'unexpected OverlayConfig entry')
    return {name: sha256(component / name) for name in sorted(expected)}


def verify_unsigned_payload(apk):
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        require(len(names) == 3 and set(names) == {
            'AndroidManifest.xml', 'resources.arsc', 'res/xml/overlays.xml'},
            'APK must contain only the resource-only unsigned overlay payload')
        require(archive.testzip() is None, 'APK ZIP checksum failure')
    require(b'APK Sig Block 42' not in Path(apk).read_bytes(), 'APK contains a signing block')


def build(scratch, certificate, sdk=None):
    scratch = verify_scratch(scratch)
    output_dir = scratch / 'face-preview-overlay'
    require(not output_dir.exists() and not output_dir.is_symlink(), 'refusing to overwrite face overlay output')
    source_hashes = verify_sources()
    signer_hash = certificate_sha256(certificate)
    sdk = sdk or os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    require(sdk, 'supply --sdk or ANDROID_HOME / ANDROID_SDK_ROOT')
    sdk = Path(sdk).expanduser().resolve()
    aapt2 = sdk / 'build-tools/36.0.0/aapt2'
    zipalign = sdk / 'build-tools/36.0.0/zipalign'
    platform = sdk / 'platforms/android-37.2/android.jar'
    require(aapt2.is_file() and os.access(aapt2, os.X_OK) and
            zipalign.is_file() and os.access(zipalign, os.X_OK) and platform.is_file(),
            'installed SDK build-tools 36.0.0 and platform android-37.2 required')
    with tempfile.TemporaryDirectory(prefix='face-overlay-build-', dir=scratch) as temporary:
        work = Path(temporary)
        env = dict(os.environ, TMPDIR=str(work) + os.sep, TMP=str(work), TEMP=str(work))
        run([aapt2, 'compile', '--dir', COMPONENT / 'res', '-o', work / 'compiled.zip'], env=env)
        run([aapt2, 'link', '-I', platform, '--manifest', COMPONENT / 'AndroidManifest.xml',
             '--no-resource-deduping', '--no-resource-removal', '-o', work / 'linked.apk',
             work / 'compiled.zip'], env=env)
        apk = work / OUTPUT
        run([zipalign, '-P', '16', '4', work / 'linked.apk', apk], env=env)
        run([zipalign, '-c', '-P', '16', '4', apk], env=env)
        verify_unsigned_payload(apk)
        require(run([aapt2, 'dump', 'packagename', apk], env=env).strip() == PACKAGE,
                'compiled overlay package mismatch')
        resources = run([aapt2, 'dump', 'resources', apk], env=env)
        boolean = re.search(r'resource (0x[0-9a-f]+) bool/' + RESOURCE +
                            r'\s*\n\s*\(\) false\b', resources)
        resource_map = re.search(r'resource (0x[0-9a-f]+) xml/overlays\s*\n', resources)
        require(boolean and resource_map and re.findall(r'resource 0x[0-9a-f]+ (\S+)', resources) ==
                ['bool/' + RESOURCE, 'xml/overlays'], 'compiled preview resource inventory/value mismatch')
        manifest = run([aapt2, 'dump', 'xmltree', '--file', 'AndroidManifest.xml', apk], env=env)
        mapping = run([aapt2, 'dump', 'xmltree', '--file', 'res/xml/overlays.xml', apk], env=env)
        require(re.search(r':targetPackage\([^)]*\)="' + re.escape(TARGET) + '"', manifest) and
                re.search(r':hasCode\([^)]*\)=false\b', manifest) and 'targetName' not in manifest and
                re.search(r':resourcesMap\([^)]*\)=@' + resource_map[1] + r'\b', manifest) and
                'target="bool/' + RESOURCE + '"' in mapping and
                'value=@' + boolean[1] in mapping, 'compiled overlay target/mapping mismatch')
        receipt = {
            'schema_version': 1, 'package': PACKAGE, 'unsigned': True,
            'artifact': OUTPUT, 'sha256': sha256(apk), 'size_bytes': apk.stat().st_size,
            'expected_signer_certificate_sha256': signer_hash,
            'source_sha256': source_hashes,
            'builder_sha256': sha256(ROOT / 'build_face_overlay.py'),
            'toolchain': {'build_tools': '36.0.0', 'platform': 'android-37.2',
                          'aapt2_version': run([aapt2, 'version'], env=env).strip(),
                          'aapt2_sha256': sha256(aapt2), 'zipalign_sha256': sha256(zipalign),
                          'android_jar_sha256': sha256(platform), 'java_compilation': False},
            'checks': {'zipalign_16k': True, 'unsigned_resource_only': True,
                       'compiled_boolean_false': True, 'compiled_package_target_mapping': True},
            'admission': ADMISSION,
            'compiled_evidence': {'resources': resources, 'manifest': manifest, 'mapping': mapping},
        }
        output_dir.mkdir()
        try:
            shutil.copyfile(apk, output_dir / OUTPUT)
            (output_dir / 'build-result.json').write_text(json.dumps(receipt, indent=2) + '\n')
        except BaseException:
            shutil.rmtree(output_dir)
            raise
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', required=True, type=Path)
    parser.add_argument('--certificate', required=True, type=Path, help='owner public X.509 DER certificate only')
    parser.add_argument('--sdk', type=Path, help='existing SDK; defaults to ANDROID_HOME / ANDROID_SDK_ROOT')
    args = parser.parse_args()
    try:
        receipt = build(args.scratch, args.certificate, args.sdk)
    except (ValueError, OSError, ET.ParseError, zipfile.BadZipFile) as error:
        parser.exit(1, f'{error}\n')
    print(json.dumps({'artifact': str(args.scratch / 'face-preview-overlay' / OUTPUT),
                      'sha256': receipt['sha256'], 'unsigned': True}, indent=2))


if __name__ == '__main__':
    main()
