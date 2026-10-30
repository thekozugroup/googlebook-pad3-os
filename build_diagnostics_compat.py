#!/usr/bin/env python3
"""Build the hash-bound Diagnostics-only module with existing tools and external signing inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

from patch_taskmanager import verify_scratch

ROOT = Path(__file__).resolve().parent
COMPONENT = ROOT / 'components/diagnostics-compat'
PACKAGE = 'org.googlebook.pad3.diagnosticscompat'
API_SHA = '843b4e1a4cddf30c1be737cc13c375561d10b1af2ed29459a0fde013c055e37b'
CERT_SHA = '3625a00c6244e94e3150604c4903800c3928e958e77a5b2d2814be1864f82eb4'


def digest(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def run(args, env):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, env=env)
    require(result.returncode == 0, Path(str(args[0])).name + ' failed: ' + (result.stdout + result.stderr)[-4000:])
    return result.stdout


def build(scratch, api, key, certificate, sdk, jdk, output):
    scratch = verify_scratch(scratch)
    require(digest(api) == API_SHA, 'Modern libxposed API101 compile input differs')
    require(digest(certificate) == CERT_SHA, 'Unexpected component signing certificate')
    output = Path(output).absolute()
    require(output == output.resolve() and output.is_relative_to(scratch) and not output.exists(), 'Output must be new and in owned scratch')
    platform = sdk / 'platforms/android-36/android.jar'
    tools = sdk / 'build-tools/36.0.0'
    for file in [platform, jdk / 'bin/javac', jdk / 'bin/java', *[tools / n for n in ['aapt2', 'd8', 'zipalign', 'apksigner']]]:
        require(file.is_file(), 'Missing supplied tool: ' + str(file))
    source_files = [*[f for f in COMPONENT.rglob('*') if f.is_file()], Path(__file__), ROOT / 'test_diagnostics_compat.py']
    source_pins = {str(f.relative_to(ROOT)): digest(f) for f in source_files}
    with tempfile.TemporaryDirectory(prefix='diagnostics-build-', dir=scratch) as temporary:
        work = Path(temporary)
        env = dict(os.environ, JAVA_HOME=str(jdk), TMPDIR=str(work),
                   JAVA_TOOL_OPTIONS='-Xmx768m -Djava.io.tmpdir=' + str(work))
        classes, dex = work / 'classes', work / 'dex'
        classes.mkdir(); dex.mkdir()
        sources = sorted((COMPONENT / 'src').rglob('*.java'))
        run([jdk / 'bin/javac', '--release', '8', '-cp', os.pathsep.join(map(str, [platform, api])),
             '-d', classes, *sources, *sorted((COMPONENT / 'tests').glob('*.java'))], env)
        checks = run([jdk / 'bin/java', '-ea', '-cp', classes,
                      'org.googlebook.pad3.diagnostics.MetricValuesSelfTest'], env)
        inputs = [f for f in classes.rglob('*.class') if not f.name.startswith('MetricValuesSelfTest')]
        run([tools / 'd8', '--release', '--min-api', '28', '--lib', platform,
             '--classpath', api, '--output', dex, *inputs], env)
        apk = work / 'linked.apk'
        run([tools / 'aapt2', 'link', '-I', platform, '--manifest', COMPONENT / 'AndroidManifest.xml', '-o', apk], env)
        with zipfile.ZipFile(apk, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(dex / 'classes.dex', 'classes.dex')
            for file in sorted((COMPONENT / 'META-INF').rglob('*')):
                if file.is_file(): archive.write(file, file.relative_to(COMPONENT).as_posix())
        aligned = work / 'aligned.apk'
        run([tools / 'zipalign', '-P', '16', '4', apk, aligned], env)
        converted = work / 'signing.pk8'
        try:
            run(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', key, '-outform', 'DER', '-out', converted], env)
            converted.chmod(0o600)
            output.parent.mkdir(parents=True, exist_ok=True)
            run([tools / 'apksigner', 'sign', '--key', converted, '--cert', certificate, '--out', output, aligned], env)
        finally: converted.unlink(missing_ok=True)
        signer = run([tools / 'apksigner', 'verify', '--verbose', '--print-certs', output], env)
        require('Signer #1 certificate SHA-256 digest: ' + CERT_SHA in signer, 'APK signer differs')
        require(run([tools / 'aapt2', 'dump', 'packagename', output], env).strip() == PACKAGE, 'Wrong APK package')
        with zipfile.ZipFile(output) as archive:
            require(archive.testzip() is None, 'Invalid APK CRC')
            require(archive.read('META-INF/xposed/scope.list').decode().strip() == 'com.google.android.factory.diagnostics', 'Wrong module scope')
            require(not any(n.startswith('io/github/libxposed') for n in archive.namelist()), 'Compile-only API was packaged')
        require(source_pins == {str(f.relative_to(ROOT)): digest(f) for f in source_files}, 'Build sources changed during compilation')
        receipt = {'package': PACKAGE, 'apk_sha256': digest(output), 'apk_bytes': output.stat().st_size,
                   'api_sha256': API_SHA, 'certificate_sha256': CERT_SHA, 'host_checks': checks.strip(),
                   'scope': ['com.google.android.factory.diagnostics'], 'minimum_modern_api': 101,
                   'sources': source_pins,
                   'device_installed': False, 'runtime_verified': False}
        output.with_suffix('.verification.json').write_text(json.dumps(receipt, indent=2) + '\n')
        return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['scratch', 'api', 'key', 'certificate', 'sdk', 'jdk', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(**vars(args)), indent=2))
