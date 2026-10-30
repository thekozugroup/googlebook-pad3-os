#!/usr/bin/env python3
"""Build the pinned Photos-only framework graft offline; no device or image operations."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import struct
import tempfile
import zipfile

from patch_taskmanager import (JADX_SHA256, code_records, digest, require,
                               split_methods, verify_dex, verify_scratch)

ROOT = Path(__file__).resolve().parent
COMPONENT = ROOT / 'components/photos-native'
HELPER = 'com/android/internal/util/googlebook/PhotosCompat'
TARGETS = {
    'android/app/ActivityThread.smali': 'handleBindApplication(Landroid/app/ActivityThread$AppBindData;)V',
    'android/app/ApplicationPackageManager.smali': 'hasSystemFeature(Ljava/lang/String;I)Z',
}


def run(args, env):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, env=env)
    require(result.returncode == 0, Path(str(args[0])).name + ': ' + (result.stdout + result.stderr)[-3000:])
    return result.stdout


def normalize(text):
    # DEX writers may omit encoded trailing static zero values; their defaults are identical.
    text = re.sub(r'(?m)^(\.field (?=[^\n]*\bstatic\b)[^\n]*:[ZBSCIJFD]) = (?:0x0|false)$', r'\1', text)
    # Absent hidden-API metadata and an explicit SDK/whitelist value both encode ART flag zero.
    text = re.sub(r'(?m)^(\.(?:method|field) [^:(=\n]*?)\bwhitelist ', r'\1', text)
    labels = {line.strip(): '@' + str(i) for i, line in enumerate(
        line for line in text.splitlines() if line.strip().startswith(':'))}
    pieces = re.split(r'("(?:[^"\\]|\\.)*")', text)
    for i in range(0, len(pieces), 2):
        pieces[i] = re.sub(r':[A-Za-z0-9_]+', lambda m: labels.get(m[0], m[0]), pieces[i])
        pieces[i] = re.sub(r'(?m)^(\s*)(const-string/jumbo|goto/16|goto/32)\b',
                           lambda m: m[1] + ('const-string' if m[2].startswith('const-string') else 'goto'), pieces[i])
    return ''.join(pieces)


def preservation(before, after):
    original = {f.relative_to(before).as_posix(): f.read_text() for f in before.rglob('*.smali')}
    patched = {f.relative_to(after).as_posix(): f.read_text() for f in after.rglob('*.smali')}
    require(original.keys() == patched.keys(), 'framework class set changed')
    unchanged_methods = 0
    for name in original:
        if name not in TARGETS:
            require(normalize(original[name]) == normalize(patched[name]), 'unrelated framework class changed: ' + name)
            continue
        old, old_metadata = split_methods(original[name])
        new, new_metadata = split_methods(patched[name])
        require(normalize(old_metadata) == normalize(new_metadata) and old.keys() == new.keys(),
                'framework metadata changed: ' + name)
        for method in old:
            if method != TARGETS[name]:
                require(normalize(old[method]) == normalize(new[method]), 'unrelated method changed: ' + method)
                unchanged_methods += 1
                continue
            require(old[method].splitlines()[0] == new[method].splitlines()[0], 'target declaration changed')
            require(re.findall(r'(?ms)^    \.annotation .*?^    \.end annotation', old[method])
                    == re.findall(r'(?ms)^    \.annotation .*?^    \.end annotation', new[method]),
                    'target annotations changed')
            require(re.findall(r'^    \.(?:registers|locals|param|end param)\b.*$', old[method], re.M)
                    == re.findall(r'^    \.(?:registers|locals|param|end param)\b.*$', new[method], re.M),
                    'target register/parameter metadata changed')
            require(re.findall(r'"(?:[^"\\]|\\.)*"', old[method])
                    == re.findall(r'"(?:[^"\\]|\\.)*"', new[method]), 'target string literals changed')
            expected, _, _ = code_records(old[method])
            _, instructions, _ = code_records(new[method])
            if name.endswith('ActivityThread.smali'):
                calls = [i for i, line in enumerate(instructions) if 'L' + HELPER + ';->onBind(' in line]
                require(len(calls) == 1, 'Photos bind hook missing/duplicated')
                index = calls[0]
                require(index >= 2 and '->appInfo:Landroid/content/pm/ApplicationInfo;' in instructions[index-2]
                        and '->packageName:Ljava/lang/String;' in instructions[index-1], 'Photos bind arguments changed')
                skipped = range(index-2, index+1)
            else:
                require('L' + HELPER + ';->feature(' in instructions[0]
                        and instructions[1] == 'move-result-object v0'
                        and instructions[2].startswith('if-eqz v0, ')
                        and 'Ljava/lang/Boolean;->booleanValue()Z' in instructions[3]
                        and instructions[4:6] == ['move-result v0', 'return v0'], 'feature guard changed')
                skipped = range(6)
            actual, _, _ = code_records(new[method], skipped)
            require(expected == actual, 'original framework flow/try/debug changed: ' + method)
    return {'original_classes': len(original), 'unchanged_classes': len(original)-2,
            'unchanged_methods_in_changed_classes': unchanged_methods,
            'changed_methods': list(TARGETS.values()), 'original_bodies_and_metadata_preserved': True}


def build(source, output, scratch, sdk, jdk, dex_tools):
    scratch = verify_scratch(scratch)
    source, output = Path(source), Path(output).absolute()
    lock = json.loads((COMPONENT / 'source-lock.json').read_text())
    require(source.is_file() and digest(source) == lock['source_framework_sha256']
            and source.stat().st_size == lock['source_framework_bytes'], 'framework source drift')
    require(digest(dex_tools) == JADX_SHA256, 'DEX tool input differs')
    require(output == output.resolve() and output.is_relative_to(scratch) and not output.exists(), 'new owned scratch output required')
    files = [*[f for f in COMPONENT.rglob('*') if f.is_file()], Path(__file__), ROOT/'test_build_photos_native.py']
    pins = {str(f.relative_to(ROOT)): digest(f) for f in files}
    with tempfile.TemporaryDirectory(prefix='photos-native-build-', dir=scratch) as directory:
        work = Path(directory)
        env = dict(os.environ, JAVA_HOME=str(jdk), TMPDIR=str(work),
                   JAVA_TOOL_OPTIONS='-XX:ActiveProcessorCount=2 -Xmx1024m -Djava.io.tmpdir='+str(work))
        classes, tools, helper = [work/n for n in ['classes', 'tools', 'helper']]
        for path in [classes, tools, helper]: path.mkdir()
        android = sdk/'platforms/android-36/android.jar'
        run([jdk/'bin/javac', '--release', '8', '-cp', android, '-d', classes,
             COMPONENT/'src'/Path(HELPER+'.java'), COMPONENT/'tests/PhotosCompatSelfTest.java'], env)
        checks = run([jdk/'bin/java', '-ea', '-cp', str(classes)+os.pathsep+str(android),
                      'com.android.internal.util.googlebook.PhotosCompatSelfTest'], env)
        run([sdk/'build-tools/36.0.0/d8', '--release', '--min-api', '35', '--lib', android,
             '--output', helper, classes/Path(HELPER+'.class')], env)
        run([jdk/'bin/javac', '--release', '17', '-cp', dex_tools, '-d', tools,
             COMPONENT/'build-support/GraftFramework.java'], env)
        with zipfile.ZipFile(source) as archive:
            require(archive.testzip() is None and len(archive.namelist()) == len(set(archive.namelist())), 'invalid framework ZIP')
            dex_names = [n for n in archive.namelist() if re.fullmatch(r'classes[2-9]?\.dex', n)]
            require(set(dex_names) == {'classes.dex', *['classes'+str(i)+'.dex' for i in range(2,7)]}, 'expected six framework DEX inputs')
            (work/'original.dex').write_bytes(archive.read('classes.dex'))
            transform = json.loads(run([jdk/'bin/java', '-cp', str(tools)+os.pathsep+str(dex_tools),
                                        'GraftFramework', work/'original.dex', work/'patched.dex', 'app'], env))
            structures = [verify_dex((work/'patched.dex').read_bytes()), verify_dex((helper/'classes.dex').read_bytes())]
            for name in ['original', 'patched']:
                run([jdk/'bin/java', '-cp', dex_tools, 'com.android.tools.smali.baksmali.Main',
                     'd', work/(name+'.dex'), '-o', work/(name+'-smali')], env)
            proof = preservation(work/'original-smali', work/'patched-smali')
            output.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(output, 'x') as target:
                for original_info in archive.infolist():
                    info = copy.copy(original_info)
                    if info.compress_type == zipfile.ZIP_STORED:
                        padding = (-(target.fp.tell()+30+len(info.filename.encode())+len(info.extra)+4)) % 4
                        info.extra += struct.pack('<HH', 0xd935, padding)+b'\0'*padding
                    target.writestr(info, (work/'patched.dex').read_bytes() if info.filename=='classes.dex' else archive.read(original_info))
                info = zipfile.ZipInfo('classes7.dex', (1980,1,1,0,0,0))
                padding = (-(target.fp.tell()+30+len(info.filename)+4)) % 4
                info.extra = struct.pack('<HH', 0xd935, padding)+b'\0'*padding
                target.writestr(info, (helper/'classes.dex').read_bytes())
        with zipfile.ZipFile(source) as original, zipfile.ZipFile(output) as target:
            require(target.testzip() is None and set(target.namelist()) == set(original.namelist())|{'classes7.dex'}, 'candidate ZIP drift')
            for name in original.namelist():
                if name!='classes.dex': require(original.read(name)==target.read(name), 'unrelated JAR member changed: '+name)
            with output.open('rb') as stream:
                for info in target.infolist():
                    if not info.filename.endswith('.dex'): continue
                    stream.seek(info.header_offset+26)
                    name_bytes, extra_bytes = struct.unpack('<HH', stream.read(4))
                    require((info.header_offset+30+name_bytes+extra_bytes) % 4 == 0, 'unaligned DEX entry')
        require(pins == {str(f.relative_to(ROOT)): digest(f) for f in files}, 'sources changed during build')
        receipt = {'source_framework_sha256': lock['source_framework_sha256'], 'candidate_sha256': digest(output),
                   'candidate_bytes': output.stat().st_size, 'scope': lock['scope'], 'sources': pins,
                   'transform': transform, 'preservation': proof, 'dex': structures, 'host_checks': checks.strip(),
                   'unchanged_original_dex': sorted(n for n in dex_names if n != 'classes.dex'),
                   'requires_boot_artifact_rebuild_or_exclusion': True,
                   'device_installed': False, 'runtime_verified': False}
        output.with_suffix('.verification.json').write_text(json.dumps(receipt, indent=2)+'\n')
        return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source','output','scratch','sdk','jdk','dex-tools']:
        parser.add_argument('--'+name, type=Path, required=True)
    args = vars(parser.parse_args())
    print(json.dumps(build(**args), indent=2))
