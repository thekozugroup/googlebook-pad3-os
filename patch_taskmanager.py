#!/usr/bin/env python3
"""Build/verify the exact Task Manager shared-client fallback offline; never install it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
COMPONENT = ROOT / 'components/taskmanager-compat'
CANDIDATE = COMPONENT / 'candidate/vendor.google.libraries.desktop.serviceability.jar'
ORIGINAL_SHA256 = '5e4d4c6336e18a3228b4ac4960ea5ecddcc556865d530db7a7094903f62695ba'
ORIGINAL_DEX_SHA256 = 'd4478840b79533666b3aa60dac477e38c4bd3b34435f5b94d6cf98de3a6d2644'
JADX = Path(os.environ.get("GOOGLEBOOK_JADX_JAR", "build-inputs/jadx/jadx-1.5.6-all.jar"))
JADX_SHA256 = '966d314282d95ff7c72f597bb9c744999856666a3b856575e3c035a9c12a0b65'
JAVA = Path(os.environ.get("JAVA_HOME", "build-inputs/jdk-21"))
SDK = Path(os.environ.get("ANDROID_HOME", "build-inputs/android-sdk"))
ANDROID = SDK / 'platforms/android-36/android.jar'
D8 = SDK / 'build-tools/36.0.0/d8'
PACKAGE = 'vendor/google/libraries/desktop/serviceability/'
MANAGER = PACKAGE + 'ServiceabilityManager.smali'
HELPER = PACKAGE + 'TaskManagerCompat'
MODE_LINE = '.field private final synthetic mTaskManagerCompat:Z'
TARGET_COUNTS = {
    '<init>(Landroid/content/Context;)V': 5,
    'fetchBatteryInfo()L' + PACKAGE + 'ServiceabilityManager$BatteryInfo;': 8,
    'fetchCpuUsageInfo()L' + PACKAGE + 'ServiceabilityManager$CpuUsageInfo;': 6,
    'fetchCpuUsageInfoWithProcessUsage([I)L' + PACKAGE + 'ServiceabilityManager$CpuUsageInfoWithProcessUsage;': 9,
    'fetchPhysicalCpusInfo()Ljava/util/List;': 6,
    'getProcessMemoryUsage([I)Ljava/util/List;': 9,
    'stopLongRunningTest(Ljava/lang/String;)V': 4,
}
METHODS = re.compile(r'^\.method [^\n]+\n.*?^\.end method\n?', re.M | re.S)


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def guard_original(path):
    path = Path(path)
    require(path.is_file() and path.stat().st_size == 47482, 'original client JAR size mismatch')
    require(digest(path) == ORIGINAL_SHA256, 'original client JAR SHA-256 mismatch')
    with zipfile.ZipFile(path) as archive:
        require(archive.namelist() == ['classes.dex', 'META-INF/MANIFEST.MF'], 'original archive layout drift')
        dex = archive.read('classes.dex')
        require(hashlib.sha256(dex).hexdigest() == ORIGINAL_DEX_SHA256, 'original client DEX SHA-256 mismatch')
        return dex, archive.read('META-INF/MANIFEST.MF')


def verify_scratch(path):
    path = Path(path).absolute()
    require(path == path.resolve() and not path.is_symlink(), 'scratch must use its real path')
    require(path.parent == Path('/private/tmp/ai-development'), 'scratch must be an owned CleanOS task root')
    require(path.is_dir() and path.stat().st_uid == os.getuid(), 'scratch owner mismatch')
    marker = path / '.cleanos-task.json'
    require(marker.is_file() and not marker.is_symlink(), 'CleanOS manifest missing')
    task = json.loads(marker.read_text())
    require(task.get('schema') == 1 and task.get('id') == path.name
            and task.get('owner') == os.getuid() and task.get('project') == str(ROOT)
            and task.get('finished') is False, 'inactive or foreign CleanOS task')
    result = subprocess.run(['tmutil', 'isexcluded', str(path)], capture_output=True, text=True, check=True)
    require('[Excluded]' in result.stdout, 'scratch backup-copy exclusion not verified')
    return path


def verify_output(path, scratch):
    path = Path(path).absolute()
    require(path == path.resolve() and not any(p.is_symlink() for p in path.parents), 'output path is a symlink')
    require(path == CANDIDATE or path.is_relative_to(scratch), 'output must be the canonical candidate or owned scratch')
    require(path.suffix == '.jar', 'candidate must be a JAR')
    require(not path.exists() and not path.with_suffix('.verification.json').exists(), 'refusing to overwrite existing output')
    return path


def run(args, env=None):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, env=env)
    if result.returncode:
        raise RuntimeError(Path(str(args[0])).name + ' failed:\n' + (result.stdout + result.stderr)[-6000:])
    return result.stdout


def uleb(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
    raise ValueError('invalid DEX uleb128')


def verify_dex(data):
    require(data[:8] == b'dex\n039\0', 'unexpected DEX version')
    require(struct.unpack_from('<I', data, 32)[0] == len(data), 'DEX file size mismatch')
    require(hashlib.sha1(data[32:]).digest() == data[12:32], 'DEX signature mismatch')
    require(zlib.adler32(data[12:]) & 0xffffffff == struct.unpack_from('<I', data, 8)[0], 'DEX checksum mismatch')
    count, offset = struct.unpack_from('<II', data, 56)
    strings = []
    for i in range(count):
        pos = struct.unpack_from('<I', data, offset + i * 4)[0]
        length, pos = uleb(data, pos)
        end = data.index(b'\0', pos)
        text = data[pos:end].replace(b'\xc0\x80', b'\0').decode('utf-8', 'surrogatepass')
        encoded = text.encode('utf-16-be', 'surrogatepass')
        require(len(encoded) // 2 == length, 'DEX string UTF-16 length mismatch')
        strings.append(encoded)
    require(all(a < b for a, b in zip(strings, strings[1:])), 'DEX StringIDs not strictly ordered')
    type_count, offset = struct.unpack_from('<II', data, 64)
    types = list(struct.unpack_from('<' + str(type_count) + 'I', data, offset))
    require(all(a < b for a, b in zip(types, types[1:])) and all(i < count for i in types), 'DEX TypeID order/index mismatch')
    for header, label in [(80, 'FieldID'), (88, 'MethodID')]:
        total, offset = struct.unpack_from('<II', data, header)
        entries = []
        for i in range(total):
            owner, kind, name = struct.unpack_from('<HHI', data, offset + i * 8)
            entries.append((owner, name, kind))
        require(all(a < b for a, b in zip(entries, entries[1:])), 'DEX ' + label + ' ordering mismatch')
    classes, offset = struct.unpack_from('<II', data, 96)
    ids = [struct.unpack_from('<I', data, offset + 32 * i)[0] for i in range(classes)]
    require(len(set(ids)) == classes and all(i < type_count for i in ids), 'DEX class index/uniqueness mismatch')
    # ClassDefs follow inheritance order, unlike the sorted identifier tables.
    positions = {value: i for i, value in enumerate(ids)}
    for i in range(classes):
        parent, interfaces = struct.unpack_from('<II', data, offset + i * 32 + 8)
        dependencies = [parent]
        if interfaces:
            size = struct.unpack_from('<I', data, interfaces)[0]
            dependencies.extend(struct.unpack_from('<' + str(size) + 'H', data, interfaces + 4))
        require(all(dep not in positions or positions[dep] < i for dep in dependencies),
                'DEX class inheritance ordering mismatch')
    return {'strings': count, 'types': type_count, 'classes': classes, 'sha256': hashlib.sha256(data).hexdigest()}


def split_methods(text):
    methods = {}
    for match in METHODS.finditer(text):
        signature = match.group().splitlines()[0].split()[-1]
        require(signature not in methods, 'duplicate method in disassembly')
        methods[signature] = match.group()
    return methods, METHODS.sub('', text)


def code_records(block, skip=()):
    """Resolve labels to kept instruction indices, including try/debug locations."""
    labels, records, instructions = {}, [], []
    depth = 0
    kept = 0
    skip = set(skip)
    for line in block.splitlines()[1:]:
        text = line.strip()
        if text.startswith(('.annotation ', '.subannotation ')):
            depth += 1
        if depth:
            if text.startswith(('.end annotation', '.end subannotation')):
                depth -= 1
            continue
        if not text or text.startswith('#'):
            continue
        if text.startswith(':'):
            labels[text] = kept
        elif text.startswith(('.packed-switch', '.sparse-switch', '.array-data')):
            raise ValueError('unexpected payload in pinned graft target')
        elif text.startswith(('.catch', '.line ', '.local ', '.end local', '.restart local', '.prologue', '.epilogue')):
            records.append(('debug/try', kept, text))
        elif not text.startswith('.'):
            index = len(instructions)
            instructions.append(text)
            if index not in skip:
                records.append(('instruction', kept, text))
                kept += 1
    def normalize(text):
        return re.sub(r':[A-Za-z0-9_]+', lambda m: '@' + str(labels[m[0]]) if m[0] in labels else m[0], text)
    return [(kind, index, normalize(text)) for kind, index, text in records], instructions, labels


def preservation(original, patched):
    before = {p.relative_to(original).as_posix(): p.read_text() for p in original.rglob('*.smali')}
    after = {p.relative_to(patched).as_posix(): p.read_text() for p in patched.rglob('*.smali')}
    require(len(before) == 153 and before.keys() <= after.keys(), 'original class set drift')
    added = sorted(after.keys() - before.keys())
    require(added and all(n == HELPER + '.smali' or n.startswith(HELPER + '$')
                         or n == PACKAGE + 'NativeProcStats.smali' for n in added), 'unexpected added class')
    for name in before:
        if name != MANAGER:
            require(before[name] == after[name], 'unrelated class changed: ' + name)
    old, outer_before = split_methods(before[MANAGER])
    new, outer_after = split_methods(after[MANAGER])
    require(old.keys() == new.keys(), 'Manager method ABI changed')
    lines = [line.strip() for line in outer_after.splitlines()]
    require(lines.count(MODE_LINE) == 1, 'private mode field drift')
    def outer(text, remove_mode=False):
        return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith('#')
                and not (remove_mode and l.strip() == MODE_LINE)]
    require(outer(outer_before) == outer(outer_after, True), 'Manager field/class/annotation ABI changed')
    changed = {key for key in old if old[key] != new[key]}
    require(changed == TARGET_COUNTS.keys(), 'changed method set differs from the exact targets')
    for signature in changed:
        require(old[signature].splitlines()[0] == new[signature].splitlines()[0], 'method declaration changed')
        require(re.findall(r'(?ms)^    \.annotation .*?^    \.end annotation', old[signature])
                == re.findall(r'(?ms)^    \.annotation .*?^    \.end annotation', new[signature]), 'method annotations changed')
        require(re.findall(r'^    \.(?:registers|param) .+$', old[signature], re.M)
                == re.findall(r'^    \.(?:registers|param) .+$', new[signature], re.M), 'method register/parameter drift')
        records, instructions, _ = code_records(old[signature])
        insertion = 0
        if signature.startswith('<init>'):
            places = [i for i, ins in enumerate(instructions) if ins.startswith('iput-object ')
                      and '->mContext:Landroid/content/Context;' in ins]
            require(len(places) == 1, 'constructor context store drift')
            insertion = places[0] + 1
        count = TARGET_COUNTS[signature]
        _, candidate_instructions, label_indices = code_records(new[signature])
        guard = candidate_instructions[insertion:insertion + count]
        if signature == 'stopLongRunningTest(Ljava/lang/String;)V':
            require(guard[0].startswith('move-object/from16 v0, p0')
                    and guard[1] == 'iget-boolean v0, v0, L' + PACKAGE + 'ServiceabilityManager;->mTaskManagerCompat:Z'
                    and guard[3] == 'return-void', 'local cancellation guard drift')
        else:
            require(any('L' + HELPER + ';->' in ins for ins in guard), 'helper call missing')
        branch = next(ins for ins in guard if ins.startswith('if-eqz '))
        require(label_indices[branch.split()[-1]] == insertion + count, 'guard does not continue at original body')
        candidate_records, _, _ = code_records(new[signature], range(insertion, insertion + count))
        require(records == candidate_records, 'original instructions/branches/try/debug changed: ' + signature)
    return {'original_classes': len(before), 'unchanged_classes': len(before) - 1,
            'helper_classes': added, 'manager_methods': len(old), 'changed_methods': sorted(changed),
            'untouched_manager_methods': len(old) - len(changed),
            'public_manager_methods': sum(bool({'public', 'protected'} & set(v.splitlines()[0].split()))
                                          for v in old.values()),
            'public_manager_fields': sum(l.strip().startswith(('.field public ', '.field protected '))
                                         for l in outer_before.splitlines()),
            'original_target_instructions_branches_try_debug_preserved': True,
            'original_fields_dtos_annotations_parameters_preserved': True,
            'compile_only_classes_in_candidate': False}


def zip_bytes(path, dex, manifest):
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in [('classes.dex', dex), ('META-INF/MANIFEST.MF', manifest)]:
            info = zipfile.ZipInfo(name, (2009, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compresslevel=9)


def build(input_jar, scratch, output=CANDIDATE):
    original, manifest = guard_original(input_jar)
    scratch = verify_scratch(scratch)
    output = verify_output(output, scratch)
    require(JADX.is_file() and digest(JADX) == JADX_SHA256, 'installed JADX/dexlib2 drift')
    require(all(p.is_file() for p in [JAVA / 'bin/java', JAVA / 'bin/javac', ANDROID, D8]), 'installed build input missing')
    with tempfile.TemporaryDirectory(prefix='taskmanager-build-', dir=scratch) as temp:
        work = Path(temp)
        options = '-Xmx768m -Djava.io.tmpdir=' + str(work)
        env = dict(os.environ, JAVA_HOME=str(JAVA), JAVA_OPTS=options,
                   JAVA_TOOL_OPTIONS=options, TMPDIR=str(work))
        api, classes, tools, dex_dir = [work / name for name in ['api', 'metrics', 'tools', 'helper-dex']]
        for directory in [api, classes, tools, dex_dir]:
            directory.mkdir()
        api_source = COMPONENT / ('compile-api/' + PACKAGE + 'ServiceabilityManager.java')
        helper = COMPONENT / ('src/' + PACKAGE + 'TaskManagerCompat.java')
        native_stats = COMPONENT / ('src/' + PACKAGE + 'NativeProcStats.java')
        native_checks = COMPONENT / 'native/NativeProcStatsSelfTest.java'
        checks = COMPONENT / ('tests/' + PACKAGE + 'MetricsSelfTest.java')
        graft = COMPONENT / 'build-support/GraftClient.java'
        protocol_sources = [COMPONENT / 'native' / name for name in ('metrics.c', 'metrics.h', 'host_tests.c')]
        protocol_test = work / 'metrics-host-tests'
        protocol_fixtures = work / 'protocol-fixtures'
        protocol_fixtures.mkdir()
        golden = work / 'golden-response.bin'
        run(['cc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
             protocol_sources[0], protocol_sources[2], '-o', protocol_test], env)
        protocol_checks = run([protocol_test, protocol_fixtures, golden], env)
        javac = JAVA / 'bin/javac'
        run([javac, '--release', '8', '-d', api, api_source], env)
        classpath = os.pathsep.join(map(str, [ANDROID, api]))
        run([javac, '--release', '8', '-cp', classpath, '-d', classes, helper, native_stats, checks, native_checks], env)
        host_checks = run([JAVA / 'bin/java', '-ea', '-cp', os.pathsep.join(map(str, [classes, api, ANDROID])),
                           'vendor.google.libraries.desktop.serviceability.MetricsSelfTest', work / 'fixtures'], env)
        host_checks += protocol_checks + run([JAVA / 'bin/java', '-ea', '-cp', os.pathsep.join(map(str, [classes, api, ANDROID])),
                            'vendor.google.libraries.desktop.serviceability.NativeProcStatsSelfTest', golden], env)
        helper_classes = sorted((classes / PACKAGE).glob('TaskManagerCompat*.class'))
        helper_classes.append(classes / PACKAGE / 'NativeProcStats.class')
        run([D8, '--release', '--min-api', '28', '--lib', ANDROID, '--classpath', api,
             '--output', dex_dir, *helper_classes], env)
        run([javac, '--release', '8', '-cp', JADX, '-d', tools, graft], env)
        (work / 'original.dex').write_bytes(original)
        transform = json.loads(run([JAVA / 'bin/java', '-Xmx768m', '-cp', os.pathsep.join(map(str, [tools, JADX])),
                                   'GraftClient', work / 'original.dex', dex_dir / 'classes.dex', work / 'patched.dex'], env))
        patched = (work / 'patched.dex').read_bytes()
        structure = verify_dex(patched)
        for name in ['original', 'patched']:
            run([JAVA / 'bin/java', '-Xmx768m', '-cp', JADX, 'com.android.tools.smali.baksmali.Main',
                 'd', work / (name + '.dex'), '-o', work / (name + '-smali')], env)
        preserved = preservation(work / 'original-smali', work / 'patched-smali')
        jar = work / 'candidate.jar'
        zip_bytes(jar, patched, manifest)
        receipt = {'original_jar_sha256': ORIGINAL_SHA256, 'original_dex_sha256': ORIGINAL_DEX_SHA256,
                   'candidate_sha256': digest(jar), 'candidate_bytes': jar.stat().st_size,
                   'dex': structure, 'transform': transform, 'preservation': preserved,
                   'host_checks': host_checks.strip(), 'sources': {str(p.relative_to(ROOT)): digest(p)
                   for p in [api_source, helper, native_stats, checks, native_checks, graft, Path(__file__), *protocol_sources]},
                   'tool_jar': str(JADX), 'tool_jar_sha256': JADX_SHA256,
                   'device_commands_run': False, 'apk_modified': False, 'device_installed': False,
                   'runtime_verified': False, 'fsv_meta_updated': False,
                   'limitations': ['Parent must verify actual Task Manager proc/sysfs/PSS authority and class loading.',
                                   'Parent must handle matching fsv_meta, dexpreopt and image integrity before integration.',
                                   'PID generation is checked around PSS; the unchanged CPU DTO does not expose starttime to its caller.']}
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('xb') as stream:
            stream.write(jar.read_bytes())
        output.chmod(0o644)
        report = output.with_suffix('.verification.json')
        with report.open('x') as stream:
            stream.write(json.dumps(receipt, indent=2) + '\n')
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path, help='exact original shared-client JAR')
    parser.add_argument('--scratch', required=True, type=Path, help='real active owned CleanOS task root')
    parser.add_argument('--output', type=Path, default=CANDIDATE)
    args = parser.parse_args()
    receipt = build(args.input, args.scratch, args.output)
    print(json.dumps({'candidate': str(args.output), 'sha256': receipt['candidate_sha256'],
                      'bytes': receipt['candidate_bytes'], 'checks': receipt['host_checks'],
                      'preservation': receipt['preservation']}, indent=2))


if __name__ == '__main__':
    main()
