#!/usr/bin/env python3
"""Extract update_engine's private Native B DT_NEEDED closure; no device/image writes."""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
from pathlib import Path

from android_disk import require
from ext4_source import command, regular_file
from native_install.payload import sha256

OBJDUMP = Path('/Library/Developer/CommandLineTools/usr/bin/llvm-objdump')
LIBRARY_PARTITION = 'system_ext'
LIBRARY_IMAGE_DIRECTORY = '/lib64/googlebook-update-engine'
DESTINATION = '/' + LIBRARY_PARTITION + LIBRARY_IMAGE_DIRECTORY
SOURCE_DESTINATIONS = {'/system/lib64/googlebook-update-engine', DESTINATION}
ENGINE_SHA = '11913b4ccc78041e55b9c79c1adf14d3be6503733a19ccebda2d36b96db9ade8'
MISSING = '_ZN7android6fs_mgr15MetadataBuilder26GrowBlockDevicesToLiveSizeERKNS0_16IPartitionOpenerE'
BIONIC = {'libc.so', 'libm.so', 'libdl.so', 'libdl_android.so'}
SOURCE_IMAGE_SHAS = {
    'system': 'ac7b37a4ea22b81e71f3a1d2081a2ddbcdf07982b34b815aa9e918210092b29a',
    'system_ext': 'a77e916d2c068016884a0b02d518bb507f8123e81ae141643de85bf47a398252',
    'product': '770d6584f03a75721c89aa8e76fc94652df302cd098b721d3bf13e260ba1187c',
}
SOURCE_RC_SHA = '6ea0df87a3efd50c1b83d9a2025ca4c2892290fd71eb70336946443365ed1c48'
RUNTIME_PROVIDERS = {
    **{n: '/apex/com.android.runtime/lib64/bionic/' + n for n in BIONIC},
    'libstatssocket.so': '/apex/com.android.os.statsd/lib64/libstatssocket.so',
    'libcom.android.tethering.connectivity_native.so': '/apex/com.android.tethering/lib64/libcom.android.tethering.connectivity_native.so',
}
ABI_KEYS = ('elf_type', 'needed', 'soname', 'exports', 'imports', 'weak_imports', 'import_versions')
RUNPATH_STATUS = 'PRIVATE_NATIVE_RUNPATH_BUNDLE_RUNTIME_PENDING'


def elf(path, objdump=OBJDUMP):
    with Path(path).open('rb') as stream:
        header = stream.read(64)
    require(len(header) == 64 and header[:6] == b'\x7fELF\x02\x01'
            and struct.unpack_from('<H', header, 18)[0] == 183, 'expected little-endian AArch64 ELF64')
    p = subprocess.run([str(objdump), '--private-headers', '--dynamic-syms', str(path)], capture_output=True, text=True)
    require(p.returncode == 0, 'LLVM ELF inspection failed')
    needed = re.findall(r'^\s*NEEDED\s+(\S+)\s*$', p.stdout, re.M)
    soname = re.findall(r'^\s*SONAME\s+(\S+)\s*$', p.stdout, re.M)
    runpath = re.findall(r'^\s*RUNPATH\s+(\S+)\s*$', p.stdout, re.M)
    rpath = re.findall(r'^\s*RPATH\s+(\S+)\s*$', p.stdout, re.M)
    require(len(soname) <= 1 and len(needed) == len(set(needed))
            and all(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.so(?:\.[A-Za-z0-9_.+-]+)?', n) for n in needed), 'unsafe/duplicate ELF dependency')
    exports, imports, weak, versioned = set(), set(), set(), {}
    for line in p.stdout.split('DYNAMIC SYMBOL TABLE:', 1)[-1].splitlines():
        columns = line.split()
        if len(columns) < 4 or re.fullmatch('[0-9a-fA-F]+', columns[0]) is None:
            continue
        name = columns[-1].split('@', 1)[0]
        if name in ('*ABS*', '*UND*') or name.startswith('.'):
            continue
        if '*UND*' in columns:
            (weak if 'w' in columns else imports).add(name)
            versions = [c.strip('()') for c in columns[1:-1] if c.startswith('(') and c.endswith(')')]
            if versions:
                versioned[name] = versions[0]
        elif '.hidden' not in columns and ('g' in columns or 'w' in columns or 'u' in columns):
            exports.add(name)
    return dict(elf_type=struct.unpack_from('<H', header, 16)[0],
                needed=needed, soname=soname[0] if soname else None, exports=sorted(exports),
                imports=sorted(imports), weak_imports=sorted(weak), import_versions=versioned,
                runpath=runpath, rpath=rpath)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def preserved_elf(path):
    """Fingerprint code/data/ABI while allowing patchelf's loader-table relocation.

    patchelf reorders section headers and updates st_shndx, so dynamic symbols
    are compared by section name rather than by their changed numeric indices.
    """
    data = Path(path).read_bytes()
    require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 for preservation check')
    h = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    require(h[10] == 64 and 0 < h[11] < 0xff00 and h[12] < h[11]
            and h[5] + h[10] * h[11] <= len(data), 'unsupported ELF section table')
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, h[5] + i * 64) for i in range(h[11])]
    def section_bytes(s):
        if s[1] == 8:  # SHT_NOBITS has no file payload.
            return b''
        require(s[4] + s[5] <= len(data), 'ELF section outside file')
        return data[s[4]:s[4] + s[5]]
    names = section_bytes(headers[h[12]])
    def string(strings, at):
        end = strings.find(b'\0', at)
        require(0 <= at < len(strings) and end >= at, 'invalid ELF string offset')
        return strings[at:end].decode()
    section_names = [string(names, s[0]) for s in headers]
    require(len(set(section_names)) == len(section_names), 'duplicate ELF section names')
    sections, symbols, dynamic = {}, [], []
    for name, s in zip(section_names, headers):
        if not s[2] & 2:  # Only SHF_ALLOC sections contribute to the loaded image.
            continue
        payload = section_bytes(s)
        if s[1] == 11:  # SHT_DYNSYM: retain every binding, visibility, value and size.
            require(s[9] == 24 and s[5] % 24 == 0 and s[6] < len(headers), 'invalid dynamic symbol table')
            strings = section_bytes(headers[s[6]])
            for at in range(0, len(payload), 24):
                n, info, other, index, value, size = struct.unpack_from('<IBBHQQ', payload, at)
                section = section_names[index] if 0 < index < len(headers) else index
                symbols.append((string(strings, n), info, other, section, value, size))
            continue
        if s[1] == 6:  # DT_STRTAB/SYMTAB/STRSZ and search-path entries may change.
            require(s[5] % 16 == 0, 'invalid ELF dynamic table')
            for at in range(0, len(payload), 16):
                tag, value = struct.unpack_from('<qQ', payload, at)
                if tag == 0:
                    break
                if tag not in (1, 5, 6, 10, 14, 15, 29):
                    dynamic.append((tag, value))
            continue
        if name == '.dynstr':
            continue
        record = {'type': s[1], 'flags': s[2], 'size': s[5], 'sha256': hashlib.sha256(payload).hexdigest()}
        # The interpreter and notes may move with the expanded program headers.
        if name != '.interp' and s[1] != 7:
            record['address'] = s[3]
        sections[name] = record
    require(h[8] == 56 or h[9] == 0, 'unsupported ELF program headers')
    require(h[4] + h[8] * h[9] <= len(data), 'ELF program table outside file')
    stack = []
    for i in range(h[9]):
        p = struct.unpack_from('<IIQQQQQQ', data, h[4] + i * h[8])
        require(p[0] != 1 or p[1] & 3 != 3, 'writable executable ELF load segment')
        if p[0] == 0x6474e551:
            stack.append((p[1], p[7]))
    return {'header': [data[6:16].hex(), *h[:4], h[6]], 'sections': sections,
            'symbols': symbols, 'dynamic': sorted(dynamic), 'stack': stack}


def runpath_file(source, destination, patchelf, objdump=OBJDUMP):
    """Transform one copy, rejecting code/data/symbol/ABI changes."""
    before, preserved = elf(source, objdump), preserved_elf(source)
    source_sha = sha256(source)
    shutil.copyfile(source, destination)
    subprocess.run([str(patchelf), '--set-rpath', DESTINATION, str(destination)], check=True,
                   capture_output=True, text=True)
    after = elf(destination, objdump)
    require(after['runpath'] == [DESTINATION] and not after['rpath'], 'exact absolute DT_RUNPATH required')
    require({k: before[k] for k in ABI_KEYS} == {k: after[k] for k in ABI_KEYS}, 'RUNPATH changed ELF ABI')
    require(preserved == preserved_elf(destination), 'RUNPATH changed executable payload or dynamic ABI')
    require(sha256(source) == source_sha, 'RUNPATH modified source input')
    return after, {'source_sha256': source_sha, 'output_sha256': sha256(destination),
                   'preserved_sha256': _digest(preserved),
                   'abi_sha256': _digest({k: before[k] for k in ABI_KEYS})}


def closure(root, fetch, external):
    """fetch returns an ELF record for a Native platform DSO; external is an explicit runtime map."""
    pending = list(root['needed']); result = {}; excluded = {}
    while pending:
        name = pending.pop(0)
        if name in result or name in excluded:
            continue
        item = fetch(name)
        if item is None:
            require(name in external, 'unresolved non-runtime dependency: ' + name)
            excluded[name] = external[name]
            continue
        require(name not in BIONIC, 'Bionic must remain supplied by the live runtime')
        require(item['elf']['soname'] in (None, name), 'SONAME differs from dependency: ' + name)
        result[name] = item
        pending.extend(item['elf']['needed'])
    return result, excluded


def symbol_boundary(root, libraries):
    require('liblp.so' in libraries and MISSING in libraries['liblp.so']['elf']['exports'],
            'Native liblp does not export observed missing method')
    exports = set(root['exports']) | {s for item in libraries.values() for s in item['elf']['exports']}
    unresolved = sorted({s for item in [root, *[v['elf'] for v in libraries.values()]] for s in item['imports']} - exports)
    require(not any(s.startswith('_Z') for s in unresolved),
            'unresolved C++ ABI symbols remain: ' + ', '.join(s for s in unresolved if s.startswith('_Z'))[:500])
    for item in [root, *[v['elf'] for v in libraries.values()]]:
        for name in set(item['imports']) & set(unresolved):
            version = item['import_versions'].get(name, '')
            require(version == 'LIBC' or version.startswith('LIBC_')
                    or version in ('LIBDL_ANDROID', 'LIBSTATSSOCKET', 'LIBCONNECTIVITY_NATIVE'),
                    'unresolved non-runtime strong symbol: ' + name)
    return unresolved


def platform_index(images):
    index = {}
    for partition, image in images.items():
        directory = '/system/lib64' if partition == 'system' else '/lib64'
        for line in command(image, 'ls -p ' + directory).decode().splitlines():
            parts = line.split('/')
            if len(parts) >= 7 and parts[1].isdigit() and re.fullmatch('[0-7]+', parts[2]):
                name = parts[5]
                if stat.S_ISREG(int(parts[2], 8)) and '.so' in name:
                    index.setdefault(name, []).append((partition, directory + '/' + name))
    return index


def _pinned_path(pin, expected=None, location=None):
    require(isinstance(pin, dict) and isinstance(pin.get('path'), (str, Path))
            and isinstance(pin.get('sha256'), str)
            and re.fullmatch('[0-9a-f]{64}', pin['sha256']), 'invalid file pin')
    path = Path(pin['path'])
    require(path.is_absolute() and path == path.resolve() and path.is_file()
            and not path.is_symlink(), 'expected canonical regular file')
    require(location is None or path == location, 'bundle file escaped expected location')
    require(expected is None or pin['sha256'] == expected, 'unexpected source pin')
    require(sha256(path) == pin['sha256'], 'file pin mismatch: ' + path.name)
    return path


def _overlay_metadata(meta, mode, label, gid=0):
    require(isinstance(meta, dict) and set(meta) == {'mode', 'uid', 'gid', 'mtime', 'mtime_nsec', 'xattrs'},
            'invalid Android metadata shape')
    require(all(type(meta[k]) is int for k in ('mode', 'uid', 'gid', 'mtime', 'mtime_nsec'))
            and (meta['mode'], meta['uid'], meta['gid'], meta['mtime'], meta['mtime_nsec'])
            == (mode, 0, gid, 1230768000, 0), 'invalid Android metadata mode/owner/time')
    require(isinstance(meta['xattrs'], dict) and set(meta['xattrs']) == {'security.selinux'}
            and isinstance(meta['xattrs']['security.selinux'], str), 'invalid library metadata xattrs')
    value = base64.b64decode(meta['xattrs']['security.selinux'], validate=True)
    require(value == label, 'invalid Android metadata SELinux label')
    return dict(meta, xattrs={'security.selinux': value})


def _derived_elf(record, original, path):
    receipt = record['transformation']
    require(set(receipt) == {'source_sha256', 'output_sha256', 'preserved_sha256', 'abi_sha256'}
            and receipt['source_sha256'] == original['sha256']
            and receipt['output_sha256'] == record['sha256'], 'RUNPATH transformation source/output mismatch')
    info = elf(path)
    require(info['runpath'] == [DESTINATION] and not info['rpath'], 'exact absolute DT_RUNPATH required')
    abi = {k: info[k] for k in ABI_KEYS}
    # The pinned original manifest predates the explicit ET_DYN field.
    original_abi = dict(original['elf'], elf_type=original['elf'].get('elf_type', 3))
    require(abi == {k: original_abi[k] for k in ABI_KEYS}
            and _digest(abi) == receipt['abi_sha256'], 'derived ELF ABI differs from Native source')
    require(_digest(preserved_elf(path)) == receipt['preserved_sha256'], 'derived ELF preservation receipt mismatch')
    return info


def integration_inputs(manifest_pin, partition=None):
    """Read-only pinned input -> (45 erofs_overlay additions, derived RC bytes).

    The separately pinned manifest engine must supply the recipe's update_engine.
    Without partition, paths are absolute runtime paths (for final image checks).
    With partition, only that image's root-relative additions are returned.
    Engine/RC remain separate system inputs; all 44 private DSOs go in system_ext.
    """
    require(partition in (None, 'system', 'system_ext', 'product'), 'unsupported image partition')
    additions, rc = _bundle_inputs(manifest_pin)
    if partition is None:
        return additions, rc
    if partition != LIBRARY_PARTITION:
        return {}, rc
    prefix = '/' + LIBRARY_PARTITION
    require(all(p.startswith(prefix + '/') for p in additions), 'bundle additions cross image partition')
    return {p[len(prefix):]: item for p, item in additions.items()}, rc


def _bundle_inputs(manifest_pin, source_only=False):
    path = _pinned_path(manifest_pin)
    blob = path.read_bytes()
    require(hashlib.sha256(blob).hexdigest() == manifest_pin['sha256'], 'manifest changed during read')
    data = json.loads(blob)
    derived = not source_only
    require((data.get('schema'), data.get('status')) == (
                (1, 'PRIVATE_NATIVE_DEPENDENCY_CLOSURE_RUNTIME_PENDING') if source_only else (2, RUNPATH_STATUS)),
            'unexpected engine bundle schema/status')
    source_destination = data['destination']
    require((source_destination in SOURCE_DESTINATIONS if source_only else source_destination == DESTINATION)
            and (source_only or data['service_option'] is None),
            'private loader destination/option mismatch')
    original = data
    if derived:
        provenance = _pinned_path(data['source_manifest'], location=path.parent / 'source-manifest.json')
        original = json.loads(provenance.read_bytes())
        require(original.get('schema') == 1
                and original.get('status') == 'PRIVATE_NATIVE_DEPENDENCY_CLOSURE_RUNTIME_PENDING'
                and original['destination'] in SOURCE_DESTINATIONS
                and original['source_images'] == data['source_images']
                and set(original['libraries']) == set(data['libraries']), 'invalid original bundle provenance')
        transform = data['transformation']
        require(transform['type'] == 'DT_RUNPATH' and transform['value'] == DESTINATION
                and transform['arguments'] == ['--set-rpath', DESTINATION]
                and transform['at_secure_required'] == 1, 'invalid RUNPATH transformation contract')
        require(data['library_partition'] == LIBRARY_PARTITION
                and data['library_image_directory'] == LIBRARY_IMAGE_DIRECTORY,
                'private library image partition mismatch')
    require(set(data['source_images']) == set(SOURCE_IMAGE_SHAS), 'incomplete Native source pins')
    for name, expected in SOURCE_IMAGE_SHAS.items():
        _pinned_path(data['source_images'][name], expected)
    source_engine = _pinned_path(original['engine'], ENGINE_SHA)
    engine = (_pinned_path(data['engine'], location=path.parent / 'update_engine') if derived else source_engine)
    root = _derived_elf(data['engine'], original['engine'], engine) if derived else elf(engine)
    if derived:
        require(data['engine']['destination'] == '/system/bin/update_engine', 'derived engine destination mismatch')
        captured = _pinned_path(data['source_capture_metadata'], location=source_engine.parent / 'native-engine-inputs.json')
        source_meta = json.loads(captured.read_bytes())['files']['update_engine']['metadata']
        require(data['engine']['metadata'] == source_meta, 'derived engine metadata differs from Native source')
        _overlay_metadata(source_meta, stat.S_IFREG | 0o755, b'u:object_r:update_engine_exec:s0\0', gid=2000)
    require(data['excluded_runtime'] == RUNTIME_PROVIDERS, 'runtime provider contract mismatch')
    directory = _overlay_metadata(data['directory_metadata'], stat.S_IFDIR | 0o755,
                                  b'u:object_r:system_lib_file:s0\0')
    additions = {source_destination: {'data': b'', 'metadata': directory}}
    require(isinstance(data['libraries'], dict) and len(data['libraries']) == 44, 'exact 44-library bundle required')
    actual = {}
    for name, record in data['libraries'].items():
        require(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@+-]*\.so(?:\.[A-Za-z0-9_.+-]+)?', name)
                and '..' not in name and name not in RUNTIME_PROVIDERS, 'unsafe/private SONAME')
        require(record['destination'] == source_destination + '/' + name
                and record['source_partition'] == 'system'
                and record['source_path'] == '/system/lib64/' + name, 'library destination/source mismatch')
        # Informational duplicates do not change the selected system-first provider.
        alternatives = record.get('alternate_native_locations', [])
        require(isinstance(alternatives, list) and all(
            isinstance(a, dict) and set(a) == {'partition', 'path'}
            and a['partition'] in ('system_ext', 'product') and a['path'] == '/lib64/' + name
            for a in alternatives), 'invalid alternate Native source location')
        require(len({(a['partition'], a['path']) for a in alternatives}) == len(alternatives),
                'duplicate alternate Native source location')
        source = _pinned_path(record, location=path.parent / 'lib64' / name)
        content = source.read_bytes()
        require(type(record['bytes']) is int and len(content) == record['bytes']
                and hashlib.sha256(content).hexdigest() == record['sha256'], 'library size/hash mismatch')
        meta = _overlay_metadata(record['metadata'], stat.S_IFREG | 0o644,
                                 b'u:object_r:system_lib_file:s0\0')
        if derived:
            old = original['libraries'][name]
            require(all(record[k] == old[k] for k in ('metadata', 'source_partition', 'source_path'))
                    and old['destination'] == original['destination'] + '/' + name,
                    'derived library source metadata mismatch')
            info = _derived_elf(record, old, source)
        else:
            info = elf(source)
        require(info['elf_type'] == 3 and info['soname'] == name, 'library ELF type/SONAME mismatch')
        actual[name] = {'elf': info}
        additions[record['destination']] = {'data': content, 'metadata': meta}
    resolved, excluded = closure(root, actual.get, RUNTIME_PROVIDERS)
    require(set(resolved) == set(actual) and excluded == RUNTIME_PROVIDERS, 'private dependency graph differs from bundle')
    symbol_boundary(root, resolved)
    require(sum(len(v['data']) for v in additions.values()) == data['total_library_bytes'], 'bundle byte count mismatch')
    original_rc = source_engine.parent / 'update_engine.rc'
    _pinned_path({'path': str(original_rc), 'sha256': SOURCE_RC_SHA}, SOURCE_RC_SHA)
    if source_only:
        # Historical RC options in the source manifest are never launch inputs.
        return additions, original_rc.read_bytes()
    record = data['service_rc']
    require(record['destination'] == '/system/etc/init/update_engine.rc'
            and record['source_sha256'] == SOURCE_RC_SHA, 'derived RC source/destination mismatch')
    _overlay_metadata(record['metadata'], stat.S_IFREG | 0o644, b'u:object_r:system_file:s0\0')
    private = _pinned_path(record, location=path.parent / 'update_engine.rc')
    rc = private.read_bytes()
    require(record['sha256'] == SOURCE_RC_SHA and rc == original_rc.read_bytes(),
            'derived RC differs from unchanged Native service contract')
    return additions, rc


def _owned_output(output):
    output = Path(output).resolve()
    require(not output.exists() and not output.is_symlink(), 'output must be new')
    # Scope output to a real owned CleanOS task; do not allow a symlink parent escape.
    roots = [p for p in (output.parent, *output.parents) if (p / '.cleanos-task.json').is_file()]
    require(roots, 'output must be inside owned CleanOS scratch')
    owner = json.loads((roots[0] / '.cleanos-task.json').read_text())
    require(owner['owner'] == os.getuid() and not owner['finished'], 'active owned CleanOS task required')
    return output


def build_runpath(manifest_pin, output, patchelf=None, objdump=OBJDUMP):
    """Derive 45 ELF copies; retain the exact original manifest as provenance."""
    path = _pinned_path(manifest_pin)
    source_blob = path.read_bytes()
    source = json.loads(source_blob)
    require(source.get('schema') == 1, 'RUNPATH producer requires the original Native bundle')
    _bundle_inputs(manifest_pin, source_only=True)
    output = _owned_output(output)
    tool_name = patchelf or shutil.which('patchelf')
    require(tool_name is not None, 'patchelf is required; parent owns installation')
    tool = Path(tool_name).resolve(strict=True)
    require(tool.is_file() and os.access(tool, os.X_OK), 'patchelf must be an installed executable')
    tool_sha = sha256(tool)
    version = subprocess.check_output([str(tool), '--version'], text=True).strip()
    require(version.startswith('patchelf '), 'unexpected RUNPATH producer tool')
    source_engine = Path(source['engine']['path'])
    capture_metadata = source_engine.parent / 'native-engine-inputs.json'
    captured = json.loads(capture_metadata.read_bytes())
    engine_meta = captured['files']['update_engine']['metadata']
    _overlay_metadata(engine_meta, stat.S_IFREG | 0o755, b'u:object_r:update_engine_exec:s0\0', gid=2000)
    output.mkdir()
    try:
        (output / 'lib64').mkdir()
        (output / 'source-manifest.json').write_bytes(source_blob)
        manifest = dict(source)
        manifest.update(schema=2, status=RUNPATH_STATUS, service_option=None, destination=DESTINATION,
                        library_partition=LIBRARY_PARTITION, library_image_directory=LIBRARY_IMAGE_DIRECTORY,
                        source_manifest={'path': str(output / 'source-manifest.json'), 'sha256': manifest_pin['sha256']},
                        source_capture_metadata={'path': str(capture_metadata), 'sha256': sha256(capture_metadata)},
                        transformation={'type': 'DT_RUNPATH', 'value': DESTINATION, 'arguments': ['--set-rpath', DESTINATION],
                                        'at_secure_required': 1, 'tool': {'path': str(tool), 'sha256': tool_sha, 'version': version}},
                        libraries={}, runtime_validated=False, donor_global_libraries_modified=False,
                        integration='Use the derived engine pin, unchanged Native RC pin, and integration_inputs additions. '
                                    'No LD_LIBRARY_PATH or noatsecure rule. Actual init service must run with AT_SECURE=1.',
                        namespace_static_contract='DT_RUNPATH remains subject to actual service namespace accessibility.')
        for name, old in [('update_engine', source['engine']), *source['libraries'].items()]:
            destination = output / name if name == 'update_engine' else output / 'lib64' / name
            info, receipt = runpath_file(Path(old['path']), destination, tool, objdump)
            destination.chmod(0o755 if name == 'update_engine' else 0o644)
            record = dict(old, path=str(destination), sha256=sha256(destination), bytes=destination.stat().st_size,
                          elf=info, transformation=receipt)
            if name == 'update_engine':
                record.update(destination='/system/bin/update_engine', metadata=engine_meta)
                manifest['engine'] = record
            else:
                record['destination'] = DESTINATION + '/' + name
                manifest['libraries'][name] = record
        original_rc = source_engine.parent / 'update_engine.rc'
        require(sha256(original_rc) == SOURCE_RC_SHA, 'captured service pin mismatch')
        rc = output / 'update_engine.rc'
        rc.write_bytes(original_rc.read_bytes())
        manifest['service_rc'] = dict(source['service_rc'], path=str(rc), sha256=SOURCE_RC_SHA)
        manifest['total_library_bytes'] = sum(x['bytes'] for x in manifest['libraries'].values())
        manifest['source_files_sha256'] = {__file__: sha256(Path(__file__))}
        root = manifest['engine']['elf']
        resolved, excluded = closure(root, manifest['libraries'].get, RUNTIME_PROVIDERS)
        require(set(resolved) == set(manifest['libraries']) and excluded == RUNTIME_PROVIDERS,
                'derived dependency graph changed')
        symbol_boundary(root, resolved)
        require(sha256(tool) == tool_sha and sha256(path) == manifest_pin['sha256'], 'producer input changed')
        target = output / 'manifest.json'
        target.write_text(json.dumps(manifest, indent=2) + '\n')
        integration_inputs({'path': str(target), 'sha256': sha256(target)})
        return manifest
    except BaseException:
        shutil.rmtree(output)
        raise


def _build_source(capture, output, objdump=OBJDUMP):
    capture, output = Path(capture).resolve(), _owned_output(output)
    pins = json.loads((capture / 'native-os-inputs.json').read_text())
    images = {}
    for name in ('system', 'system_ext', 'product'):
        record = pins[name + '_b']; p = Path(record['path'])
        require(p.is_absolute() and p.is_file() and not p.is_symlink() and sha256(p) == record['sha256'], 'Native source image pin mismatch')
        images[name] = p
    engine = capture / 'update_engine'
    require(sha256(engine) == ENGINE_SHA, 'wrong Native engine')
    source = json.loads((capture / 'native-engine-inputs.json').read_text())
    runtime = {}
    for line in (capture / 'update-engine-linker-check.txt').read_text().splitlines():
        m = re.match(r'\s*(\S+)\s+=>\s+(/apex/\S+)\s+\(', line)
        if m:
            runtime[m[1]] = m[2]
    require(BIONIC <= runtime.keys(), 'captured Bionic/APEX provider map missing')
    index = platform_index(images)
    output.mkdir(); libdir = output / 'lib64'; libdir.mkdir(); work = output / '.work'; work.mkdir()
    try:
        def fetch(name):
            if name in BIONIC or name not in index:
                return None
            # Explicit native default search order: system, system_ext, product.
            partition, path = index[name][0]
            item = regular_file(images[partition], path, work)
            destination = libdir / name; destination.write_bytes(item['data'])
            data = elf(destination, objdump)
            meta = dict(item['metadata'], mtime_nsec=0)
            meta['xattrs'] = {k:base64.b64encode(v).decode() for k,v in meta['xattrs'].items()}
            return dict(path=str(destination), destination=DESTINATION + '/' + name,
                        sha256=sha256(destination), bytes=destination.stat().st_size,
                        source_partition=partition, source_path=path, metadata=meta, elf=data,
                        alternate_native_locations=[dict(partition=p,path=q) for p,q in index[name][1:]])
        root = elf(engine, objdump)
        libraries, excluded = closure(root, fetch, runtime)
        unresolved = symbol_boundary(root, libraries)
        original_rc = capture / 'update_engine.rc'
        require(sha256(original_rc) == source['files']['update_engine.rc']['sha256'], 'captured service hash mismatch')
        private_rc = output / 'update_engine.rc'
        private_rc.write_bytes(original_rc.read_bytes())
        manifest = dict(schema=1, status='PRIVATE_NATIVE_DEPENDENCY_CLOSURE_RUNTIME_PENDING', engine=dict(path=str(engine),sha256=ENGINE_SHA,elf=root),
                        source_images={n:dict(path=str(p),sha256=pins[n+'_b']['sha256']) for n,p in images.items()},
                        libraries=libraries, excluded_runtime=excluded, destination=DESTINATION, service_option=None,
                        service_rc=dict(path=str(private_rc), destination='/system/etc/init/update_engine.rc',
                                        sha256=sha256(private_rc), source_sha256=sha256(original_rc),
                                        metadata=source['files']['update_engine.rc']['metadata']),
                        directory_metadata=dict(mode=stat.S_IFDIR|0o755,uid=0,gid=0,mtime=1230768000,mtime_nsec=0,
                                                xattrs={'security.selinux':base64.b64encode(b'u:object_r:system_lib_file:s0\0').decode()}),
                        total_library_bytes=sum(x['bytes'] for x in libraries.values()), missing_method_provider='liblp.so',
                        unresolved_strong_runtime_boundary_symbols=unresolved, unresolved_private_cpp_symbols=[],
                        runtime_validated=False, donor_global_libraries_modified=False,
                        integration='Source-only extraction for the RUNPATH producer; not an assembler input.',
                        limitations=['APEX/Bionic providers stay on the live OS; their actual symbol/version compatibility and namespace behavior require the parent runtime check.',
                                     'Only DT_NEEDED is enumerated; runtime dlopen dependencies are not claimed complete.'])
        (output / 'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        return manifest
    except BaseException:
        shutil.rmtree(output)
        raise
    finally:
        if work.exists():
            work.rmdir()


def build(capture, output, objdump=OBJDUMP, patchelf=None):
    """Reproducible capture-to-RUNPATH path, retaining only the final bundle."""
    output = _owned_output(output)
    source_output = output.parent / ('.' + output.name + '-source')
    require(not source_output.exists(), 'temporary source output must be new')
    try:
        _build_source(capture, source_output, objdump)
        manifest = source_output / 'manifest.json'
        return build_runpath({'path': str(manifest), 'sha256': sha256(manifest)}, output, patchelf, objdump)
    finally:
        if source_output.exists():
            shutil.rmtree(source_output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--capture-root',type=Path)
    source.add_argument('--runpath-manifest',type=Path)
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--patchelf',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = (build_runpath({'path': str(args.runpath_manifest), 'sha256': args.manifest_sha256},
                            args.output, args.patchelf) if args.runpath_manifest else build(args.capture_root, args.output, patchelf=args.patchelf))
    print(json.dumps(dict(libraries=len(result['libraries']), bytes=result['total_library_bytes'],
                          manifest={'path': str(args.output.resolve()/'manifest.json'),
                                    'sha256': sha256(args.output/'manifest.json')},
                          engine={k: result['engine'][k] for k in ('path', 'sha256')},
                          service_rc={k: result['service_rc'][k] for k in ('path', 'sha256')})))


if __name__ == '__main__':
    main()
