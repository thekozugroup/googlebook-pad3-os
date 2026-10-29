#!/usr/bin/env python3
"""Emit the five-image offline B replacement plan. Never execute device commands."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from native_install.layout import parse_text_layout
from native_install.payload import require, sha256
from native_install.fstab import entries, unpack_vendor_boot, unpack_recovery

LOGICAL = ('odm', 'product', 'system', 'system_dlkm', 'system_ext', 'vendor', 'vendor_dlkm')
PHYSICAL = ('boot', 'init_boot', 'vendor_boot', 'dtbo', 'recovery', 'vbmeta_system', 'vbmeta_vendor', 'vbmeta')
PARTITIONS = set(LOGICAL + PHYSICAL)
WRITE_ORDER = ('system_ext', 'product', 'system', 'vendor_boot', 'recovery')
ROLLBACK_ORDER = ('system', 'product', 'system_ext', 'vendor_boot', 'recovery')
MIB = 1024 * 1024
OWNER_CONSENT = 'when ready proceed to flash the OS and erase data'
SOURCE = 'https://android.googlesource.com/platform/system/core/+/900221fe337e185924d2870d5b123392d5f227c1/fastboot/device/commands.cpp'


def checked(record):
    path = Path(record['path'])
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'absolute regular image required')
    require(re.fullmatch('[0-9a-f]{64}', record['sha256']) is not None
            and sha256(path) == record['sha256'], 'image hash mismatch: ' + path.name)
    size = path.stat().st_size
    require(size > 0 and size % 4096 == 0, 'raw 4K-aligned image required')
    require(record.get('bytes', size) == size, 'capture byte length mismatch')
    return dict(path=str(path), sha256=record['sha256'], bytes=size)


def replacement_budget(old, new):
    require(set(old) == set(LOGICAL) and set(new) == set(LOGICAL), 'all seven logical sizes required')
    require(all(type(v) is int and v > 0 and v % 4096 == 0 for v in [*old.values(), *new.values()]), 'invalid logical sizes')
    require(all(new[n] == old[n] for n in ('vendor', 'odm', 'vendor_dlkm', 'system_dlkm')), 'hardware logical sizes changed')
    require(all(new[n] <= old[n] for n in ('system_ext', 'product')), 'system_ext/product must shrink first')
    freed = sum(old[n] - new[n] for n in ('system_ext', 'product'))
    growth = max(0, new['system'] - old['system'])
    # Extra space for aligned growth extents; do not count or delete existing COW storage.
    reserve = 3 * MIB if growth else 0
    require(freed >= growth + reserve, 'shrinks do not safely fund system growth; stop for separate unused-COW review')
    return dict(bytes_freed_before_system=freed, system_growth_bytes=growth,
                alignment_reserve_bytes=reserve, final_logical_bytes=sum(new.values()),
                net_bytes_freed=sum(old.values()) - sum(new.values()), cow_deletions=[])


def observed(text, key):
    values = re.findall(r'^' + re.escape(key) + r':\s*([^\r\n]+)', text, re.M)
    require(len(values) == 1, 'missing/duplicate fastboot observation: ' + key)
    return values[0].strip()


def format_filesystems(vendor_boot, recovery):
    proof = {}
    for name, image, unpack in (('vendor_boot', vendor_boot, unpack_vendor_boot), ('recovery', recovery, unpack_recovery)):
        text = unpack(Path(image).read_bytes())['fstab']
        rows = list(entries(text))
        for mount in ('/metadata', '/data'):
            selected = [row for row in rows if row[1] == mount]
            require(len(selected) == 1 and selected[0][2] == 'f2fs', 'both exact fstabs must require F2FS: ' + name + mount)
        proof[name] = hashlib.sha256(text.encode()).hexdigest()
    return dict(metadata='f2fs', userdata='f2fs', fstab_sha256=proof)


def make_plan(userspace_manifest, capture_root, fastboot):
    manifest, c = Path(userspace_manifest), Path(capture_root)
    build = json.loads(manifest.read_text())
    require(build['status'] == 'NATIVE_USERSPACE_ASSEMBLED_UNBOOTED' and set(build['images']) == {'system', 'system_ext', 'product'}, 'assembled three-image manifest required')
    require(build['public_image']['adb_key_paths_absent'] is True and build['public_image']['diagnostic_init_properties_and_service_paths_rejected'] is True, 'public image sanitization required')
    backups = {}
    for filename in ('boot-inputs.json', 'logical-inputs.json', 'native-os-inputs.json'):
        for name, record in json.loads((c / filename).read_text()).items():
            require(name.endswith('_b') and name[:-2] in PARTITIONS and name[:-2] not in backups, 'unexpected/duplicate backup')
            backups[name[:-2]] = checked(record)
    require(set(backups) == PARTITIONS, 'all 15 exact Native B rollback images required')
    require(backups['boot']['sha256'] == '15e43ca52b939d9780438d32d302f1575c3e99c2df4836d500fe2940cab64448'
            and backups['init_boot']['sha256'] == 'bdc61ad17b24711bca838e51fbdc4fbbed5c7a2bc4ab1bffa043551645764f16', 'wrong native hardware/root base')
    for name, expected in {
        'vbmeta':'ec2ba58a474d3f8e09aecbdfcb2815b4a4f3dcc7f7ecbe0427cd914a9015a1fa',
        'vbmeta_system':'c3e9e803d81bc1574ff7f3af6086b97e90109c674067cc28d7bb4189fdd56d5f',
        'vbmeta_vendor':'49a62ff953d5f8c13396d4e6d3f04e3c1008647017b42137eac080ca8d03f399'
    }.items():
        require(backups[name]['sha256'] == expected, 'requires exact native AVB flags 3/0/0; unchanged vbmeta')
    images = dict(backups)
    images.update({name: checked(record) for name, record in build['images'].items()})
    prepared = c / 'prepared-native-boot-chain/manifest.json'
    patches = json.loads(prepared.read_text())['files']
    for name in ('vendor_boot', 'recovery'):
        images[name] = checked(patches[name + '-erofs-unsigned.img'])
        require(images[name]['bytes'] == backups[name]['bytes'], 'prepared ramdisk image must retain physical partition size')
    require(images['vendor_boot']['sha256'] == '21266e40b3a292b0bcb489439a8a02e607e63fe9fc9d2a6cc967c192aa8e21e4'
            and images['recovery']['sha256'] == '163100ce0eaa18c9f83fe0dd85a33a17ebe25799533714888b16d9824bde1ddc', 'wrong bounded EROFS ramdisk patches')
    format_proof = format_filesystems(images['vendor_boot']['path'], images['recovery']['path'])
    source = c / 'super-layout-1.txt'
    layout = parse_text_layout(source.read_text())
    require(all(p['size'] == backups[p['name']]['bytes'] for p in layout['partitions']), 'backup size differs from B extents')
    budget = replacement_budget({n: backups[n]['bytes'] for n in LOGICAL}, {n: images[n]['bytes'] for n in LOGICAL})
    variables, queries = c / 'fastbootd-readonly-variables.txt', c / 'fastbootd-partition-queries.txt'
    text = variables.read_text()
    require(observed(text, 'product') in ('OP6190L1', 'erhai', 'OPD2415'), 'wrong device')
    for key, value in {'is-userspace':'yes', 'current-slot':'b', 'unlocked':'yes', 'snapshot-update-status':'none', 'super-partition-name':'super'}.items():
        require(observed(text, key) == value, 'unsafe fastboot state: ' + key)
    require(int(observed(text, 'partition-size:super'), 0) == layout['super_device']['total_size'], 'super geometry differs')
    require(observed(queries.read_text(), 'is-logical:system_b') == 'yes'
            and int(observed(queries.read_text(), 'partition-size:system_b'), 0) == backups['system']['bytes'], 'live system B differs')
    fb = str(Path(fastboot).resolve())
    require(Path(fb).is_file(), 'existing host fastboot binary required')
    def command(*args): return [fb, *map(str, args)]
    def writes(order, records):
        result = []
        for name in order:
            if name in LOGICAL:
                result.append(command('resize-logical-partition', name + '_b', records[name]['bytes']))
            result.append(command('flash', name + '_b', records[name]['path']))
        return result
    preflight = ['product', 'is-userspace', 'unlocked', 'current-slot', 'snapshot-update-status', 'partition-size:super']
    preflight += [f'partition-size:{n}_b' for n in WRITE_ORDER]
    preflight += ['partition-type:userdata', 'partition-type:metadata']
    return dict(schema=2, status='OWNER_APPROVED_PLAN_DEVICE_COMMANDS_NOT_RUN', preferred_route='offline_fastbootd_replace_current_B',
                initial_target_slot='b', owner_consent=OWNER_CONSENT, userdata_backup_waived=True,
                userspace_manifest_sha256=sha256(manifest), prepared_manifest_sha256=sha256(prepared),
                fastboot=dict(path=fb, sha256=sha256(Path(fb))), candidate=images, rollback_images=backups,
                host_evidence_sha256={p.name:sha256(p) for p in (source, variables, queries)}, allocation=budget,
                format_filesystems=format_proof, fetch_supported=False, device_hash_readback='DEFERRED_UNTIL_ROOTED_NATIVE_BOOT',
                execution_approved=True, reset_approved=True, device_commands_executed=0, source=SOURCE,
                stages=[
                    dict(name='READ_ONLY_PREFLIGHT', argv=[command('getvar', q) for q in preflight], require=[
                        'Repeat current host observations immediately before writes. Require B, unlocked fastbootd, NONE snapshots.',
                        'Parent verifies all OS/COW mappings unmounted and linear, no active updater or COW users; HAL/libsnapshot NONE.',
                        'Current B sizes match captures; unchanged ten images were captured with verified hashes and have had no writer since.',
                        'Rehash all candidate/backup images. Review actual package, bounded EROFS ramdisks and initial trust/manager/engine.',
                        'Owner consent is recorded verbatim; userdata backup waived. No further confirmation is required.']),
                    dict(name='REPLACE_FIVE_B_IMAGES', argv=writes(WRITE_ORDER, images), require=[
                        'Offline fastbootd only. Preserve B group and all other partitions. Never create A, delete COW or flash super.',
                        'Check success after each resize/flash; stop on error and remain in fastbootd. No Android boot between images.']),
                    dict(name='VERIFY_BEFORE_WIPE', argv=[command('getvar', 'current-slot'), command('getvar', 'snapshot-update-status')], require=[
                        'Fetch is unsupported on this device. Accept verified host image hashes, every successful transfer/write ACK and expected partition-size checks; retain all logs.',
                        'Require unchanged ten other images, expected seven logical sizes, B current and snapshot NONE. Device hash readback is deferred until rooted native boot, not claimed verified.',
                        'B is already selected. No set_active call or boot/root/vbmeta rewrite is needed.']),
                    dict(name='APPROVED_EXPLICIT_F2FS_FORMAT', argv=[command('format:f2fs', 'metadata'), command('format:f2fs', 'userdata')], require=[
                        'Require snapshot NONE/no COW dependency and postflash fastbootd access. Both exact prepared fstabs require F2FS; SDK make_f2fs exists.',
                        'Live partition types are RAW: -w erases but skips formatting. Explicit format:f2fs overrides RAW using the proven fstab types.',
                        'Require mkfs success and sending/writing ACKs for metadata and userdata separately before boot; preserve logs.']),
                    dict(name='BOOT_B_AFTER_SUCCESSFUL_WIPE', argv=[command('reboot')], require=[
                        'Require successful userdata and metadata reset first; B must remain current.',
                        'After rooted native boot, obtain read-only exact-length hashes of the five changed partitions and compare the manifest; fetch was unavailable.',
                        'Verify users/headless mode, root/manager, SYSTEM-namespace engine DSOs and updater.'])],
                rollback=dict(order=list(ROLLBACK_ORDER), argv=writes(ROLLBACK_ORDER, backups),
                              require=['Remain in offline fastbootd, B current, unmounted and snapshot NONE; rehash backups first.',
                                       'Restore smaller original system FIRST to fund product/system_ext expansion, then stock vendor_boot/recovery. Unchanged ten images stay untouched.',
                                       'Use host hash checks, successful write ACKs and original logical sizes while fetch is unavailable; defer device hashes until rooted native boot. If data was reset or new OS booted, reset again before rollback boot under recorded erase consent.',
                                       'All 15 backups remain available. Never assume slot A rollback, restore old slot-0 metadata or restore userdata.']),
                limitations=['No device writes, recovery format or boot tested by this helper.',
                             'If shrink budget or live allocator fails, stop for separately reviewed unused-COW recovery; no automatic deletion.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('userspace-manifest', 'capture-root', 'fastboot', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = make_plan(args.userspace_manifest, args.capture_root, args.fastboot)
    with args.output.open('x') as out:
        json.dump(result, out, indent=2)
        out.write('\n')


if __name__ == '__main__':
    main()
