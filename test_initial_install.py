"""Offline B replacement: image binding, shrink ordering, host evidence and rollback."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from native_install import initial_install as install
from native_install.payload import sha256


def layout():
    records = [f'  Name: {n}_b\n  Group: oneplus_dynamic_partitions_b\n  Attributes: readonly,updated\n  Extents:\n    0 .. 32767 linear super {2048+i*32768}\n' for i,n in enumerate(install.LOGICAL)]
    records.append('  Name: system_b-cow\n  Group: cow\n  Attributes: none\n  Extents:\n    0 .. 4095 linear super 300000\n')
    return ('Slot 1:\nMetadata version: 10.2\nMetadata max size: 65536 bytes\nMetadata slot count: 3\nHeader flags: virtual_ab_device\nPartition table:\n------------------------\n'
            + '------------------------\n'.join(records) + 'Super partition layout:\nBlock device table:\n'
            '  Partition name: super\n  First sector: 2048\n  Size: 11711471616 bytes\n  Flags: none\nGroup table:\n'
            '  Name: default\n  Maximum size: 0 bytes\n  Flags: none\n'
            '  Name: oneplus_dynamic_partitions_b\n  Maximum size: 11707277312 bytes\n  Flags: none\n'
            '  Name: cow\n  Maximum size: 0 bytes\n  Flags: none\n')


class InitialInstallTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'super-layout-1.txt').write_text(layout())
        (self.root/'fastbootd-readonly-variables.txt').write_text('product: OP6190L1\nis-userspace: yes\ncurrent-slot: b\nunlocked: yes\nsnapshot-update-status: none\nsuper-partition-name: super\npartition-size:super: 0x2BA0EE000\n')
        (self.root/'fastbootd-partition-queries.txt').write_text("getvar:is-logical:system_a FAILED (remote: 'Partition not found')\nis-logical:system_b: yes\npartition-size:system_b: 0x1000000\n")
        self.fb = self.root/'fastboot-never-execute'; self.fb.write_bytes(b'Not executable. Offline only.')
        self.records = {n:dict(path=str(self.root/(n+'_b.img')), sha256=f'{i+1:064x}', bytes=16*install.MIB if n in install.LOGICAL else 4096) for i,n in enumerate(sorted(install.PARTITIONS))}
        self.records['boot']['sha256']='15e43ca52b939d9780438d32d302f1575c3e99c2df4836d500fe2940cab64448'
        self.records['init_boot']['sha256']='bdc61ad17b24711bca838e51fbdc4fbbed5c7a2bc4ab1bffa043551645764f16'
        groups=(('boot-inputs.json',('boot','init_boot','dtbo','vendor_boot','vbmeta','vbmeta_system','vbmeta_vendor')),('logical-inputs.json',('vendor','odm','vendor_dlkm','system_dlkm','recovery')),('native-os-inputs.json',('system','system_ext','product')))
        for filename,names in groups:
            (self.root/filename).write_text(json.dumps({n+'_b':self.records[n] for n in names}))
        images={n:dict(record) for n,record in self.records.items()}
        for i,n in enumerate(install.WRITE_ORDER):
            images[n].update(path=str(self.root/(n+'-candidate.img')),sha256=f'{100+i:064x}')
        images['system_ext']['bytes']=images['product']['bytes']=4*install.MIB
        images['system']['bytes']=24*install.MIB
        self.plan=dict(schema=1,target_slot='a',capture=dict(slot='b',lpdump_text_1=dict(sha256=sha256(self.root/'super-layout-1.txt'))),images=images,avb_mode='preserve-native-disabled')
        self.records['vbmeta']['sha256']='ec2ba58a474d3f8e09aecbdfcb2815b4a4f3dcc7f7ecbe0427cd914a9015a1fa'
        self.records['vbmeta_system']['sha256']='c3e9e803d81bc1574ff7f3af6086b97e90109c674067cc28d7bb4189fdd56d5f'
        self.records['vbmeta_vendor']['sha256']='49a62ff953d5f8c13396d4e6d3f04e3c1008647017b42137eac080ca8d03f399'
        q=self.root/'boot-inputs.json'; d=json.loads(q.read_text())
        for n in ('vbmeta','vbmeta_system','vbmeta_vendor'): d[n+'_b']=self.records[n]
        q.write_text(json.dumps(d))
        self.plan['images']['vendor_boot']['sha256']='21266e40b3a292b0bcb489439a8a02e607e63fe9fc9d2a6cc967c192aa8e21e4'
        self.plan['images']['recovery']['sha256']='163100ce0eaa18c9f83fe0dd85a33a17ebe25799533714888b16d9824bde1ddc'
        self.native=self.root/'userspace-build.json'

    def generate(self, mutation=None):
        build=dict(status='NATIVE_USERSPACE_ASSEMBLED_UNBOOTED',images={n:self.plan['images'][n] for n in ('system','system_ext','product')},public_image=dict(adb_key_paths_absent=True,diagnostic_init_properties_and_service_paths_rejected=True))
        if mutation: mutation(build)
        self.native.write_text(json.dumps(build))
        d=self.root/'prepared-native-boot-chain';d.mkdir(exist_ok=True)
        (d/'manifest.json').write_text(json.dumps(dict(files={n+'-erofs-unsigned.img':self.plan['images'][n] for n in ('vendor_boot','recovery')})))
        with patch.object(install,'checked',side_effect=lambda record:dict(record)), patch.object(install,'format_filesystems',return_value=dict(metadata='f2fs',userdata='f2fs')):
            return install.make_plan(self.native,self.root,self.fb)

    def test_only_five_b_images_shrink_first_no_a_cow_or_wipe(self):
        p=self.generate(); self.assertEqual(p['initial_target_slot'],'b'); self.assertTrue(p['execution_approved']); self.assertTrue(p['reset_approved'])
        writes=p['stages'][1]['argv']; flashes=[a for a in writes if a[1]=='flash']
        self.assertEqual([a[2] for a in flashes],[n+'_b' for n in install.WRITE_ORDER])
        self.assertEqual([a[2] for a in writes if a[1]=='resize-logical-partition'],['system_ext_b','product_b','system_b'])
        forbidden={'create-logical-partition','delete-logical-partition','erase','format','set_active','update-super'}
        self.assertFalse(any(forbidden.intersection(a) for s in p['stages'] for a in s['argv']))
        self.assertFalse(any('-w' in a for stage in p['stages'][:3] for a in stage['argv']))
        self.assertEqual(p['allocation']['cow_deletions'],[])
        self.assertEqual(p['allocation']['net_bytes_freed'],16*install.MIB)
        self.assertEqual(len(p['rollback_images']),15)

    def test_rollback_system_shrinks_first_and_uses_original_images(self):
        p=self.generate(); cmds=p['rollback']['argv']; flashes=[a for a in cmds if a[1]=='flash']
        self.assertEqual([a[2] for a in flashes],[n+'_b' for n in install.ROLLBACK_ORDER])
        self.assertEqual(flashes[0][3],self.records['system']['path'])
        self.assertEqual(cmds[0][1:3],['resize-logical-partition','system_b'])
        self.assertEqual(cmds[0][3],str(16*install.MIB))
        self.assertEqual(flashes[-2][3],self.records['vendor_boot']['path'])
        self.assertEqual(flashes[-1][3],self.records['recovery']['path'])

    def test_approval_not_required_to_construct_offline_plan(self):
        p=self.generate(); self.assertEqual(p['device_commands_executed'],0)
        self.assertEqual(p['owner_consent'], 'when ready proceed to flash the OS and erase data')
        self.assertEqual([a[1:] for a in p['stages'][-2]['argv']], [['format:f2fs','metadata'],['format:f2fs','userdata']])
        self.assertFalse(p['fetch_supported'])
        self.assertEqual(p['device_hash_readback'], 'DEFERRED_UNTIL_ROOTED_NATIVE_BOOT')
        self.assertIn('transfer/write ACK',str(p['stages'][2]['require']))
        self.assertEqual(p['stages'][-1]['argv'][0][1:], ['reboot'])

    def test_wrong_live_slot_refused(self):
        q=self.root/'fastbootd-readonly-variables.txt'; q.write_text(q.read_text().replace('current-slot: b','current-slot: a'))
        with self.assertRaisesRegex(ValueError,'current-slot'): self.generate()

    def test_pending_snapshot_refused(self):
        q=self.root/'fastbootd-readonly-variables.txt'; q.write_text(q.read_text().replace('snapshot-update-status: none','snapshot-update-status: merging'))
        with self.assertRaisesRegex(ValueError,'snapshot-update-status'): self.generate()

    def test_no_boot_or_vbmeta_change_allowed(self):
        q=self.root/'boot-inputs.json'; d=json.loads(q.read_text()); d['vbmeta_b']['sha256']='f'*64; q.write_text(json.dumps(d))
        with self.assertRaisesRegex(ValueError,'unchanged vbmeta'): self.generate()

    def test_private_userspace_refused(self):
        with self.assertRaisesRegex(ValueError,'sanitization'):
            self.generate(lambda build:build['public_image'].update(adb_key_paths_absent=False))

    def test_insufficient_shrink_stops_without_deleting_cow(self):
        self.plan['images']['system']['bytes']=50*install.MIB
        with self.assertRaisesRegex(ValueError,'unused-COW review'): self.generate()

    def test_system_ext_growth_is_not_treated_as_shrink(self):
        self.plan['images']['system_ext']['bytes']=20*install.MIB
        with self.assertRaisesRegex(ValueError,'shrink first'): self.generate()

    def test_missing_backup_refused(self):
        q=self.root/'logical-inputs.json'; d=json.loads(q.read_text()); del d['recovery_b']; q.write_text(json.dumps(d))
        with self.assertRaisesRegex(ValueError,'rollback images'): self.generate()

    def test_unassembled_manifest_refused(self):
        with self.assertRaisesRegex(ValueError,'assembled'):
            self.generate(lambda build:build.update(status='NOT_BUILT'))

    def test_physical_image_cannot_truncate_or_expand_partition(self):
        self.plan['images']['recovery']['bytes']=8192
        with self.assertRaisesRegex(ValueError,'partition size'): self.generate()

    def test_real_file_hash_tampering_refused(self):
        q=self.root/'raw.img'; q.write_bytes(bytes(4096)); record=dict(path=str(q),sha256=sha256(q),bytes=4096)
        self.assertEqual(install.checked(record)['bytes'],4096); q.write_bytes(b'x'*4096)
        with self.assertRaisesRegex(ValueError,'hash mismatch'): install.checked(record)

    def test_explicit_f2fs_requires_both_native_fstabs(self):
        p=self.root/'ramdisk-fixture'; p.write_bytes(b'fixture')
        fstab='/dev/block/by-name/metadata /metadata f2fs defaults wait\n/dev/block/by-name/userdata /data f2fs defaults wait\n'
        with patch.object(install,'unpack_vendor_boot',return_value=dict(fstab=fstab)), patch.object(install,'unpack_recovery',return_value=dict(fstab=fstab)):
            proof=install.format_filesystems(p,p)
        self.assertEqual(proof['metadata'],'f2fs'); self.assertEqual(proof['userdata'],'f2fs')
        self.assertEqual(set(proof['fstab_sha256']),{'vendor_boot','recovery'})

    def test_conflicting_recovery_fstype_refuses_raw_override(self):
        p=self.root/'ramdisk-fixture'; p.write_bytes(b'fixture')
        fstab='/dev/block/by-name/metadata /metadata f2fs defaults wait\n/dev/block/by-name/userdata /data f2fs defaults wait\n'
        with patch.object(install,'unpack_vendor_boot',return_value=dict(fstab=fstab)), patch.object(install,'unpack_recovery',return_value=dict(fstab=fstab.replace('/metadata f2fs','/metadata ext4'))):
            with self.assertRaisesRegex(ValueError,'both exact fstabs'): install.format_filesystems(p,p)


if __name__=='__main__': unittest.main()
