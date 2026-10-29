"""Real ELF64 fixtures exercise SDK parsing, private closure and the observed liblp ABI failure."""
from pathlib import Path
import shutil
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
from native_install import engine_libraries as bundle


def arm64_elf(needed=(), soname=None, exports=(), imports=(), weak=(), machine=183,
              runpath=None, rpath=None, loadable=False):
    strings = bytearray(b'\0')
    def string(value):
        at = len(strings); strings.extend(value.encode()+b'\0'); return at
    deps = [string(n) for n in needed]
    soname_at = string(soname) if soname else None
    runpath_at = string(runpath) if runpath is not None else None
    rpath_at = string(rpath) if rpath is not None else None
    symbols = bytearray(bytes(24))
    for names, info, section in ((exports,0x12,5),(imports,0x12,0),(weak,0x22,0)):
        for name in names:
            symbols.extend(struct.pack('<IBBHQQ',string(name),info,0,section,0x1000 if section else 0,4 if section else 0))
    dynamic = b''.join(struct.pack('<qQ',1,n) for n in deps)
    if soname_at is not None: dynamic += struct.pack('<qQ',14,soname_at)
    if runpath_at is not None: dynamic += struct.pack('<qQ',29,runpath_at)
    if rpath_at is not None: dynamic += struct.pack('<qQ',15,rpath_at)
    if loadable:
        dynamic += b''.join(struct.pack('<qQ',tag,value) for tag,value in ((5,0),(10,len(strings)),(6,0),(11,24)))
    dynamic += struct.pack('<qQ',0,0)
    section_names = b'\0.dynstr\0.dynamic\0.dynsym\0.shstrtab\0.text\0'
    blobs = [bytes(strings),dynamic,bytes(symbols),section_names,b'\xc0\x03\x5f\xd6']
    result = bytearray(bytes(64+56*3 if loadable else 64)); offsets=[]
    for blob in blobs:
        result.extend(bytes((-len(result))%8)); offsets.append(len(result));result.extend(blob)
    result.extend(bytes((-len(result))%8));shoff=len(result); result.extend(bytes(64))
    for i,(name,typ,flags,link,info,entry) in enumerate((('.dynstr',3,2,0,0,0),('.dynamic',6,3,1,0,16),('.dynsym',11,2,1,1,24),('.shstrtab',3,0,0,0,0),('.text',1,6,0,0,0))):
        address = 0x10000+offsets[i] if loadable and flags&2 else (0x1000 if i==4 else 0)
        result.extend(struct.pack('<IIQQQQIIQQ',section_names.index(name.encode()),typ,flags,address,offsets[i],len(blobs[i]),link,info,8,entry))
    result[:16]=b'\x7fELF\x02\x01\x01'+bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH',result,16,3,machine,1,0,64 if loadable else 0,shoff,0,64,56 if loadable else 0,3 if loadable else 0,64,6,4)
    if loadable:
        for at in range(offsets[1],offsets[1]+len(dynamic),16):
            tag=struct.unpack_from('<q',result,at)[0]
            if tag in (5,6):struct.pack_into('<Q',result,at+8,0x10000+offsets[0 if tag==5 else 2])
        for at,values in [(64,(1,5,0,0x10000,0x10000,len(result),len(result),0x1000)),
                          (120,(2,6,offsets[1],0x10000+offsets[1],0x10000+offsets[1],len(dynamic),len(dynamic),8)),
                          (176,(0x6474e551,6,0,0,0,0,0,16))]:
            struct.pack_into('<IIQQQQQQ',result,at,*values)
    return bytes(result)


class EngineLibrariesTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
    def elf(self,name,**kwargs):
        p=self.root/name;p.write_bytes(arm64_elf(**kwargs));return bundle.elf(p)
    def test_sdk_reads_real_arm64_dynamic_dependencies_and_symbols(self):
        e=self.elf('engine',needed=('liblp.so','android.hardware.boot@1.0.so','libc.so'),imports=(bundle.MISSING,'puts'),weak=('optional_feature',))
        self.assertEqual(e['needed'],['liblp.so','android.hardware.boot@1.0.so','libc.so'])
        self.assertIn(bundle.MISSING,e['imports']);self.assertNotIn('optional_feature',e['imports']);self.assertIn('optional_feature',e['weak_imports'])
    def test_native_transitive_closure_handles_cycles_without_runtime_copy(self):
        root=self.elf('engine',needed=('liblp.so',),imports=(bundle.MISSING,'puts'))
        root['import_versions']['puts']='LIBC'
        items={'liblp.so':{'elf':self.elf('liblp.so',soname='liblp.so',needed=('libbase.so','libc.so'),exports=(bundle.MISSING,))},'libbase.so':{'elf':self.elf('libbase.so',soname='libbase.so',needed=('liblp.so',),exports=('base_api',))}}
        libraries,excluded=bundle.closure(root,items.get,{'libc.so':'/apex/com.android.runtime/lib64/bionic/libc.so'})
        self.assertEqual(set(libraries),{'liblp.so','libbase.so'});self.assertEqual(set(excluded),{'libc.so'})
        self.assertEqual(bundle.symbol_boundary(root,libraries),['puts'])
    def test_donor_like_liblp_missing_exact_method_is_rejected(self):
        root=self.elf('engine',needed=('liblp.so',),imports=(bundle.MISSING,))
        wrong={'liblp.so':{'elf':self.elf('liblp.so',soname='liblp.so',exports=('old_metadata_builder',))}}
        with self.assertRaisesRegex(ValueError,'observed missing method'):bundle.symbol_boundary(root,wrong)
    def test_other_private_cpp_abi_holes_are_rejected(self):
        root=self.elf('engine',imports=(bundle.MISSING,'_Z14absent_privatev'))
        libs={'liblp.so':{'elf':self.elf('liblp.so',exports=(bundle.MISSING,))}}
        with self.assertRaisesRegex(ValueError,r'C\+\+ ABI'):bundle.symbol_boundary(root,libs)
    def test_unversioned_missing_c_symbol_is_not_assumed_runtime(self):
        root=self.elf('engine',imports=(bundle.MISSING,'missing_private_c_api'))
        libs={'liblp.so':{'elf':self.elf('liblp.so',exports=(bundle.MISSING,))}}
        with self.assertRaisesRegex(ValueError,'non-runtime strong symbol'):bundle.symbol_boundary(root,libs)
    def test_missing_dependency_cannot_fall_back_to_donor(self):
        root=self.elf('engine',needed=('missing.so',))
        with self.assertRaisesRegex(ValueError,'non-runtime'):bundle.closure(root,lambda n:None,{})
    def test_soname_collision_is_rejected(self):
        root=self.elf('engine',needed=('liblp.so',));wrong={'elf':self.elf('bad.so',soname='different.so')}
        with self.assertRaisesRegex(ValueError,'SONAME'):bundle.closure(root,lambda n:wrong,{})
    def test_wrong_architecture_and_unsafe_needed_are_rejected(self):
        with self.assertRaisesRegex(ValueError,'AArch64'):self.elf('x86.so',machine=62)
        with self.assertRaisesRegex(ValueError,'unsafe'):self.elf('unsafe.so',needed=('/vendor/lib64/libbad.so',))
    def test_runpath_and_rpath_are_distinguished_by_real_elf_reader(self):
        info=self.elf('runpath',runpath=bundle.DESTINATION,rpath='$ORIGIN')
        self.assertEqual(info['runpath'],[bundle.DESTINATION]);self.assertEqual(info['rpath'],['$ORIGIN'])
    def test_preservation_signature_detects_changed_executable_bytes(self):
        p=self.root/'engine';p.write_bytes(arm64_elf(exports=('entry',)))
        before=bundle.preserved_elf(p)
        p.write_bytes(p.read_bytes().replace(b'\xc0\x03\x5f\xd6',b'\x1f\x20\x03\xd5'))
        self.assertNotEqual(before,bundle.preserved_elf(p))
    @unittest.skipUnless(shutil.which('patchelf'),'installed patchelf required')
    def test_actual_patchelf_preserves_loadable_arm64_code_and_symbols(self):
        p=self.root/'lib.so';p.write_bytes(arm64_elf(soname='lib.so',exports=('entry',),loadable=True))
        before=p.read_bytes();derived=self.root/'derived.so'
        info,receipt=bundle.runpath_file(p,derived,Path(shutil.which('patchelf')))
        self.assertEqual(p.read_bytes(),before)
        self.assertEqual(info['runpath'],[bundle.DESTINATION]);self.assertEqual(info['rpath'],[])
        self.assertEqual(receipt['preserved_sha256'],bundle._digest(bundle.preserved_elf(p)))
    def test_abi_and_code_tampering_rejected_despite_updated_output_pin(self):
        p=self.root/'derived';p.write_bytes(arm64_elf(soname='lib.so',exports=('entry',),runpath=bundle.DESTINATION))
        info=bundle.elf(p);original={'sha256':'a'*64,'elf':info}
        record={'sha256':'b'*64,'transformation':{'source_sha256':'a'*64,'output_sha256':'b'*64,
                'preserved_sha256':bundle._digest(bundle.preserved_elf(p)),
                'abi_sha256':bundle._digest({k:info[k] for k in bundle.ABI_KEYS})}}
        bundle._derived_elf(record,original,p)
        p.write_bytes(p.read_bytes().replace(b'\xc0\x03\x5f\xd6',b'\x1f\x20\x03\xd5'))
        with self.assertRaisesRegex(ValueError,'preservation receipt'):bundle._derived_elf(record,original,p)
        p.write_bytes(arm64_elf(soname='lib.so',exports=('different',),runpath=bundle.DESTINATION))
        with self.assertRaisesRegex(ValueError,'ABI differs'):bundle._derived_elf(record,original,p)
    def test_origin_legacy_rpath_and_extra_paths_rejected(self):
        p=self.root/'derived'
        for opts in ({'runpath':'$ORIGIN'},{'rpath':bundle.DESTINATION},
                     {'runpath':bundle.DESTINATION+':/data/local/tmp'}):
            p.write_bytes(arm64_elf(**opts));info=bundle.elf(p)
            record={'sha256':'b'*64,'transformation':{'source_sha256':'a'*64,'output_sha256':'b'*64,
                    'preserved_sha256':'c'*64,'abi_sha256':'d'*64}}
            with self.assertRaisesRegex(ValueError,'exact absolute DT_RUNPATH'):
                bundle._derived_elf(record,{'sha256':'a'*64,'elf':info},p)



class SourceBundleInputsTest(unittest.TestCase):
    def setUp(self):
        import base64,json,hashlib,copy
        from unittest.mock import patch
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.capture=self.root/'capture';self.capture.mkdir()
        self.artifact=self.root/'bundle';self.artifact.mkdir();(self.artifact/'lib64').mkdir()
        self.json,self.hashlib,self.copy=json,hashlib,copy
        def pin(path):return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        self.pin=pin
        image_pins={}
        for name in ('system','system_ext','product'):
            p=self.capture/(name+'-source');p.write_bytes(name.encode());image_pins[name]=pin(p)
        names=['liblp.so']+['libfixture%02d.so'%i for i in range(43)]
        engine=self.capture/'update_engine';engine.write_bytes(arm64_elf(needed=names+list(bundle.RUNTIME_PROVIDERS),imports=(bundle.MISSING,),loadable=True))
        original=self.capture/'update_engine.rc';original.write_bytes(b'service update_engine /system/bin/update_engine --foreground\n    user root\n')
        private=self.artifact/'update_engine.rc';private.write_bytes(original.read_bytes())
        def meta(mode,label):return dict(mode=mode,uid=0,gid=0,mtime=1230768000,mtime_nsec=0,xattrs={'security.selinux':base64.b64encode(label).decode()})
        libmeta=meta(stat.S_IFREG|0o644,b'u:object_r:system_lib_file:s0\0')
        libraries={}
        for name in names:
            p=self.artifact/'lib64'/name;p.write_bytes(arm64_elf(soname=name,exports=(bundle.MISSING,) if name=='liblp.so' else (),loadable=True))
            libraries[name]=dict(pin(p),destination=bundle.DESTINATION+'/'+name,source_partition='system',source_path='/system/lib64/'+name,
                                 metadata=copy.deepcopy(libmeta),bytes=p.stat().st_size,alternate_native_locations=[])
        self.data=dict(schema=1,status='PRIVATE_NATIVE_DEPENDENCY_CLOSURE_RUNTIME_PENDING',source_images=image_pins,engine=pin(engine),
                       destination=bundle.DESTINATION,service_option=None,excluded_runtime=bundle.RUNTIME_PROVIDERS.copy(),
                       directory_metadata=meta(stat.S_IFDIR|0o755,b'u:object_r:system_lib_file:s0\0'),libraries=libraries,
                       total_library_bytes=sum(x['bytes'] for x in libraries.values()),
                       service_rc=dict(pin(private),destination='/system/etc/init/update_engine.rc',source_sha256=pin(original)['sha256'],metadata=meta(stat.S_IFREG|0o644,b'u:object_r:system_file:s0\0')))
        self.manifest=self.artifact/'manifest.json'
        self.patches=patch.multiple(bundle,SOURCE_IMAGE_SHAS={n:p['sha256'] for n,p in image_pins.items()},ENGINE_SHA=pin(engine)['sha256'],SOURCE_RC_SHA=pin(original)['sha256'])
        self.patches.start();self.addCleanup(self.patches.stop)
    def load(self):
        self.manifest.write_text(self.json.dumps(self.data));return bundle._bundle_inputs(self.pin(self.manifest),source_only=True)
    def test_returns_ready_overlay_data_and_private_rc_without_writes(self):
        self.manifest.write_text(self.json.dumps(self.data));before={p:self.pin(p)['sha256'] for p in self.artifact.rglob('*') if p.is_file()}
        additions,rc=bundle._bundle_inputs(self.pin(self.manifest),source_only=True)
        self.assertEqual(len(additions),45);self.assertEqual(additions[bundle.DESTINATION]['data'],b'')
        self.assertEqual(additions[bundle.DESTINATION+'/liblp.so']['metadata']['xattrs']['security.selinux'],b'u:object_r:system_lib_file:s0\0')
        self.assertEqual(rc,(self.artifact/'update_engine.rc').read_bytes())
        self.assertEqual(before,{p:self.pin(p)['sha256'] for p in before})
    def test_wrong_manifest_pin_rejected(self):
        self.manifest.write_text(self.json.dumps(self.data))
        with self.assertRaisesRegex(ValueError,'pin mismatch'):bundle._bundle_inputs(dict(self.pin(self.manifest),sha256='0'*64),source_only=True)
    def test_every_native_source_pin_is_revalidated(self):
        Path(self.data['source_images']['product']['path']).write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'pin mismatch'):self.load()
    def test_private_destination_and_option_are_fixed(self):
        self.data['destination']='/system/lib64'
        with self.assertRaisesRegex(ValueError,'destination/option'):self.load()
    def test_exact_count_and_soname_safety(self):
        entry=self.data['libraries'].pop('libfixture00.so');self.data['libraries']['../escape.so']=entry
        with self.assertRaisesRegex(ValueError,'SONAME'):self.load()
    def test_metadata_mode_and_label_are_checked(self):
        self.data['libraries']['liblp.so']['metadata']['mode']=stat.S_IFREG|0o777
        with self.assertRaisesRegex(ValueError,'mode/owner/time'):self.load()
        self.data['libraries']['liblp.so']['metadata']['mode']=stat.S_IFREG|0o644
        self.data['libraries']['liblp.so']['metadata']['xattrs']['security.selinux']='dTpvYmplY3RfcjpzeXN0ZW1fZmlsZTpzMAA='
        with self.assertRaisesRegex(ValueError,'SELinux label'):self.load()
    def test_symlink_or_replaced_private_dso_rejected(self):
        p=Path(self.data['libraries']['liblp.so']['path']);p.unlink();p.symlink_to(self.artifact/'lib64/libfixture00.so')
        with self.assertRaisesRegex(ValueError,'canonical regular'):self.load()
    def test_real_elf_soname_must_match_filename(self):
        p=Path(self.data['libraries']['liblp.so']['path']);p.write_bytes(arm64_elf(soname='wrong.so',exports=(bundle.MISSING,)));self.data['libraries']['liblp.so'].update(self.pin(p),bytes=p.stat().st_size)
        with self.assertRaisesRegex(ValueError,'SONAME'):self.load()
    def test_native_rc_pin_is_required_and_source_bundle_is_not_launch_input(self):
        self.manifest.write_text(self.json.dumps(self.data))
        with self.assertRaisesRegex(ValueError,'schema/status'):bundle.integration_inputs(self.pin(self.manifest))
        (self.capture/'update_engine.rc').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'pin mismatch'):self.load()
    def test_informational_native_duplicates_preserve_selected_system_provider(self):
        record=self.data['libraries']['liblp.so']
        record['alternate_native_locations']=[{'partition':'product','path':'/lib64/liblp.so'}]
        additions,_=self.load()
        self.assertEqual(additions[bundle.DESTINATION+'/liblp.so']['data'],Path(record['path']).read_bytes())
        record['alternate_native_locations']=[{'partition':'vendor','path':'/lib64/liblp.so'}]
        with self.assertRaisesRegex(ValueError,'alternate Native source'):self.load()

    def prepare_runpath_source(self, source_destination=None):
        import base64
        if source_destination is not None:
            self.data['destination']=source_destination
            for name,record in self.data['libraries'].items():
                record['destination']=source_destination+'/'+name
        for record in [self.data['engine'],*self.data['libraries'].values()]:
            record['elf']=bundle.elf(Path(record['path']))
            # Reproduce the actual legacy manifest, which lacks only elf_type.
            record['elf'].pop('elf_type')
        meta=dict(mode=stat.S_IFREG|0o755,uid=0,gid=2000,mtime=1230768000,mtime_nsec=0,
                  xattrs={'security.selinux':base64.b64encode(b'u:object_r:update_engine_exec:s0\0').decode()})
        (self.capture/'native-engine-inputs.json').write_text(self.json.dumps({'files':{'update_engine':{'metadata':meta}}}))
        self.manifest.write_text(self.json.dumps(self.data))
        return self.pin(self.manifest)

    @unittest.skipUnless(shutil.which('patchelf'),'installed patchelf required')
    def test_full_45_file_producer_and_readonly_integration_contract(self):
        pin=self.prepare_runpath_source('/system/lib64/googlebook-update-engine');source_bytes=self.manifest.read_bytes()
        output=self.root/'derived'
        with patch.object(bundle,'_owned_output',return_value=output):
            data=bundle.build_runpath(pin,output,Path(shutil.which('patchelf')))
        manifest=output/'manifest.json'
        additions,rc=bundle.integration_inputs(self.pin(manifest))
        self.assertEqual(len(additions),45)
        self.assertEqual(rc,(self.capture/'update_engine.rc').read_bytes())
        self.assertNotIn(b'LD_LIBRARY_PATH',rc);self.assertIsNone(data['service_option'])
        self.assertEqual((output/'source-manifest.json').read_bytes(),source_bytes)
        self.assertEqual(self.manifest.read_bytes(),source_bytes)
        for record in [data['engine'],*data['libraries'].values()]:
            self.assertEqual(record['elf']['runpath'],[bundle.DESTINATION])
            self.assertEqual(record['elf']['rpath'],[])
        self.assertEqual(data['engine']['metadata']['gid'],2000)
        self.assertEqual(data['engine']['destination'],'/system/bin/update_engine')
        self.assertNotIn('/system/bin/update_engine',additions)
        self.assertEqual(data['library_partition'],'system_ext')
        self.assertEqual(data['library_image_directory'],'/lib64/googlebook-update-engine')
        self.assertEqual(data['destination'],'/system_ext/lib64/googlebook-update-engine')
        image_additions,image_rc=bundle.integration_inputs(self.pin(manifest),partition='system_ext')
        self.assertEqual(image_rc,rc);self.assertEqual(len(image_additions),45)
        self.assertEqual(set(image_additions),{p.removeprefix('/system_ext') for p in additions})
        self.assertTrue(all(p=='/lib64/googlebook-update-engine' or p.startswith('/lib64/googlebook-update-engine/') for p in image_additions))
        for part in ('system','product'):
            empty,part_rc=bundle.integration_inputs(self.pin(manifest),partition=part)
            self.assertEqual(empty,{});self.assertEqual(part_rc,rc)
        with self.assertRaisesRegex(ValueError,'unsupported image partition'):
            bundle.integration_inputs(self.pin(manifest),partition='vendor')
        for field,value,message in [('service_option','    setenv LD_LIBRARY_PATH '+bundle.DESTINATION,'destination/option'),
                                    ('destination','/system/lib64','destination/option')]:
            changed=self.copy.deepcopy(data);changed[field]=value;manifest.write_text(self.json.dumps(changed))
            with self.assertRaisesRegex(ValueError,message):bundle.integration_inputs(self.pin(manifest))
        changed=self.copy.deepcopy(data);changed['engine']['metadata']['gid']=0;manifest.write_text(self.json.dumps(changed))
        with self.assertRaisesRegex(ValueError,'metadata differs'):bundle.integration_inputs(self.pin(manifest))
        changed=self.copy.deepcopy(data);changed['engine']['transformation']['source_sha256']='0'*64;manifest.write_text(self.json.dumps(changed))
        with self.assertRaisesRegex(ValueError,'transformation source/output'):bundle.integration_inputs(self.pin(manifest))
        changed=self.copy.deepcopy(data);changed['library_partition']='system';manifest.write_text(self.json.dumps(changed))
        with self.assertRaisesRegex(ValueError,'image partition mismatch'):bundle.integration_inputs(self.pin(manifest))
        changed=self.copy.deepcopy(data);changed['library_image_directory']=bundle.DESTINATION;manifest.write_text(self.json.dumps(changed))
        with self.assertRaisesRegex(ValueError,'image partition mismatch'):bundle.integration_inputs(self.pin(manifest))
        changed=self.copy.deepcopy(data);rc_path=Path(changed['service_rc']['path'])
        rc_path.write_bytes(rc+b'    setenv LD_LIBRARY_PATH '+bundle.DESTINATION.encode()+b'\n')
        changed['service_rc'].update(self.pin(rc_path));manifest.write_text(self.json.dumps(changed))
        with self.assertRaisesRegex(ValueError,'unchanged Native service contract'):bundle.integration_inputs(self.pin(manifest))

    def test_failed_transform_removes_only_new_output_and_preserves_original(self):
        pin=self.prepare_runpath_source();source_bytes=self.manifest.read_bytes();output=self.root/'failed'
        with patch.object(bundle,'_owned_output',return_value=output), \
             patch.object(bundle.subprocess,'check_output',return_value='patchelf fixture'), \
             patch.object(bundle,'runpath_file',side_effect=ValueError('invalid transformation')):
            with self.assertRaisesRegex(ValueError,'invalid transformation'):
                bundle.build_runpath(pin,output,Path('/usr/bin/true'))
        self.assertFalse(output.exists());self.assertEqual(self.manifest.read_bytes(),source_bytes)


if __name__=='__main__':
    unittest.main()
