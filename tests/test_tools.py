import io
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import json
import zlib
import struct
import hashlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import prepare_ipa
import extract_sysroot
import pack_cache
import pack_macho
import copy
import analyze_device_fault
import run_device


class CachePackageTests(unittest.TestCase):
    def test_swift_witness_arguments_are_bound_to_callers_and_data_imports(self):
        base = 0x100000000
        data = bytearray(0x5000)
        struct.pack_into('<3I', data, 0x1000, 0xf0000000, 0xf9400800, 0x940003fe)
        struct.pack_into('<3I', data, 0x2000, 0xd0000010, 0xf9400210, 0xd61f0200)
        library = '/System/Library/Frameworks/SwiftUI.framework/SwiftUI'
        symbol = '_$s4Test1VVAA1PAAMc'
        meta = dict(sliceOffset=0, dependencies=[dict(path='/usr/lib/swift/libswiftCore.dylib'), dict(path=library)],
                    segments=[dict(vmAddress=base+0x4000, vmSize=0x1000, protection=3)], sections=[
                    dict(segmentName='__TEXT', name=name, vmAddress=base+offset, fileOffset=offset, size=12)
                    for name, offset in [('__text',0x1000), ('__stubs',0x2000)]])
        fixups = dict(preferredBase=base, imports=[
            dict(name=name, libraryOrdinal=ordinal, weak=False, addend=0)
            for name, ordinal in [('_swift_getWitnessTable',1),(symbol,2)]], fixups=[
            dict(vmOffset=slot, authentication=None, target={'kind':'bind','import':index,'addend':0})
            for index, slot in enumerate([0x4000,0x4010])])
        self.assertEqual(pack_macho.swift_witness_arguments(data, meta, fixups), [(0x4010,0x100c,library,symbol)])
        bad = copy.deepcopy(meta)
        bad['segments'][0]['protection'] = 5
        with self.assertRaises(ValueError):
            pack_macho.swift_witness_arguments(data, bad, fixups)
        bad = copy.deepcopy(fixups)
        bad['imports'][1]['addend'] = 1
        with self.assertRaises(ValueError):
            pack_macho.swift_witness_arguments(data, meta, bad)
        bad = copy.deepcopy(fixups)
        bad['imports'][0]['name'] = '_other_runtime_function'
        self.assertEqual(pack_macho.swift_witness_arguments(data, meta, bad), [])

    def test_swift_conformance_exports_require_readonly_noninstruction_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            base, page = 0x180000000, 0x4000
            data = bytearray(page * 2)
            name = b'_$s4Test1VMc'
            root = b'\0\1' + name + b'\0' + bytes([len(name)+4])
            trie = root + b'\3\0\x80\x20\0'
            struct.pack_into('<8I',data,0,0xfeedfacf,0x100000c,0,6,3,240,0,0)
            struct.pack_into('<II16sQQQQiiII',data,32,25,152,b'__TEXT',base,page,0,page,5,5,1,0)
            struct.pack_into('<16s16sQQIIIIIIII',data,104,b'__const',b'__TEXT',base+0x1000,0x100,
                             0x1000,2,0,0,0,0,0,0)
            struct.pack_into('<II16sQQQQiiII',data,184,25,72,b'__LINKEDIT',base+page,page,page,len(trie),1,1,0,0)
            struct.pack_into('<4I',data,256,0x80000033,16,page,len(trie))
            data[page:page+len(trie)] = trie
            path = Path(directory)/'owned-swift-metadata'
            path.write_bytes(data)
            cache = dict(preferredBase=base, images=[dict(path='/swift',address=base)], files=[dict(path=str(path), mappings=[
                dict(address=base+i*page,size=page,fileOffset=i*page,protection=p,maxProtection=p)
                for i,p in enumerate([5,1])])])
            self.assertEqual(pack_cache.export_offset(cache,'/swift',name.decode(),swift_conformance=True),0x1000)
            with self.assertRaises(ValueError):
                pack_cache.export_offset(cache,'/swift',name.decode())
            struct.pack_into('<I',data,168,0x80000400) # an instruction section is never metadata
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                pack_cache.export_offset(cache,'/swift',name.decode(),swift_conformance=True)

    def test_swift_opaque_arguments_require_audited_thunks_and_local_descriptors(self):
        base = 0x100000000
        data = bytearray(0x5000)
        def adrp(register, source, target):
            immediate = ((target // 4096) - (source // 4096)) & 0x1fffff
            return 0x90000000 | ((immediate & 3) << 29) | ((immediate >> 2) << 5) | register
        struct.pack_into('<4I', data, 0x1000, adrp(1, base+0x1000, base+0x3000),
                         0x91004021, 0x52800022, 0x140003fd)
        struct.pack_into('<3I', data, 0x2000, adrp(16, base+0x2000, base+0x4000),
                         0xf9400210, 0xd61f0200)
        struct.pack_into('<Ii', data, 0x3010, 0x200c4, -20)
        meta = dict(sliceOffset=0, dependencies=[dict(path='/usr/lib/swift/libswiftCore.dylib')], sections=[
            dict(segmentName='__TEXT', name=name, vmAddress=base+offset, fileOffset=offset, size=size)
            for name, offset, size in [('__text',0x1000,16), ('__stubs',0x2000,12), ('__constg_swiftt',0x3000,32)]])
        fixups = dict(preferredBase=base, imports=[dict(name='_swift_getOpaqueTypeConformance2',
                      libraryOrdinal=1, weak=False, addend=0)], fixups=[dict(vmOffset=0x4000,
                      authentication=None, target=dict(kind='bind', import_=0, addend=0))])
        fixups['fixups'][0]['target']['import'] = fixups['fixups'][0]['target'].pop('import_')
        self.assertEqual(pack_macho.swift_opaque_arguments(data, meta, fixups),
                         [(0x3010, 0xffffffec000200c4, 0x1000)])
        for at, value in [(0x3010, 17), (0x3014, 0x4000)]:
            bad = bytearray(data)
            struct.pack_into('<I', bad, at, value)
            with self.assertRaises(ValueError):
                pack_macho.swift_opaque_arguments(bad, meta, fixups)
        bad = copy.deepcopy(fixups)
        bad['fixups'][0]['authentication'] = dict(key=2)
        with self.assertRaises(ValueError):
            pack_macho.swift_opaque_arguments(data, meta, bad)
        bad = copy.deepcopy(fixups)
        bad['imports'][0]['name'] = '_some_other_function'
        self.assertEqual(pack_macho.swift_opaque_arguments(data, meta, bad), [])
        bad = copy.deepcopy(meta)
        bad['sections'][2]['segmentName'] = '__DATA'
        with self.assertRaises(ValueError):
            pack_macho.swift_opaque_arguments(data, bad, fixups)

    def test_dependency_depth_limits_transitive_cache_images(self):
        cache = {'images': [
            {'path': '/A', 'address': 1},
            {'path': '/B', 'address': 2},
            {'path': '/C', 'address': 3},
            {'path': '/D', 'address': 4},
        ]}
        def image_segments(cache, address, kind, reexports=None, dependencies=None):
            links = {
                1: (['/B', '/D'], ['/D']),
                2: (['/C'], []),
                3: (['/A'], []),
                4: (['/A'], []),
            }
            deps, reexports_here = links[address]
            dependencies.extend(deps)
            reexports.extend(reexports_here)
            return [{'name': '__TEXT', 'address': address, 'size': 1}], [(address, 1)]
        demand = {'images': ['/A'], 'dependencyDepth': 2, 'reexports': True}
        with patch.object(pack_cache, 'image_segments', side_effect=image_segments):
            images = pack_cache.demand_images(cache, demand)
        self.assertEqual([image['path'] for image in images], ['/A', '/B', '/D', '/C'])
        self.assertEqual([image['closureDepth'] for image in images], [0, 1, 1, 2])

    def test_objc_bindings_resolve_only_direct_data_exports_without_cycles(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            data = bytearray(3 * page)
            name = b'_OBJC_CLASS_$_Own'
            def uleb(value):
                result = bytearray()
                while value >= 128:
                    result.append((value & 127) | 128)
                    value >>= 7
                return bytes(result) + bytes([value])
            child = 2 + len(name) + 2
            root = b'\0\1' + name + b'\0' + bytes([child])
            def trie(target=page, flags=0):
                payload = uleb(flags) + uleb(target)
                return root + bytes([len(payload)]) + payload + b'\0'
            blob = trie()
            struct.pack_into('<8I', data, 0, 0xfeedfacf, 0x100000c, 0, 6, 4, 232, 0, 0)
            mappings = []
            for index, (segment_name, protection) in enumerate([
                    (b'__TEXT', 5), (b'__DATA', 3), (b'__LINKEDIT', 1)]):
                struct.pack_into('<II16sQQQQiiII', data, 32 + index * 72, 25, 72, segment_name,
                                 base + index * page, page, index * page, page,
                                 protection, protection, 0, 0)
                mappings.append(dict(address=base + index * page, size=page,
                                     fileOffset=index * page, protection=protection, maxProtection=protection))
            struct.pack_into('<4I', data, 248, 0x80000033, 16, 2 * page, len(blob))
            source = Path(directory) / 'owned-objc-exports'
            cache = dict(preferredBase=base, images=[dict(address=base, path='/libOwn')],
                         files=[dict(path=str(source), mappings=mappings)])
            data[2 * page:2 * page + len(blob)] = blob
            source.write_bytes(data)
            self.assertEqual(pack_cache.export_offset(cache, '/libOwn', name.decode()), page)
            for invalid in [trie(flags=8), trie(flags=0x20), trie(target=0), root[:-1] + b'\0' + blob[len(root):]]:
                modified = bytearray(data)
                modified[2 * page:2 * page + len(invalid)] = invalid
                source.write_bytes(modified)
                with self.assertRaises(ValueError):
                    pack_cache.export_offset(cache, '/libOwn', name.decode())

    def test_arm64_objc_ro_adapter_records_only_local_bounded_class_metadata(self):
        base = 0x100000000
        data = bytearray(0x4000)
        struct.pack_into('<8I', data, 0, 0xfeedfacf, 0x100000c, 0, 2, 2, 224, 0, 0)
        for at, name, address, offset, prot, sections, length in [
                (32, b'__TEXT', base, 0, 5, 0, 72),
                (104, b'__DATA', base + 0x2000, 0x2000, 3, 1, 152)]:
            struct.pack_into('<II16sQQQQiiII', data, at, 25, length, name,
                             address, 0x2000, offset, 0x2000, prot, prot, sections, 0)
        data[176:192] = b'__objc_classlist'
        struct.pack_into('<QQ', data, 208, base + 0x2100, 8)
        meta = dict(sliceOffset=0, segments=[
            dict(vmAddress=base, vmSize=0x2000, protection=5),
            dict(vmAddress=base + 0x2000, vmSize=0x2000, protection=3)])
        fixups = dict(preferredBase=base, fixups=[
            dict(vmOffset=slot, target=dict(kind='rebase', offset=target, high8=0), authentication=None)
            for slot, target in [(0x2100, 0x2200), (0x2200, 0x2240),
                                 (0x2220, 0x2302), (0x2260, 0x2348)]])
        self.assertEqual(pack_macho.objc_ro_slots(data, meta, fixups),
                         [(0x2220, 0x2302), (0x2260, 0x2348)])
        for slot, change in [(0, dict(target=dict(kind='bind'))),
                             (2, dict(authentication=dict(key=2))),
                             (2, dict(target=dict(kind='rebase', offset=0x9000, high8=0)))]:
            bad = copy.deepcopy(fixups)
            bad['fixups'][slot].update(change)
            with self.assertRaises(ValueError):
                pack_macho.objc_ro_slots(data, meta, bad)
        meta['segments'][1]['protection'] = 1
        with self.assertRaisesRegex(ValueError, 'writable App data'):
            pack_macho.objc_ro_slots(data, meta, fixups)

    def test_shared_stubs_select_their_got_pages_with_signed_adrp_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            data = bytearray(3 * page)
            # A lookalike instruction in the file header must not be decoded.
            struct.pack_into('<II', data, 0, 0x90000011, 0xf9400230)
            for at in [page, page + 16]:
                struct.pack_into('<4I', data, at, 0x90000091, 0x91020231, 0xf9400230, 0xd61f0200)
            source = Path(directory) / 'owned-shared-stubs'
            source.write_bytes(data)
            target = dict(address=base + 9 * page, size=page, fileOffset=2 * page,
                          protection=1, maxProtection=3, flags=0)
            cache = dict(preferredBase=base, files=[dict(path=str(source), mappings=[
                dict(address=base + 4 * page, size=2 * page, fileOffset=0,
                     protection=5, maxProtection=5, flags=8), target])])
            self.assertEqual(pack_cache.stub_data_spans(cache), [[9 * page, 10 * page]])
            target['maxProtection'] = 5
            with self.assertRaisesRegex(ValueError, 'GOT slot'):
                pack_cache.stub_data_spans(cache)
            target.update(address=base + page, maxProtection=3)
            for at in [page, page + 16]:
                struct.pack_into('<I', data, at, 0x90ffff91)  # ADRP -16 * 4096
            source.write_bytes(data)
            self.assertEqual(pack_cache.stub_data_spans(cache), [[page, 2 * page]])

    def test_selector_stub_pages_follow_direct_branches_from_selected_code(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            data = bytearray(6 * page)
            def branch(source, target):
                return 0x94000000 | (((target - source) >> 2) & 0x03ffffff)
            struct.pack_into('<I', data, 0, branch(base, base + 2 * page))
            struct.pack_into('<I', data, 2 * page, branch(base + 2 * page, base + 3 * page))
            source = Path(directory) / 'owned-selector-stubs'
            source.write_bytes(data)
            cache = dict(preferredBase=base, regionSize=6 * page,
                         images=[dict(path='/usr/lib/objc/libobjcMsgSend.dylib', address=base),
                                 dict(path='/System/Library/Frameworks/Test.framework/Test', address=base + 5 * page)],
                         files=[dict(path=str(source), mappings=[dict(address=base, size=6 * page,
                             fileOffset=0, protection=5, maxProtection=5, flags=0)])])
            self.assertEqual(pack_cache.selector_stub_pages(cache, [(base, 4)]), [
                [2 * page, 3 * page], [3 * page, 4 * page]])
            struct.pack_into('<I', data, 0, 0xd503201f)
            source.write_bytes(data)
            self.assertEqual(pack_cache.selector_stub_pages(cache, [(base, 4)]), [])

    def test_selector_stub_pages_include_numbered_msgsend_shards(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            data = bytearray(6 * page)
            struct.pack_into('<I', data, 0, 0x94000000 | (2 * page // 4))
            source = Path(directory) / 'numbered-selector-stubs'
            source.write_bytes(data)
            cache = dict(preferredBase=base, regionSize=6 * page,
                         images=[dict(path='/usr/lib/objc/libobjcMsgSend5.dylib', address=base),
                                 dict(path='/System/Library/Frameworks/Test.framework/Test', address=base + 5 * page)],
                         files=[dict(path=str(source), mappings=[dict(address=base, size=6 * page,
                             fileOffset=0, protection=5, maxProtection=5, flags=0)])])
            self.assertEqual(pack_cache.selector_stub_pages(cache, [(base, 4)]),
                             [[2 * page, 3 * page]])
            cache['images'][0]['path'] = '/usr/lib/objc/libobjcMsgSendOther.dylib'
            self.assertEqual(pack_cache.selector_stub_pages(cache, [(base, 4)]), [])

    def test_executable_header_budget_fills_smallest_original_rx_gap(self):
        page, base = pack_cache.PAGE, 0x180000000
        cache = dict(files=[dict(path='cache', mappings=[dict(address=base,
                     size=12 * page, fileOffset=0, protection=5, maxProtection=5)])])
        ranges = [dict(address=base + at * page, offset=at * page, size=page,
                       path='cache', fileOffset=at * page, protection=5,
                       initialProtection=5) for at in (0, 2, 10)]
        result = pack_cache.coalesce_executable_ranges(cache, ranges, 2)
        self.assertEqual([(r['offset'], r['size']) for r in result],
                         [(0, 3 * page), (10 * page, page)])
        self.assertEqual(ranges[0]['size'], page)
        cache['files'][0]['mappings'] = [
            dict(address=base, size=page, fileOffset=0, protection=5, maxProtection=5),
            dict(address=base + 2 * page, size=10 * page, fileOffset=2 * page,
                 protection=5, maxProtection=5)]
        # A gap spanning an unmapped interval cannot become executable.
        result = pack_cache.coalesce_executable_ranges(cache, ranges, 2)
        self.assertEqual(result[0]['size'], page)
        with self.assertRaisesRegex(ValueError, 'Cannot meet ELF'):
            pack_cache.coalesce_executable_ranges(cache, ranges, 1)

    def test_selector_hash_selects_bounded_table_and_referenced_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            data = bytearray(3 * page)
            struct.pack_into('<QQ', data, 464, 512, 48)
            struct.pack_into('<I', data, 512, 4)
            struct.pack_into('<Q', data, 536, page)
            struct.pack_into('<5I', data, page, 0, 4, 2, 62, 3)
            struct.pack_into('<4i', data, page + 1064, page, page + 16, 0, 0)
            data[2 * page:2 * page + 4] = b'one\0'
            data[2 * page + 16:2 * page + 20] = b'two\0'
            source = Path(directory) / 'owned-selector-cache'
            source.write_bytes(data)
            cache = dict(preferredBase=base, files=[dict(path=str(source), mappings=[
                dict(address=base, size=len(data), fileOffset=0, protection=1)])])
            self.assertEqual(pack_cache.selector_ranges(cache),
                             [[0, page], [page, 2 * page], [2 * page, 3 * page]])
            class_data = bytearray(data)
            table = page + 2048
            struct.pack_into('<Q', class_data, 544, table)
            struct.pack_into('<5I', class_data, table, 0, 4, 1, 62, 3)
            struct.pack_into('<i', class_data, table + 1064, 2 * page + 16 - table)
            struct.pack_into('<I', class_data, table + 1112, 1)
            source.write_bytes(class_data)
            self.assertEqual(len(pack_cache.selector_ranges(cache)), 4)
            struct.pack_into('<I', class_data, table + 1112, (1 << 24) + 1)
            source.write_bytes(class_data)
            with self.assertRaisesRegex(ValueError, 'duplicate object count'):
                pack_cache.selector_ranges(cache)
            info_data = bytearray(data)
            struct.pack_into('<QQ', info_data, 520, 768, 900)
            struct.pack_into('<II', info_data, 768, 1, 24)
            struct.pack_into('<q', info_data, 784, 2 * page + 100 - 784)
            struct.pack_into('<II', info_data, 900, 1, 8)
            cache['images'] = [dict(address=base)]
            source.write_bytes(info_data)
            self.assertEqual(len(pack_cache.selector_ranges(cache)), 6)
            struct.pack_into('<I', info_data, 772, 32)
            source.write_bytes(info_data)
            with self.assertRaisesRegex(ValueError, 'header info table'):
                pack_cache.selector_ranges(cache)
            for offset, value in [(page + 4, 3), (page + 8, 5), (page + 16, 2),
                                  (page + 1064, 3 * page)]:
                bad = bytearray(data)
                struct.pack_into('<I', bad, offset, value)
                source.write_bytes(bad)
                with self.assertRaises(ValueError):
                    pack_cache.selector_ranges(cache)
            data[2 * page:] = b'x' * page
            source.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'Unterminated'):
                pack_cache.selector_ranges(cache)

    def test_fault_data_ownership_uses_sections_instead_of_nearest_text_header(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            data = bytearray(3 * page)
            for index in range(2):
                offset = index * page
                struct.pack_into('<8I', data, offset, 0xfeedfacf, 0x100000c, 0, 6,
                                 2 if index == 0 else 1, 224 if index == 0 else 72, 0, 0)
                struct.pack_into('<II16sQQQQiiII', data, offset + 32, 25, 72, b'__TEXT',
                                 base + offset, page, offset, page, 5, 5, 0, 0)
            struct.pack_into('<II16sQQQQiiII', data, 104, 25, 152, b'__DATA',
                             base + 2 * page, page, 2 * page, page, 3, 3, 1, 0)
            data[176:192] = b'__thread_vars'.ljust(16, b'\0')
            struct.pack_into('<QQ', data, 208, base + 2 * page + 128, 24)
            source = Path(directory) / 'owned-section-cache'
            source.write_bytes(data)
            cache = dict(images=[dict(address=base, path='/owner'),
                                 dict(address=base + page, path='/later-header')],
                         files=[dict(path=str(source), mappings=[
                             dict(address=base, size=len(data), fileOffset=0)])])
            found = analyze_device_fault.find_image(cache, base + 2 * page + 136)
            self.assertEqual((found['path'], found['section']), ('/owner', '__thread_vars'))
            self.assertEqual(analyze_device_fault.find_image(cache, base + page + 16)['path'],
                             '/later-header')
            self.assertIsNone(analyze_device_fault.find_image(cache, base + 2 * page + 512))
            self.assertIsNone(analyze_device_fault.find_image(cache, base + 4 * page))

    def test_thread_variable_descriptors_are_writable_bounded_triples(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            image = bytearray(page)
            struct.pack_into('<8I', image, 0, 0xfeedfacf, 0x100000c, 0, 6, 1, 152, 0, 0)
            struct.pack_into('<II16sQQQQiiII', image, 32, 25, 152, b'__DATA',
                             base, page, 0, page, 3, 3, 1, 0)
            struct.pack_into('<QQ', image, 136, base + 512, 48)
            struct.pack_into('<I', image, 168, 0x13)
            source = Path(directory) / 'owned-tlv-cache'
            source.write_bytes(image)
            cache = dict(files=[dict(path=str(source), mappings=[
                dict(address=base, size=page, fileOffset=0)])])
            thunks = []
            pack_cache.image_segments(cache, base, 6, thread_variables=thunks)
            self.assertEqual(thunks, [(base + 512, 48)])
            for at, value in [(144, 47), (136, base + 513), (92, 5)]:
                bad = bytearray(image)
                if at == 92:
                    struct.pack_into('<I', bad, at, value)
                else:
                    struct.pack_into('<Q', bad, at, value)
                source.write_bytes(bad)
                with self.assertRaisesRegex(ValueError, 'thread variable'):
                    pack_cache.image_segments(cache, base, 6, thread_variables=[])

    def test_metadata_headers_use_readonly_pages_and_preserve_selected_code(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            image = bytearray(6 * page)
            addresses = [base + page, base + 3 * page + 64, base + 3 * page + 512]
            for address in addresses:
                struct.pack_into('<8I', image, address - base,
                                 0xfeedfacf, 0x100000c, 0, 6, 0, 0, 0, 0)
            source = Path(directory) / 'owned-cache-headers'
            source.write_bytes(image)
            cache = dict(preferredBase=base, regionSize=len(image), images=[
                dict(address=a) for a in addresses], files=[dict(path=str(source), mappings=[
                    dict(address=base, size=page, fileOffset=0, protection=5, maxProtection=5)]),
                    dict(path=str(source), mappings=[
                    dict(address=base + page, size=5 * page, fileOffset=page,
                         protection=5, maxProtection=5)])])
            code = [dict(name='__TEXT', address=base + page, size=page)]
            ranges = pack_cache.select(cache, code, headers=True)
            self.assertEqual([(r['offset'], r['size'], r['protection']) for r in ranges],
                             [(0, 2 * page, 5), (3 * page, page, 1)])
            self.assertEqual(ranges[-1]['fileOffset'], 3 * page)
            struct.pack_into('<I', image, 3 * page + 64 + 20, 1024 * 1024 + 1)
            source.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'metadata header'):
                pack_cache.select(cache, code, headers=True)

    def test_data_pages_are_verified_in_readonly_blob_before_runtime_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            page = pack_cache.PAGE
            content = b'owned-data-page'.ljust(page, b'\0')
            image = bytearray(2 * page)
            image[:6] = b'\x7fELF\x02\x01'
            struct.pack_into('<HH', image, 16, 3, 183)
            struct.pack_into('<Q', image, 32, 64)
            struct.pack_into('<HH', image, 54, 56, 2)
            struct.pack_into('<II6Q', image, 64, 1, 4, 0, 0, 0, 2 * page, 2 * page, page)
            struct.pack_into('<II6Q', image, 120, 1, 4, 2 * page, 4 * page, 4 * page, 0, page, page)
            image[page:] = content
            library = Path(directory) / 'owned-cache-data.so'
            library.write_bytes(image)
            ranges = [dict(offset=0, size=page, protection=3, dataOffset=0,
                           packedSha256=hashlib.sha256(content).hexdigest())]
            pack_cache.verify_elf(library, ranges, 4 * page, page, page)
            image[page] ^= 1
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'contents'):
                pack_cache.verify_elf(library, ranges, 4 * page, page, page)
            image[page:] = content
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'escapes'):
                pack_cache.verify_elf(library, ranges, 4 * page, page, 4 * page)
            ranges[0]['protection'] = 5
            with self.assertRaisesRegex(ValueError, 'non-executable'):
                pack_cache.verify_elf(library, ranges, 4 * page, page, page)

    def test_dylib_links_require_bounded_terminated_install_names(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            image = bytearray(page)
            struct.pack_into('<8I', image, 0, 0xfeedfacf, 0x100000c, 0, 6, 2, 104, 0, 0)
            struct.pack_into('<II16sQQQQiiII', image, 32, 25, 72, b'__TEXT', base, page, 0, page, 5, 5, 0, 0)
            struct.pack_into('<6I', image, 104, 0x8000001f, 32, 24, 0, 0, 0)
            image[128:136] = b'/next\0\0\0'
            source = Path(directory) / 'owned-reexport-cache'
            source.write_bytes(image)
            cache = {'files': [dict(path=str(source), mappings=[dict(address=base, size=page, fileOffset=0)])]}
            names = []
            pack_cache.image_segments(cache, base, 6, names)
            self.assertEqual(names, ['/next'])
            dependencies = []
            pack_cache.image_segments(cache, base, 6, names, dependencies)
            self.assertEqual(dependencies, ['/next'])
            struct.pack_into('<II', image, 104, 0xC, 32)
            source.write_bytes(image)
            dependencies = []
            pack_cache.image_segments(cache, base, 6, [], dependencies)
            self.assertEqual(dependencies, ['/next'])
            struct.pack_into('<II', image, 104, 0x8000001f, 32)
            struct.pack_into('<I', image, 112, 8)
            source.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'name offset'):
                pack_cache.image_segments(cache, base, 6, [])
            struct.pack_into('<I', image, 112, 24)
            image[128:136] = b'nonullll'
            source.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'Unterminated'):
                pack_cache.image_segments(cache, base, 6, [])

    def test_export_trie_uses_linkedit_file_to_vm_translation(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            image = bytearray(2 * page)
            struct.pack_into('<8I', image, 0, 0xfeedfacf, 0x100000c, 0x80000002, 6, 3, 160, 0, 0)
            for at, name, address, file_offset, protection in [
                    (32, b'__TEXT', base, 0, 5), (104, b'__LINKEDIT', base + 4 * page, page, 1)]:
                struct.pack_into('<II16sQQQQiiII', image, at, 25, 72, name, address, page,
                                 file_offset, page, protection, protection, 0, 0)
            struct.pack_into('<4I', image, 176, 0x80000033, 16, page + 8, 32)
            source = Path(directory) / 'owned-export-cache'
            source.write_bytes(image)
            cache = {'files': [dict(path=str(source), mappings=[
                dict(address=base, size=page, fileOffset=0),
                dict(address=base + 4 * page, size=page, fileOffset=page)])]}
            segments, _ = pack_cache.image_segments(cache, base, 6)
            self.assertEqual(segments[1]['exportsAddress'], base + 4 * page + 8)
            self.assertEqual(segments[1]['exportsSize'], 32)
            struct.pack_into('<I', image, 184, 2 * page - 8)
            source.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'escapes LINKEDIT'):
                pack_cache.image_segments(cache, base, 6)

    def test_cached_library_instruction_sections_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            page, base = pack_cache.PAGE, 0x180000000
            image = bytearray(page)
            command_size = 72 + 2 * 80
            struct.pack_into('<8I', image, 0, 0xfeedfacf, 0x100000c, 0x80000002, 6, 1, command_size, 0, 0)
            struct.pack_into('<II16sQQQQiiII', image, 32, 25, command_size, b'__TEXT', base, page, 0, page, 5, 5, 2, 0)
            for i, flags in enumerate([0x80000400, 0]):
                at = 32 + 72 + i * 80
                struct.pack_into('<QQ', image, at + 32, base + 512 + 4 * i, 4)
                struct.pack_into('<I', image, at + 64, flags)
            source = Path(directory) / 'owned-library-cache'
            source.write_bytes(image)
            cache = {'files': [dict(path=str(source), mappings=[dict(address=base, size=page, fileOffset=0)])]}
            segments, code = pack_cache.image_segments(cache, base, 6)
            self.assertEqual(code, [(base + 512, 4)])
            self.assertEqual(segments[0]['size'], page)
            with self.assertRaisesRegex(ValueError, 'header'):
                pack_cache.image_segments(cache, base, 7)
            struct.pack_into('<Q', image, 32 + 72 + 32, base + page)
            source.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'escapes'):
                pack_cache.image_segments(cache, base, 6)

    def test_demand_pages_preserve_gaps_and_reject_unmapped_addresses(self):
        page = pack_cache.PAGE
        cache = {'preferredBase': 0x180000000, 'regionSize': 8 * page, 'files': []}
        def mapping(offset, size):
            return dict(address=cache['preferredBase'] + offset, size=size,
                        fileOffset=page, protection=1, maxProtection=1)
        cache['files'] = [dict(path='header', mappings=[mapping(0, page)]),
                          dict(path='data', mappings=[mapping(4 * page, 3 * page)])]
        ranges = pack_cache.select(cache, [], pages=[5 * page, 4 * page, 5 * page])
        self.assertEqual([(r['offset'], r['size']) for r in ranges], [(0, page), (4 * page, 2 * page)])
        self.assertEqual(ranges[1]['fileOffset'], page)
        for offset in [-page, 1, 8 * page, 2 * page]:
            with self.assertRaises(ValueError):
                pack_cache.select(cache, [], pages=[offset])
        ranges = pack_cache.select(cache, [], spans=[(4 * page, 7 * page)])
        self.assertEqual(ranges[1]['size'], 3 * page)
        for span in [(0, 0), (page, 3 * page), (-page, 0), (4 * page, 9 * page), (1, page)]:
            with self.assertRaises(ValueError):
                pack_cache.select(cache, [], spans=[span])
        stub_mapping = cache['files'][1]['mappings'][0]
        stub_mapping.update(flags=8, maxProtection=5, protection=5)
        ranges = pack_cache.select(cache, [], stubs=True)
        self.assertEqual([(r['offset'], r['size']) for r in ranges], [(0, page), (4 * page, 3 * page)])
        self.assertEqual(ranges[1]['protection'], 5)
        lazy_ranges = pack_cache.select(cache, [], stubs=True, lazy_data=True)
        self.assertEqual([(r['offset'], r['size'], r['protection']) for r in lazy_ranges],
                         [(4 * page, 3 * page, 5)])

    def test_linked_vm_layout_protections_and_page_bytes_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / 'owned-cache.so'
            page = pack_cache.PAGE
            content = b'owned-cache-fixture'.ljust(page, b'\0')
            image = bytearray(2 * page)
            image[:6] = b'\x7fELF\x02\x01'
            struct.pack_into('<HH', image, 16, 3, 183)
            struct.pack_into('<Q', image, 32, 64)
            struct.pack_into('<HH', image, 54, 56, 1)
            struct.pack_into('<II6Q', image, 64, 1, 4, page, page, page, page, page, page)
            image[page:] = content
            library.write_bytes(image)
            ranges = [{'offset': 0, 'size': page, 'protection': 1,
                       'packedSha256': hashlib.sha256(content).hexdigest()}]
            pack_cache.verify_elf(library, ranges, page, page)
            image[page] ^= 1
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'contents'):
                pack_cache.verify_elf(library, ranges, page, page)
            image[page:] = content
            struct.pack_into('<I', image, 68, 7)
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'permissions'):
                pack_cache.verify_elf(library, ranges, page, page)
            struct.pack_into('<I', image, 68, 4)
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'reserve'):
                pack_cache.verify_elf(library, ranges, page, page * 2)
            struct.pack_into('<H', image, 56, 293)
            library.write_bytes(image)
            pack_cache.verify_elf(library, ranges, page, page)
            with self.assertRaisesRegex(ValueError, 'program-header byte limit'):
                pack_cache.verify_elf(library, ranges, page, page, max_header_bytes=16384)
            struct.pack_into('<H', image, 56, 2049)
            library.write_bytes(image)
            with self.assertRaisesRegex(ValueError, 'Invalid ELF program header'):
                pack_cache.verify_elf(library, ranges, page, page)


class ImportTests(unittest.TestCase):
    def make_ipa(self, path, extra=None, executable="Hello"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Payload/Hello.app/Info.plist", plistlib.dumps({
                "CFBundleExecutable": executable, "CFBundleIdentifier": "test.hello",
                "MinimumOSVersion": "27.0",
            }))
            archive.writestr("Payload/Hello.app/Hello", prepare_ipa.make_probe())
            if extra:
                archive.writestr(*extra)

    def test_stages_original_executable_and_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ipa = root / "Hello.ipa"
            self.make_ipa(ipa)
            with patch.object(prepare_ipa, "ROOT", root), patch.object(prepare_ipa, "RAW", root / "raw"), patch("sys.stdout", io.StringIO()):
                prepare_ipa.stage(ipa)
            self.assertEqual((root / "raw/target/executable").read_bytes(), prepare_ipa.make_probe())
            self.assertTrue((root / "artifacts/imported/Hello.app/Info.plist").exists())
            self.assertEqual((root / "raw/target/bundle/Hello").read_bytes(), prepare_ipa.make_probe())
            manifest = json.loads((root / "raw/target/manifest.json").read_text())
            self.assertEqual(manifest['bundleDirectory'], 'Hello.app')
            self.assertEqual(manifest['bundleFiles'], ['Hello', 'Info.plist'])

    def test_rejects_archive_traversal_and_symlinks_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["../escape", "/escape", "Payload/Hello.app/../../escape", "Payload\\escape"]:
                ipa = root / "bad.ipa"
                self.make_ipa(ipa, (name, b"bad"))
                with self.assertRaises(ValueError):
                    prepare_ipa.stage(ipa)
            link = zipfile.ZipInfo("Payload/Hello.app/link")
            link.create_system = 3
            link.external_attr = 0o120777 << 16
            self.make_ipa(ipa, (link, "../../escape"))
            with self.assertRaises(ValueError):
                prepare_ipa.stage(ipa)


    def test_rejects_executable_path_in_plist(self):
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / "bad.ipa"
            self.make_ipa(ipa, executable="../escape")
            with self.assertRaises(ValueError):
                prepare_ipa.stage(ipa)


class SystemImageTests(unittest.TestCase):
    def test_only_completed_crc_verified_download_can_be_decrypted(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'SystemOS.dmg.aea'
            archive.with_suffix('.aea.partial').write_bytes(b'partial')
            with self.assertRaises(ValueError):
                extract_sysroot.wait_for_download(archive, None)
            archive.write_bytes(b'owned-system-image-fixture')
            meta = archive.with_suffix('.aea.source.json')
            source = {'size': archive.stat().st_size, 'crc32': zlib.crc32(archive.read_bytes())}
            meta.write_text(json.dumps(source))
            self.assertEqual(extract_sysroot.wait_for_download(archive, None), source)
            corrupted = bytearray(archive.read_bytes())
            corrupted[0] ^= 1
            archive.write_bytes(corrupted)
            with self.assertRaises(ValueError):
                extract_sysroot.wait_for_download(archive, None)

class DeviceCommandTests(unittest.TestCase):
    def test_command_output_tolerates_invalid_utf8(self):
        result = run_device.run(
            [sys.executable, '-c', 'import sys; sys.stdout.buffer.write(bytes([255]))'], capture=True)
        self.assertEqual(result.stdout, '\ufffd')

    def test_device_run_restarts_after_debug_sandbox_staging(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            hap = output / 'app.hap'
            hap.touch()
            events = []
            def run(command, **kwargs):
                events.append(command)
                return subprocess.CompletedProcess(command, 0, '', '')
            report = {'dyldBootstrap': {'status': 'cache-data-not-staged', 'faultPc': '0'}}
            with patch.object(sys, 'argv', ['run_device', '--skip-build', '--skip-install',
                                           '--output', str(output)]), \
                    patch.object(run_device, 'HAP', hap), \
                    patch.object(run_device, 'run', side_effect=run), \
                    patch.object(run_device, 'stage_cache_data', side_effect=lambda _: events.append('stage')), \
                    patch.object(run_device, 'launch_application', side_effect=lambda _: events.append('launch')), \
                    patch.object(run_device, 'decode_report', return_value=(report, json.dumps(report))), \
                    patch.object(run_device, 'capture_screenshot', return_value=output / 'screen.jpeg'):
                run_device.main()
            stop = ['hdc', 'shell', 'aa', 'force-stop', run_device.DEFAULT_BUNDLE]
            stage = events.index('stage')
            self.assertEqual(events[stage - 1], stop)
            self.assertEqual(events[stage + 1], stop)
            self.assertGreater(events.index('launch'), stage + 1)
            self.assertTrue((output / 'device-compat-report.json').is_file())

    def test_only_cache_faults_request_cache_analysis(self):
        self.assertFalse(run_device.has_cache_fault({'faultPc': '0', 'status': 'cache-data-not-staged'}))
        self.assertFalse(run_device.has_cache_fault({'faultPc': '123', 'detail': 'PC dyld+0x123'}))
        self.assertTrue(run_device.has_cache_fault({'faultPc': '123', 'detail': 'PC cache+0x123, fault'}))

    def test_cache_data_staging_uses_path_below_debug_mount(self):
        from types import SimpleNamespace
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            pack = output / 'cache-data.pack'
            pack.write_bytes(b'cache fixture')
            manifest = {'bytes': pack.stat().st_size, 'primaryUUID': 'uuid',
                        'sha256': hashlib.sha256(pack.read_bytes()).hexdigest()}
            pack.with_suffix('.pack.json').write_text(json.dumps(manifest))
            pages = output / 'pages.json'
            pages.write_text(json.dumps({'primaryUUID': 'uuid'}))
            args = SimpleNamespace(cache_data_pack=pack, stage_cache_data=True, output=output,
                                   device=None, bundle='app', warm_up=False)
            results = [subprocess.CompletedProcess([], 0, '', ''),
                       subprocess.CompletedProcess([], 0, 'FileTransfer finish', ''),
                       subprocess.CompletedProcess([], 0, 'FileTransfer finish', '')]
            with patch.object(run_device, 'PAGES', pages), \
                    patch.object(run_device, 'run', side_effect=results) as run:
                run_device.stage_cache_data(args)
            remote = 'data/storage/el2/base/haps/harmonios/files/sysroot/cache-data.pack'
            self.assertEqual(run.call_args_list[1].args[0],
                             ['hdc', 'file', 'send', '-b', 'app', '-z', pack.resolve(), remote])

    def test_incomplete_run_preserves_logs_when_screenshot_fails(self):
        from types import SimpleNamespace
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(bundle='fun.oboard.hamintosh', device='phone',
                                   output=Path(directory))
            results = [subprocess.CompletedProcess([], 1, '', ''),
                       subprocess.CompletedProcess([], 0, 'guest waiting', ''),
                       subprocess.CompletedProcess([], 0, 'fatal signal evidence', '')]
            with patch.object(run_device, 'run', side_effect=results) as run, \
                    patch.object(run_device, 'capture_screenshot', side_effect=RuntimeError('offline')):
                evidence = run_device.capture_incomplete_run(args, 'partial report')
            self.assertFalse(evidence['processObservedAlive'])
            self.assertEqual(evidence['screenshotError'], 'offline')
            self.assertEqual((args.output / 'report-device-incomplete.log').read_text(), 'partial report')
            self.assertEqual((args.output / 'incomplete-system.log').read_text(), 'fatal signal evidence')
            self.assertEqual(json.loads((args.output / 'incomplete-run.json').read_text()), evidence)
            self.assertEqual(run.call_args_list[0].args[0],
                             ['hdc', '-t', 'phone', 'shell', 'pidof', args.bundle])

    def test_incomplete_run_distinguishes_pid_from_device_errors(self):
        from types import SimpleNamespace
        import subprocess
        for code, output, alive in [(0, '123 456\n', True),
                                    (0, '[Fail] device offline', False),
                                    (1, '123', False)]:
            with self.subTest(code=code, output=output), tempfile.TemporaryDirectory() as directory:
                args = SimpleNamespace(bundle='app', device=None, output=Path(directory))
                result = subprocess.CompletedProcess([], code, output, '')
                with patch.object(run_device, 'run', return_value=result), \
                        patch.object(run_device, 'capture_screenshot', return_value=Path(directory) / 'screen.jpeg'):
                    evidence = run_device.capture_incomplete_run(args, '')
                self.assertEqual(evidence['processObservedAlive'], alive)

    def test_launch_command_uses_explicit_bundle_and_ability(self):
        from types import SimpleNamespace
        args = SimpleNamespace(bundle='fun.oboard.hamintosh', ability='HarmoniosAbility')
        self.assertEqual(
            run_device.launch_command(args),
            ['aa', 'start', '-a', 'HarmoniosAbility', '-b', 'fun.oboard.hamintosh'],
        )


if __name__ == "__main__":
    unittest.main()
