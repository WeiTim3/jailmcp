#!/usr/bin/env python3
"""0.3.5 file-interface tests: unittest, real temp directories, real dirfd semantics.

Offline only; no production token, service or device access. Every fixture lives in a
temporary directory and drives bridge.invoke() with the real maintenance_runtime
anchors (only STATE and the UID assertion are substituted, as test_api does).
"""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'source-v030'))
import bridge as b
import maintenance_runtime as rt

# Minis shared mount reports physical UID501 to fstat() while the process runs as
# another user; plain Linux and the device need no shim. Test-only metadata
# normalization, exactly as test_api.py does it.
probe = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY)
SHARED_METADATA = os.fstat(probe).st_uid != os.stat('/tmp').st_uid
os.close(probe)
REAL_FSTAT = os.fstat

def test_fstat(fd):
    st = REAL_FSTAT(fd)
    values = list(st)
    values[4] = os.geteuid()
    values[0] = (st.st_mode & ~0o777) | (0o700 if stat.S_ISDIR(st.st_mode) else 0o600)
    return os.stat_result(values)

def oct_mode(value):
    return int(value, 8) & 0o777

class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = self.base / '.bridge-state'
        self.state.mkdir(mode=0o700)
        self.project = self.base / 'project'
        self.project.mkdir()
        self.other = self.base / 'other'
        self.other.mkdir()
        for patcher in (patch.object(rt, 'STATE', self.state), patch.object(rt, 'mobile')):
            patcher.start()
            self.addCleanup(patcher.stop)
        if SHARED_METADATA:
            patcher = patch.object(os, 'fstat', side_effect=test_fstat)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.configure({'main': str(self.project), 'second': str(self.other)})

    def configure(self, projects):
        rt.save('config-v030.json', {'projects': projects, 'allow_mobile_shell': True})
        rt.save('active-v030.json', {'current': 'a' * 64, 'previous': None})

    def put(self, name, data=b'abc', mode=None):
        path = self.project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if mode is not None:
            path.chmod(mode)
        return path

    def call(self, name, **args):
        return b.invoke(name, args)

    def refused(self, name, **args):
        with self.assertRaises((ValueError, OSError)) as caught:
            self.call(name, **args)
        return caught.exception


class ListDir(Fixture):
    def setUp(self):
        super().setUp()
        self.put('a.bin', b'12345')
        self.put('b.bin', b'B' * 32)
        (self.project / 'sub').mkdir()
        self.put('sub/c.txt', b'hi')
        (self.project / 'zlink').symlink_to('b.bin')

    def test_paging_sorted_and_bounded(self):
        first = self.call('jb_list_dir', project='main', limit=2)
        self.assertEqual([e['name'] for e in first['entries']], ['a.bin', 'b.bin'])
        self.assertEqual((first['total'], first['returned'], first['has_more']), (4, 2, True))
        second = self.call('jb_list_dir', project='main', limit=2, offset=2)
        self.assertEqual([e['name'] for e in second['entries']], ['sub', 'zlink'])
        self.assertEqual((second['total'], second['returned'], second['has_more']), (4, 2, False))
        beyond = self.call('jb_list_dir', project='main', limit=2, offset=9)
        self.assertEqual((beyond['returned'], beyond['has_more']), (0, False))

    def test_entry_types_and_lstat_metadata(self):
        entries = {e['name']: e for e in self.call('jb_list_dir', project='main', path='')['entries']}
        target = self.project / 'a.bin'
        self.assertEqual(entries['a.bin']['type'], 'file')
        self.assertEqual(entries['a.bin']['size'], 5)
        self.assertEqual(entries['a.bin']['is_symlink'], False)
        self.assertEqual(entries['a.bin']['mtime'], int(target.stat().st_mtime))
        if not SHARED_METADATA:
            self.assertEqual(oct_mode(entries['a.bin']['mode']), 0o644)
        self.assertEqual(entries['sub']['type'], 'dir')
        # The symlink is reported with the LINK's own metadata: st_size is the
        # length of the target string (5), not the size of b.bin (32).
        self.assertEqual(entries['zlink']['type'], 'symlink')
        self.assertTrue(entries['zlink']['is_symlink'])
        self.assertEqual(entries['zlink']['size'], len('b.bin'))
        self.assertNotEqual(entries['zlink']['size'], (self.project / 'b.bin').stat().st_size)
        listed = self.call('jb_list_dir', project='main', path='sub')
        self.assertEqual([e['name'] for e in listed['entries']], ['c.txt'])
        self.assertEqual(listed['path'], 'sub')

    def test_other_file_types_reported(self):
        if SHARED_METADATA:
            self.skipTest('Minis shared mount cannot create FIFO; plain Linux covers this test')
        os.mkfifo(self.project / 'pipe')
        entries = {e['name']: e for e in self.call('jb_list_dir', project='main')['entries']}
        self.assertEqual(entries['pipe']['type'], 'other')

    def test_limit_and_offset_bounds_rejected(self):
        for args in ({'limit': 1001}, {'limit': 0}, {'limit': -1}, {'limit': True},
                     {'limit': '5'}, {'limit': 5.0}, {'offset': -1}, {'offset': True},
                     {'offset': '0'}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.call('jb_list_dir', project='main', **args)
        self.assertEqual(self.call('jb_list_dir', project='main', limit=1000)['limit'], 1000)

    def test_paths_refused(self):
        for path in ('../other', '/etc', '.', '..', '.bridge-state', 'a.bin/..',
                     'sub/../../other', 'x\x00', 'sub//c.txt', './sub'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.call('jb_list_dir', project='main', path=path)
        # A symlinked directory is never entered, even for plain listing.
        self.refused('jb_list_dir', project='main', path='zlink')
        (self.project / 'dirlink').symlink_to(self.other, target_is_directory=True)
        self.refused('jb_list_dir', project='main', path='dirlink')
        self.refused('jb_list_dir', project='main', path='dirlink/inside')
        self.refused('jb_list_dir', project='missing')
        # A regular file is not a directory.
        self.refused('jb_list_dir', project='main', path='a.bin')


class Stat(Fixture):
    def test_regular_file(self):
        self.put('data.bin', b'hello world', mode=0o640)
        result = self.call('jb_stat', project='main', path='data.bin')
        self.assertEqual(result['type'], 'file')
        self.assertEqual(result['size'], 11)
        self.assertEqual(result['nlink'], 1)
        self.assertEqual(result['is_symlink'], False)
        self.assertEqual(result['sha256'], hashlib.sha256(b'hello world').hexdigest())
        self.assertIsNone(result['sha256_skipped'])
        self.assertIsNone(result['target'])
        self.assertEqual(result['uid'], os.geteuid())
        self.assertEqual(result['gid'], os.stat(self.project / 'data.bin').st_gid)
        self.assertEqual(result['mtime'], int((self.project / 'data.bin').stat().st_mtime))
        if not SHARED_METADATA:
            self.assertEqual(oct_mode(result['mode']), 0o640)

    def test_symlink_target_reported_without_following(self):
        if SHARED_METADATA:
            self.skipTest('Minis shared mount cannot create symlinks; plain Linux covers this test')
        self.put('real.bin', b'R' * 64)
        (self.project / 'link.bin').symlink_to('real.bin')
        result = self.call('jb_stat', project='main', path='link.bin')
        self.assertEqual(result['type'], 'symlink')
        self.assertTrue(result['is_symlink'])
        self.assertEqual(result['target'], 'real.bin')
        self.assertEqual(result['size'], len('real.bin'))
        self.assertIsNone(result['sha256'])
        self.assertEqual(result['sha256_skipped'], 'symlink-not-followed')
        dangling = self.call('jb_stat', project='main', path='link.bin')['target']
        self.assertEqual(dangling, 'real.bin')
        (self.project / 'broken').symlink_to('nowhere')
        broken = self.call('jb_stat', project='main', path='broken')
        self.assertEqual(broken['target'], 'nowhere')
        self.assertIsNone(broken['sha256'])

    def test_oversize_file_skips_hash(self):
        self.put('big.bin', b'x' * (b.STAT_HASH_LIMIT + 1))
        result = self.call('jb_stat', project='main', path='big.bin')
        self.assertEqual(result['size'], b.STAT_HASH_LIMIT + 1)
        self.assertIsNone(result['sha256'])
        self.assertEqual(result['sha256_skipped'], 'larger-than-hash-limit')
        self.assertEqual(result['hash_limit'], b.STAT_HASH_LIMIT)
        self.put('edge.bin', b'y' * b.STAT_HASH_LIMIT)
        self.assertEqual(self.call('jb_stat', project='main', path='edge.bin')['sha256'],
                         hashlib.sha256(b'y' * b.STAT_HASH_LIMIT).hexdigest())

    def test_directory_and_special_files_skip_hash(self):
        (self.project / 'sub').mkdir()
        result = self.call('jb_stat', project='main', path='sub')
        self.assertEqual(result['type'], 'dir')
        self.assertIsNone(result['sha256'])
        self.assertEqual(result['sha256_skipped'], 'not-a-regular-file')

    def test_hardlink_skips_hash(self):
        source = self.put('linked.bin', b'z')
        os.link(source, self.project / 'alias.bin')
        result = self.call('jb_stat', project='main', path='alias.bin')
        self.assertEqual(result['nlink'], 2)
        self.assertIsNone(result['sha256'])
        self.assertEqual(result['sha256_skipped'], 'multiple-links')

    def test_missing_and_traversal_refused(self):
        self.refused('jb_stat', project='main', path='absent.bin')
        for path in ('../other', '/etc/passwd', '.bridge-state', '.bridge-state/token', 'a/../b'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.call('jb_stat', project='main', path=path)


class Delete(Fixture):
    def test_file_and_symlink(self):
        target = self.put('gone.bin', b'x')
        result = self.call('jb_delete', project='main', path='gone.bin')
        self.assertTrue(result['deleted'])
        self.assertEqual(result['counts'], {'files': 1, 'directories': 0, 'symlinks': 0,
                                            'others': 0, 'entries': 1})
        self.assertFalse(target.exists())
        if not SHARED_METADATA:
            keep = self.put('keep.bin', b'keep')
            (self.project / 'link').symlink_to('keep.bin')
            outcome = self.call('jb_delete', project='main', path='link')
            self.assertEqual(outcome['counts']['symlinks'], 1)
            self.assertFalse((self.project / 'link').exists())
            self.assertEqual(keep.read_bytes(), b'keep')

    def test_empty_directory_only(self):
        (self.project / 'empty').mkdir()
        result = self.call('jb_delete', project='main', path='empty')
        self.assertEqual(result['counts']['directories'], 1)
        self.assertFalse((self.project / 'empty').exists())

    def test_nonempty_directory_needs_recursive_and_confirm(self):
        self.put('tree/inner.bin', b'x')
        self.refused('jb_delete', project='main', path='tree')
        self.refused('jb_delete', project='main', path='tree', recursive=True)
        self.refused('jb_delete', project='main', path='tree', confirm=True)
        self.refused('jb_delete', project='main', path='tree', recursive='yes', confirm=True)
        self.assertTrue((self.project / 'tree/inner.bin').exists())
        result = self.call('jb_delete', project='main', path='tree', recursive=True, confirm=True)
        self.assertEqual(result['counts'], {'files': 1, 'directories': 1, 'symlinks': 0,
                                            'others': 0, 'entries': 2})
        self.assertFalse((self.project / 'tree').exists())

    def test_recursive_never_follows_symlink_out_of_project(self):
        if SHARED_METADATA:
            self.skipTest('Minis shared mount cannot create symlinks; plain Linux covers this test')
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'keep.bin').write_bytes(b'never delete')
        (self.project / 'tree' / 'deep').mkdir(parents=True)
        (self.project / 'tree' / 'inner.bin').write_bytes(b'x')
        (self.project / 'tree' / 'deep' / 'deeper.bin').write_bytes(b'y')
        (self.project / 'tree' / 'escape').symlink_to(outside, target_is_directory=True)
        (self.project / 'tree' / 'deep' / 'escape2').symlink_to(outside / 'keep.bin')
        result = self.call('jb_delete', project='main', path='tree', recursive=True, confirm=True)
        self.assertEqual(result['counts']['files'], 2)
        self.assertEqual(result['counts']['directories'], 2)
        self.assertEqual(result['counts']['symlinks'], 2)
        self.assertFalse((self.project / 'tree').exists())
        self.assertEqual((outside / 'keep.bin').read_bytes(), b'never delete')
        self.assertTrue(outside.is_dir())

    def test_entry_cap_fails_loudly(self):
        for index in range(4):
            self.put('capped/f%d.bin' % index, b'x')
        with patch.object(b, 'MAX_DELETE_ENTRIES', 3):
            self.refused('jb_delete', project='main', path='capped', recursive=True, confirm=True)

    def test_project_root_and_private_state_refused(self):
        keep = self.put('keep.bin', b'keep')
        for path in ('', '.', '..', '/', 'sub/..', 'sub/../..'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.call('jb_delete', project='main', path=path, recursive=True, confirm=True)
        self.refused('jb_delete', project='main', path='.bridge-state', recursive=True, confirm=True)
        self.assertTrue(self.project.is_dir())
        self.assertEqual(keep.read_bytes(), b'keep')
        self.assertFalse((self.project / '.bridge-state').exists())


class Rename(Fixture):
    def test_same_project_move(self):
        source = self.put('from.bin', b'payload')
        result = self.call('jb_rename', project='main', src='from.bin', dst='to.bin')
        self.assertTrue(result['renamed'])
        self.assertFalse(result['overwritten'])
        self.assertFalse(source.exists())
        self.assertEqual((self.project / 'to.bin').read_bytes(), b'payload')
        (self.project / 'sub').mkdir()
        self.call('jb_rename', project='main', src='to.bin', dst='sub/to.bin')
        self.assertEqual((self.project / 'sub/to.bin').read_bytes(), b'payload')

    def test_destination_exists_refused_unless_overwrite(self):
        self.put('a.bin', b'first')
        self.put('b.bin', b'second')
        self.refused('jb_rename', project='main', src='a.bin', dst='b.bin')
        self.assertEqual((self.project / 'a.bin').read_bytes(), b'first')
        self.assertEqual((self.project / 'b.bin').read_bytes(), b'second')
        result = self.call('jb_rename', project='main', src='a.bin', dst='b.bin', overwrite=True)
        self.assertTrue(result['overwritten'])
        self.assertFalse((self.project / 'a.bin').exists())
        self.assertEqual((self.project / 'b.bin').read_bytes(), b'first')

    def test_directory_destination_refused_even_with_overwrite(self):
        self.put('a.bin', b'x')
        (self.project / 'adir').mkdir()
        self.refused('jb_rename', project='main', src='a.bin', dst='adir', overwrite=True)
        self.assertTrue((self.project / 'adir').is_dir())

    def test_traversal_and_cross_project_refused(self):
        self.put('a.bin', b'x')
        (self.project / 'sub').mkdir()
        for src, dst in (('a.bin', '../other/a.bin'), ('a.bin', '/tmp/a.bin'),
                         ('../other/x', 'a.bin'), ('.bridge-state/token', 'a.bin'),
                         ('a.bin', '.bridge-state/token'), ('a.bin', 'sub/../../other'),
                         ('', 'a.bin'), ('a.bin', ''), ('a.bin', '.')):
            with self.subTest(src=src, dst=dst), self.assertRaises(ValueError):
                self.call('jb_rename', project='main', src=src, dst=dst)
        with self.assertRaises(OSError):   # a regular file is not a directory anchor
            self.call('jb_rename', project='main', src='a.bin', dst='a.bin/child')
        self.assertEqual((self.project / 'a.bin').read_bytes(), b'x')
        self.assertFalse((self.other / 'a.bin').exists())

    def test_no_parent_creation_and_symlink_component_refused(self):
        if SHARED_METADATA:
            self.skipTest('Minis shared mount cannot create symlinks; plain Linux covers this test')
        self.put('a.bin', b'x')
        self.assertRaises(OSError, self.call, 'jb_rename', project='main', src='a.bin',
                          dst='newdir/a.bin')
        self.assertFalse((self.project / 'newdir').exists())
        (self.project / 'dirlink').symlink_to(self.other, target_is_directory=True)
        self.refused('jb_rename', project='main', src='a.bin', dst='dirlink/a.bin')
        self.refused('jb_rename', project='main', src='dirlink/x', dst='a.bin')


class Search(Fixture):
    def setUp(self):
        super().setUp()
        self.put('a.txt', b'alpha\n')
        self.put('b.log', b'beta\n')
        self.put('sub/c.txt', b'x = 1\ny = 2\nneedle = 3\n')
        self.put('sub/d.log', b'needle here\n')

    def paths(self, result):
        return sorted(match['path'] for match in result['matches'])

    def test_name_glob(self):
        result = self.call('jb_search', project='main', name_pattern='*.txt')
        self.assertEqual(self.paths(result), ['a.txt', 'sub/c.txt'])
        self.assertFalse(result['truncated'])
        self.assertEqual(result['reasons'], [])
        self.assertEqual(result['matches_count'], 2)
        dirs = self.call('jb_search', project='main', name_pattern='su*')
        self.assertEqual(self.paths(dirs), ['sub'])
        self.assertEqual(dirs['matches'][0]['type'], 'dir')
        absolute = self.call('jb_search', project='main', name_pattern='/etc/*')
        self.assertEqual(absolute['matches'], [])

    def test_content_hits_with_line_numbers(self):
        result = self.call('jb_search', project='main', content='needle', root='sub')
        self.assertEqual(self.paths(result), ['sub/c.txt', 'sub/d.log'])
        by_path = {m['path']: m for m in result['matches']}
        self.assertEqual(by_path['sub/c.txt']['line'], 3)
        self.assertEqual(by_path['sub/c.txt']['excerpt'], 'needle = 3')
        self.assertEqual(by_path['sub/d.log']['line'], 1)
        self.assertEqual(by_path['sub/d.log']['excerpt'], 'needle here')
        self.assertGreater(result['bytes_read'], 0)
        # Both filters together still report ONE entry per file, whichever matched.
        both = self.call('jb_search', project='main', name_pattern='*.txt', content='needle')
        self.assertEqual(self.paths(both), ['a.txt', 'sub/c.txt', 'sub/d.log'])
        combined = {m['path']: m for m in both['matches']}
        self.assertEqual(combined['a.txt']['name_match'], True)
        self.assertIsNone(combined['a.txt']['line'])
        self.assertTrue(combined['sub/c.txt']['name_match'])
        self.assertEqual(combined['sub/c.txt']['line'], 3)
        self.assertFalse(combined['sub/d.log']['name_match'])
        self.assertEqual(combined['sub/d.log']['line'], 1)

    def test_excerpt_is_bounded(self):
        long_line = b'A' * 400 + b'needle' + b'B' * 400 + b'\n'
        self.put('long.txt', long_line)
        result = self.call('jb_search', project='main', content='needle', name_pattern='long*')
        match = result['matches'][0]
        self.assertEqual(match['line'], 1)
        self.assertLessEqual(len(match['excerpt']), b.EXCERPT)
        self.assertIn('needle', match['excerpt'])
        self.assertTrue(match['excerpt_truncated'])
        short = self.call('jb_search', project='main', content='needle', root='sub')
        self.assertFalse(any(m['excerpt_truncated'] for m in short['matches']))

    def test_bounds_are_enforced_and_reported(self):
        limited = self.call('jb_search', project='main', name_pattern='*', limit=1)
        self.assertEqual(limited['matches_count'], 1)
        self.assertTrue(limited['truncated'])
        self.assertEqual(limited['reasons'], ['limit'])
        files = self.call('jb_search', project='main', name_pattern='*', max_files=1)
        self.assertEqual(files['files_scanned'], 1)
        self.assertEqual(files['reasons'], ['files'])
        self.assertTrue(files['truncated'])
        big = self.put('bigdir/big.bin', b'needle' + b'z' * 400)
        small = self.call('jb_search', project='main', root='bigdir', content='needle',
                          max_file_bytes=16)
        self.assertEqual(small['matches'], [])
        self.assertEqual(small['skipped_large'], 1)
        self.assertEqual(small['reasons'], [])
        self.assertGreaterEqual(big.stat().st_size, 400)
        with patch.object(b, 'SEARCH_SECONDS', 0.0):
            timed = self.call('jb_search', project='main', name_pattern='*')
        self.assertTrue(timed['truncated'])
        self.assertEqual(timed['reasons'], ['time'])
        self.assertEqual(timed['matches'], [])
        for args in ({'limit': 1001}, {'limit': 0}, {'max_files': 0}, {'max_files': 100001},
                     {'max_file_bytes': 0}, {'max_file_bytes': 16777217}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.call('jb_search', project='main', name_pattern='*', **args)
        with self.assertRaises(ValueError):
            self.call('jb_search', project='main')
        with self.assertRaises(ValueError):
            self.call('jb_search', project='main', name_pattern='x' * 257)

    def test_symlinked_directory_not_descended(self):
        if SHARED_METADATA:
            self.skipTest('Minis shared mount cannot create symlinks; plain Linux covers this test')
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'hidden.txt').write_bytes(b'outside needle\n')
        (self.project / 'escape').symlink_to(outside, target_is_directory=True)
        self.put('inside.txt', b'inside needle\n')
        names = self.call('jb_search', project='main', name_pattern='*.txt')
        self.assertEqual(self.paths(names), ['a.txt', 'inside.txt', 'sub/c.txt'])
        content = self.call('jb_search', project='main', content='outside needle')
        self.assertEqual(content['matches'], [])
        self.assertGreaterEqual(content['symlink_entries_not_followed'], 1)

    def test_root_bounds_refused(self):
        for root in ('../other', '/etc', '.bridge-state', '.', '..'):
            with self.subTest(root=root), self.assertRaises(ValueError):
                self.call('jb_search', project='main', root=root, name_pattern='*')
        self.refused('jb_search', project='main', root='absent', name_pattern='*')


class Chunks(Fixture):
    def test_multi_chunk_write_reassembles_exactly(self):
        payload = bytes(range(256)) * 1000
        pieces = (payload[:100000], payload[100000:200000], payload[200000:])
        offset = 0
        for index, piece in enumerate(pieces):
            result = self.call('jb_write_chunk', project='main', path='blob.bin', offset=offset,
                               data_base64=base64.b64encode(piece).decode(),
                               final=index == len(pieces) - 1)
            offset += len(piece)
            self.assertEqual(result['written'], len(piece))
            self.assertEqual(result['size'], offset)
            self.assertEqual(result['sha256'], hashlib.sha256(payload[:offset]).hexdigest())
            self.assertEqual(result['synced'], index == len(pieces) - 1)
            self.assertFalse(result['atomic'])
        self.assertEqual((self.project / 'blob.bin').read_bytes(), payload)
        rebuilt = b''
        reading = 0
        while True:
            chunk = self.call('jb_read_chunk', project='main', path='blob.bin', offset=reading,
                              length=131072)
            self.assertEqual(chunk['sha256'], hashlib.sha256(payload).hexdigest())
            self.assertEqual(chunk['total_size'], len(payload))
            rebuilt += base64.b64decode(chunk['data_base64'])
            reading += chunk['returned']
            if chunk['eof']:
                self.assertEqual(reading, len(payload))
                break
        self.assertEqual(rebuilt, payload)
        self.assertEqual(len(pieces), 3)

    def test_full_size_chunk_accepted(self):
        piece = b'q' * b.MAX_CHUNK
        result = self.call('jb_write_chunk', project='main', path='max.bin', offset=0,
                           data_base64=base64.b64encode(piece).decode())
        self.assertEqual(result['written'], b.MAX_CHUNK)
        chunk = self.call('jb_read_chunk', project='main', path='max.bin', length=b.MAX_CHUNK)
        self.assertEqual(base64.b64decode(chunk['data_base64']), piece)
        self.assertTrue(chunk['eof'])

    def test_expected_sha256_compare_and_swap(self):
        self.put('cas.bin', b'original')
        self.refused('jb_write_chunk', project='main', path='cas.bin', offset=0,
                     data_base64=base64.b64encode(b'changed').decode(),
                     expected_sha256='0' * 64)
        self.assertEqual((self.project / 'cas.bin').read_bytes(), b'original')
        self.refused('jb_write_chunk', project='main', path='absent.bin', offset=0,
                     data_base64=base64.b64encode(b'x').decode(), expected_sha256='0' * 64)
        # Without truncate an in-place overwrite keeps the tail: only the written
        # range is replaced, exactly like a POSIX pwrite.
        tail = self.call('jb_write_chunk', project='main', path='cas.bin', offset=0,
                         data_base64=base64.b64encode(b'CH').decode(),
                         expected_sha256=hashlib.sha256(b'original').hexdigest())
        self.assertTrue(tail['cas_checked'])
        self.assertEqual((self.project / 'cas.bin').read_bytes(), b'CHiginal')
        self.assertEqual(tail['sha256'], hashlib.sha256(b'CHiginal').hexdigest())
        self.assertEqual(tail['size'], 8)
        # truncate=True at offset 0 is the way to start a fresh file.
        result = self.call('jb_write_chunk', project='main', path='cas.bin', offset=0,
                           data_base64=base64.b64encode(b'changed').decode(),
                           expected_sha256=hashlib.sha256(b'CHiginal').hexdigest(),
                           truncate=True)
        self.assertEqual(result['sha256'], hashlib.sha256(b'changed').hexdigest())
        self.assertEqual((self.project / 'cas.bin').read_bytes(), b'changed')

    def test_offsets_truncate_and_final(self):
        self.put('x.bin', b'0123456789')
        self.refused('jb_write_chunk', project='main', path='x.bin', offset=11,
                     data_base64=base64.b64encode(b'z').decode())
        self.refused('jb_write_chunk', project='main', path='new.bin', offset=5,
                     data_base64=base64.b64encode(b'z').decode())
        self.refused('jb_read_chunk', project='main', path='x.bin', offset=11)
        edge = self.call('jb_read_chunk', project='main', path='x.bin', offset=10)
        self.assertEqual((edge['returned'], edge['eof']), (0, True))
        result = self.call('jb_write_chunk', project='main', path='x.bin', offset=0,
                           data_base64=base64.b64encode(b'abc').decode(), truncate=True, final=True)
        self.assertEqual(result['size'], 3)
        self.assertTrue(result['truncated'])
        self.assertTrue(result['synced'])
        self.assertEqual((self.project / 'x.bin').read_bytes(), b'abc')
        self.refused('jb_write_chunk', project='main', path='x.bin', offset=2,
                     data_base64=base64.b64encode(b'z').decode(), truncate=True)
        for args in ({'offset': -1}, {'offset': 1 << 41}, {'offset': True}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.call('jb_write_chunk', project='main', path='x.bin', data_base64='',
                          **args)

    def test_length_and_base64_bounds(self):
        self.put('x.bin', b'0123456789')
        for length in (0, -1, b.MAX_CHUNK + 1, True):
            with self.subTest(length=length), self.assertRaises(ValueError):
                self.call('jb_read_chunk', project='main', path='x.bin', length=length)
        with self.assertRaises(ValueError):
            self.call('jb_write_chunk', project='main', path='x.bin', offset=0,
                      data_base64=base64.b64encode(b'z' * (b.MAX_CHUNK + 1)).decode())
        with self.assertRaises(ValueError):
            self.call('jb_write_chunk', project='main', path='x.bin', offset=0,
                      data_base64='not base64!!')
        with self.assertRaises(ValueError):
            self.call('jb_write_chunk', project='main', path='x.bin', offset=0, data_base64=1)
        with self.assertRaises(ValueError):
            self.call('jb_write_chunk', project='main', path='x.bin', offset=0,
                      data_base64=base64.b64encode(b'z').decode(),
                      expected_sha256='short')

    def test_symlinks_hardlinks_and_special_files_refused(self):
        if SHARED_METADATA:
            self.skipTest('Minis shared mount cannot create symlinks; plain Linux covers this test')
        self.put('target.bin', b'target')
        (self.project / 'link.bin').symlink_to('target.bin')
        self.refused('jb_read_chunk', project='main', path='link.bin')
        self.refused('jb_write_chunk', project='main', path='link.bin', offset=0,
                     data_base64=base64.b64encode(b'x').decode())
        self.assertEqual((self.project / 'target.bin').read_bytes(), b'target')
        os.link(self.project / 'target.bin', self.project / 'hard.bin')
        self.refused('jb_read_chunk', project='main', path='hard.bin')
        self.refused('jb_write_chunk', project='main', path='hard.bin', offset=0,
                     data_base64=base64.b64encode(b'x').decode())
        os.mkfifo(self.project / 'pipe')
        self.refused('jb_read_chunk', project='main', path='pipe')
        (self.project / 'adir').mkdir()
        self.refused('jb_read_chunk', project='main', path='adir')
        for path in ('../other/x', '/etc/hosts', '.bridge-state/token'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.call('jb_read_chunk', project='main', path=path)
            with self.assertRaises(ValueError):
                self.call('jb_write_chunk', project='main', path=path, offset=0,
                          data_base64=base64.b64encode(b'x').decode())


class Mkdir(Fixture):
    def test_single_level_default_mode(self):
        result = self.call('jb_mkdir', project='main', path='one')
        self.assertTrue(result['created'])
        self.assertEqual(result['type'], 'dir')
        self.assertEqual(result['name'], 'one')
        self.assertEqual(result['created_components'], ['one'])
        self.assertEqual(result['created_directories'], 1)
        self.assertFalse(result['parents'])
        self.assertEqual(result['requested_mode'], '0o700')
        self.assertTrue((self.project / 'one').is_dir())
        if not SHARED_METADATA:
            self.assertEqual(result['mode'], '0o700')
            self.assertEqual((self.project / 'one').stat().st_mode & 0o777, 0o700)

    def test_parents_false_requires_an_existing_parent(self):
        self.refused('jb_mkdir', project='main', path='missing/leaf')
        self.assertFalse((self.project / 'missing').exists())
        self.refused('jb_mkdir', project='main', path='a/b/c')
        self.assertFalse((self.project / 'a').exists())
        # An existing parent is enough; only the parent has to exist.
        (self.project / 'have').mkdir()
        self.assertEqual(self.call('jb_mkdir', project='main', path='have/leaf')['name'], 'leaf')

    def test_parents_true_creates_the_chain_one_step_at_a_time(self):
        result = self.call('jb_mkdir', project='main', path='a/b/c', parents=True)
        self.assertEqual(result['created_components'], ['a', 'b', 'c'])
        self.assertEqual(result['created_directories'], 3)
        self.assertTrue((self.project / 'a' / 'b' / 'c').is_dir())
        # Existing components are reused and not reported as created.
        again = self.call('jb_mkdir', project='main', path='a/b/d', parents=True)
        self.assertEqual(again['created_components'], ['d'])
        # parents=True is not required to be truthful about which parts existed.
        self.assertEqual(again['created_directories'], 1)

    def test_existing_leaf_refused_and_kind_reported(self):
        (self.project / 'adir').mkdir()
        (self.project / 'afile').write_bytes(b'x')
        for name, kind in (('adir', 'dir'), ('afile', 'file')):
            with self.subTest(name=name), self.assertRaises(ValueError) as caught:
                self.call('jb_mkdir', project='main', path=name)
            self.assertIn('already exists as a %s' % kind, str(caught.exception))
        if not SHARED_METADATA:
            (self.project / 'alink').symlink_to('afile')
            with self.assertRaises(ValueError) as caught:
                self.call('jb_mkdir', project='main', path='alink')
            self.assertIn('already exists as a symlink', str(caught.exception))
            self.assertTrue((self.project / 'alink').is_symlink())
        self.assertEqual((self.project / 'afile').read_bytes(), b'x')
        # A missing leaf under an existing parent is created, not reported.
        self.assertTrue(self.call('jb_mkdir', project='main', path='adir/sub')['created'])

    def test_mode_applied_and_clamped(self):
        for mode, expected in (('0700', 0o700), ('0755', 0o755), ('0750', 0o750),
                               ('0711', 0o711), ('0777', 0o777), ('700', 0o700),
                               ('755', 0o755)):
            with self.subTest(mode=mode):
                result = self.call('jb_mkdir', project='main', path='m' + mode, mode=mode)
                self.assertEqual(result['requested_mode'], oct(expected))
                self.assertTrue((self.project / ('m' + mode)).is_dir())
                if not SHARED_METADATA:
                    self.assertEqual(result['mode'], oct(expected))
                    created = (self.project / ('m' + mode)).stat().st_mode
                    self.assertEqual(created & 0o777, expected)
                    self.assertFalse(created & 0o7000,
                                     'privileged bits must never be set')
        # Nothing outside 0700..0777, no privileged bits, no non-octal or non-string.
        for bad in ('0600', '0700x', '0', '00', '07', '07000', '1700', '2755', '4755',
                    '7777', '0x777', 'not-a-mode', '', ' 0700', '0700 ', 0o700, 700,
                    True, None):
            with self.subTest(mode=bad), self.assertRaises(ValueError):
                self.call('jb_mkdir', project='main', path='bad', mode=bad)

    def test_traversal_absolute_and_private_state_refused(self):
        for path in ('/etc', 'etc/', '', '.', '..', '../other/x', 'a/../b', 'a//b',
                     './a', 'a/./b', '.bridge-state', '.bridge-state/x', 'a/.bridge-state',
                     'x/.bridge-state/y', 'a\x00b'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.call('jb_mkdir', project='main', path=path)
            with self.assertRaises(ValueError):
                self.call('jb_mkdir', project='main', path=path, parents=True)
        self.assertEqual(sorted(p.name for p in self.project.iterdir()), [])
        self.refused('jb_mkdir', project='unknown', path='a')

    def test_symlinked_parent_component_refused(self):
        if SHARED_METADATA:
            self.skipTest('Minis shared mount cannot create symlinks; plain Linux covers this')
        outside = self.other / 'outside'
        outside.mkdir()
        (self.project / 'link').symlink_to(outside, target_is_directory=True)
        self.refused('jb_mkdir', project='main', path='link/sub')
        self.refused('jb_mkdir', project='main', path='link/sub', parents=True)
        self.assertFalse((outside / 'sub').exists())
        # A symlinked component in the middle is refused even when the leaf is new.
        (self.project / 'real').mkdir()
        (self.project / 'real' / 'inner').symlink_to(outside, target_is_directory=True)
        self.refused('jb_mkdir', project='main', path='real/inner/leaf', parents=True)
        self.assertFalse((outside / 'leaf').exists())
        # A file where a directory is needed is refused, never replaced.
        (self.project / 'plain').write_bytes(b'file')
        with self.assertRaises((ValueError, OSError)):
            self.call('jb_mkdir', project='main', path='plain/sub', parents=True)
        self.assertEqual((self.project / 'plain').read_bytes(), b'file')


class Uploads(Fixture):
    def payload(self, size=200000):
        return bytes(range(256)) * (size // 256) + b'z' * (size % 256)

    def stage(self, data, chunks=3):
        session = self.call('jb_upload_begin')
        upload_id = session['upload_id']
        step = max(1, len(data) // chunks)
        offset = 0
        results = []
        for index in range(chunks):
            piece = data[offset:offset + step] if index < chunks - 1 else data[offset:]
            results.append(self.call('jb_upload_chunk', upload_id=upload_id, offset=offset,
                                     data_base64=base64.b64encode(piece).decode()))
            offset += len(piece)
        return upload_id, results

    def upload_dirs(self):
        area = self.state / 'uploads-v030'
        return sorted(p.name for p in area.iterdir()) if area.exists() else []

    def test_multi_chunk_reassembly_then_commit_is_exact(self):
        data = self.payload()
        upload_id, results = self.stage(data)
        offset = 0
        for result in results:
            offset += result['written']
            self.assertEqual(result['sha256'], hashlib.sha256(data[:offset]).hexdigest())
            self.assertEqual(result['size'], offset)
            self.assertTrue(result['synced'])
            self.assertFalse(result['atomic'])
            self.assertFalse(result['visible_in_project'])
        self.assertEqual(sorted(self.upload_dirs()), [upload_id])
        self.assertEqual(sorted(p.name for p in self.project.iterdir()), [])
        committed = self.call('jb_upload_commit', upload_id=upload_id, project='main',
                              path='out.bin',
                              expected_sha256=hashlib.sha256(data).hexdigest())
        self.assertTrue(committed['committed'])
        self.assertTrue(committed['atomic'])
        self.assertTrue(committed['fsynced'])
        self.assertFalse(committed['replaced'])
        self.assertIn(committed['install'], ('moved', 'copied'))
        self.assertEqual(committed['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(committed['size'], len(data))
        self.assertEqual((self.project / 'out.bin').read_bytes(), data)
        # The id is consumed and the staging is gone.
        self.assertEqual(self.upload_dirs(), [])
        # The file is a normal project file for every other tool.
        read = self.call('jb_read_chunk', project='main', path='out.bin', length=131072)
        self.assertEqual(read['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(read['total_size'], len(data))

    def test_commit_hash_mismatch_leaves_destination_untouched(self):
        self.put('dest.bin', b'ORIGINAL')
        upload_id, _ = self.stage(b'REPLACEMENT', chunks=1)
        self.refused('jb_upload_commit', upload_id=upload_id, project='main', path='dest.bin',
                     expected_sha256='0' * 64, overwrite=True)
        self.assertEqual((self.project / 'dest.bin').read_bytes(), b'ORIGINAL')
        self.assertEqual(self.upload_dirs(), [upload_id])
        # The staging survived a refused commit, so the correct hash still works.
        ok = self.call('jb_upload_commit', upload_id=upload_id, project='main', path='dest.bin',
                       expected_sha256=hashlib.sha256(b'REPLACEMENT').hexdigest(), overwrite=True)
        self.assertTrue(ok['replaced'])
        self.assertEqual((self.project / 'dest.bin').read_bytes(), b'REPLACEMENT')
        # A malformed expected_sha256 is refused before anything is installed.
        self.put('dest.bin', b'ORIGINAL')
        upload_id, _ = self.stage(b'X', chunks=1)
        self.refused('jb_upload_commit', upload_id=upload_id, project='main', path='dest.bin',
                     expected_sha256='short', overwrite=True)
        self.assertEqual((self.project / 'dest.bin').read_bytes(), b'ORIGINAL')

    def test_commit_refuses_existing_without_overwrite(self):
        self.put('dest.bin', b'ORIGINAL')
        (self.project / 'adir').mkdir()
        upload_id, _ = self.stage(b'NEW', chunks=1)
        self.refused('jb_upload_commit', upload_id=upload_id, project='main', path='dest.bin')
        self.assertEqual((self.project / 'dest.bin').read_bytes(), b'ORIGINAL')
        # A directory is never replaced, not even with overwrite=true.
        self.refused('jb_upload_commit', upload_id=upload_id, project='main', path='adir',
                     overwrite=True)
        self.assertTrue((self.project / 'adir').is_dir())
        self.assertEqual(self.upload_dirs(), [upload_id])
        self.assertEqual(self.call('jb_upload_commit', upload_id=upload_id, project='main',
                                   path='dest.bin', overwrite=True)['size'], 3)

    def test_commit_never_leaves_a_partial_file(self):
        self.put('dest.bin', b'ORIGINAL')
        upload_id, _ = self.stage(b'COMPLETE-NEW-CONTENT', chunks=1)
        real = os.replace
        # 1. A plain failure of the single install step: nothing is installed and
        #    no temporary file is left next to the destination.
        def failing(src, dst, **kwargs):
            raise OSError(errno.EIO, 'install failed')
        with patch.object(os, 'replace', side_effect=failing):
            self.refused('jb_upload_commit', upload_id=upload_id, project='main',
                         path='dest.bin', overwrite=True)
        self.assertEqual((self.project / 'dest.bin').read_bytes(), b'ORIGINAL')
        self.assertEqual([p.name for p in self.project.iterdir()], ['dest.bin'])
        # 2. Cross-device rename: the copy fallback still installs the WHOLE file.
        def cross_device(src, dst, **kwargs):
            if src == 'data': raise OSError(errno.EXDEV, 'cross-device link')
            return real(src, dst, **kwargs)
        with patch.object(os, 'replace', side_effect=cross_device):
            copied = self.call('jb_upload_commit', upload_id=upload_id, project='main',
                               path='dest.bin', overwrite=True)
        self.assertEqual(copied['install'], 'copied')
        self.assertEqual((self.project / 'dest.bin').read_bytes(), b'COMPLETE-NEW-CONTENT')
        self.assertEqual([p.name for p in self.project.iterdir()], ['dest.bin'])
        # 3. The fallback failing after the temporary file was written: the old
        #    content survives and the partial temporary file is removed.
        self.put('dest.bin', b'ORIGINAL-AGAIN')
        upload_id, _ = self.stage(b'NEVER-VISIBLE', chunks=1)
        def broken_copy(src, dst, **kwargs):
            if src == 'data': raise OSError(errno.EXDEV, 'cross-device link')
            raise OSError(errno.EIO, 'temporary install failed')
        with patch.object(os, 'replace', side_effect=broken_copy):
            self.refused('jb_upload_commit', upload_id=upload_id, project='main',
                         path='dest.bin', overwrite=True)
        self.assertEqual((self.project / 'dest.bin').read_bytes(), b'ORIGINAL-AGAIN')
        self.assertEqual([p.name for p in self.project.iterdir()], ['dest.bin'])

    def test_abort_removes_staging_and_consumes_the_id(self):
        upload_id, _ = self.stage(b'abc', chunks=1)
        self.assertEqual(self.upload_dirs(), [upload_id])
        aborted = self.call('jb_upload_abort', upload_id=upload_id)
        self.assertTrue(aborted['aborted'])
        self.assertTrue(aborted['removed'])
        self.assertEqual(self.upload_dirs(), [])
        self.assertEqual(sorted(p.name for p in self.project.iterdir()), [])
        # Idempotent, and the id can never be reused.
        again = self.call('jb_upload_abort', upload_id=upload_id)
        self.assertTrue(again['aborted'])
        self.assertFalse(again['removed'])
        for call in (lambda: self.call('jb_upload_chunk', upload_id=upload_id, offset=0,
                                       data_base64=base64.b64encode(b'x').decode()),
                     lambda: self.call('jb_upload_commit', upload_id=upload_id,
                                       project='main', path='x.bin')):
            with self.assertRaises((ValueError, OSError)):
                call()
        self.assertFalse((self.project / 'x.bin').exists())

    def test_completed_id_is_not_reusable(self):
        upload_id, _ = self.stage(b'first', chunks=1)
        self.call('jb_upload_commit', upload_id=upload_id, project='main', path='x.bin')
        self.assertEqual((self.project / 'x.bin').read_bytes(), b'first')
        for call in (lambda: self.call('jb_upload_chunk', upload_id=upload_id, offset=0,
                                       data_base64=base64.b64encode(b'second').decode()),
                     lambda: self.call('jb_upload_commit', upload_id=upload_id,
                                       project='main', path='x.bin', overwrite=True)):
            with self.assertRaises((ValueError, OSError)):
                call()
        self.assertEqual((self.project / 'x.bin').read_bytes(), b'first')

    def test_concurrent_upload_bound(self):
        sessions = [self.call('jb_upload_begin') for _ in range(b.MAX_UPLOADS)]
        self.assertEqual(len({s['upload_id'] for s in sessions}), b.MAX_UPLOADS)
        self.assertEqual(sessions[-1]['open_uploads'], b.MAX_UPLOADS)
        self.refused('jb_upload_begin')
        self.assertEqual(len(self.upload_dirs()), b.MAX_UPLOADS)
        self.call('jb_upload_abort', upload_id=sessions[0]['upload_id'])
        replacement = self.call('jb_upload_begin')
        self.assertEqual(replacement['open_uploads'], b.MAX_UPLOADS)
        self.assertEqual(len(self.upload_dirs()), b.MAX_UPLOADS)
        for session in sessions[1:]:
            self.call('jb_upload_abort', upload_id=session['upload_id'])
        self.call('jb_upload_abort', upload_id=replacement['upload_id'])
        self.assertEqual(self.upload_dirs(), [])

    def test_total_size_cap(self):
        with patch.object(b, 'MAX_UPLOAD_TOTAL', 10):
            first = self.call('jb_upload_begin')['upload_id']
            second = self.call('jb_upload_begin')['upload_id']
            self.assertEqual(self.call('jb_upload_chunk', upload_id=first, offset=0,
                                       data_base64=base64.b64encode(b'0123456789').decode()
                                       )['size'], 10)
            # The cap is area-wide: the second upload cannot push the total over it.
            self.refused('jb_upload_chunk', upload_id=second, offset=0,
                         data_base64=base64.b64encode(b'0123456789').decode())
            # Nor can one upload grow past it by offset alone.
            self.refused('jb_upload_chunk', upload_id=first, offset=10,
                         data_base64=base64.b64encode(b'x').decode())
            self.refused('jb_upload_chunk', upload_id=first, offset=20,
                         data_base64=base64.b64encode(b'x').decode())
            self.assertEqual(self.call('jb_upload_chunk', upload_id=second, offset=0,
                                       data_base64='')['size'], 0)
        self.assertEqual(self.call('jb_upload_commit', upload_id=first, project='main',
                                   path='capped.bin')['size'], 10)

    def test_offset_and_cas_rules(self):
        upload_id = self.call('jb_upload_begin')['upload_id']
        self.refused('jb_upload_chunk', upload_id=upload_id, offset=5,
                     data_base64=base64.b64encode(b'z').decode())
        first = self.call('jb_upload_chunk', upload_id=upload_id, offset=0,
                          data_base64=base64.b64encode(b'abcdef').decode())
        self.assertEqual(first['sha256'], hashlib.sha256(b'abcdef').hexdigest())
        self.assertEqual(first['size'], 6)
        self.assertFalse(first['cas_checked'])
        # Compare-and-swap checks the WHOLE staged content before writing.
        self.refused('jb_upload_chunk', upload_id=upload_id, offset=0,
                     data_base64=base64.b64encode(b'X').decode(), expected_sha256='0' * 64)
        self.assertEqual(self.call('jb_upload_chunk', upload_id=upload_id, offset=0,
                                   data_base64='')['sha256'],
                         hashlib.sha256(b'abcdef').hexdigest())
        swapped = self.call('jb_upload_chunk', upload_id=upload_id, offset=3,
                            data_base64=base64.b64encode(b'D').decode(),
                            expected_sha256=hashlib.sha256(b'abcdef').hexdigest())
        self.assertTrue(swapped['cas_checked'])
        self.assertEqual(swapped['sha256'], hashlib.sha256(b'abcDef').hexdigest())
        self.refused('jb_upload_chunk', upload_id=upload_id, offset=7,
                     data_base64=base64.b64encode(b'z').decode())
        for args in ({'offset': -1}, {'offset': 1 << 41}, {'offset': True}, {'offset': 1.0}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.call('jb_upload_chunk', upload_id=upload_id, data_base64='', **args)
        self.refused('jb_upload_chunk', upload_id=upload_id, offset=0, data_base64='not base64!!')
        self.refused('jb_upload_chunk', upload_id=upload_id, offset=0, data_base64=1)
        self.refused('jb_upload_chunk', upload_id=upload_id, offset=0, data_base64='',
                     expected_sha256='short')
        for bad in ('', 'x' * 32, ('a' * 31), ('a' * 33), ('A' * 32), ('g' * 32), 1, None):
            with self.subTest(upload_id=bad), self.assertRaises(ValueError):
                self.call('jb_upload_chunk', upload_id=bad, offset=0, data_base64='')
            with self.assertRaises(ValueError):
                self.call('jb_upload_abort', upload_id=bad)
            with self.assertRaises(ValueError):
                self.call('jb_upload_commit', upload_id=bad, project='main', path='x.bin')
        # An unknown but well formed id is refused everywhere.
        unknown = 'f' * 32
        self.refused('jb_upload_chunk', upload_id=unknown, offset=0, data_base64='')
        self.refused('jb_upload_commit', upload_id=unknown, project='main', path='x.bin')
        self.assertTrue(self.call('jb_upload_abort', upload_id=unknown)['aborted'])

    def test_path_and_private_state_refusals_at_commit(self):
        upload_id, _ = self.stage(b'payload', chunks=1)
        for path in ('/etc/hosts', '', '.', '..', '../other/x', 'a/../b', 'a//b',
                     '.bridge-state', '.bridge-state/token', 'a/.bridge-state/x',
                     'missing/x', 'a\x00b'):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                self.call('jb_upload_commit', upload_id=upload_id, project='main', path=path)
        self.refused('jb_upload_commit', upload_id=upload_id, project='unknown', path='x.bin')
        # Nothing was created in the other project, and the staging is untouched.
        self.assertEqual(sorted(p.name for p in self.other.iterdir()), [])
        self.assertEqual(self.upload_dirs(), [upload_id])
        # The staged bytes are only visible after a successful commit.
        self.assertEqual(sorted(p.name for p in self.project.iterdir()), [])
        result = self.call('jb_upload_commit', upload_id=upload_id, project='main', path='ok.bin')
        self.assertIn(result['install'], ('moved', 'copied'))
        self.assertEqual((self.project / 'ok.bin').read_bytes(), b'payload')
        self.assertFalse((self.project / 'a').exists())

    def test_commit_creates_no_parent_directory(self):
        upload_id, _ = self.stage(b'payload', chunks=1)
        with self.assertRaises(OSError):
            self.call('jb_upload_commit', upload_id=upload_id, project='main', path='nope/x.bin')
        self.assertFalse((self.project / 'nope').exists())
        self.assertEqual(self.upload_dirs(), [upload_id])

    def test_staging_is_invisible_and_unreachable(self):
        self.put('ordinary.txt', b'ordinary')
        upload_id, _ = self.stage(b'STAGED-SECRET', chunks=1)
        self.assertEqual(sorted(p.name for p in self.project.iterdir()), ['ordinary.txt'])
        listed = self.call('jb_list_dir', project='main')
        self.assertEqual([e['name'] for e in listed['entries']], ['ordinary.txt'])
        found = self.call('jb_search', project='main', content='STAGED-SECRET')
        self.assertEqual(found['matches'], [])
        for path in ('.bridge-state', '.bridge-state/uploads-v030',
                     '.bridge-state/uploads-v030/' + upload_id,
                     '.bridge-state/uploads-v030/' + upload_id + '/data'):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    self.call('jb_read_chunk', project='main', path=path)
                with self.assertRaises(ValueError):
                    self.call('jb_stat', project='main', path=path)
                with self.assertRaises(ValueError):
                    self.call('jb_write_chunk', project='main', path=path, offset=0,
                              data_base64=base64.b64encode(b'x').decode())
                with self.assertRaises(ValueError):
                    self.call('jb_list_dir', project='main', path=path)
                with self.assertRaises(ValueError):
                    self.call('jb_delete', project='main', path=path)
        # The staging area is not a project root and no tool can widen roots.
        self.refused('jb_upload_commit', upload_id=upload_id, project='main',
                     path='.bridge-state/uploads-v030/' + upload_id + '/data')

    def test_stale_sweep_is_bounded_and_stays_inside_the_upload_area(self):
        outside = self.base / 'unrelated'
        outside.mkdir()
        (outside / 'keep.txt').write_bytes(b'keep')
        (self.state / 'token').write_text('TEST-PLACEHOLDER-NOT-PRODUCTION')
        area = self.state / 'uploads-v030'
        area.mkdir(mode=0o700)
        old = time.time() - 7200

        def make(name, data, mtime):
            directory = area / name
            directory.mkdir(mode=0o700)
            (directory / 'data').write_bytes(data)
            (directory / 'meta.json').write_bytes(b'{}')
            for entry in (directory, directory / 'data', directory / 'meta.json'):
                os.utime(entry, (mtime, mtime))
            return directory

        dead = make('a' * 32, b'stale', old)
        live = make('b' * 32, b'live', old)
        os.utime(live / 'data', None)          # actively written: never stale
        foreign = make('not-an-upload-id', b'keep', old)
        session = self.call('jb_upload_begin')
        self.assertEqual(session['swept_stale'], 1)
        self.assertFalse(dead.exists())
        self.assertTrue((live / 'data').exists())
        self.assertTrue((foreign / 'data').exists())
        self.assertEqual((outside / 'keep.txt').read_bytes(), b'keep')
        self.assertEqual((self.state / 'token').read_text(), 'TEST-PLACEHOLDER-NOT-PRODUCTION')
        self.assertIn(session['upload_id'], self.upload_dirs())
        self.assertIn('b' * 32, self.upload_dirs())
        # A swept id is gone for good.
        self.refused('jb_upload_commit', upload_id='a' * 32, project='main', path='x.bin')

    def test_upload_area_metadata_is_reported(self):
        session = b.invoke('jb_upload_begin', {'project': 'main', 'name': 'named.bin'})
        self.assertEqual(session['concurrent_limit'], b.MAX_UPLOADS)
        self.assertEqual(session['total_limit'], b.MAX_UPLOAD_TOTAL)
        self.assertEqual(session['staged'], 0)
        self.assertEqual(session['sha256'], hashlib.sha256(b'').hexdigest())
        self.assertFalse(session['visible_in_project'])
        self.assertEqual(session['staged_total'], 0)
        committed = self.call('jb_upload_commit', upload_id=session['upload_id'],
                              project='main', path='empty.bin')
        self.assertEqual(committed['size'], 0)
        self.assertEqual((self.project / 'empty.bin').read_bytes(), b'')
        for args in ({'project': 'unknown'}, {'name': 'x/y'}, {'name': 'x' * 129},
                     {'name': 'x\x00y'}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                b.invoke('jb_upload_begin', args)


class Projects(Fixture):
    def test_lists_configured_roots_and_missing_root_is_reported(self):
        missing = self.base / 'absent-root'
        self.configure({'main': str(self.project), 'ghost': str(missing)})
        result = self.call('jb_projects')
        self.assertEqual(result['count'], 2)
        self.assertFalse(result['mutable'])
        self.assertEqual(result['projects']['main']['path'], str(self.project))
        self.assertTrue(result['projects']['main']['exists'])
        self.assertTrue(result['projects']['main']['is_directory'])
        self.assertFalse(result['projects']['main']['is_symlink'])
        self.assertFalse(result['projects']['ghost']['exists'])
        self.assertFalse(result['projects']['ghost']['is_directory'])
        self.assertEqual(result['projects']['ghost']['path'], str(missing))
        missing.mkdir()
        self.assertTrue(self.call('jb_projects')['projects']['ghost']['exists'])

    def test_root_replaced_by_file_or_symlink_is_reported(self):
        if SHARED_METADATA:
            self.skipTest('Minis shared mount cannot create symlinks; plain Linux covers this test')
        target = self.base / 'not-a-dir'
        target.write_bytes(b'file')
        (self.project / 'linkroot').symlink_to(target)
        self.configure({'main': str(self.project), 'file': str(target),
                        'link': str(self.project / 'linkroot')})
        result = self.call('jb_projects')['projects']
        self.assertTrue(result['file']['exists'])
        self.assertFalse(result['file']['is_directory'])
        self.assertFalse(result['link']['is_directory'])
        self.assertTrue(result['link']['is_symlink'])


class PrivateState(Fixture):
    """The state directory sits INSIDE the project root here, the worst case."""

    def setUp(self):
        super().setUp()
        self.configure({'main': str(self.base), 'second': str(self.other)})
        (self.base / 'ordinary.txt').write_bytes(b'ordinary content\n')
        (self.state / 'token').write_text('TEST-PLACEHOLDER-NOT-PRODUCTION-' * 2)
        (self.state / 'token').chmod(0o600)

    def assert_state_intact(self):
        self.assertTrue((self.state / 'token').exists())
        self.assertEqual((self.state / 'token').stat().st_mode & 0o777, 0o600)

    def test_every_new_path_tool_refuses_the_state_directory(self):
        cases = [
            ('jb_list_dir', {'project': 'main', 'path': '.bridge-state'}),
            ('jb_list_dir', {'project': 'main', 'path': '.bridge-state/versions-v030'}),
            ('jb_list_dir', {'project': 'main', 'path': 'project/.bridge-state'}),
            ('jb_stat', {'project': 'main', 'path': '.bridge-state'}),
            ('jb_stat', {'project': 'main', 'path': '.bridge-state/token'}),
            ('jb_delete', {'project': 'main', 'path': '.bridge-state'}),
            ('jb_delete', {'project': 'main', 'path': '.bridge-state/token'}),
            ('jb_delete', {'project': 'main', 'path': '.bridge-state', 'recursive': True,
                           'confirm': True}),
            ('jb_rename', {'project': 'main', 'src': '.bridge-state/token', 'dst': 'stolen'}),
            ('jb_rename', {'project': 'main', 'src': 'ordinary.txt',
                           'dst': '.bridge-state/token'}),
            ('jb_search', {'project': 'main', 'root': '.bridge-state', 'name_pattern': '*'}),
            ('jb_search', {'project': 'main', 'root': '.bridge-state', 'content': 'PLACEHOLDER'}),
            ('jb_read_chunk', {'project': 'main', 'path': '.bridge-state/token'}),
            ('jb_write_chunk', {'project': 'main', 'path': '.bridge-state/token', 'offset': 0,
                                'data_base64': base64.b64encode(b'x').decode()}),
            ('jb_mkdir', {'project': 'main', 'path': '.bridge-state'}),
            ('jb_mkdir', {'project': 'main', 'path': '.bridge-state/evil'}),
            ('jb_mkdir', {'project': 'main', 'path': '.bridge-state/evil', 'parents': True}),
            ('jb_mkdir', {'project': 'main', 'path': 'project/.bridge-state/inner',
                          'parents': True}),
        ]
        for name, args in cases:
            with self.subTest(tool=name, args=args), self.assertRaises(ValueError):
                b.invoke(name, args)
        self.assert_state_intact()
        self.assertTrue((self.state / 'token').exists())

    def test_mkdir_never_creates_the_state_directory(self):
        # The state directory exists; a name-only check would still be the only
        # thing standing between the caller and it. Both orders are exercised.
        self.refused('jb_mkdir', project='main', path='.bridge-state/token')
        self.assertFalse((self.state / 'token').is_dir())
        missing = self.base / 'ghost-state'
        target = self.base / 'ordinary-dir'
        target.mkdir()
        (target / '.bridge-state').symlink_to(missing, target_is_directory=True)
        self.refused('jb_mkdir', project='main', path='ordinary-dir/.bridge-state/x',
                     parents=True)
        self.refused('jb_mkdir', project='main', path='ordinary-dir/.bridge-state',
                     parents=True)
        self.assertFalse(missing.exists())
        self.assert_state_intact()

    def test_upload_commit_refuses_the_state_directory_and_arguments(self):
        session = self.call('jb_upload_begin')
        upload_id = session['upload_id']
        self.call('jb_upload_chunk', upload_id=upload_id, offset=0,
                  data_base64=base64.b64encode(b'payload').decode())
        for path in ('.bridge-state', '.bridge-state/token', '.bridge-state/uploads-v030',
                     'project/.bridge-state/x'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.call('jb_upload_commit', upload_id=upload_id, project='main', path=path)
        # The refusals left the staging alone: the same id still commits normally.
        committed = self.call('jb_upload_commit', upload_id=upload_id, project='main',
                              path='legit.bin')
        self.assertEqual(committed['size'], len(b'payload'))
        self.assertEqual((self.base / 'legit.bin').read_bytes(), b'payload')
        self.assert_state_intact()
        # The committed id is consumed and the staging area is empty again.
        self.assertEqual(sorted((self.state / 'uploads-v030').iterdir()), [])

    def test_staging_area_is_not_a_readable_project(self):
        session = self.call('jb_upload_begin')
        self.call('jb_upload_chunk', upload_id=session['upload_id'], offset=0,
                  data_base64=base64.b64encode(b'TEST-PLACEHOLDER-STAGED').decode())
        found = self.call('jb_search', project='main', content='TEST-PLACEHOLDER')
        self.assertEqual(found['matches'], [])
        listed = self.call('jb_list_dir', project='main')
        self.assertNotIn('.bridge-state', [e['name'] for e in listed['entries']])
        self.assertEqual(listed['total'], 3)
        self.assertNotIn('token', json.dumps(listed))
        self.assert_state_intact()

    def test_listing_and_search_never_report_the_state_directory(self):
        listed = self.call('jb_list_dir', project='main')
        self.assertNotIn('.bridge-state', [entry['name'] for entry in listed['entries']])
        self.assertEqual(listed['excluded_private'], 1)
        self.assertEqual(listed['total'], 3)  # other, ordinary.txt, project
        self.assertEqual(sorted(entry['name'] for entry in listed['entries']),
                         ['ordinary.txt', 'other', 'project'])
        found = self.call('jb_search', project='main', name_pattern='*')
        self.assertNotIn('.bridge-state', self.paths(found))
        secret = self.call('jb_search', project='main', content='TEST-PLACEHOLDER')
        self.assertEqual(secret['matches'], [])
        self.assertEqual(secret['files_scanned'], 1)
        self.assert_state_intact()

    def paths(self, result):
        return [match['path'] for match in result['matches']]

    def test_recursive_delete_never_enters_the_state_directory(self):
        # Worst case: the state directory is a CHILD of the tree being deleted. The
        # walk must fail loudly instead of removing it.
        inner = self.project / '.bridge-state'
        inner.mkdir(mode=0o700)
        (inner / 'token').write_text('TEST-PLACEHOLDER-NOT-PRODUCTION')
        with patch.object(rt, 'STATE', inner):
            self.refused('jb_delete', project='main', path='project', recursive=True,
                         confirm=True)
        self.assertTrue((inner / 'token').exists())
        self.assertEqual((inner / 'token').read_text(), 'TEST-PLACEHOLDER-NOT-PRODUCTION')
        self.assertTrue(self.project.is_dir())


class Authorization(Fixture):
    NEW = {
        'jb_list_dir': {'project': 'main'},
        'jb_stat': {'project': 'main'},
        'jb_delete': {'project': 'main', 'path': 'x'},
        'jb_rename': {'project': 'main', 'src': 'x', 'dst': 'y'},
        'jb_search': {'project': 'main'},
        'jb_find': {'name_pattern': 'x'},
        'jb_read_chunk': {'project': 'main', 'path': 'x'},
        'jb_write_chunk': {'project': 'main', 'path': 'x', 'offset': 0, 'data_base64': ''},
        'jb_projects': {},
        'jb_mkdir': {'project': 'main', 'path': 'x'},
        # jb_upload_begin takes no required argument, so the missing-argument loop
        # below has nothing to strip; every other upload tool does.
        'jb_upload_begin': {},
        'jb_upload_chunk': {'upload_id': 'a' * 32, 'offset': 0, 'data_base64': ''},
        'jb_upload_commit': {'upload_id': 'a' * 32, 'project': 'main', 'path': 'x'},
        'jb_upload_abort': {'upload_id': 'a' * 32},
    }

    def test_registry_matches_expected_tools(self):
        expected = ['jb_device_info', 'jb_process_list', 'jb_maintenance_info', 'jb_read_file',
                    'jb_write_file', 'jb_edit_file', 'jb_exec', 'jb_stage_update',
                    'jb_validate_update', 'jb_apply_update', 'jb_restart', 'jb_rollback',
                    'jb_list_dir', 'jb_stat', 'jb_delete', 'jb_rename', 'jb_search',
                    'jb_read_chunk', 'jb_write_chunk', 'jb_projects',
                    'jb_mkdir', 'jb_upload_begin', 'jb_upload_chunk',
                    'jb_upload_commit', 'jb_upload_abort', 'jb_find']
        self.assertEqual([tool['name'] for tool in b.TOOLS], expected)
        self.assertEqual(sorted(b.SPEC), sorted(expected))
        for tool in b.TOOLS:
            self.assertFalse(tool['inputSchema']['additionalProperties'])
        self.assertEqual(b.VERSION, '0.3.8')
        # 0.3.5 appends five tools after the twenty 0.3.4 tools: the first twenty
        # keep their exact names, order and schemas.
        self.assertEqual(len(expected), 26)
        self.assertEqual(b.SPEC['jb_mkdir']['required'], ['project', 'path'])
        self.assertEqual(sorted(b.SPEC['jb_mkdir']['properties']),
                         ['mode', 'parents', 'path', 'project'])
        self.assertEqual(b.SPEC['jb_upload_begin']['required'], [])
        self.assertEqual(b.SPEC['jb_upload_chunk']['required'],
                         ['upload_id', 'offset', 'data_base64'])
        self.assertEqual(b.SPEC['jb_upload_commit']['required'],
                         ['upload_id', 'project', 'path'])
        self.assertEqual(b.SPEC['jb_upload_abort']['required'], ['upload_id'])

    def unknown_keys(self, name):
        properties = set(b.SPEC[name]['properties'])
        foreign = set()
        for other, spec in b.SPEC.items():
            if other != name:
                foreign |= set(spec['properties'])
        return ['zz_unknown'] + sorted(foreign - properties)

    def test_unknown_arguments_rejected(self):
        for name, args in self.NEW.items():
            for key in self.unknown_keys(name):
                with self.subTest(tool=name, key=key), self.assertRaises(ValueError):
                    b.invoke(name, dict(args, **{key: 1}))

    def test_missing_required_argument_rejected(self):
        for name, args in self.NEW.items():
            for key in list(args):
                stripped = dict(args)
                stripped.pop(key)
                with self.subTest(tool=name, missing=key), self.assertRaises(ValueError):
                    b.invoke(name, stripped)
        self.assertTrue(b.SPEC['jb_list_dir']['required'] == ['project'])
        self.assertEqual(b.SPEC['jb_write_chunk']['required'],
                         ['project', 'path', 'offset', 'data_base64'])
        self.assertEqual(b.SPEC['jb_projects']['required'], [])

    def test_argument_types_are_strict(self):
        self.put('x', b'x')
        for name, args in (('jb_delete', {'project': 'main', 'path': 'x', 'recursive': 1}),
                           ('jb_delete', {'project': 'main', 'path': 'x', 'confirm': 'true'}),
                           ('jb_list_dir', {'project': 'main', 'limit': True}),
                           ('jb_read_chunk', {'project': 'main', 'path': 'x', 'offset': 1.0}),
                           ('jb_stat', {'project': 1, 'path': 'x'}),
                           ('jb_mkdir', {'project': 'main', 'path': 'x', 'parents': 'yes'}),
                           ('jb_mkdir', {'project': 'main', 'path': 'x', 'mode': 0o700}),
                           ('jb_upload_chunk', {'upload_id': 'a' * 32, 'offset': True,
                                                'data_base64': ''}),
                           ('jb_upload_commit', {'upload_id': 'a' * 32, 'project': 'main',
                                                 'path': 'x', 'overwrite': 1}),
                           ('jb_upload_abort', {'upload_id': 1})):
            with self.subTest(tool=name, args=args), self.assertRaises(ValueError):
                b.invoke(name, args)

    def test_existing_tools_behaviour_unchanged(self):
        written = self.call('jb_write_file', project='main', path='old.bin',
                            data_base64=base64.b64encode(b'hello world').decode())
        self.assertEqual(sorted(written), ['bytes', 'sha256', 'written'])
        read = self.call('jb_read_file', project='main', path='old.bin')
        self.assertEqual(sorted(read), ['bytes', 'data_base64', 'sha256'])
        self.assertEqual(read['sha256'], hashlib.sha256(b'hello world').hexdigest())
        edited = self.call('jb_edit_file', project='main', path='old.bin', old='world',
                           new='there', expected_sha256=read['sha256'])
        self.assertEqual(sorted(edited), ['bytes', 'sha256', 'written'])
        self.assertEqual((self.project / 'old.bin').read_bytes(), b'hello there')
        # A chunked write leaves a file the 0.3.x tools still read identically.
        self.call('jb_write_chunk', project='main', path='chunk.bin', offset=0,
                  data_base64=base64.b64encode(b'chunked').decode())
        again = self.call('jb_read_file', project='main', path='chunk.bin')
        self.assertEqual(base64.b64decode(again['data_base64']), b'chunked')
        info = self.call('jb_maintenance_info')
        self.assertEqual(sorted(info),
                         ['active', 'api', 'apply', 'audit', 'authority', 'exec',
                          'max_file_bytes', 'paths', 'pid', 'projects', 'root_helper', 'sandbox',
                          'source_sha256', 'supervised', 'supervisor', 'uid', 'version'])
        device = self.call('jb_device_info')
        self.assertEqual(sorted(device),
                         ['bridge', 'ios', 'machine', 'pid', 'release', 'source_sha256',
                          'system', 'uid'])
        self.assertEqual(device['bridge'], '0.3.8')

    def test_no_root_helper_no_token_no_root_widening(self):
        self.put('x', b'x')
        for name, args in self.NEW.items():
            with self.subTest(tool=name):
                try:
                    result = self.call(name, **args)
                except (ValueError, OSError):
                    continue
                self.assertNotIn('token', str(result))
                self.assertNotIn('root_helper', str(result))
        source = Path(b.__file__).read_text()
        block = source[source.index('# 0.3.5 file interface.'):source.index('\ndef invoke(')]
        for forbidden in ('setuid', 'sudo', 'token', 'geteuid() == 0'):
            self.assertNotIn(forbidden, block)
        self.assertFalse(hasattr(b, 'root'))
        # No new tool can register, replace or widen a configured root: 'projects'
        # is not an argument of any of them, and jb_projects is read-only.
        for name in self.NEW:
            self.assertNotIn('projects', b.SPEC[name]['properties'])
        self.assertEqual(b.SPEC['jb_projects']['properties'], {})
        self.assertEqual(self.call('jb_delete', project='main', path='x')['deleted'], True)


class LegacyListdirSemantics(Fixture):
    """The device runs Python 3.9.9, where os.listdir(fd) CLOSES the descriptor,
    while 3.12 leaves it open. Listing must therefore happen through a duplicate,
    otherwise every tool that keeps using its dirfd after listing (list_dir,
    recursive delete, search) dies with EBADF on the real device.
    """

    @staticmethod
    def consuming_listdir(real):
        """A stand-in matching 3.9's behaviour: list, then close the descriptor."""
        def wrapper(target):
            if isinstance(target, int):
                try:
                    return real(target)
                finally:
                    try: os.close(target)
                    except OSError: pass
            return real(target)
        return wrapper

    def setUp(self):
        super().setUp()
        # Project layout: one dir with files, so list/delete/search all walk it.
        self.put('dir/a.txt', b'alpha\n')
        self.put('dir/b.txt', b'beta\n')
        self.project.joinpath('dir', 'sub').mkdir()

    def test_list_dir_survives_descriptor_consuming_listdir(self):
        real = os.listdir
        with patch.object(os, 'listdir', self.consuming_listdir(real)):
            result = self.call('jb_list_dir', project='main', path='dir')
        names = sorted(e['name'] for e in result['entries'])
        self.assertEqual(names, ['a.txt', 'b.txt', 'sub'])
        for entry in result['entries']:
            self.assertIn(entry['type'], ('file', 'dir'))

    def test_recursive_delete_survives_descriptor_consuming_listdir(self):
        real = os.listdir
        with patch.object(os, 'listdir', self.consuming_listdir(real)):
            result = self.call('jb_delete', project='main', path='dir',
                               recursive=True, confirm=True)
        self.assertFalse((self.project / 'dir').exists())
        self.assertGreaterEqual(result['counts']['entries'], 3)

    def test_search_survives_descriptor_consuming_listdir(self):
        real = os.listdir
        with patch.object(os, 'listdir', self.consuming_listdir(real)):
            result = self.call('jb_search', project='main', name_pattern='*.txt')
        found = sorted(m['path'] for m in result['matches'])
        self.assertEqual(found, ['dir/a.txt', 'dir/b.txt'])

    def test_mkdir_and_uploads_survive_descriptor_consuming_listdir(self):
        # 0.3.5 lists the upload area twice per begin (stale sweep, then inventory)
        # and lists inside one upload directory per abort/commit, so both must go
        # through list_names() as well.
        real = os.listdir
        area = self.state / 'uploads-v030'
        area.mkdir(mode=0o700)
        stale = area / ('a' * 32)
        stale.mkdir(mode=0o700)
        (stale / 'data').write_bytes(b'')
        old = time.time() - 7200
        for entry in (stale, stale / 'data'):
            os.utime(entry, (old, old))
        with patch.object(os, 'listdir', self.consuming_listdir(real)):
            created = self.call('jb_mkdir', project='main', path='d/e', parents=True)
            self.assertEqual(created['created_components'], ['d', 'e'])
            session = self.call('jb_upload_begin')
            self.assertEqual(session['swept_stale'], 1)
            upload_id = session['upload_id']
            self.call('jb_upload_chunk', upload_id=upload_id, offset=0,
                      data_base64=base64.b64encode(b'payload').decode())
            committed = self.call('jb_upload_commit', upload_id=upload_id, project='main',
                                  path='out.bin')
            self.assertEqual(committed['sha256'], hashlib.sha256(b'payload').hexdigest())
            second = self.call('jb_upload_begin')['upload_id']
            aborted = self.call('jb_upload_abort', upload_id=second)
            self.assertTrue(aborted['removed'])
        self.assertFalse(stale.exists())
        self.assertEqual((self.project / 'out.bin').read_bytes(), b'payload')
        self.assertTrue((self.project / 'd' / 'e').is_dir())

    def test_helper_keeps_the_callers_descriptor_usable(self):
        real = os.listdir
        fd = os.open(str(self.project), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(lambda: os.close(fd) if os.path.exists('/proc/self/fd') is not None else None)
        with patch.object(os, 'listdir', self.consuming_listdir(real)):
            names = b.list_names(fd)
            # The original descriptor must still work for the follow-up calls.
            os.stat('dir', dir_fd=fd, follow_symlinks=False)
        self.assertIn('dir', names)



if __name__ == '__main__':
    unittest.main(verbosity=2)
