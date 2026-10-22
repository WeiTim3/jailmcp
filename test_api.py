"""Portable unit tests and real subprocess/socket supervisor tests.
All fixtures use temporary directories; no production token or service access.
"""
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parent / "source-v030"))
import bridge as b
import launcher as launch
import maintenance_runtime as rt

HERE = Path(__file__).parent / "source-v030"
# Minis shared mount reports physical UID501 to fstat(), virtual UID0 to
# stat(), and ignores chmod. Test-only metadata normalization; no production
# permission check is disabled or modified. Plain Linux needs no shim.
probe = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY)
SHARED_METADATA = os.fstat(probe).st_uid != os.stat('/tmp').st_uid
os.close(probe)
REAL_FSTAT = os.fstat

def test_fstat(fd):
    st = REAL_FSTAT(fd)
    values = list(st)
    values[4] = os.geteuid()
    values[0] = (st.st_mode & ~0o777) | (0o700 if __import__('stat').S_ISDIR(st.st_mode) else 0o600)
    return os.stat_result(values)

class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = self.base / '.bridge-state'; self.state.mkdir(mode=0o700)
        self.project = self.base / 'project'; self.project.mkdir()
        self.p = patch.object(rt, 'STATE', self.state); self.p.start(); self.addCleanup(self.p.stop)
        self.m = patch.object(rt, 'mobile'); self.m.start(); self.addCleanup(self.m.stop)
        if SHARED_METADATA:
            patcher = patch.object(os, 'fstat', side_effect=test_fstat)
            patcher.start(); self.addCleanup(patcher.stop)
        (self.state / 'token').write_text('TEST-PLACEHOLDER-NOT-PRODUCTION-' * 2)
        (self.state / 'token').chmod(0o600)
        rt.save('config-v030.json', {'projects': {'main': str(self.project)}, 'allow_mobile_shell': True})
        rt.save('active-v030.json', {'current': 'a' * 64, 'previous': None})
        b.EXIT_REQUESTED.clear()
    def put(self, name, data=b'abc'):
        file = self.project / name; file.write_bytes(data); return file

class Files(Fixture):
    def test_atomic_write_read_edit(self):
        args = {'project': 'main', 'path': 'x', 'data_base64': base64.b64encode(b'hello world').decode()}
        b.invoke('jb_write_file', args)
        old = b.invoke('jb_read_file', {'project': 'main', 'path': 'x'})
        result = b.invoke('jb_edit_file', {'project': 'main', 'path': 'x', 'old': 'world', 'new': 'mobile', 'expected_sha256': old['sha256']})
        self.assertTrue(result['written']); self.assertEqual((self.project/'x').read_bytes(), b'hello mobile')
        if not SHARED_METADATA: self.assertEqual((self.project/'x').stat().st_mode & 0o777, 0o600)
    def test_exact_match_and_cas(self):
        self.put('x', b'a a')
        for old, sha in [('a', rt.sha(b'a a')), ('z', rt.sha(b'a a')), ('a a', '0'*64)]:
            with self.assertRaises(ValueError):
                b.invoke('jb_edit_file', {'project': 'main', 'path': 'x', 'old': old, 'new': 'b', 'expected_sha256': sha})
    def test_traversal(self):
        for path in ('../token', '/etc/passwd', 'x//y', './x', '.bridge-state/token', 'a/../b', 'x\x00'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                with rt.target('main', path): pass
    def test_symlink_leaf_and_parent(self):
        if SHARED_METADATA: self.skipTest('Minis shared mount cannot create symlinks; plain Linux covers this test')
        self.put('real'); (self.project/'link').symlink_to('real')
        (self.project/'dir').symlink_to(self.state, target_is_directory=True)
        for path in ('link', 'dir/token'):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                b.invoke('jb_read_file', {'project': 'main', 'path': path})
            with self.assertRaises((ValueError, OSError)):
                b.invoke('jb_write_file', {'project': 'main', 'path': path, 'data_base64': ''})
    def test_hardlinks_refused(self):
        file = self.put('real'); os.link(file, self.project/'hard')
        with self.assertRaises(ValueError): b.invoke('jb_read_file', {'project': 'main', 'path': 'hard'})
        with self.assertRaises(ValueError): b.invoke('jb_write_file', {'project': 'main', 'path': 'hard', 'data_base64': ''})
    def test_fifo_refused(self):
        if SHARED_METADATA: self.skipTest('Minis shared mount cannot create FIFO; plain Linux covers this test')
        os.mkfifo(self.project/'fifo')
        with self.assertRaises(ValueError): b.invoke('jb_read_file', {'project': 'main', 'path': 'fifo'})
    def test_private_state_project_refused(self):
        rt.save('config-v030.json', {'projects': {'bad': str(self.state)}, 'allow_mobile_shell': True})
        with self.assertRaises(ValueError): rt.project_fd('bad')
    def test_private_state_default_project(self):
        rt.save('config-v030.json', {'projects': {'main': str(self.base)}, 'allow_mobile_shell': True})
        with self.assertRaises(ValueError): b.invoke('jb_read_file', {'project': 'main', 'path': '.bridge-state/token'})
    def test_project_unknown(self):
        with self.assertRaises(ValueError): rt.project_fd('unknown')
    def test_size_limit(self):
        self.put('large', b'x'*(rt.MAX_FILE+1))
        with self.assertRaises(ValueError): b.invoke('jb_read_file', {'project': 'main', 'path': 'large'})
    def test_token_preserved(self):
        p = self.state/'token'; p.chmod(0o640)
        before=(p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
        self.assertTrue(rt.token())
        self.assertEqual(before, (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns))
    def test_no_token_regeneration(self):
        (self.state/'token').unlink()
        with self.assertRaises(FileNotFoundError): rt.token()
        self.assertFalse((self.state/'token').exists())
    def test_schema_exact(self):
        for args in ({'unexpected': 1}, []):
            with self.assertRaises(ValueError): b.invoke('jb_device_info', args)
    def test_atomic_failure_preserves_old(self):
        self.put('x', b'old')
        with rt.target('main', 'x') as (fd, name), patch.object(rt.os, 'replace', side_effect=OSError('test')):
            with self.assertRaises(OSError): rt.write_at(fd, name, b'new')
        self.assertEqual((self.project/'x').read_bytes(), b'old')
        self.assertEqual(len(list(self.project.iterdir())), 1)

class Commands(Fixture):
    def test_execution_cwd_and_clean_env(self):
        with patch.dict(os.environ, {'UNRELATED_SECRET_FOR_TEST': 'DO_NOT_INHERIT'}):
            r=rt.command('pwd; printf "%s" "${UNRELATED_SECRET_FOR_TEST-unset}"', 'main')
        self.assertEqual(r['exit_code'],0); self.assertIn(str(self.project),r['stdout']); self.assertIn('unset',r['stdout'])
        self.assertNotIn('DO_NOT_INHERIT',r['stdout'])
    def test_output_disk_and_response_bound(self):
        r=rt.command('yes x', 'main', 3, 100)
        self.assertLessEqual(len(r['stdout']),100); self.assertTrue(r['truncated'])
        self.assertFalse(r['timed_out'])
    def test_timeout_and_group_kill(self):
        r=rt.command('sleep 30 & wait', 'main', 1)
        self.assertTrue(r['timed_out']); self.assertNotEqual(r['exit_code'],0)
    def test_disabled_shell(self):
        c=rt.config();c['allow_mobile_shell']=False;rt.save('config-v030.json',c)
        with self.assertRaises(ValueError): rt.command('true','main')
    def test_limits(self):
        for kw in ({'timeout':0},{'timeout':61},{'timeout':True},{'output_limit':32769}):
            with self.assertRaises(ValueError): rt.command('true','main',**kw)
    def test_nonzero_exit(self):
        r=rt.command('echo error >&2; exit 7','main')
        self.assertEqual(r['exit_code'],7); self.assertIn('error',r['stderr'])
    def test_audit_no_command_or_secrets(self):
        result=b.rpc({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'jb_exec','arguments':{'project':'main','command':'printf TEST-OUTPUT-SECRET'}}})
        self.assertFalse(result['result']['isError'])
        with rt.state() as fd: data=rt.read_at(fd,'audit-v030.jsonl')
        self.assertNotIn(b'TEST-OUTPUT-SECRET',data); self.assertNotIn(b'printf',data)
    def test_audit_bounded(self):
        for _ in range(105): rt.audit('jb_restart',True)
        self.assertEqual(len((self.state/'audit-v030.jsonl').read_bytes().splitlines()),100)

class Updates(Fixture):
    def test_stage_hash_syntax(self):
        data=b"print('example')\n"; version=rt.sha(data)
        rt.stage(data,version);self.assertEqual(rt.code(version),data)
        with self.assertRaises(ValueError): rt.stage(data,'0'*64)
        with self.assertRaises(SyntaxError): rt.stage(b'if',rt.sha(b'if'))
    def test_modified_version(self):
        data=b'pass\n'; version=rt.stage(data,rt.sha(data))
        (self.state/'versions-v030'/version/'bridge.py').write_bytes(b'changed')
        with self.assertRaises(ValueError): rt.code(version)
    def test_pending_and_consume(self):
        data=b'pass\n'; version=rt.stage(data,rt.sha(data))
        with patch.object(b,'SUPERVISED',True):
            result=b.invoke('jb_apply_update',{'sha256':version})
        self.assertTrue(result['queued']);self.assertTrue(b.EXIT_REQUESTED.is_set())
        pointer=launch.consume(rt.load('active-v030.json'))
        self.assertEqual(pointer['current'],'a'*64);self.assertEqual(pointer['trial'],version)
        self.assertFalse((self.state/'pending-v030.json').exists())
    def test_stale_pending_rejected(self):
        rt.save('pending-v030.json',{'base':'b'*64,'target':'c'*64})
        p=launch.consume(rt.load('active-v030.json'))
        self.assertNotIn('trial',p);self.assertFalse((self.state/'pending-v030.json').exists())
    def test_restart_requires_supervisor(self):
        with patch.object(b,'SUPERVISED',False),self.assertRaises(ValueError):b.invoke('jb_restart',{})
    def test_uid_guard(self):
        self.m.stop()
        try:
            with patch.object(rt.os,'getuid',return_value=0),patch.object(rt.os,'geteuid',return_value=0):
                with self.assertRaises(RuntimeError): rt.mobile()
        finally:self.m.start()
    def test_python39_parse_all(self):
        for file in HERE.glob('*.py'): ast.parse(file.read_text(),feature_version=(3,9))

class HTTP(Fixture):
    def setUp(self):
        super().setUp()
        self.server=b.Server(('127.0.0.1',0),b.Handler)
        self.port=self.server.server_address[1]
        p=patch.object(rt,'PORT',self.port);p.start();self.addCleanup(p.stop)
        self.server.token=rt.token()
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
    def post(self,body=None,headers=None):
        if body is None:body=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/list'}).encode()
        if headers is None:headers={'Authorization':'Bearer '+rt.token()}
        req=urllib.request.Request('http://127.0.0.1:%d/mcp'%self.port,body,headers=headers)
        return urllib.request.urlopen(req,timeout=3)
    def test_authenticated_list(self):
        with self.post() as r:self.assertEqual(len(json.load(r)['result']['tools']),31)
    def test_authentication_required(self):
        for headers in ({},{'Authorization':'Bearer incorrect'}):
            with self.assertRaises(urllib.error.HTTPError) as e:self.post(headers=headers)
            self.assertEqual(e.exception.code,401)
    def test_origin_and_host(self):
        for extra in ({'Origin':'https://example.invalid'},{'Host':'example.invalid'}):
            with self.assertRaises(urllib.error.HTTPError) as e:self.post(headers=dict({'Authorization':'Bearer '+rt.token()},**extra))
            self.assertEqual(e.exception.code,403)
    def test_body_limit(self):
        # The server answers 413 and closes the connection without draining an
        # oversized body, so the client may observe either the status code or a
        # connection reset while it is still sending. Both mean "refused"; what
        # must never happen is the body being accepted.
        try:
            self.post(b'x' * (b.MAX_BODY + 1))
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 413)
        except (urllib.error.URLError, OSError) as e:
            # The server refuses and closes without draining the oversized body, so the
            # client observes a connection-level error (reset / broken pipe) rather than
            # a status code. Any of those still means "refused", never "accepted".
            message = str(e).lower()
            self.assertTrue(
                any(word in message for word in ('reset', 'broken pipe', 'aborted', 'connection')),
                'unexpected refusal error: %r' % (e,))
        else:
            self.fail('oversized body was accepted')
        # Boundary control: a normally sized body is read and rejected later as JSON,
        # never as a size rejection. Kept small so the check is timing-independent.
        try:
            self.post(b'x' * 4096)
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
        except urllib.error.URLError as e:
            self.fail('under-limit body was not read: %s' % e)
    def test_bad_json(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.post(b'{')
        self.assertEqual(e.exception.code,400)
    def test_full_size_chunk_over_the_wire(self):
        # A MAX_CHUNK (262144 byte) payload is ~349528 base64 characters, so the
        # transport limit itself has to be large enough for jb_write_chunk.
        piece=b'w'*b.MAX_CHUNK
        body=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{
            'name':'jb_write_chunk','arguments':{'project':'main','path':'wire.bin','offset':0,
            'data_base64':base64.b64encode(piece).decode(),'final':True}}}).encode()
        self.assertGreater(len(body),200000)
        with self.post(body) as r:result=json.load(r)['result']
        self.assertFalse(result['isError'])
        written=json.loads(result['content'][0]['text'])
        self.assertEqual(written['written'],b.MAX_CHUNK)
        self.assertEqual(written['sha256'],hashlib.sha256(piece).hexdigest())
        self.assertTrue(written['synced'])
        with rt.target('main','wire.bin') as (fd,name):
            self.assertEqual(rt.read_at(fd,name,limit=b.MAX_CHUNK),piece)
    def test_concurrency_bound(self):
        for _ in range(4):self.assertTrue(self.server.slots.acquire(False))
        try:
            s=socket.create_connection(('127.0.0.1',self.port),timeout=2)
            try:self.assertEqual(s.recv(1),b'')
            finally:s.close()
        finally:
            for _ in range(4):self.server.slots.release()
    def test_notification_202(self):
        with self.post(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'}).encode()) as r:self.assertEqual(r.status,202)

class RealSupervisor(Fixture):
    """Test-only copy substitutes UID assertion and paths; production has no bypass."""
    def setUp(self):
        super().setUp()
        self.runtime_dir=self.base/'runtime';self.runtime_dir.mkdir()
        probe=socket.socket();probe.bind(('127.0.0.1',0));self.port=probe.getsockname()[1];probe.close()
        source=(HERE/'maintenance_runtime.py').read_text()
        source=source.replace("STATE = Path('/var/mobile/Documents/OpenMinis-Jailbreak/.bridge-state')",'STATE = Path(%r)'%str(self.state))
        source=source.replace("STORE = Path('/usr/local/lib/openminis-jb')",'STORE = Path(%r)'%str(self.runtime_dir))
        source=source.replace('PORT = 18765','PORT = %d'%self.port)
        source=source.replace('if os.getuid() != 501 or os.geteuid() != 501:', 'if os.getuid() != %d or os.geteuid() != %d:'%(os.getuid(),os.geteuid()))
        if SHARED_METADATA:
            source += '\n# TEST COPY ONLY: shared mount metadata adapter.\n' + 'REAL_FSTAT = os.fstat\n' + __import__('inspect').getsource(test_fstat) + '\nos.fstat = test_fstat\n'
        (self.runtime_dir/'maintenance_runtime.py').write_text(source)
        launcher=(HERE/'launcher.py').read_text().replace("device.get('uid') != 501", "device.get('uid') != %d"%os.getuid()).replace("info.get('uid') != 501", "info.get('uid') != %d"%os.getuid()).replace('HEALTH_SECONDS = 20','HEALTH_SECONDS = 4')
        (self.runtime_dir/'launcher.py').write_text(launcher)
        self.original=(HERE/'bridge.py').read_bytes()
        self.first=rt.stage(self.original,rt.sha(self.original))
        rt.save('active-v030.json',{'current':self.first,'previous':None})
        self.proc=subprocess.Popen([sys.executable,'-B',str(self.runtime_dir/'launcher.py')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        self.addCleanup(self.stop)
        self.wait_healthy(self.first)
    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:self.proc.wait(5)
            except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait()
    def call(self,name,args=None):
        request=urllib.request.Request('http://127.0.0.1:%d/mcp'%self.port,
            json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args or {}}}).encode(),
            headers={'Authorization':'Bearer '+rt.token()})
        with urllib.request.urlopen(request,timeout=3) as response:result=json.load(response)['result']
        if result.get('isError'):raise AssertionError(result)
        return json.loads(result['content'][0]['text'])
    def wait_healthy(self,version,old_pid=None):
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            try:
                p=rt.load('active-v030.json');s=rt.load('supervisor-v030.json')
                d=self.call('jb_device_info')
                if p['current']==version and 'trial' not in p and s['event']=='healthy' and s['current']==version and d['source_sha256']==version and (old_pid is None or d['pid']!=old_pid):return d
            except Exception:pass
            time.sleep(0.1)
        self.fail('Supervisor did not become healthy; process exit=%s'%self.proc.poll())
    def stage(self,data):
        sha=rt.sha(data)
        self.call('jb_stage_update',{'data_base64':base64.b64encode(data).decode(),'sha256':sha})
        self.call('jb_validate_update',{'sha256':sha})
        return sha
    def test_real_upgrade_rollback_restart_bad_update(self):
        before=self.call('jb_device_info')
        second=self.stage(re.sub(rb"VERSION = '[^']+'", b"VERSION = '0.3.1-test'", self.original, count=1))
        self.assertTrue(self.call('jb_apply_update',{'sha256':second})['queued'])
        upgraded=self.wait_healthy(second,before['pid']);self.assertEqual(upgraded['bridge'],'0.3.1-test')
        self.call('jb_rollback');rolled=self.wait_healthy(self.first,upgraded['pid'])
        self.call('jb_restart');restarted=self.wait_healthy(self.first,rolled['pid'])
        bad=self.stage(b'raise RuntimeError("TEST ONLY")\n')
        self.call('jb_apply_update',{'sha256':bad})
        self.wait_healthy(self.first,restarted['pid'])
        self.assertEqual(rt.load('active-v030.json')['current'],self.first)
    def test_trial_crash_recovery(self):
        self.stop()
        p=rt.load('active-v030.json');p['trial']='f'*64;rt.save('active-v030.json',p)
        self.proc=subprocess.Popen([sys.executable,'-B',str(self.runtime_dir/'launcher.py')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        self.wait_healthy(self.first)
        self.assertNotIn('trial',rt.load('active-v030.json'))


if __name__ == "__main__": unittest.main(verbosity=2)
