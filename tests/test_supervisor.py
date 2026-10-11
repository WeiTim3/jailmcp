#!/usr/bin/env python3
"""Real-process regression tests for the 0.3.2-3 supervisor orphan-child fix.

No mocks and no skips. This Linux machine runs the packaged runtime exactly the
way the plist does on iOS:
  * the packaged runtime is placed at /usr/local/lib/openminis-jb (root owned),
  * the mobile anchor is the real /var/mobile/Documents with a real /private/var
    alias, both UID501 as on iOS,
  * the supervisor is started as UID501 through the packaged plist BOOT string,
  * its child is the real packaged bridge listening on 127.0.0.1:18765,
  * removal runs the packaged helper text (prerm payload) as UID501.
Everything else (launchd, jbroot, dpkg hooks) is outside this file; see
REVISION3_VALIDATION.md for the exact scope of what is and is not proven.
The only token read here is the one mobile_setup generates locally for this
fixture; no device secret is read and the device is never touched.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE / 'source-v030')]
import package_lifecycle as lc

MOBILE_UID = 501
MOBILE_GID = 501
STORE = Path('/usr/local/lib/openminis-jb')
DOCS = Path('/var/mobile/Documents')
PRIVATE = Path('/private')
PRIVATE_VAR = PRIVATE / 'var'
BASE = DOCS / 'OpenMinis-Jailbreak'
STATE = BASE / '.bridge-state'
PORT = 18765
BOUND = 8.0          # test-side patience; the supervisor's own shutdown bound is 3s
STARTUP_BOUND = 35.0 # test-side patience for a cold Python child on this machine
PACKAGED = ('launcher.py', 'maintenance_runtime.py', 'bridge.py', 'mobile_setup.py')
CHILD_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/var/mobile', 'PYTHONUNBUFFERED': '1'}
FIXTURES = HERE / 'test_fixtures'
# 0.3.2-2 launcher, byte-identical to the shipped 0.3.2-2 source archive entry.
PREFIX = {'launcher.py': '5a9db4f9953587f80882df2fd04818a31a267d740789e1685b67ede17b2e97f3',
          'maintenance_runtime.py': 'e38fe25d1d61ba759824a3d17af2101af0fbc1a6533c3444e8636211d95af46a',
          'bridge.py': '425029fd6c59d9a0df39849357a3ac66773bc2140c1b6f4c62978d917fc766eb',
          'mobile_setup.py': '78ed4a0f75a16ba15298649713db62d3434c86e894ba0a3cace5385907389550'}
STUB_BRIDGE = (b"import os, signal, socket, sys, time\n"
               b"signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
               b"signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
               b"signal.signal(signal.SIGHUP, signal.SIG_IGN)\n"
               b"listener = socket.socket()\n"
               b"listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
               b"listener.bind(('127.0.0.1', %d))\n"
               b"listener.listen(1)\n"
               b"open(%r, 'w').write(str(os.getpid()))\n"
               b"while True: time.sleep(1)\n")


def drop():
    # Real privilege drop to the mobile identity; no UID assertion is bypassed.
    os.setgroups([MOBILE_GID]); os.setgid(MOBILE_GID); os.setuid(MOBILE_UID)


def mobile_run(args, timeout=40):
    return subprocess.run([str(a) for a in args], preexec_fn=drop, env=CHILD_ENV,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout)


def mobile_popen(args, stderr):
    return subprocess.Popen([str(a) for a in args], preexec_fn=drop, env=CHILD_ENV,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=stderr, start_new_session=True)


def port_free(port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(('127.0.0.1', port)); probe.listen(1)
        except OSError:
            return False
    return True


def wait_for(predicate, timeout, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(): return True
        time.sleep(interval)
    return False


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def kill_group(pid):
    """Test-only cleanup: terminate the fixture process group owned by this suite.

    Used solely by the negative-control test to clear the deliberately orphaned
    child it created; it never touches a real device process.
    """
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    wait_for(lambda: not alive(pid), BOUND)


def mobile_owned(pid):
    """Only UID501 fixture processes of this suite may ever be signalled."""
    try:
        with open('/proc/%d/status' % pid) as stream:
            for line in stream:
                if line.startswith('Uid:'): return int(line.split()[1]) == MOBILE_UID
    except (OSError, ValueError, IndexError):
        return False
    return False


def packaged_helper_text():
    """Helper text exactly as embedded in the built prerm (fallback: source)."""
    import build
    if build.OUT.exists():
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['dpkg-deb', '-e', str(build.OUT), directory], check=True)
            text = (Path(directory) / 'prerm').read_text()
            payload = text.split("<<'OPENMINIS_PACKAGE_PY'\n", 1)[1].rsplit('\nOPENMINIS_PACKAGE_PY', 1)[0]
            namespace = {}
            exec(compile(payload, '<prerm>', 'exec'), namespace)
            if namespace.get('REMOVAL'): return namespace['REMOVAL']
    return (HERE / 'removal_helper.py').read_text()


class SupervisorRealEnvironment(unittest.TestCase):
    """Real UID501 service, real sockets, real signals, real helper payload."""

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise AssertionError('root is required to create the UID501 fixture')
        cls.created = {'passwd': False, 'group': False, 'private': False, 'docs': False,
                       'mobile': False, 'store': False}
        cls.passwd_lines = []
        cls.group_lines = []
        try:
            pwd.getpwnam('mobile')
        except KeyError:
            cls.passwd_lines = ['mobile:x:%d:%d:mobile fixture:/var/mobile:/bin/sh\n' % (MOBILE_UID, MOBILE_GID)]
            with open('/etc/passwd', 'a') as stream: stream.writelines(cls.passwd_lines)
            cls.created['passwd'] = True
        try:
            import grp
            grp.getgrgid(MOBILE_GID)
        except KeyError:
            cls.group_lines = ['mobile:x:%d:\n' % MOBILE_GID]
            with open('/etc/group', 'a') as stream: stream.writelines(cls.group_lines)
            cls.created['group'] = True
        if not DOCS.exists():
            DOCS.mkdir(parents=True)
            os.chown(DOCS, MOBILE_UID, MOBILE_GID); os.chmod(DOCS, 0o755)
            os.chown(DOCS.parent, 0, 0); os.chmod(DOCS.parent, 0o755)
            cls.created['docs'] = True
        if not PRIVATE_VAR.exists():
            PRIVATE.mkdir(exist_ok=True)
            PRIVATE_VAR.symlink_to('/var')
            cls.created['private'] = True
        if STORE.exists():
            extra = set(p.name for p in STORE.iterdir()) - set(PACKAGED)
            if extra: raise AssertionError('unexpected pre-existing root store content: %s' % sorted(extra))
        else:
            STORE.mkdir(parents=True)
            cls.created['store'] = True
        os.chmod(STORE, 0o755)
        for name in PACKAGED:
            source = HERE / name if name == 'mobile_setup.py' else HERE / 'source-v030' / name
            target = STORE / name
            target.write_bytes(source.read_bytes())
            os.chmod(target, 0o644); os.chown(target, 0, 0)
        cls.bridge_sha = hashlib.sha256((HERE / 'source-v030' / 'bridge.py').read_bytes()).hexdigest()
        import shutil
        if BASE.exists():
            # Fixture-only canonical path, recreated by mobile_setup below.
            shutil.rmtree(BASE)
        cls.removal_text = packaged_helper_text()
        if cls.removal_text != (HERE / 'removal_helper.py').read_text():
            raise AssertionError('packed helper text differs from source helper')
        cls.token_seed = mobile_run([sys.executable, '-I', '-B', '-c',
            "import sys; sys.path.insert(0, %r); import mobile_setup; mobile_setup.setup()" % str(STORE)])
        if cls.token_seed.returncode:
            raise AssertionError('fixture mobile_setup failed: %r' % cls.token_seed.stderr[-400:])
        cls.created['mobile'] = True

    @classmethod
    def tearDownClass(cls):
        cls.quiet()
        if cls.created['store'] and STORE.exists():
            for name in PACKAGED:
                try: (STORE / name).unlink()
                except FileNotFoundError: pass
            try: STORE.rmdir()
            except OSError: pass
        if BASE.exists():
            import shutil
            shutil.rmtree(BASE, ignore_errors=True)
        if cls.created['docs']:
            try: DOCS.rmdir()
            except OSError: pass
            try: DOCS.parent.rmdir()
            except OSError: pass
        if cls.created['private']:
            try: PRIVATE_VAR.unlink()
            except OSError: pass
            try: PRIVATE.rmdir()
            except OSError: pass
        for path, entries in (('/etc/passwd', cls.passwd_lines), ('/etc/group', cls.group_lines)):
            if entries:
                with open(path) as stream: kept = [line for line in stream if line not in entries]
                with open(path, 'w') as stream: stream.writelines(kept)

    # -- fixture plumbing ---------------------------------------------------
    @classmethod
    def quiet(cls):
        """Destroy only UID501 fixture processes a previous test started."""
        try: status = json.loads((STATE / 'supervisor-v030.json').read_bytes())
        except Exception: status = {}
        try: stub = int((STATE / 'stub-child').read_text())
        except Exception: stub = None
        for pid in (status.get('child_pid'), stub):
            if isinstance(pid, int) and pid > 1 and mobile_owned(pid): kill_group(pid)
        pid = status.get('supervisor_pid')
        if isinstance(pid, int) and pid > 1 and mobile_owned(pid):
            try: os.kill(pid, signal.SIGKILL)
            except OSError: pass
        wait_for(lambda: port_free(), 8, 0.1)
        for name in ('supervisor-v030.json', 'stub-child'):
            try: (STATE / name).unlink()
            except OSError: pass

    def setUp(self):
        self.proc = None
        self.stderr_path = '/tmp/openminis-supervisor-%d.err' % os.getpid()
        self.addCleanup(self.tearDownFixture)
        patcher = patch.object(lc, 'REMOVAL', self.removal_text)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.quiet()

    def tearDownFixture(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            try: self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired: pass
        self.quiet()
        if not port_free():
            self.fail('fixture leak: port %d still bound after test' % PORT)

    def status(self):
        try: return json.loads((STATE / 'supervisor-v030.json').read_bytes())
        except Exception: return {}

    def start(self, boot=None):
        stderr = open(self.stderr_path, 'wb')
        self.addCleanup(stderr.close)
        self.proc = mobile_popen([sys.executable, '-I', '-B', '-c', boot or lc.BOOT], stderr)
        return self.proc

    def stop(self, sig=signal.SIGTERM, bound=BOUND):
        if self.proc.poll() is None: self.proc.send_signal(sig)
        try: return self.proc.wait(timeout=bound)
        except subprocess.TimeoutExpired:
            self.fail('supervisor ignored signal %d for %.1fs; stderr=%r'
                      % (sig, bound, open(self.stderr_path).read()[-300:]))

    def call(self, name, arguments=None):
        import urllib.request
        token = (STATE / 'token').read_text().strip()
        request = urllib.request.Request('http://127.0.0.1:%d/mcp' % PORT,
            json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                        'params': {'name': name, 'arguments': arguments or {}}}).encode(),
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=3) as response:
            result = json.load(response)['result']
        if result.get('isError'): raise AssertionError(result)
        return json.loads(result['content'][0]['text'])

    def wait_healthy(self, timeout=35):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.fail('supervisor exited rc=%s stderr=%r'
                          % (self.proc.poll(), open(self.stderr_path).read()[-300:]))
            status = self.status()
            if status.get('event') == 'healthy':
                try: info = self.call('jb_device_info')
                except Exception:
                    time.sleep(0.1); continue
                if (info['uid'] == MOBILE_UID and info['pid'] == status['child_pid']
                        and info['source_sha256'] == status['current']):
                    return status
            time.sleep(0.1)
        self.fail('supervisor never became healthy; stderr=%r' % open(self.stderr_path).read()[-300:])

    def helper(self, expression, timeout=40):
        """Run the packaged helper text verbatim, as UID501, on real paths."""
        return mobile_run([sys.executable, '-I', '-B', '-c',
                           self.removal_text + '\nchecked(' + repr(expression) + ')'], timeout)

    def state_as_mobile(self, code):
        return mobile_run([sys.executable, '-I', '-B', '-c',
            "import sys; sys.path.insert(0, %r); import maintenance_runtime as rt; rt.mobile(); " % str(STORE) + code])

    # -- required behaviour tests ------------------------------------------
    def test_01_live_service_refuses_fresh_and_blocks_stopped(self):
        self.start()
        self.wait_healthy()
        token = (STATE / 'token').read_text().strip()
        self.assertEqual(len(token), 64)
        fresh = self.helper('fresh')
        self.assertEqual((fresh.returncode, fresh.stderr.decode().strip()),
                         (1, 'HELPER_FAIL:project-conflict'))
        stopped = self.helper('stopped')
        self.assertEqual((stopped.returncode, stopped.stderr.decode().strip()),
                         (1, 'HELPER_FAIL:stopped'))
        child = self.status()['child_pid']
        self.assertEqual(self.stop(), 0)
        self.assertFalse(alive(child))
        self.assertTrue(port_free())

    def stage_stub(self):
        """Stage the SIGTERM-ignoring stub bridge as the active version."""
        stub = STUB_BRIDGE % (PORT, str(STATE / 'stub-child'))
        sha = hashlib.sha256(stub).hexdigest()
        staged = self.state_as_mobile(
            "import base64; v = rt.stage(base64.b64decode(%r), %r); "
            "rt.save('active-v030.json', {'current': v, 'previous': %r}); print(v)"
            % (base64.b64encode(stub).decode(), sha, self.bridge_sha))
        self.assertEqual(staged.returncode, 0, staged.stderr[-400:])
        self.addCleanup(self.restore_bridge)
        return sha

    def test_02_sigterm_during_startup_phase_releases_child_and_port(self):
        """Startup/health-wait phase, with a child that ignores SIGTERM."""
        self.stage_stub()
        self.start()
        self.assertTrue(wait_for(lambda: (STATE / 'stub-child').exists() or self.proc.poll() is not None, 35),
                        'stub child never started; rc=%s status=%s stderr=%r'
                        % (self.proc.poll(), self.status(), open(self.stderr_path).read()[-400:]))
        child = int((STATE / 'stub-child').read_text())
        self.assertNotEqual(self.status().get('event'), 'healthy')
        self.assertTrue(alive(child))
        os.killpg(child, signal.SIGTERM)
        time.sleep(0.5)
        self.assertTrue(alive(child), 'stub child was expected to ignore SIGTERM')
        self.assertEqual(self.stop(), 0)          # group SIGTERM, then group SIGKILL
        self.assertTrue(wait_for(lambda: not alive(child), BOUND))
        self.assertTrue(port_free())

    def test_03_sigterm_during_healthy_poll_loop_releases_child_and_port(self):
        self.start()
        status = self.wait_healthy()
        child = status['child_pid']
        self.assertTrue(alive(child))
        self.assertFalse(port_free())
        self.assertEqual(self.stop(), 0)
        self.assertFalse(alive(child))
        self.assertTrue(port_free())

    def test_04_sigkill_supervisor_watchdog_releases_child_and_port(self):
        """The device regression: launchd SIGKILLs the supervisor, no cleanup runs."""
        self.start()
        status = self.wait_healthy()
        child = status['child_pid']
        self.assertTrue(alive(child))
        os.kill(self.proc.pid, signal.SIGKILL)
        self.assertEqual(self.proc.wait(timeout=BOUND), -signal.SIGKILL)
        self.assertEqual(self.status().get('event'), 'healthy')  # no cleanup branch ran
        self.assertTrue(wait_for(lambda: not alive(child), BOUND),
                        'orphan child survived the supervisor SIGKILL (defect reproduced)')
        self.assertTrue(wait_for(lambda: port_free(), BOUND),
                        'port %d still bound after the supervisor SIGKILL' % PORT)
        self.assertEqual(self.status().get('event'), 'healthy')

    def test_05_watchdog_works_for_sigterm_ignoring_bridge_version(self):
        """No per-version cooperation: boot-level watchdog only."""
        self.stage_stub()
        self.start()
        if not wait_for(lambda: (STATE / 'stub-child').exists(), STARTUP_BOUND):
            self.fail('stub bridge never started; supervisor rc=%s status=%s stderr=%r'
                      % (self.proc.poll(), self.status(), open(self.stderr_path).read()[-500:]))
        child = int((STATE / 'stub-child').read_text())
        self.assertTrue(wait_for(lambda: not port_free(), BOUND))
        os.killpg(child, signal.SIGTERM)
        time.sleep(0.5)
        self.assertTrue(alive(child), 'stub bridge was expected to survive SIGTERM')
        self.assertFalse(port_free())
        os.kill(self.proc.pid, signal.SIGKILL)
        self.assertEqual(self.proc.wait(timeout=BOUND), -signal.SIGKILL)
        self.assertTrue(wait_for(lambda: not alive(child), BOUND),
                        'watchdog did not release the non-cooperating child')
        self.assertTrue(wait_for(lambda: port_free(), BOUND), 'port still held by the non-cooperating child')

    def restore_bridge(self):
        self.state_as_mobile("rt.save('active-v030.json', {'current': %r, 'previous': None})" % self.bridge_sha)

    def test_06_repeated_sigterm_no_deadlock_no_orphan(self):
        self.start()
        child = self.wait_healthy()['child_pid']
        self.proc.send_signal(signal.SIGTERM)
        self.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.proc.wait(timeout=BOUND), 0)
        self.assertFalse(alive(child))
        self.assertTrue(port_free())

    def test_07_remove_path_returns_success_and_releases_everything(self):
        """Install fixture -> removal path: helper stopped() passes, no orphan."""
        self.start()
        child = self.wait_healthy()['child_pid']
        ordinary = BASE / 'ordinary-user-file.txt'
        ordinary.write_text('preserve me')
        os.chown(ordinary, MOBILE_UID, MOBILE_GID)
        self.assertEqual(self.helper('stopped').returncode, 1)
        self.assertEqual(self.stop(), 0)          # equivalent of launchctl bootout
        with patch.object(lc, 'active', return_value=None):
            lc.stage('prerm-dispatch')
            self.assertIsNone(lc.remove_stop())    # packaged prerm stop path succeeds
            self.assertEqual(lc.STAGE, 'prerm-orphan-guard')
        self.assertFalse(alive(child))
        self.assertTrue(port_free())
        self.assertEqual(self.helper('stopped').returncode, 0)
        cleanup = self.helper('cleanup')
        self.assertEqual(cleanup.returncode, 0, cleanup.stderr[-300:])
        self.assertFalse(STATE.exists())
        self.assertEqual(ordinary.read_text(), 'preserve me')
        self.assertEqual(self.helper('cleanup').returncode, 0)
        self.assertEqual(ordinary.read_text(), 'preserve me')
        ordinary.unlink()

    def test_08_helper_failure_report_is_bounded_not_repeated(self):
        holder = socket.socket()
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(('127.0.0.1', PORT))
        holder.listen(1)
        self.addCleanup(holder.close)
        lc.stage('prerm-dispatch')
        for _ in range(40):
            result = lc.removal('stopped()')       # real helper text, real UID501
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr.decode().strip(), 'HELPER_FAIL:stopped')
        self.assertEqual(lc.STAGE, 'prerm-dispatch/HELPER_FAIL:stopped')
        self.assertEqual(lc.STAGE.count('HELPER_FAIL'), 1)
        self.assertLess(len(lc.STAGE), 64)

        class Clock:
            def __init__(self): self.now = 0.0
            def monotonic(self): self.now += 1.0; return self.now
            def sleep(self, seconds): pass

        with patch.object(lc, 'time', Clock()), patch.object(lc, 'active', return_value=None):
            lc.stage('prerm-dispatch')
            with self.assertRaises(RuntimeError) as raised:
                lc.remove_stop()
            self.assertIn('bounded stop', str(raised.exception))
            self.assertIn('before any payload removal', str(raised.exception))
        self.assertEqual(lc.STAGE, 'prerm-orphan-guard/HELPER_FAIL:stopped')
        self.assertEqual(lc.STAGE.count('HELPER_FAIL'), 1)

    def test_09_prefix_launcher_reproduces_orphan_defect(self):
        """Negative control: the shipped 0.3.2-2 launcher leaves the orphan."""
        import shutil
        import tempfile
        work = Path(tempfile.mkdtemp(prefix='openminis-prefix-'))
        self.addCleanup(shutil.rmtree, work, True)
        old_store = work / 'store'
        old_project = work / 'project'
        old_state = old_project / '.bridge-state'
        old_store.mkdir()
        os.chown(work, MOBILE_UID, MOBILE_GID)
        os.chmod(work, 0o755)
        probe = socket.socket(); probe.bind(('127.0.0.1', 0))
        old_port = probe.getsockname()[1]; probe.close()
        for name in PACKAGED:
            data = (FIXTURES / (name[:-3] + '-0.3.2-2.py')).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), PREFIX[name], name)
            if name == 'maintenance_runtime.py':
                text = data.decode()
                text = text.replace("STATE = Path('/var/mobile/Documents/OpenMinis-Jailbreak/.bridge-state')",
                                    'STATE = Path(%r)' % str(old_state))
                text = text.replace("STORE = Path('/usr/local/lib/openminis-jb')",
                                    'STORE = Path(%r)' % str(old_store))
                text = text.replace('PORT = 18765', 'PORT = %d' % old_port)
                data = text.encode()
            elif name == 'mobile_setup.py':
                data = data.replace(b"BASE = Path('/var/mobile/Documents/OpenMinis-Jailbreak')",
                                    ('BASE = Path(%r)' % str(old_project)).encode())
                data = data.replace(b"ALIAS = Path('/var/mobile/Documents/openminis-jailbreak')",
                                    ('ALIAS = Path(%r)' % str(work / 'alias')).encode())
            (old_store / name).write_bytes(data); os.chmod(old_store / name, 0o644)
        setup = mobile_run([sys.executable, '-I', '-B', '-c',
            "import sys; sys.path.insert(0, %r); import mobile_setup; mobile_setup.setup()" % str(old_store)])
        self.assertEqual(setup.returncode, 0, setup.stderr[-400:])
        boot = ("import sys,runpy; sys.path.insert(0,%r); runpy.run_path(%r,run_name='__main__')"
                % (str(old_store), str(old_store / 'launcher.py')))
        stderr = open('/tmp/openminis-prefix-%d.err' % os.getpid(), 'wb')
        self.addCleanup(stderr.close)
        proc = mobile_popen([sys.executable, '-I', '-B', '-c', boot], stderr)
        self.addCleanup(proc.kill)
        deadline = time.monotonic() + 25
        status = {}
        while time.monotonic() < deadline:
            try: status = json.loads((old_state / 'supervisor-v030.json').read_bytes())
            except Exception: status = {}
            if status.get('event') == 'healthy': break
            if proc.poll() is not None: break
            time.sleep(0.1)
        self.assertEqual(status.get('event'), 'healthy', 'pre-fix launcher did not start')
        child = status['child_pid']
        # This fixture deliberately orphans the child, so register cleanup BEFORE any
        # assertion that can fail: a leaked orphan would keep the port bound and make
        # every later test in the suite flaky.
        self.addCleanup(kill_group, child)
        self.assertTrue(alive(child))
        os.kill(proc.pid, signal.SIGKILL)
        self.assertEqual(proc.wait(timeout=BOUND), -signal.SIGKILL)
        time.sleep(3)
        self.assertTrue(alive(child), 'expected the 0.3.2-2 launcher to orphan its child')
        self.assertFalse(port_free(old_port), 'expected the pre-fix orphan to keep holding the port')
        kill_group(child)
        self.assertTrue(wait_for(lambda: port_free(old_port), BOUND), 'failed to clean the control orphan')

    def test_10_launcher_source_contract(self):
        import ast
        source = (HERE / 'source-v030' / 'launcher.py').read_text()
        tree = ast.parse(source)
        functions = {n.name: ast.get_source_segment(source, n)
                     for n in tree.body if isinstance(n, ast.FunctionDef)}
        handler = functions['stop']
        for forbidden in ('killpg', 'kill(', 'wait(', 'open(', 'print(', 'signal.signal'):
            self.assertNotIn(forbidden, handler)
        self.assertIn('killpg', functions['terminate'])
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)):
                first = node.body[0] if node.body else None
                if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                        and isinstance(first.value.value, str)):
                    docstrings.add(id(first.value))
        offenders = [n.value for n in ast.walk(tree)
                     if isinstance(n, ast.Constant) and isinstance(n.value, str)
                     and id(n) not in docstrings and re.search(r'pkill|killall', n.value)]
        offenders += [n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and re.search(r'pkill|killall', n.id)]
        offenders += [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and re.search(r'pkill|killall', n.attr)]
        self.assertEqual(offenders, [])
        self.assertIn('pass_fds=(read_fd,)', functions['spawn'])
        self.assertIn('start_new_session=True', functions['spawn'])
        boot = [line for line in functions['boot_for'].splitlines() if 'BOOT' in line]
        self.assertTrue(boot)
        template = source.split('BOOT = (', 1)[1].split(')\n\ndef boot_for', 1)[0]
        self.assertIn('_openminis_parent_watch', template)
        self.assertIn('os._exit(0)', template)
        self.assertIn('_openminis_parent_watch', source.split('data=sys.stdin.buffer.read')[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
