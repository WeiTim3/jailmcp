#!/usr/bin/env python3
"""In-place upgrade tests: full simulated dpkg sequences for OpenMinis-Jailbreak.

Everything here is offline and local: the root store, the plist, the transaction
directory and the UID501 mobile state all live in a private fixture tree, launchd
is a fake, and the mobile helpers are the *real* embedded helper strings executed
in-process with maintenance_runtime redirected at the fixture. No device path and
no production token is ever read.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE / 'source-v030')]
import package_lifecycle as lc
import maintenance_runtime as rt
import mobile_setup as seed

FIXTURES = HERE / 'test_fixtures'
# Fixture trees live beside the root store (never inside it): /var/minis/workspace
# is a mount that ignores chmod, and /tmp is world-writable, so neither can hold a
# realistic 0700 transaction directory or pass guard().
FIXTURE_PARENT = Path('/usr/local/lib/openminis-jb-upgrade-fixture')

def fixture_root():
    FIXTURE_PARENT.mkdir(mode=0o755, exist_ok=True)
    os.chmod(str(FIXTURE_PARENT), 0o755)
    root = Path(tempfile.mkdtemp(prefix='run-', dir=str(FIXTURE_PARENT)))
    os.chmod(str(root), 0o700)
    return root
RELEASES = ('0.3.3-1+experimental', '0.3.5-1+experimental')

def tree_bytes(name):
    return (HERE / name if name == 'mobile_setup.py' else HERE / 'source-v030' / name).read_bytes()

def runtime_bytes(name, release):
    """Bytes of one root runtime file as installed by the given release.

    The old bridges are extracted byte-for-byte from the shipped debs; every
    other file is byte-identical between those releases (asserted by the
    allowlist test), so the current tree copy is used for them.
    """
    if release is None: raise KeyError(release)
    if release in ('0.3.3-1+experimental', '0.3.5-1+experimental') and name == 'bridge.py':
        return (FIXTURES / ('bridge-%s.py' % release.split('+')[0])).read_bytes()
    return tree_bytes(name)

PACKAGED = dict((name, hashlib.sha256(tree_bytes(name)).hexdigest()) for name in lc.RUNTIME)

def release_hashes(release):
    return dict((name, hashlib.sha256(runtime_bytes(name, release)).hexdigest()) for name in lc.RUNTIME)

AUDIT = b'{"time": 1, "event": "jb_device_info", "success": true, "uid": 501}\n'

def variant(data, tag):
    """A distinct but still valid version of a bridge (hash changes, still compiles)."""
    return data + b'\n# upgrade-fixture variant: ' + tag.encode() + b'\n'

def wipe(path):
    if path.is_dir(): shutil.rmtree(str(path), True)


class Mobile:
    """A real on-disk copy of the UID501 state, driven by the packaged helpers."""

    def __init__(self, root, bridge=None, previous=None, audit=AUDIT, empty=False):
        self.base = root / 'Documents' / 'OpenMinis-Jailbreak'
        self.alias = root / 'Documents' / 'openminis-jailbreak'
        self.state = self.base / '.bridge-state'
        self.versions = self.state / 'versions-v030'
        self.audit_initial = audit
        self.empty = empty
        if empty:
            documents = root / 'Documents'
            documents.mkdir(mode=0o700)
            os.chmod(documents, 0o700)
            return
        self.state.mkdir(parents=True, mode=0o700)
        os.chmod(self.state, 0o700)
        self.versions = self.state / 'versions-v030'
        self.versions.mkdir(mode=0o700)
        self.audit_initial = audit
        self.write('token', (os.urandom(32).hex() + '\n').encode(), 0o600)
        self.write('config-v030.json', json.dumps({'allow_mobile_shell': True,
            'projects': {'main': str(self.base)}}, sort_keys=True).encode(), 0o600)
        if audit is not None: self.write('audit-v030.jsonl', audit, 0o600)
        self.stage(bridge)
        pointer = {'current': hashlib.sha256(bridge).hexdigest()}
        if previous is not None:
            self.stage(previous); pointer['previous'] = hashlib.sha256(previous).hexdigest()
        self.set_pointer(pointer)

    def path(self, name):
        return self.state / name

    def write(self, name, data, mode=0o600):
        path = self.path(name)
        path.write_bytes(data)
        os.chmod(path, mode)
        return path

    def stage(self, data):
        version = hashlib.sha256(data).hexdigest()
        folder = self.versions / version
        folder.mkdir(mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
        (folder / 'bridge.py').write_bytes(data)
        os.chmod(folder / 'bridge.py', 0o600)
        return version

    def pointer(self):
        return json.loads(self.path('active-v030.json').read_bytes())

    def set_pointer(self, value):
        self.write('active-v030.json', json.dumps(value, sort_keys=True).encode())

    def current(self):
        path = self.path('active-v030.json')
        if not path.exists(): return None
        return json.loads(path.read_bytes()).get('current')

    def state_bytes(self):
        if self.empty: return {}
        return dict((name, self.path(name).read_bytes() if self.path(name).exists() else None)
                    for name in ('token', 'config-v030.json', 'audit-v030.jsonl', 'active-v030.json'))

    def version_count(self):
        return len([child for child in self.versions.iterdir() if child.is_dir()])


class Launchd:
    """Minimal launchd stand-in: registration state and the version it runs."""

    def __init__(self, harness, registered=True, broken_new=False, always_fail=False):
        self.harness = harness
        self.registered = registered
        self.calls = []
        self.running = harness.mobile.current() if registered else None
        self.broken_new = broken_new
        self.always_fail = always_fail
        self.health_calls = 0

    def active(self):
        return 'user/501' if self.registered else None

    def run(self, args, mobile=False, timeout=25):
        argv = [str(a) for a in args]
        self.calls.append(argv)
        if argv[:1] == ['/usr/bin/launchctl']:
            if argv[1:2] == ['bootout']:
                self.registered = False; self.running = None
            elif argv[1:2] == ['bootstrap']:
                self.registered = True; self.running = self.harness.mobile.current()
            return Mock(returncode=0, stdout=b'', stderr=b'')
        raise AssertionError('unexpected root command: ' + repr(argv))

    def healthy(self):
        self.health_calls += 1
        if not self.registered: raise RuntimeError('service is not registered')
        if self.always_fail or (self.broken_new and self.running == PACKAGED['bridge.py']):
            raise RuntimeError('simulated unhealthy bridge')
        if self.running != self.harness.mobile.current():
            raise RuntimeError('simulated version mismatch')


class Harness:
    """Simulated root filesystem + mobile home + launchd for one dpkg run."""

    def __init__(self, test, release=None, plist=True, mobile_bridge=None, mobile_previous=None,
                 registered=None, audit=True, listener_free=True, broken_new=False, always_fail=False,
                 receipt=True, empty_mobile=False):
        self.test = test
        self.root = fixture_root()
        test.addCleanup(wipe, self.root)
        self.store = self.root / 'store'
        self.dest = self.root / 'service.plist'
        self.transaction = self.root / 'transaction'
        self.previous = self.root / 'previous-runtime'
        self.receipt = self.store / '.clean-install-v032'
        self.boot = hashlib.sha256(('boot:' + str(self.root)).encode()).hexdigest()
        self.listener_free = listener_free
        self.installed = release
        if release is not None:
            self.store.mkdir(mode=0o755)
            for name in lc.RUNTIME:
                path = self.store / name
                path.write_bytes(runtime_bytes(name, release))
                os.chmod(path, 0o644)
            if receipt:
                self.receipt.write_bytes(b'OpenMinis-Jailbreak clean-install ' + release.encode() + b'\n')
                os.chmod(self.receipt, 0o600)
        self.plist_bytes = plistlib.dumps(lc.expected(Path('/')))
        if plist:
            self.dest.write_bytes(self.plist_bytes)
            os.chmod(self.dest, 0o644)
        if empty_mobile:
            self.mobile = Mobile(self.root, empty=True)
        else:
            bridge = mobile_bridge if mobile_bridge is not None else variant(tree_bytes('bridge.py'), 'installed')
            previous = mobile_previous if mobile_previous is not None else variant(tree_bytes('bridge.py'), 'older')
            self.mobile = Mobile(self.root, bridge, previous, audit=(AUDIT if audit else None))
        self.launchd = Launchd(self, registered=(release is not None) if registered is None else registered,
                               broken_new=broken_new, always_fail=always_fail)
        self.start_patches()

    # --- patch management ---------------------------------------------------
    def start_patches(self):
        targets = {
            'STORE': self.store, 'DEST': self.dest, 'TRANSACTION': self.transaction,
            'PREVIOUS': self.previous, 'RECEIPT': self.receipt, 'HASHES': dict(PACKAGED),
        }
        for name, value in targets.items():
            self.patch(name, value)
        self.patch_call('preflight', Path('/'))
        self.patch_call('helper_preflight', Path('/'))
        self.patch_call('installed_version', lc.VERSION)
        self.patch_call('boot_stamp', self.boot)
        self.patch_method('run', self.launchd.run)
        self.patch_method('active', self.launchd.active)
        self.patch_method('healthy', self.launchd.healthy)
        self.patch_method('mobile', self.mobile_call)
        self.patch_method('removal', self.removal)
        self.patch_attr(seed, 'BASE', self.mobile.base)
        self.patch_attr(seed, 'ALIAS', self.mobile.alias)

    def apply(self, patcher):
        patcher.start()
        self.test.addCleanup(patcher.stop)
        return patcher

    def patch(self, name, value):
        return self.apply(patch.object(lc, name, value))

    def patch_call(self, name, value):
        return self.apply(patch.object(lc, name, Mock(return_value=value)))

    def patch_method(self, name, function):
        return self.apply(patch.object(lc, name, function))

    def patch_attr(self, module, name, value):
        return self.apply(patch.object(module, name, value))

    # --- 0.3.7 harness additions ------------------------------------------
    def partial_unpack(self, kind='truncate'):
        """A failed unpack: files missing, truncated, or the payload dir gone."""
        if kind == 'missing':
            wipe(self.store)
            return
        if kind == 'plist':
            if self.dest.exists(): self.dest.unlink()
        self.store.mkdir(mode=0o755, exist_ok=True)
        for name in lc.RUNTIME:
            path = self.store / name
            path.write_bytes(b'# truncated by the failed unpack\n')
            os.chmod(path, 0o644)

    def abort(self, action='abort-upgrade', version=RELEASES[0]):
        """Drive `postrm abort-upgrade/abort-install`; must never raise."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lc.main('postrm', [action, version])
        return out.getvalue()

    def helper(self, *args):
        """Drive the root recovery helper CLI; returns (status, output)."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = lc.restore_main([str(a) for a in args])
        return status, out.getvalue()

    def previous_files(self):
        if not lc.PREVIOUS.is_dir(): return {}
        return dict((str(p.relative_to(lc.PREVIOUS)), p.read_bytes())
                    for p in lc.PREVIOUS.rglob('*') if p.is_file())

    def previous_meta(self):
        return json.loads((lc.PREVIOUS / 'meta.json').read_bytes())

    def retained_runtime(self):
        folder = lc.PREVIOUS / 'runtime'
        return dict((name, hashlib.sha256((folder / name).read_bytes()).hexdigest())
                    for name in lc.RUNTIME)

    def removal(self, code):
        if code == 'stopped()' and not self.listener_free:
            return Mock(returncode=1, stdout=b'', stderr=b'HELPER_FAIL:stopped')
        return Mock(returncode=0, stdout=b'', stderr=b'')

    # --- the mobile side: real helper source, fixture files ----------------
    def mobile_call(self, code, timeout=30):
        out = io.StringIO()
        context = [patch.object(rt, 'mobile', staticmethod(lambda: None)),
                   patch.object(rt, 'STATE', self.mobile.state),
                   patch.object(rt, 'STORE', self.store)]
        for item in context: item.start()
        try:
            with contextlib.redirect_stdout(out):
                exec(compile(code, '<mobile-helper>', 'exec'), {'__name__': 'harness'})
        finally:
            for item in reversed(context): item.stop()
        return Mock(returncode=0, stdout=out.getvalue().encode(), stderr=b'')

    # --- dpkg-facing verbs --------------------------------------------------
    def preinst(self, action='upgrade', version=RELEASES[0]):
        return lc.main('preinst', [action, version])

    def postinst(self, action='configure', version=lc.VERSION):
        return lc.main('postinst', [action, version])

    def unpack(self, release=lc.VERSION):
        self.store.mkdir(mode=0o755, exist_ok=True)
        for name in lc.RUNTIME:
            path = self.store / name
            path.write_bytes(runtime_bytes(name, release))
            os.chmod(path, 0o644)

    def upgrade(self, release=RELEASES[0], version_of_deb=lc.VERSION):
        """dpkg's normal order: preinst upgrade -> unpack -> postinst configure."""
        self.preinst('upgrade', release)
        self.unpack()
        self.postinst('configure', version_of_deb)

    def snapshot(self):
        return {'store': dict((name, (self.store / name).read_bytes() if (self.store / name).exists() else None)
                              for name in lc.RUNTIME),
                'plist': self.dest.read_bytes() if self.dest.exists() else None,
                'receipt': self.receipt.read_bytes() if self.receipt.exists() else None,
                'state': self.mobile.state_bytes(),
                'pointer': self.mobile.pointer(),
                'versions': self.mobile.version_count(),
                'registered': self.launchd.registered,
                'running': self.launchd.running}

    # --- helpers ------------------------------------------------------------
    def meta(self):
        path = self.transaction / 'meta.json'
        self.test.assertTrue(path.exists(), 'expected a transaction snapshot')
        return json.loads(path.read_bytes())

    def snapshot_runtime(self):
        return dict((name, hashlib.sha256((self.transaction / 'runtime' / name).read_bytes()).hexdigest())
                    for name in lc.RUNTIME)


class UpgradeCase(unittest.TestCase):
    """Shared assertions for every upgrade test."""

    def assert_user_state_preserved(self, before, harness):
        after = harness.snapshot()
        for name in ('token', 'config-v030.json', 'audit-v030.jsonl'):
            self.assertEqual(before['state'][name], after['state'][name],
                             'mobile %s must not change during an upgrade' % name)
        self.assertIsNotNone(after['state']['token'])

    def assert_nothing_mutated(self, before, harness):
        after = harness.snapshot()
        self.assertEqual(before['store'], after['store'])
        self.assertEqual(before['plist'], after['plist'])
        self.assertEqual(before['pointer'], after['pointer'])
        self.assertEqual(before['registered'], after['registered'])
        self.assertEqual(before['running'], after['running'])
        self.assertEqual(before['state'], after['state'])


class UpgradeSequenceTests(UpgradeCase):
    """Full dpkg sequences: preinst upgrade -> unpack -> postinst configure."""

    def test_upgrade_from_0_3_3_sequence(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        before = harness.snapshot()
        self.assertEqual(dict((n, hashlib.sha256((harness.store / n).read_bytes()).hexdigest())
                              for n in lc.RUNTIME), release_hashes('0.3.3-1+experimental'))
        old_mobile = harness.mobile.current()
        harness.preinst('upgrade', '0.3.3-1+experimental')
        # preinst: snapshot taken, service stopped, nothing else touched.
        meta = harness.meta()
        self.assertEqual(meta['schema'], lc.SCHEMA)
        self.assertEqual(meta['boot'], harness.boot)
        self.assertEqual(meta['runtime'], release_hashes('0.3.3-1+experimental'))
        self.assertEqual(meta['mobile']['pointer'], before['pointer'])
        self.assertEqual(meta['committed'], False)
        self.assertEqual(meta['from_version'], '0.3.3-1+experimental')
        self.assertEqual(harness.snapshot_runtime(), release_hashes('0.3.3-1+experimental'))
        self.assertEqual(harness.transaction.joinpath('plist').read_bytes(), before['plist'])
        self.assertFalse(harness.launchd.registered)
        self.assertIn(['/usr/bin/launchctl', 'bootout', 'system/' + lc.LABEL], harness.launchd.calls)
        self.assert_user_state_preserved(before, harness)
        # dpkg unpack + configure
        harness.unpack()
        harness.postinst('configure', lc.VERSION)
        after = harness.snapshot()
        self.assertEqual(after['store'], dict((n, runtime_bytes(n, lc.VERSION)) for n in lc.RUNTIME))
        self.assertEqual(harness.mobile.pointer(),
                         {'current': PACKAGED['bridge.py'], 'previous': old_mobile})
        self.assertEqual((harness.mobile.versions / PACKAGED['bridge.py'] / 'bridge.py').read_bytes(),
                         tree_bytes('bridge.py'))
        self.assertTrue(harness.launchd.registered)
        self.assertEqual(harness.launchd.running, PACKAGED['bridge.py'])
        self.assertTrue(harness.launchd.health_calls >= 1)
        self.assertFalse(harness.transaction.exists(), 'committed snapshot must be discarded')
        self.assertEqual(harness.receipt.read_bytes(), lc.RECEIPT_DATA)
        self.assert_user_state_preserved(before, harness)

    def test_upgrade_from_0_3_5_sequence(self):
        harness = Harness(self, release='0.3.5-1+experimental')
        before = harness.snapshot()
        old_mobile = harness.mobile.current()
        harness.preinst('upgrade', '0.3.5-1+experimental')
        self.assertEqual(harness.meta()['runtime'], release_hashes('0.3.5-1+experimental'))
        self.assertEqual(harness.meta()['label'], '0.3.5-1')
        harness.unpack()
        harness.postinst('configure', lc.VERSION)
        after = harness.snapshot()
        self.assertEqual(after['pointer'], {'current': PACKAGED['bridge.py'], 'previous': old_mobile})
        self.assertEqual(harness.launchd.running, PACKAGED['bridge.py'])
        self.assertFalse(harness.transaction.exists())
        self.assert_user_state_preserved(before, harness)

    def test_upgrade_mobile_bridge_already_current_is_a_noop_switch(self):
        harness = Harness(self, release='0.3.3-1+experimental',
                          mobile_bridge=tree_bytes('bridge.py'),
                          mobile_previous=variant(tree_bytes('bridge.py'), 'older'))
        before = harness.snapshot()
        versions = harness.mobile.version_count()
        harness.preinst('upgrade', '0.3.3-1+experimental')
        harness.unpack()
        harness.postinst('configure', lc.VERSION)
        after = harness.snapshot()
        self.assertEqual(after['pointer'], before['pointer'], 'active pointer must not move when shas match')
        self.assertEqual(harness.mobile.version_count(), versions, 'no new version directory expected')
        self.assertTrue(harness.launchd.registered)
        self.assertEqual(harness.launchd.running, PACKAGED['bridge.py'])
        self.assert_user_state_preserved(before, harness)

    def test_same_version_upgrade(self):
        harness = Harness(self, release=lc.VERSION, mobile_bridge=tree_bytes('bridge.py'))
        before = harness.snapshot()
        harness.preinst('upgrade', lc.VERSION)
        self.assertEqual(harness.meta()['label'], 'packaged ' + lc.VERSION)
        harness.unpack()
        harness.postinst('configure', lc.VERSION)
        after = harness.snapshot()
        self.assertEqual(after['pointer'], before['pointer'])
        self.assertTrue(harness.launchd.registered)
        self.assertEqual(harness.launchd.running, PACKAGED['bridge.py'])
        self.assertFalse(harness.transaction.exists())
        self.assert_user_state_preserved(before, harness)

    def test_two_consecutive_upgrades_are_idempotent(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        before = harness.snapshot()
        harness.upgrade('0.3.3-1+experimental')
        first = harness.snapshot()
        harness.preinst('upgrade', lc.VERSION)
        harness.unpack()
        harness.postinst('configure', lc.VERSION)
        second = harness.snapshot()
        self.assertEqual(first['store'], second['store'])
        self.assertEqual(first['pointer'], second['pointer'])
        self.assertEqual(first['plist'], second['plist'])
        self.assertTrue(harness.launchd.registered)
        self.assert_user_state_preserved(before, harness)

    def test_fresh_install_sequence_still_works(self):
        harness = Harness(self, release=None, plist=False, empty_mobile=True)
        harness.preinst('install', lc.VERSION)
        self.assertFalse(harness.store.exists())
        self.assertFalse(harness.dest.exists())
        self.assertFalse(harness.transaction.exists())
        harness.unpack()
        harness.postinst('configure', lc.VERSION)
        self.assertEqual(harness.mobile.current(), PACKAGED['bridge.py'])
        self.assertEqual(len(harness.mobile.path('token').read_bytes().decode().strip()), 64)
        self.assertEqual(harness.mobile.path('token').stat().st_mode & 0o777, 0o600)
        self.assertEqual(harness.mobile.pointer(), {'current': PACKAGED['bridge.py'], 'previous': None})
        self.assertTrue(harness.dest.exists())
        self.assertTrue(harness.launchd.registered)
        self.assertEqual(harness.launchd.running, PACKAGED['bridge.py'])
        self.assertEqual(harness.receipt.read_bytes(), lc.RECEIPT_DATA)
        self.assertFalse(harness.transaction.exists())


class UpgradeRecoveryTests(UpgradeCase):
    """Failure paths must restore the old state and keep dpkg able to finish."""

    def test_health_failure_restores_everything(self):
        harness = Harness(self, release='0.3.3-1+experimental', broken_new=True)
        before = harness.snapshot()
        old_mobile = harness.mobile.current()
        harness.preinst('upgrade', '0.3.3-1+experimental')
        harness.unpack()
        stderr = io.StringIO()
        with self.assertRaises(RuntimeError):
            with contextlib.redirect_stderr(stderr):
                harness.postinst('configure', lc.VERSION)
        message = stderr.getvalue()
        self.assertIn('UPGRADE FAILED', message)
        self.assertEqual(message.count('\n'), 1, 'exactly one upgrade failure message')
        self.assertTrue(lc.REPORTED, 'the failure must be reported once, as a non-zero dpkg exit')
        after = harness.snapshot()
        self.assertEqual(after['store'], before['store'], 'old root runtime restored')
        self.assertEqual(after['plist'], before['plist'], 'old plist restored')
        self.assertEqual(after['pointer'], before['pointer'], 'old mobile active pointer restored')
        self.assertEqual(after['state'], before['state'], 'token/config/audit untouched')
        self.assertTrue(harness.launchd.registered, 'service must not be left stopped')
        self.assertEqual(harness.launchd.running, old_mobile, 'old version restarted')
        self.assertTrue(harness.transaction.exists(), 'uncommitted snapshot kept for the retry')
        self.assertFalse(harness.meta()['committed'])
        self.assert_user_state_preserved(before, harness)

    def test_retry_after_failed_upgrade_succeeds(self):
        harness = Harness(self, release='0.3.3-1+experimental', broken_new=True)
        before = harness.snapshot()
        harness.preinst('upgrade', '0.3.3-1+experimental')
        harness.unpack()
        with self.assertRaises(RuntimeError):
            harness.postinst('configure', lc.VERSION)
        # A later dpkg run retries the same upgrade with a fixed build.
        harness.launchd.broken_new = False
        harness.preinst('upgrade', lc.VERSION)
        harness.unpack()
        harness.postinst('configure', lc.VERSION)
        self.assertEqual(harness.mobile.pointer(),
                         {'current': PACKAGED['bridge.py'], 'previous': before['pointer']['current']})
        self.assertFalse(harness.transaction.exists())
        self.assertTrue(harness.launchd.registered)
        self.assert_user_state_preserved(before, harness)

    def test_refused_before_mutation_for_unknown_runtime(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        (harness.store / 'bridge.py').write_bytes(b'# unknown bridge build\n')
        before = harness.snapshot()
        with self.assertRaises(RuntimeError):
            harness.preinst('upgrade', '0.3.3-1+experimental')
        self.assertEqual(lc.STAGE, 'upgrade-runtime-allowlist')
        self.assertFalse(harness.transaction.exists())
        self.assertFalse(any('bootout' in call for call in harness.launchd.calls))
        self.assert_nothing_mutated(before, harness)

    def test_refused_before_mutation_for_mixed_runtime(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        (harness.store / 'launcher.py').write_bytes((FIXTURES / 'launcher-0.3.2-2.py').read_bytes())
        before = harness.snapshot()
        with self.assertRaises(RuntimeError):
            harness.preinst('upgrade', '0.3.3-1+experimental')
        self.assertEqual(lc.STAGE, 'upgrade-runtime-allowlist')
        self.assert_nothing_mutated(before, harness)
        self.assertFalse(harness.transaction.exists())

    def test_refused_before_mutation_for_unknown_plist(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        plist = plistlib.loads(harness.plist_bytes)
        plist['Label'] = 'app.openminis.somethingelse'
        harness.dest.write_bytes(plistlib.dumps(plist))
        before = harness.snapshot()
        with self.assertRaises(RuntimeError):
            harness.preinst('upgrade', '0.3.3-1+experimental')
        self.assertEqual(lc.STAGE, 'upgrade-plist-shape')
        self.assert_nothing_mutated(before, harness)
        self.assertFalse(harness.transaction.exists())

    def test_refused_before_mutation_for_dangling_active_pointer(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.mobile.set_pointer({'current': 'a' * 64, 'previous': None})
        before = harness.snapshot()
        with self.assertRaises(Exception):
            harness.preinst('upgrade', '0.3.3-1+experimental')
        self.assertEqual(lc.STAGE, 'upgrade-mobile-state')
        self.assert_nothing_mutated(before, harness)
        self.assertFalse(harness.transaction.exists())

    def test_refused_when_listener_is_still_held(self):
        harness = Harness(self, release='0.3.3-1+experimental', listener_free=False)
        before = harness.snapshot()
        with patch.object(lc, 'LISTENER_SECONDS', 0.6):
            with self.assertRaises(RuntimeError):
                harness.preinst('upgrade', '0.3.3-1+experimental')
        self.assertEqual(lc.STAGE, 'upgrade-listener-released')
        self.assertTrue(harness.launchd.registered, 'service must be restarted after an aborted stop')
        self.assertFalse(harness.transaction.exists(), 'an aborted upgrade leaves no snapshot')
        self.assert_nothing_mutated(before, harness)

    def test_configure_failure_after_a_lost_snapshot_restarts_service(self):
        # postinst without a snapshot (legacy receipt, packaged runtime in place):
        # the mobile switch is still attempted and rolled back in-process.
        harness = Harness(self, release=lc.VERSION, registered=True, broken_new=True,
                          mobile_bridge=tree_bytes('bridge.py'))
        harness.receipt.write_bytes(b'OpenMinis-Jailbreak clean-install 0.3.3-1+experimental\n')
        before = harness.snapshot()
        stderr = io.StringIO()
        with self.assertRaises(RuntimeError):
            with contextlib.redirect_stderr(stderr):
                harness.postinst('configure', lc.VERSION)
        self.assertIn('UPGRADE FAILED', stderr.getvalue())
        after = harness.snapshot()
        self.assertEqual(after['pointer'], before['pointer'])
        self.assertEqual(after['state'], before['state'])
        self.assertTrue(harness.launchd.registered)


class UpgradeSnapshotTests(UpgradeCase):
    """Leftover, stale and cross-boot snapshots are validated, never trusted."""

    def test_leftover_snapshot_matching_this_boot_is_replaced(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.preinst('upgrade', '0.3.3-1+experimental')
        first = harness.meta()
        harness.preinst('upgrade', '0.3.3-1+experimental')       # simulated retry
        second = harness.meta()
        self.assertLessEqual(first['created'], second['created'])
        self.assertEqual(second['runtime'], first['runtime'])
        harness.unpack()
        harness.postinst('configure', lc.VERSION)
        self.assertFalse(harness.transaction.exists())

    def test_leftover_snapshot_from_another_boot_is_refused(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.preinst('upgrade', '0.3.3-1+experimental')
        before = harness.snapshot()
        meta = harness.meta()
        with patch.object(lc, 'boot_stamp', Mock(return_value='f' * 64)):
            with self.assertRaises(RuntimeError):
                harness.preinst('upgrade', '0.3.3-1+experimental')
        self.assertEqual(lc.STAGE, 'upgrade-leftover-snapshot')
        self.assertEqual(harness.meta(), meta, 'the leftover snapshot must not be touched')
        self.assert_nothing_mutated(before, harness)

    def test_leftover_snapshot_not_describing_disk_state_is_refused(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.preinst('upgrade', '0.3.3-1+experimental')
        meta = harness.meta()
        meta['plist'] = 'f' * 64
        (harness.transaction / 'meta.json').write_bytes(json.dumps(meta, sort_keys=True).encode())
        before = harness.snapshot()
        with self.assertRaises(RuntimeError):
            harness.preinst('upgrade', '0.3.3-1+experimental')
        self.assertEqual(lc.STAGE, 'upgrade-leftover-snapshot')
        self.assertEqual(harness.meta()['plist'], 'f' * 64, 'leftover preserved untouched')
        self.assert_nothing_mutated(before, harness)

    def test_leftover_snapshot_with_malformed_metadata_is_refused(self):
        for tamper in ('salt', 'schema', 'boot', 'to_version'):
            with self.subTest(tamper=tamper):
                harness = Harness(self, release='0.3.3-1+experimental')
                harness.preinst('upgrade', '0.3.3-1+experimental')
                meta = harness.meta()
                if tamper == 'salt':
                    meta['mobile'][tamper] = 'not-a-salt'
                else:
                    meta[tamper] = 'not-a-value'
                (harness.transaction / 'meta.json').write_bytes(json.dumps(meta, sort_keys=True).encode())
                before = harness.snapshot()
                with self.assertRaises(RuntimeError):
                    harness.preinst('upgrade', '0.3.3-1+experimental')
                self.assertEqual(lc.STAGE, 'upgrade-leftover-snapshot', tamper)
                self.assert_nothing_mutated(before, harness)

    def test_committed_leftover_snapshot_is_discarded(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.preinst('upgrade', '0.3.3-1+experimental')
        meta = harness.meta()
        meta['committed'] = True
        (harness.transaction / 'meta.json').write_bytes(json.dumps(meta, sort_keys=True).encode())
        harness.preinst('upgrade', '0.3.3-1+experimental')
        self.assertFalse(harness.meta()['committed'])

    def test_unrecognised_transaction_is_refused_in_preinst(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.transaction.mkdir(mode=0o700)
        (harness.transaction / 'meta.json').write_bytes(b'{"schema": "something-else"}')
        before = harness.snapshot()
        with self.assertRaises(RuntimeError):
            harness.preinst('upgrade', '0.3.3-1+experimental')
        self.assertEqual(lc.STAGE, 'upgrade-leftover-snapshot')
        self.assert_nothing_mutated(before, harness)

    def test_unrecognised_transaction_does_not_block_configure(self):
        harness = Harness(self, release=lc.VERSION, mobile_bridge=tree_bytes('bridge.py'))
        harness.transaction.mkdir(mode=0o700)
        (harness.transaction / 'meta.json').write_bytes(b'{"schema": "something-else"}')
        before = harness.snapshot()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            harness.postinst('configure', lc.VERSION)
        self.assertIn('unrecognised upgrade transaction', stderr.getvalue())
        self.assertEqual(harness.mobile.pointer(), before['pointer'])
        self.assertTrue(harness.launchd.registered)
        self.assert_user_state_preserved(before, harness)
        self.assertTrue(harness.transaction.exists(), 'unverified leftovers are preserved, not deleted')


class UpgradeHelperTests(UpgradeCase):
    """The embedded UID501 helpers themselves."""

    def test_helpers_are_python39_parseable(self):
        import ast
        for name in ('MOBILE_FINGERPRINT', 'MOBILE_RECONCILE', 'MOBILE_RESTORE'):
            ast.parse(getattr(lc, name), feature_version=(3, 9))
            self.assertTrue(lc.mobile_arg(getattr(lc, name), {'salt': '00'}).startswith('_ARG = '))

    def test_allowlist_matches_the_shipped_releases(self):
        mixed = dict(release_hashes('0.3.3-1+experimental'))
        mixed['launcher.py'] = hashlib.sha256((FIXTURES / 'launcher-0.3.2-2.py').read_bytes()).hexdigest()
        with patch.object(lc, 'HASHES', dict(PACKAGED)):
            self.assertEqual(lc.KNOWN_SETS['0.3.3-1'], release_hashes('0.3.3-1+experimental'))
            self.assertEqual(lc.KNOWN_SETS['0.3.5-1'], release_hashes('0.3.5-1+experimental'))
            self.assertEqual(lc.known_set(release_hashes('0.3.3-1+experimental')), '0.3.3-1')
            self.assertEqual(lc.known_set(release_hashes('0.3.5-1+experimental')), '0.3.5-1')
            self.assertEqual(lc.known_set(release_hashes(lc.VERSION)), 'packaged ' + lc.VERSION)
            self.assertIsNone(lc.known_set(mixed))
            self.assertIsNone(lc.known_set(dict(mixed, **{'bridge.py': 'f' * 64})))

    def test_packaged_payload_and_the_deployed_runtime_sets(self):
        """Every release that changes bridge.py lists the previous runtime as an
        upgrade source, so a device still running it can upgrade in place."""

        def hashes(bridge):
            return {'launcher.py': 'b905c063a8e7235b2e40cd1e3137e77372537d4611ff0af1e410049e9f96b497',
                    'maintenance_runtime.py': 'e38fe25d1d61ba759824a3d17af2101af0fbc1a6533c3444e8636211d95af46a',
                    'bridge.py': bridge,
                    'mobile_setup.py': '78ed4a0f75a16ba15298649713db62d3434c86e894ba0a3cace5385907389550'}

        listed = {'0.3.6-1': '1d64cb7fe9de833751e0dc3d7a3fcb123b108afd99df07c27ffbed3b0539c385',
                  '0.3.9-1': 'e74d21d5cc1189911617d9e2b5f6e28dead7466f7cf68082206f9c9cc3aaaf43',
                  '0.3.10-1': '5401eca53b7446cedc5a8d82c7d3799fad1fc9e1aa219bfaea4bacdfd93d221d',
                  '0.3.11-1': 'e4325d728807ead392e82c1bf1b63169e82069b7db30f3fae052c194d13cba94'}
        with patch.object(lc, 'HASHES', dict(PACKAGED)):
            for label, bridge in listed.items():
                self.assertEqual(lc.KNOWN_SETS[label], hashes(bridge))
                self.assertNotEqual(PACKAGED['bridge.py'], bridge)
                self.assertEqual(lc.known_set(hashes(bridge)), label)
            self.assertEqual(lc.known_set(dict(PACKAGED)), 'packaged ' + lc.VERSION)
            for name in ('launcher.py', 'maintenance_runtime.py', 'mobile_setup.py'):
                self.assertEqual(PACKAGED[name], hashes(listed['0.3.6-1'])[name])

    def test_helper_refuses_when_packaged_bridge_changed(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        before = harness.snapshot()
        with self.assertRaises(Exception):
            lc.mobile_out(lc.MOBILE_RECONCILE, {'bridge': 'f' * 64})
        self.assert_nothing_mutated(before, harness)

    def test_fingerprint_is_read_only(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        before = harness.snapshot()
        live = lc.fingerprint()
        self.assertEqual(set(live['state']), {'token', 'config', 'audit'})
        self.assertEqual(live['pointer'], before['pointer'])
        self.assert_nothing_mutated(before, harness)

    def test_restore_pointer_puts_the_exact_pointer_back(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        original = harness.mobile.pointer()
        harness.mobile.set_pointer({'current': PACKAGED['bridge.py'], 'previous': original['current']})
        lc.restore_pointer(original)
        self.assertEqual(harness.mobile.pointer(), original)


ABORT_PREFIX = 'NOTICE: OpenMinis-Jailbreak abort recovery:'

class AbortRecoveryTests(UpgradeCase):
    """dpkg aborted between preinst and postinst (RISK 1, fixed in 0.3.7).

    dpkg calls the NEW package's `postrm abort-upgrade <old-version>` after a
    failed payload unpack. The service is stopped by then and the runtime files
    may be missing or truncated, so the restore may only rely on the uncommitted
    same-boot snapshot and its manifest.
    """

    def assert_one_line(self, output):
        lines = [line for line in output.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, 'exactly one line expected, got %r' % output)
        return lines[0]

    def assert_nothing_replaced(self, harness, partial=b'# truncated by the failed unpack\n'):
        self.assertEqual((harness.store / 'bridge.py').read_bytes(), partial)

    def test_abort_upgrade_restores_the_same_boot_snapshot(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        before = harness.snapshot()
        old_mobile = harness.mobile.current()
        harness.preinst('upgrade', '0.3.3-1+experimental')
        meta = harness.meta()
        harness.partial_unpack()
        harness.receipt.unlink()                      # the unpack took the receipt too
        line = self.assert_one_line(harness.abort())
        self.assertEqual(line, lc.ABORT_OK)
        after = harness.snapshot()
        self.assertEqual(after['store'], dict((name, runtime_bytes(name, '0.3.3-1+experimental'))
                                              for name in lc.RUNTIME), 'old root runtime restored')
        self.assertEqual(after['plist'], before['plist'], 'old plist restored byte-for-byte')
        self.assertEqual(after['pointer'], before['pointer'], 'old mobile pointer restored')
        self.assertEqual(after['state'], before['state'], 'token/config/audit untouched')
        self.assertEqual(after['receipt'], before['receipt'], 'ownership receipt restored')
        self.assertTrue(harness.launchd.registered, 'the service must not be left stopped')
        self.assertEqual(harness.launchd.running, old_mobile, 'old version running again')
        self.assertTrue(harness.launchd.health_calls >= 1, 'health check was performed')
        self.assertEqual(harness.meta(), meta, 'the snapshot is kept for review, unchanged')
        self.assertFalse(harness.meta()['committed'])
        self.assert_user_state_preserved(before, harness)

    def test_abort_upgrade_is_idempotent(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        before = harness.snapshot()
        harness.preinst('upgrade', '0.3.3-1+experimental')
        harness.partial_unpack()
        self.assertEqual(self.assert_one_line(harness.abort()), lc.ABORT_OK)
        first = harness.snapshot()
        first_tx = (harness.transaction / 'meta.json').read_bytes()
        self.assertEqual(self.assert_one_line(harness.abort()), lc.ABORT_OK)
        self.assertEqual(harness.snapshot(), first, 'a second abort changes nothing')
        self.assertEqual((harness.transaction / 'meta.json').read_bytes(), first_tx)
        self.assertEqual(first['store'], before['store'])
        self.assert_user_state_preserved(before, harness)

    def test_abort_upgrade_without_a_snapshot_is_one_notice_and_no_op(self):
        harness = Harness(self, release=lc.VERSION, mobile_bridge=tree_bytes('bridge.py'))
        before = harness.snapshot()
        line = self.assert_one_line(harness.abort())
        self.assertTrue(line.startswith(ABORT_PREFIX), line)
        self.assertIn('no uncommitted upgrade snapshot', line)
        self.assert_nothing_mutated(before, harness)

    def test_abort_install_is_dispatched_and_safe(self):
        harness = Harness(self, release=None, plist=False)
        before = harness.snapshot()
        line = self.assert_one_line(harness.abort('abort-install'))
        self.assertTrue(line.startswith(ABORT_PREFIX), line)
        self.assert_nothing_mutated(before, harness)

    def test_abort_upgrade_with_a_committed_snapshot_is_a_notice_no_op(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.preinst('upgrade', '0.3.3-1+experimental')
        meta = harness.meta(); meta['committed'] = True
        (harness.transaction / 'meta.json').write_bytes(json.dumps(meta, sort_keys=True).encode())
        before = harness.snapshot()
        line = self.assert_one_line(harness.abort())
        self.assertIn('already committed', line)
        self.assert_nothing_mutated(before, harness)
        self.assertTrue(harness.transaction.exists(), 'a committed leftover is not consumed here')

    def test_abort_upgrade_from_another_boot_is_a_notice_no_op(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.preinst('upgrade', '0.3.3-1+experimental')
        before = harness.snapshot()
        with patch.object(lc, 'boot_stamp', Mock(return_value='f' * 64)):
            line = self.assert_one_line(harness.abort())
        self.assertIn('earlier boot', line)
        self.assert_nothing_mutated(before, harness)

    def test_abort_upgrade_without_boot_identity_is_a_notice_no_op(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.preinst('upgrade', '0.3.3-1+experimental')
        before = harness.snapshot()
        with patch.object(lc, 'boot_stamp', Mock(side_effect=RuntimeError('no sysctl'))):
            line = self.assert_one_line(harness.abort())
        self.assertIn('boot identity could not be established', line)
        self.assert_nothing_mutated(before, harness)

    def test_abort_upgrade_with_an_unrecognised_snapshot_is_a_notice_no_op(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.preinst('upgrade', '0.3.3-1+experimental')
        (harness.transaction / 'meta.json').write_bytes(b'{"schema": "something-else"}')
        before = harness.snapshot()
        line = self.assert_one_line(harness.abort())
        self.assertIn('not a recognised', line)
        self.assert_nothing_mutated(before, harness)
        self.assertTrue(harness.transaction.exists())

    def test_abort_upgrade_with_a_corrupt_snapshot_replaces_nothing(self):
        for tamper in ('file', 'meta'):
            with self.subTest(tamper=tamper):
                harness = Harness(self, release='0.3.3-1+experimental')
                harness.preinst('upgrade', '0.3.3-1+experimental')
                harness.partial_unpack()
                if tamper == 'file':
                    path = harness.transaction / 'runtime' / 'bridge.py'
                    path.write_bytes(path.read_bytes() + b'# tampered\n')
                else:
                    meta = harness.meta(); meta['runtime']['bridge.py'] = 'f' * 64
                    (harness.transaction / 'meta.json').write_bytes(
                        json.dumps(meta, sort_keys=True).encode())
                before = harness.snapshot()
                line = self.assert_one_line(harness.abort())
                self.assertIn('does not match its manifest', line)
                self.assert_nothing_mutated(before, harness)
                self.assert_nothing_replaced(harness)

    def test_abort_upgrade_after_a_partial_unpack_restores_or_refuses_cleanly(self):
        for kind in ('truncate', 'missing', 'plist'):
            with self.subTest(kind=kind):
                harness = Harness(self, release='0.3.3-1+experimental')
                before = harness.snapshot()
                harness.preinst('upgrade', '0.3.3-1+experimental')
                harness.partial_unpack(kind)
                if harness.receipt.exists(): harness.receipt.unlink()
                line = self.assert_one_line(harness.abort())
                self.assertEqual(line, lc.ABORT_OK, line)
                after = harness.snapshot()
                self.assertEqual(after['store'], before['store'])
                self.assertEqual(after['plist'], before['plist'])
                self.assertEqual(after['receipt'], before['receipt'])
                self.assertEqual(after['state'], before['state'])
                self.assertTrue(harness.launchd.registered)
                self.assertEqual(harness.launchd.running, before['pointer']['current'])
                self.assert_user_state_preserved(before, harness)

    def test_abort_upgrade_then_the_next_upgrade_still_completes(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        before = harness.snapshot()
        harness.preinst('upgrade', '0.3.3-1+experimental')
        harness.partial_unpack()
        harness.abort()
        # dpkg is not wedged: the same upgrade can simply be retried.
        harness.upgrade('0.3.3-1+experimental')
        self.assertEqual(harness.mobile.pointer(),
                         {'current': PACKAGED['bridge.py'], 'previous': before['pointer']['current']})
        self.assertFalse(harness.transaction.exists())
        self.assertTrue(harness.launchd.registered)
        self.assertEqual(harness.launchd.running, PACKAGED['bridge.py'])
        self.assertEqual(harness.retained_runtime(), release_hashes('0.3.3-1+experimental'),
                         'the successful retry also retains the previous runtime')
        self.assert_user_state_preserved(before, harness)

    def test_abort_upgrade_restarts_a_service_that_was_still_registered(self):
        # The abort must also cope with a service that came back on its own
        # (launchd KeepAlive) before dpkg reached the postrm.
        harness = Harness(self, release='0.3.3-1+experimental')
        before = harness.snapshot()
        harness.preinst('upgrade', '0.3.3-1+experimental')
        harness.partial_unpack()
        harness.launchd.registered = True
        harness.launchd.running = PACKAGED['bridge.py']
        line = self.assert_one_line(harness.abort())
        self.assertEqual(line, lc.ABORT_OK, line)
        self.assertEqual(harness.launchd.running, before['pointer']['current'])
        self.assertEqual(harness.snapshot()['store'], before['store'])
        self.assert_user_state_preserved(before, harness)


class PreviousRuntimeTests(UpgradeCase):
    """A successful upgrade retains the previous runtime (RISK 2, 0.3.7)."""

    def test_successful_upgrade_retains_the_previous_runtime(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        before = harness.snapshot()
        old_hashes = release_hashes('0.3.3-1+experimental')
        harness.upgrade('0.3.3-1+experimental')
        self.assertTrue(lc.PREVIOUS.is_dir(), 'a successful upgrade must retain the previous runtime')
        info = lc.PREVIOUS.stat()
        self.assertEqual(info.st_uid, 0)
        self.assertEqual(info.st_mode & 0o777, 0o700)
        manifest = harness.previous_meta()
        self.assertEqual(manifest['schema'], lc.PREV_SCHEMA)
        self.assertEqual(manifest['runtime'], old_hashes)
        self.assertEqual(manifest['plist'], hashlib.sha256(before['plist']).hexdigest())
        self.assertEqual(manifest['pointer'], before['pointer'])
        self.assertEqual(manifest['boot'], harness.boot)
        self.assertEqual(manifest['from_label'], '0.3.3-1')
        self.assertEqual(manifest['from_version'], '0.3.3-1+experimental')
        self.assertEqual(manifest['to_version'], lc.VERSION)
        self.assertEqual(harness.retained_runtime(), old_hashes)
        files = harness.previous_files()
        self.assertEqual(sorted(files), ['meta.json', 'plist'] +
                         sorted('runtime/' + name for name in lc.RUNTIME))
        self.assertEqual(files['plist'], before['plist'])
        self.assertEqual(files['runtime/bridge.py'],
                         runtime_bytes('bridge.py', '0.3.3-1+experimental'))
        for path in lc.PREVIOUS.rglob('*'):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        # No user data is ever copied into the rollback area.
        self.assertNotIn('token', ' '.join(files))
        self.assertNotIn('config', ' '.join(files))
        self.assertNotIn('audit', ' '.join(files))
        self.assertNotIn('active', ' '.join(files))
        self.assertFalse(harness.transaction.exists(),
                         'the in-flight snapshot is still discarded after a commit')
        self.assert_user_state_preserved(before, harness)

    def test_a_second_upgrade_replaces_the_retained_runtime(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.upgrade('0.3.3-1+experimental')
        first = harness.previous_files()
        self.assertEqual(harness.retained_runtime(), release_hashes('0.3.3-1+experimental'))
        harness.preinst('upgrade', lc.VERSION)
        harness.unpack()
        harness.postinst('configure', lc.VERSION)
        self.assertEqual(harness.retained_runtime(), PACKAGED)
        self.assertEqual(harness.previous_meta()['from_label'], 'packaged ' + lc.VERSION)
        self.assertNotEqual(harness.previous_files(), first, 'the newest previous replaces the older')
        leftovers = [path.name for path in lc.PREVIOUS.parent.iterdir()
                     if path.name.startswith('.openminis-previous-')]
        self.assertEqual(leftovers, [], 'no staging tree is left behind')

    def test_the_rollback_area_is_not_an_in_flight_transaction(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.upgrade('0.3.3-1+experimental')
        retained = harness.previous_files()
        # A failed configure keeps its own uncommitted snapshot and must not
        # create, change or consume the retained rollback copy.
        harness.launchd.broken_new = True
        harness.preinst('upgrade', lc.VERSION)
        harness.unpack()
        with self.assertRaises(RuntimeError):
            harness.postinst('configure', lc.VERSION)
        self.assertTrue(harness.transaction.exists())
        self.assertFalse(harness.meta()['committed'])
        self.assertEqual(harness.previous_files(), retained)
        # A later preinst that discards/replaces that leftover leaves it alone too.
        harness.launchd.broken_new = False
        harness.preinst('upgrade', lc.VERSION)
        self.assertEqual(harness.previous_files(), retained)

    def test_a_failed_activation_never_retains_anything(self):
        harness = Harness(self, release='0.3.3-1+experimental', broken_new=True)
        harness.preinst('upgrade', '0.3.3-1+experimental')
        harness.unpack()
        with self.assertRaises(RuntimeError):
            harness.postinst('configure', lc.VERSION)
        self.assertFalse(lc.PREVIOUS.exists(),
                         'nothing is retained unless the new runtime proved healthy')

    def test_removal_purges_only_a_verified_rollback_area(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.upgrade('0.3.3-1+experimental')
        harness.launchd.registered = False; harness.launchd.running = None
        with patch.object(lc, 'receipt', return_value=True), \
             patch.object(lc, 'root', Mock(return_value=Path('/'))):
            lc.main('postrm', ['purge'])
        self.assertFalse(lc.PREVIOUS.exists(), 'the verified rollback area goes with the package')

    def test_removal_preserves_an_unverified_rollback_area(self):
        harness = Harness(self, release='0.3.3-1+experimental')
        harness.upgrade('0.3.3-1+experimental')
        harness.launchd.registered = False; harness.launchd.running = None
        (lc.PREVIOUS / 'meta.json').write_bytes(b'{"schema": "something-else"}')
        with patch.object(lc, 'receipt', return_value=True), \
             patch.object(lc, 'root', Mock(return_value=Path('/'))):
            lc.main('postrm', ['purge'])
        self.assertTrue(lc.PREVIOUS.is_dir(), 'an unverified rollback area is preserved for review')
        self.assertEqual((lc.PREVIOUS / 'meta.json').read_bytes(), b'{"schema": "something-else"}')


class RestoreHelperTests(UpgradeCase):
    """The root recovery helper openminis-jb-restore-runtime (RISK 2, 0.3.7)."""

    def retained(self, release='0.3.3-1+experimental'):
        harness = Harness(self, release=release)
        harness.before = harness.snapshot()
        harness.upgrade(release)
        harness.after_upgrade = harness.snapshot()
        harness.launchd.calls.clear()
        return harness

    def assert_user_data_untouched(self, harness):
        self.assert_user_state_preserved(harness.before, harness)
        self.assertEqual(harness.snapshot()['state']['token'], harness.before['state']['token'])
        self.assertEqual(harness.snapshot()['state']['config-v030.json'],
                         harness.before['state']['config-v030.json'])
        self.assertEqual(harness.snapshot()['state']['audit-v030.jsonl'],
                         harness.before['state']['audit-v030.jsonl'])

    def test_full_restore_returns_to_the_previous_runtime(self):
        harness = self.retained()
        status, out = harness.helper()
        self.assertEqual(status, 0, out)
        self.assertIn('restored the root runtime', out)
        self.assertIn('restored the service plist', out)
        self.assertIn('restored the mobile active pointer', out)
        self.assertIn('health check passed', out)
        after = harness.snapshot()
        self.assertEqual(after['store'], dict((name, runtime_bytes(name, '0.3.3-1+experimental'))
                                              for name in lc.RUNTIME))
        self.assertEqual(after['plist'], harness.before['plist'])
        self.assertEqual(after['pointer'], harness.before['pointer'])
        self.assertTrue(harness.launchd.registered)
        self.assertEqual(harness.launchd.running, harness.before['pointer']['current'])
        self.assertIn(['/usr/bin/launchctl', 'bootout', 'system/' + lc.LABEL], harness.launchd.calls)
        self.assertTrue(lc.PREVIOUS.is_dir(), 'the retained copy survives the restore')
        self.assert_user_data_untouched(harness)

    def test_dry_run_changes_nothing(self):
        harness = self.retained()
        status, out = harness.helper('--dry-run')
        self.assertEqual(status, 0, out)
        self.assertIn('dry-run', out)
        self.assertEqual(harness.snapshot(), harness.after_upgrade)
        self.assertEqual(harness.launchd.calls, [], 'a dry run never touches launchd')
        self.assert_user_data_untouched(harness)

    def test_pointer_only_leaves_the_root_runtime_alone(self):
        harness = self.retained()
        status, out = harness.helper('--pointer-only')
        self.assertEqual(status, 0, out)
        self.assertIn('pointer-only', out)
        after = harness.snapshot()
        self.assertEqual(after['store'], harness.after_upgrade['store'], 'root runtime untouched')
        self.assertEqual(after['plist'], harness.after_upgrade['plist'], 'plist untouched')
        self.assertEqual(after['pointer'], harness.before['pointer'], 'pointer restored')
        self.assertTrue(harness.launchd.registered)
        self.assert_user_data_untouched(harness)

    def test_helper_is_idempotent(self):
        harness = self.retained()
        self.assertEqual(harness.helper()[0], 0)
        first = harness.snapshot()
        harness.launchd.calls.clear()
        status, out = harness.helper()
        self.assertEqual(status, 0, out)
        self.assertEqual(harness.snapshot(), first)
        self.assert_user_data_untouched(harness)

    def test_helper_refuses_when_the_snapshot_does_not_match_its_manifest(self):
        harness = self.retained()
        path = lc.PREVIOUS / 'runtime' / 'bridge.py'
        path.write_bytes(path.read_bytes() + b'# tampered\n')
        before = harness.snapshot()
        status, out = harness.helper()
        self.assertEqual(status, 1)
        self.assertIn('REFUSED', out)
        self.assertEqual(harness.snapshot(), before)
        self.assertEqual(harness.launchd.calls, [])
        self.assert_user_data_untouched(harness)

    def test_helper_refuses_a_corrupt_or_unknown_manifest(self):
        cases = ('schema', 'runtime-hash', 'pointer', 'mode', 'missing')
        for case in cases:
            with self.subTest(case=case):
                harness = self.retained()
                if case == 'missing':
                    wipe(lc.PREVIOUS)
                else:
                    meta = harness.previous_meta()
                    if case == 'schema': meta['schema'] = 'something-else'
                    elif case == 'runtime-hash': meta['runtime']['bridge.py'] = 'zz'
                    elif case == 'pointer': meta['pointer'] = {'current': 'not-a-sha'}
                    (lc.PREVIOUS / 'meta.json').write_bytes(json.dumps(meta, sort_keys=True).encode())
                    if case == 'mode': os.chmod(lc.PREVIOUS, 0o755)
                before = harness.snapshot()
                status, out = harness.helper()
                self.assertEqual(status, 1, out)
                self.assertIn('REFUSED', out)
                self.assertEqual(harness.snapshot(), before)
                self.assertEqual(harness.launchd.calls, [])
                self.assert_user_data_untouched(harness)

    def test_helper_refuses_when_the_retained_plist_is_not_the_expected_shape(self):
        harness = self.retained()
        before = harness.snapshot()
        with patch.object(lc, 'equivalent', Mock(return_value=False)):
            status, out = harness.helper()
        self.assertEqual(status, 1)
        self.assertIn('REFUSED', out)
        self.assertIn('plist', out)
        self.assertEqual(harness.snapshot(), before)
        self.assertEqual(harness.launchd.calls, [])

    def test_helper_rejects_unknown_arguments_and_prints_usage(self):
        harness = self.retained()
        status, out = harness.helper('--force')
        self.assertEqual(status, 2)
        self.assertIn('REFUSED', out)
        self.assertEqual(harness.snapshot(), harness.after_upgrade)
        status, out = harness.helper('--help')
        self.assertEqual(status, 0)
        self.assertIn('--pointer-only', out)
        self.assertIn('--dry-run', out)

    def test_helper_leaves_an_in_flight_transaction_alone(self):
        harness = self.retained()
        harness.transaction.mkdir(mode=0o700)
        (harness.transaction / 'meta.json').write_bytes(b'{"schema": "something-else"}')
        status, out = harness.helper('--dry-run')
        self.assertEqual(status, 0, out)
        self.assertIn('left untouched', out)
        self.assertEqual((harness.transaction / 'meta.json').read_bytes(),
                         b'{"schema": "something-else"}')
        self.assertTrue(harness.transaction.is_dir())

    def test_helper_notes_a_dpkg_version_mismatch_but_still_restores(self):
        harness = self.retained()
        with patch.object(lc, 'installed_version', Mock(return_value='9.9.9-1+experimental')):
            status, out = harness.helper()
        self.assertEqual(status, 0, out)
        self.assertIn('dpkg records 9.9.9-1+experimental', out)
        self.assertEqual(harness.snapshot()['pointer'], harness.before['pointer'])

    def test_helper_restores_the_pointer_when_the_payload_is_unchanged(self):
        # The 0.3.6 -> 0.3.7 payload is byte-identical, so the material effect of
        # a rollback here is the mobile active pointer and the service restart.
        harness = Harness(self, release='0.3.6-1+experimental',
                          mobile_bridge=variant(tree_bytes('bridge.py'), 'installed'))
        before = harness.snapshot()
        harness.before = before
        harness.upgrade('0.3.6-1+experimental')
        harness.launchd.calls.clear()
        self.assertEqual(harness.retained_runtime(), PACKAGED)
        status, out = harness.helper()
        self.assertEqual(status, 0, out)
        self.assertEqual(harness.snapshot()['pointer'], before['pointer'])
        self.assertEqual(harness.snapshot()['store'], before['store'])
        self.assertTrue(harness.launchd.registered)
        self.assert_user_data_untouched(harness)


if __name__ == '__main__':
    unittest.main(verbosity=2)
