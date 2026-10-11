#!/usr/bin/env python3
import ast
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch, Mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'source-v030'))
sys.path.insert(0, str(HERE))
import package_lifecycle as lc
import maintenance_runtime as rt
import mobile_setup as seed
import build

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.receipt_patch = patch.object(lc, 'receipt', return_value=True)
        self.receipt_patch.start()
        self.addCleanup(self.receipt_patch.stop)
    def test_python39_grammar(self):
        for p in list((HERE / 'source-v030').glob('*.py')) + list(HERE.glob('*.py')):
            ast.parse(p.read_bytes(), feature_version=(3, 9))
    def test_archive(self):
        raw = subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(build.OUT)])
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            names = [m.name for m in t]
            for m in t:
                self.assertEqual((m.uid,m.gid),(0,0))
                self.assertEqual(m.mode,0o755 if m.isdir() else 0o644)
                self.assertFalse(m.issym() or m.islnk())
            self.assertFalse(any('/Library' in n or '.bridge-state' in n or n.endswith('/token') for n in names))
            self.assertFalse(any(n.endswith(('.deb','.pyc','test_package.py')) for n in names))
            for name in ('launcher.py','maintenance_runtime.py','bridge.py'):
                self.assertEqual(t.extractfile('./usr/local/lib/openminis-jb/'+name).read(), (HERE/'source-v030'/name).read_bytes())
        meta = subprocess.check_output(['dpkg-deb','-f',str(build.OUT)]).decode()
        self.assertIn('Version: ' + build.VERSION, meta)
        self.assertEqual(lc.RECEIPT_DATA, ('OpenMinis-Jailbreak clean-install ' + build.VERSION + '\n').encode())
        self.assertIn('Architecture: iphoneos-arm64e',meta)
        self.assertIn('python3.9 (>= 3.9.9-2)',meta)
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(['dpkg-deb','-e',str(build.OUT),d],check=True)
            for phase in ('preinst','postinst','prerm','postrm'):
                p=Path(d)/phase
                self.assertEqual(p.stat().st_mode & 0o777,0o755)
                subprocess.run(['sh','-n',str(p)],check=True)
                code=p.read_text().split("<<'OPENMINIS_PACKAGE_PY'\n")[1].rsplit('\nOPENMINIS_PACKAGE_PY',1)[0]
                ast.parse(code,feature_version=(3,9))
                self.assertIn('HASHES = {',code)
                namespace = {'__name__': 'package_test'}
                exec(compile(code, '<maintainer>', 'exec'), namespace)
                self.assertEqual(namespace['REMOVAL'], (HERE/'removal_helper.py').read_text())
                self.assertEqual(namespace['RECEIPT_DATA'], lc.RECEIPT_DATA)
    def test_fresh_mobile_and_idempotency(self):
        # Real filesystem and token operations; mock only UID and ownership guards.
        with tempfile.TemporaryDirectory() as d:
            base=Path(d)/'OpenMinis-Jailbreak'; alias=Path(d)/'openminis-jailbreak'
            state=base/'.bridge-state'
            with patch.object(seed,'BASE',base),patch.object(seed,'ALIAS',alias),patch.object(rt,'STATE',state),patch.object(rt,'STORE',HERE/'source-v030'),patch.object(rt,'mobile'),patch.object(os,'geteuid',return_value=os.getuid()):
                seed.setup()
                before={str(p.relative_to(base)):p.read_bytes() for p in base.rglob('*') if p.is_file()}
                self.assertEqual(len(rt.token()),64)
                self.assertFalse(alias.exists())
                self.assertEqual((state/'token').stat().st_mode & 0o777,0o600)
                self.assertEqual(state.stat().st_mode & 0o777,0o700)
                self.assertEqual(rt.config()['projects']['main'],str(base))
                self.assertFalse(alias.is_symlink())
                with self.assertRaises(ValueError): seed.setup(validate=True)
                seed.setup()
                after={str(p.relative_to(base)):p.read_bytes() for p in base.rglob('*') if p.is_file()}
                self.assertEqual(before,after)
    def test_conflicting_alias(self):
        with tempfile.TemporaryDirectory() as d:
            alias=Path(d)/'lower';alias.mkdir()
            with patch.object(seed,'ALIAS',alias),patch.object(seed,'BASE',Path(d)/'Upper'),patch.object(rt,'STATE',alias/'.bridge-state'),patch.object(rt,'mobile'):
                with self.assertRaises(ValueError):seed.setup()
                self.assertTrue(alias.is_dir())
    def test_live_adoption_never_stops_or_seeds(self):
        with patch.object(lc,'preflight'),patch.object(lc,'known'),patch.object(lc,'active',return_value='user/501'),patch.object(lc,'validate_mobile') as valid,patch.object(lc,'healthy') as health,patch.object(lc,'stop') as stop,patch.object(lc,'mobile') as mobile:
            lc.main('postinst',['configure'])
            valid.assert_called_once();health.assert_called_once();stop.assert_not_called();mobile.assert_not_called()
    def test_upgrade_prerm_noop(self):
        with patch.object(lc,'preflight') as pre,patch.object(lc,'stop') as stop:
            lc.main('prerm',['upgrade','0.3.0-2'])
            pre.assert_not_called();stop.assert_not_called()
    def test_remove_stops_only_label(self):
        with patch.object(lc,'active',side_effect=['user/501',None]),patch.object(lc,'run',return_value=Mock(returncode=0)) as run:
            lc.stop()
            run.assert_called_once_with(['/usr/bin/launchctl','bootout','system/'+lc.LABEL])
    def test_failed_fresh_activation_removes_only_generated_plist(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'service.plist'
            with patch.object(lc,'DEST',dest),patch.object(lc,'preflight',return_value=Path('/')),patch.object(lc,'known'),patch.object(lc,'active',return_value=None),patch.object(lc,'mobile',return_value=Mock(returncode=0)),patch.object(lc,'expected',return_value={'Label':lc.LABEL}),patch.object(lc,'atomic',side_effect=dest.write_bytes),patch.object(lc,'run',return_value=Mock(returncode=1)),patch.object(lc,'stop') as stop:
                with self.assertRaises(RuntimeError):lc.main('postinst',['configure'])
                self.assertFalse(dest.exists());stop.assert_called_once()
    def test_unknown_runtime_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            store=Path(d); (store/'launcher.py').write_text('unknown')
            with patch.object(lc,'STORE',store),patch.object(lc,'HASHES',{'launcher.py':'0'*64}),patch.object(lc,'guard'):
                with self.assertRaises(RuntimeError):lc.known(Path('/'))
    def test_wrong_platform_blocked(self):
        with patch.object(sys,'platform','linux'):
            with self.assertRaises(RuntimeError):lc.preflight()
    def test_unknown_service_path_blocked(self):
        with patch.object(lc,'run',return_value=Mock(returncode=0,stdout=b'user/501/app.openminis.jbbridge = {\n path = /wrong\n')):
            with self.assertRaises(RuntimeError):lc.active()
    def test_postrm_preserves_data(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'service.plist';dest.write_bytes(b'owned')
            data=Path(d)/'token';data.write_bytes(b'synthetic-secret')
            with patch.object(lc,'DEST',dest),patch.object(lc,'guard'),patch.object(lc,'root'),patch.object(lc,'equivalent',return_value=True),patch.object(lc,'removal',return_value=Mock(returncode=0,stdout=b'')),patch.object(lc,'active',return_value=None):
                lc.main('postrm',['purge'])
            self.assertFalse(dest.exists());self.assertEqual(data.read_bytes(),b'synthetic-secret')

    def test_successful_fresh_configure(self):
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'service.plist'
            with patch.object(lc,'DEST',dest),patch.object(lc,'preflight',return_value=Path('/')),patch.object(lc,'known'),patch.object(lc,'active',side_effect=[None,'user/501']),patch.object(lc,'mobile',return_value=Mock(returncode=0)) as mobile,patch.object(lc,'expected',return_value={'Label':lc.LABEL}),patch.object(lc,'atomic',side_effect=dest.write_bytes),patch.object(lc,'run',return_value=Mock(returncode=0)) as run,patch.object(lc,'equivalent',return_value=True),patch.object(lc,'healthy') as health:
                lc.main('postinst',['configure'])
                self.assertTrue(dest.exists());health.assert_called_once()
                run.assert_called_once_with(['/usr/bin/launchctl','bootstrap','system',dest])
                mobile.assert_called_once_with('import mobile_setup; mobile_setup.setup()')

    def _preinst_after_removal(self, **overrides):
        """Drive preinst for an 'install <old-version>' invocation on a config-files record."""
        with tempfile.TemporaryDirectory() as d:
            store=Path(d)/'store'; dest=Path(d)/'service.plist'
            patches=[patch.object(lc,'STORE',store),patch.object(lc,'DEST',dest),
                     patch.object(lc,'preflight',return_value=Path('/')),patch.object(lc,'known'),
                     patch.object(lc,'active',return_value=None)]
            for p in patches: p.start()
            try:
                for name,value in overrides.items():
                    if not callable(value): value=Mock(return_value=value)
                    p=patch.object(lc,name,value); p.start(); patches.append(p)
                return lc.main('preinst',['install','0.3.2-3+experimental'])
            finally:
                for p in patches: p.stop()

    def test_reinstall_after_removal_needs_no_purge(self):
        # dpkg keeps a 'deinstall ok config-files' record after removal; reinstalling
        # then is still a clean install and must not demand a manual purge.
        with patch.object(lc,'removal',return_value=Mock(returncode=0)):
            self._preinst_after_removal(prior_state='deinstall ok config-files')

    def test_install_over_installed_payload_refused(self):
        with self.assertRaises(RuntimeError):
            self._preinst_after_removal(prior_state='install ok installed')

    def test_upgrade_action_always_refused(self):
        with self.assertRaises(RuntimeError):
            lc.main('preinst',['upgrade','0.3.2-3+experimental'])

    def test_unreadable_status_falls_back_to_artifacts_conservatively(self):
        with tempfile.TemporaryDirectory() as d:
            store=Path(d)/'store'; store.mkdir()
            with patch.object(lc,'STORE',store),patch.object(lc,'DEST',Path(d)/'x.plist'),patch.object(lc,'prior_state',return_value=None):
                with self.assertRaises(RuntimeError):
                    lc.main('preinst',['install','0.3.2-3+experimental'])

    def test_prior_state_parses_dpkg_output(self):
        with patch.object(lc,'run',return_value=Mock(returncode=0,stdout=b'deinstall ok config-files\n')):
            self.assertEqual(lc.prior_state(),'deinstall ok config-files')
        with patch.object(lc,'run',return_value=Mock(returncode=1,stdout=b'')):
            self.assertIsNone(lc.prior_state())

if __name__=='__main__':unittest.main(verbosity=2)
