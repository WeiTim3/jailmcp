#!/usr/bin/env python3
"""Offline tests: Linux Python3.12, launchd/Roothide mocked, real signals/sockets."""
import ast
import contextlib
import fcntl
import os
import plistlib
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE/'source-v030')]
import package_lifecycle as lc
import removal_helper as rm
import launcher
import bridge
import maintenance_runtime as rt

@contextlib.contextmanager
def documents_fixture():
    with tempfile.TemporaryDirectory() as d:
        os.chown(d, 501, -1)
        with patch.object(rm, 'DOCS', d), patch.object(rm, 'DOCS_ALIAS', d), patch.object(rm, 'identity'):
            yield d

class FixedDefectRegressionTests(unittest.TestCase):
    """Guards for the two defects reported from the device on 0.3.2-4."""

    def test_ps_path_probes_fixed_locations(self):
        with tempfile.TemporaryDirectory() as d:
            good = Path(d) / 'ps'; good.write_text('#!/bin/sh\n'); good.chmod(0o755)
            missing = Path(d) / 'missing' / 'ps'
            with patch.object(bridge, 'PS_CANDIDATES', (str(missing), str(good))):
                self.assertEqual(bridge.ps_path(), str(good))
            with patch.object(bridge, 'PS_CANDIDATES', (str(missing),)):
                with self.assertRaises(ValueError): bridge.ps_path()

    def test_process_list_runs_resolved_absolute_ps(self):
        # A bare 'ps' is not on the daemon PATH, which is what broke the tool.
        with patch.object(bridge.rt, 'mobile'), \
             patch.object(bridge.rt, 'config', return_value={'projects': {'main': '/tmp'}}), \
             patch.object(bridge, 'ps_path', return_value='/rootfs/bin/ps'), \
             patch.object(bridge.rt, 'command', return_value={'exit_code': 0, 'stdout': '  PID\n    1\n'}) as cmd:
            out = bridge.invoke('jb_process_list', {})
        self.assertEqual(cmd.call_args[0][0], '/rootfs/bin/ps -axo pid,uid,comm')
        self.assertEqual(out['executable'], '/rootfs/bin/ps')
        self.assertEqual(out['limit'], 100)

    def test_os_version_reads_system_plist(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'SystemVersion.plist'
            p.write_bytes(plistlib.dumps({'ProductName': 'iPhone OS', 'ProductVersion': '16.4.1',
                                          'ProductBuildVersion': '20E252'}))
            with patch.object(bridge, 'SYSTEM_VERSION_PLIST', str(p)):
                self.assertEqual(bridge.os_version(), {'version': '16.4.1', 'build': '20E252'})
            with patch.object(bridge, 'SYSTEM_VERSION_PLIST', str(Path(d) / 'absent')):
                self.assertIsNone(bridge.os_version())

    def test_device_info_exposes_ios_version(self):
        with patch.object(bridge.rt, 'mobile'), \
             patch.object(bridge, 'os_version', return_value={'version': '16.4.1', 'build': '20E252'}):
            self.assertEqual(bridge.invoke('jb_device_info', {})['ios']['build'], '20E252')


class SafetyTests(unittest.TestCase):
    def test_upgrade_refused_before_any_operation_for_unknown_baseline(self):
        # 0.3.6 replaced the clean-install-only guard with in-place upgrades, but an
        # upgraded baseline still has to match the explicit known-good allowlist.
        for args in (['upgrade','0.3.0-1'],['upgrade','0.3.1-1'],['upgrade','99']):
            with patch.object(lc,'preflight',return_value=Path('/')) as pre, \
                 patch.object(lc,'runtime_hashes',return_value=None), \
                 patch.object(lc,'run') as run,patch.object(lc,'remove_residue') as clean:
                with self.assertRaises(RuntimeError): lc.main('preinst',args)
                pre.assert_called_once();run.assert_not_called();clean.assert_not_called()
                self.assertEqual(lc.STAGE,'upgrade-runtime-allowlist')

    def test_upgrade_never_imports_packaged_runtime_as_root(self):
        # Every mobile-side step of the upgrade runs through mobile(), which drops
        # to UID501 first, and the helpers only read or compile mobile state.
        import ast
        source = Path(lc.__file__).read_text()
        self.assertIn('], mobile=True, timeout=timeout)', source)
        tree = ast.parse(source)
        imported = {alias.name.split('.')[0] for node in ast.walk(tree)
                    if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module.split('.')[0] for node in ast.walk(tree)
                     if isinstance(node, ast.ImportFrom) and node.module}
        self.assertEqual(imported & {'maintenance_runtime', 'mobile_setup', 'launcher', 'bridge'}, set())
        for helper in ('MOBILE_FINGERPRINT', 'MOBILE_RECONCILE', 'MOBILE_RESTORE'):
            text = getattr(lc, helper)
            self.assertIn('rt.mobile()', text)
            self.assertNotIn('exec(', text)

    def test_install_over_installed_rejected_with_status_probe_only(self):
        # Reinstalling over a package dpkg still records as installed stays refused,
        # and the only thing touched beforehand is the read-only status query.
        for old in ('0.3.0-1','0.3.2-3+experimental'):
            with patch.object(lc,'preflight') as pre,patch.object(lc,'run') as run,patch.object(lc,'remove_residue') as clean:
                run.return_value=Mock(returncode=0,stdout=b'install ok installed\n')
                with self.assertRaises(RuntimeError): lc.main('preinst',['install',old])
                pre.assert_not_called();clean.assert_not_called()
                self.assertEqual([c.args[0] for c in run.call_args_list],
                                 [['/usr/bin/dpkg-query','-W','-f=${Status}','app.openminis.jailbreak']])

    def test_install_over_removed_record_is_not_refused_by_the_guard(self):
        # 'deinstall ok config-files' means the payload is gone: the guard must let
        # the install continue to the normal preinst validation instead of demanding
        # a manual purge.
        with patch.object(lc,'run',return_value=Mock(returncode=0,stdout=b'deinstall ok config-files\n')), \
             patch.object(lc,'preflight',return_value=Path('/')) as pre, patch.object(lc,'known') as known:
            with self.assertRaises(RuntimeError) as caught:
                lc.main('preinst',['install','0.3.2-3+experimental'])
            self.assertNotIn('CLEAN-INSTALL ONLY',str(caught.exception))
            pre.assert_called_once();known.assert_called_once()

    def test_recovery_paths_never_read_user_state_or_run_user_code_as_root(self):
        # 0.3.7: the abort path and the recovery helper are root code. They must
        # never read the token (not even to fingerprint it), never touch
        # token/config/audit, and never import or execute user-writable code.
        # The mobile active pointer moves only through the UID501 helper.
        source = Path(lc.__file__).read_text()
        block = source[source.index('def previous_directory():'):source.index('def confirm_listener_released():')]
        self.assertIn('def postrm_abort(action):', block)
        self.assertIn('def restore_main(argv):', block)
        self.assertIn('def retain_previous(meta):', block)
        for forbidden in ('MOBILE_FINGERPRINT', 'import maintenance_runtime', 'import bridge',
                          'import launcher', 'import mobile_setup', 'exec(', 'rt.token()',
                          'read_at(', 'fingerprint('):
            self.assertNotIn(forbidden, block)
        self.assertIn('restore_pointer', block)
        self.assertIn('restore_pointer(pointer)', block)
        self.assertNotIn('mobile_out(', block)
        self.assertNotIn('mobile_arg(', block)
        self.assertEqual(lc.PREVIOUS, Path('/usr/local/lib/openminis-jb-previous'))
        self.assertEqual(lc.PREV_EXEC, '/usr/local/bin/openminis-jb-restore-runtime')
        self.assertNotEqual(lc.PREVIOUS, lc.TRANSACTION)

    def test_abort_upgrade_hooks_do_not_clean(self):
        for phase,action in [('prerm','upgrade'),('prerm','failed-upgrade'),('postrm','upgrade'),('postrm','failed-upgrade'),('postrm','abort-install'),('postrm','abort-upgrade'),('postrm','disappear'),('postinst','abort-remove')]:
            with patch.object(lc,'preflight') as pre,patch.object(lc,'removal') as clean:
                lc.main(phase,[action,'0.3.2'])
                pre.assert_not_called();clean.assert_not_called()

    def test_signal_handler_no_reentrant_wait(self):
        child=Mock()
        with patch.object(launcher,'CHILD',child),patch.object(launcher,'STOP',False):
            launcher.stop(signal.SIGTERM,None)
            self.assertTrue(launcher.STOP);self.assertEqual(child.mock_calls,[])
        src=Path(launcher.__file__).read_text()
        self.assertNotIn('CHILD.wait()',src)
        # 0.3.2-3: process-group signalling is required, but ONLY outside the
        # handler. The handler itself must stay async-signal-safe.
        tree=ast.parse(src)
        handler=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='stop')
        body=ast.get_source_segment(src,handler)
        for forbidden in ('killpg','kill(','wait(','open(','print(','signal.signal'):
            self.assertNotIn(forbidden,body)
        terminate=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='terminate')
        self.assertIn('os.killpg',ast.get_source_segment(src,terminate))
        # No pkill/killall anywhere in executable code (docstrings may name them).
        docstrings=set()
        for node in ast.walk(tree):
            if isinstance(node,(ast.Module,ast.FunctionDef,ast.ClassDef)) and node.body:
                first=node.body[0]
                if (isinstance(first,ast.Expr) and isinstance(first.value,ast.Constant)
                        and isinstance(first.value.value,str)): docstrings.add(id(first.value))
        for node in ast.walk(tree):
            if (isinstance(node,ast.Constant) and isinstance(node.value,str)
                    and id(node) not in docstrings):
                self.assertNotIn('pkill',node.value);self.assertNotIn('killall',node.value)
            if isinstance(node,(ast.Name,ast.Attribute)):
                label=getattr(node,'id',None) or getattr(node,'attr',None) or ''
                self.assertNotIn('pkill',label);self.assertNotIn('killall',label)
        spawn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='spawn')
        self.assertIn('pass_fds=(read_fd,)',ast.get_source_segment(src,spawn))
        self.assertIn('start_new_session=True',ast.get_source_segment(src,spawn))

    def test_all_tools_registered(self):
        # 0.3.3 shipped twelve tools; 0.3.4 added the eight file-interface tools;
        # 0.3.5 appends jb_mkdir and the four staged-upload tools and must not have
        # changed, removed or reordered anything that shipped before it.
        self.assertEqual(len(bridge.TOOLS),26)
        self.assertEqual([tool['name'] for tool in bridge.TOOLS][:12],
                         ['jb_device_info','jb_process_list','jb_maintenance_info','jb_read_file',
                          'jb_write_file','jb_edit_file','jb_exec','jb_stage_update',
                          'jb_validate_update','jb_apply_update','jb_restart','jb_rollback'])
        self.assertEqual([tool['name'] for tool in bridge.TOOLS][12:20],
                         ['jb_list_dir','jb_stat','jb_delete','jb_rename','jb_search',
                          'jb_read_chunk','jb_write_chunk','jb_projects'])
        self.assertEqual([tool['name'] for tool in bridge.TOOLS][20:],
                         ['jb_mkdir','jb_upload_begin','jb_upload_chunk','jb_upload_commit',
                          'jb_upload_abort','jb_find'])
        self.assertEqual(sorted(bridge.SPEC),sorted(tool['name'] for tool in bridge.TOOLS))
        for tool in bridge.TOOLS:
            self.assertFalse(tool['inputSchema']['additionalProperties'])
        self.assertEqual(bridge.VERSION,'0.3.8')
        self.assertEqual(rt.STATE,Path('/var/mobile/Documents/OpenMinis-Jailbreak/.bridge-state'))
        # No new tool can widen its own roots: none takes a 'projects' argument and
        # none reaches outside the configured roots.
        for name in ('jb_mkdir','jb_upload_begin','jb_upload_chunk','jb_upload_commit',
                     'jb_upload_abort'):
            self.assertNotIn('projects',bridge.SPEC[name]['properties'])
        source=Path(bridge.__file__).read_text()
        self.assertIn("'api': 3",source)          # the API level is unchanged
        block=source[source.index('# 0.3.5 file interface.'):source.index('\ndef invoke(')]
        for forbidden in ('setuid','sudo','token','geteuid() == 0','import shutil'):
            self.assertNotIn(forbidden,block)

    def test_fresh_alias_and_data_refuse_without_mutation(self):
        with documents_fixture() as d,patch.object(rm,'socket_free') as free:
            alias=Path(d)/rm.ALIAS;alias.symlink_to('/nonexistent')
            with self.assertRaises(RuntimeError): rm.fresh()
            self.assertTrue(alias.is_symlink());free.assert_not_called()
            alias.unlink();base=Path(d)/rm.BASE;base.mkdir();(base/'ordinary').write_text('keep')
            with self.assertRaises(RuntimeError):rm.fresh()
            self.assertEqual((base/'ordinary').read_text(),'keep')

    def test_clean_state_remove_purge_and_symlink(self):
        with documents_fixture() as d:
            root=Path(d);base=root/rm.BASE;base.mkdir();os.chown(base,501,-1)
            state=base/'.bridge-state';state.mkdir();(state/'token').write_text('test')
            outside=root/'private-backup';outside.mkdir();(outside/'keep').write_text('never delete')
            (state/'evil').symlink_to(outside,target_is_directory=True)
            (base/'ordinary').write_text('keep');(root/rm.ALIAS).symlink_to(outside)
            rm.cleanup();rm.cleanup()
            self.assertFalse(state.exists());self.assertEqual((base/'ordinary').read_text(),'keep')
            self.assertEqual((outside/'keep').read_text(),'never delete');self.assertTrue((root/rm.ALIAS).is_symlink())
            (base/'ordinary').unlink();rm.cleanup();self.assertFalse(base.exists());rm.cleanup()

    def test_canonical_symlink_never_traversed(self):
        with documents_fixture() as d:
            target=Path(d)/'backup';(target/'.bridge-state').mkdir(parents=True);(target/'.bridge-state'/'token').write_text('keep')
            (Path(d)/rm.BASE).symlink_to(target)
            rm.cleanup();self.assertTrue((target/'.bridge-state'/'token').exists())

    def test_listener_blocks_fresh_and_stopped(self):
        with socket.socket() as s,patch.object(rm,'identity'):
            s.bind(('127.0.0.1',0));s.listen(1)
            with patch.object(rm,'PORT',s.getsockname()[1]):
                with self.assertRaises(OSError):rm.socket_free()
                with self.assertRaises(OSError):rm.stopped()

    def test_unknown_service_blocks_before_stop(self):
        with patch.object(lc,'preflight'),patch.object(lc,'known',side_effect=RuntimeError('unknown')),patch.object(lc,'remove_stop') as stop:
            with self.assertRaises(RuntimeError):lc.main('prerm',['remove'])
            stop.assert_not_called()

    def test_postrm_optional_errors_no_wedge(self):
        receipt_patch = patch.object(lc, 'receipt', return_value=True)
        receipt_patch.start(); self.addCleanup(receipt_patch.stop)
        with patch.object(lc,'guard'),patch.object(lc,'DEST',Path('/not-present-x')),patch.object(lc,'active',return_value=None),patch.object(lc,'removal',side_effect=OSError('unavailable')):
            lc.main('postrm',['remove']);lc.main('postrm',['purge'])
        with patch.object(lc,'guard'),patch.object(lc,'DEST',Path('/not-present-x')),patch.object(lc,'active',return_value=None),patch.object(lc,'removal',side_effect=[Mock(returncode=0),OSError('cleanup')]):
            lc.main('postrm',['purge'])

    def test_cancel_reaps_outside_process_lock(self):
        child=Mock()
        def wait(**kw):
            self.assertTrue(rt.PROCESS_LOCK.acquire(False))
            rt.PROCESS_LOCK.release()
            return 0
        child.wait.side_effect=wait
        with patch.object(rt,'PROCESSES',{child}),patch.object(rt,'STOPPING',False),patch.object(os,'killpg') as kill:
            rt.stop_commands()
            self.assertTrue(rt.STOPPING);kill.assert_called_once();child.wait.assert_called_once()

    def test_missing_receipt_preserves_data(self):
        with patch.object(lc,'receipt',return_value=False),patch.object(lc,'removal') as removal:
            lc.main('postrm',['purge']);removal.assert_not_called()

    def test_fresh_preinst_selfcontained(self):
        with patch.object(lc,'preflight'),patch.object(lc,'known'),patch.object(lc,'STORE',Path('/missing-openminis-test')),patch.object(lc,'DEST',Path('/missing-openminis-test.plist')),patch.object(lc,'active',return_value=None),patch.object(lc,'removal',return_value=Mock(returncode=0)) as removal,patch.object(lc,'mobile') as mobile:
            lc.main('preinst',['install'])
            removal.assert_called_once_with('fresh()');mobile.assert_not_called()

    def test_bounded_kill_fallback(self):
        child=Mock();child.poll.return_value=None
        child.wait.side_effect=[subprocess.TimeoutExpired('owned',2),0]
        launcher.terminate(child)
        child.terminate.assert_called_once();child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count,2)

    def test_loaded_wrong_program_rejected(self):
        text=('user/501/'+lc.LABEL+' = {\n path = /verified\n program = /other\n arguments = {\n /other\n -I\n -B\n -c\n '+lc.BOOT+'\n }\n}')
        with patch.object(lc,'run',return_value=Mock(returncode=0,stdout=text.encode())),patch.object(lc,'DEST',Mock(exists=lambda:True)),patch.object(os.path,'samefile',side_effect=lambda a,b:a=='/verified'):
            with self.assertRaises(RuntimeError):lc.active()

    def test_embedded_no_removed_payload_import(self):
        self.assertNotIn('import maintenance_runtime',Path(rm.__file__).read_text())
        self.assertNotIn('ps',Path(rm.__file__).read_text().split('def identity')[1])
        self.assertNotIn('os.kill',Path(rm.__file__).read_text())

    def test_system_private_var_mapping_and_documents_mapping(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); logical=root/'var'; private=root/'private'; private.mkdir()
            real=root/'real-documents'; real.mkdir(); os.chown(real,501,-1)
            (logical/'mobile').mkdir(parents=True)
            (logical/'mobile'/'Documents').symlink_to(real, target_is_directory=True)
            (private/'var').symlink_to(logical, target_is_directory=True)
            with patch.object(rm,'DOCS',str(logical/'mobile'/'Documents')), patch.object(rm,'DOCS_ALIAS',str(private/'var'/'mobile'/'Documents')), patch.object(rm,'identity'), patch.object(rm,'socket_free'):
                rm.fresh()
                base=real/rm.BASE; base.mkdir(); os.chown(base,501,-1)
                state=base/'.bridge-state'; state.mkdir(); (state/'owned').write_text('delete')
                (base/'ordinary').write_text('keep'); (real/'unrelated').write_text('untouched')
                rm.stopped(); rm.cleanup()
                self.assertFalse(state.exists())
                self.assertEqual((base/'ordinary').read_text(),'keep')
                self.assertEqual((real/'unrelated').read_text(),'untouched')

    def test_anchor_mismatch_and_wrong_owner_fail_closed(self):
        with documents_fixture() as d, tempfile.TemporaryDirectory() as alternate:
            os.chown(alternate,501,-1)
            with patch.object(rm,'DOCS_ALIAS',alternate):
                with self.assertRaises(RuntimeError): rm.fresh()
                with self.assertRaises(RuntimeError): rm.cleanup()
            os.chown(d,0,-1)
            with self.assertRaises(RuntimeError): rm.fresh()

    def test_state_symlink_blocks_stop_preserves_target(self):
        with documents_fixture() as d, patch.object(rm,'socket_free'):
            root=Path(d); base=root/rm.BASE; base.mkdir(); os.chown(base,501,-1)
            outside=root/'unrelated'; outside.mkdir(); (outside/'keep').write_text('unchanged')
            (base/'.bridge-state').symlink_to(outside,target_is_directory=True)
            with self.assertRaises(OSError): rm.stopped()
            # cleanup may unlink the state symlink name, never follow it.
            rm.cleanup()
            self.assertEqual((outside/'keep').read_text(),'unchanged')

    def test_fresh_helper_errors_are_fixed_tags(self):
        import io
        with patch.object(rm,'fresh',side_effect=RuntimeError('synthetic-secret')), patch.object(rm,'STAGE','documents-anchor'):
            output=io.StringIO()
            with contextlib.redirect_stderr(output), self.assertRaises(SystemExit): rm.checked('fresh')
            self.assertEqual(output.getvalue(),'HELPER_FAIL:documents-anchor\n')

    def test_diagnostic_same_helper_and_safe_stage(self):
        import io
        # The repository ships the diagnostic under tools/; the package tree and older
        # checkouts kept it beside the sources. Accept either location and whichever
        # revision filenames are present, newest first.
        names = ['openminis-preflight-readonly-v032r4.py', 'openminis-preflight-readonly-v032r3.py',
                 'openminis-preflight-readonly-v032r2.py']
        roots = [HERE.parent, HERE.parent / 'tools', HERE / 'tools', HERE]
        candidates = [root / name for name in names for root in roots]
        path = next((p for p in candidates if p.is_file()), None)
        if path is None:
            self.skipTest('no preflight diagnostic shipped in this layout')
        source=path.read_text(); ast.parse(source,feature_version=(3,9))
        ns={'__name__':'diagnostic_test'}; exec(compile(source,str(path),'exec'),ns)
        self.assertEqual(ns['REMOVAL'],Path(rm.__file__).read_text())
        def failed_fresh(code):
            ns['stage']('mobile-fresh/HELPER_FAIL:documents-anchor')
            return Mock(returncode=1)
        ns.update(preflight=lambda:None, active=lambda:None, removal=failed_fresh,
            run=lambda args:Mock(returncode=0,stdout=b'rc '),
            STORE=Path('/missing-revision-store'), DEST=Path('/missing-revision-plist'))
        out=io.StringIO()
        with contextlib.redirect_stdout(out): self.assertEqual(ns['diagnostic'](),1)
        self.assertIn('stage=package-status-not-purged',out.getvalue())
        self.assertIn('stage=mobile-fresh/HELPER_FAIL:documents-anchor',out.getvalue())
        self.assertNotIn('Traceback',out.getvalue())

    def real_supervisor(self,healthy):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d)
            code='''import sys,os,time,socket,subprocess,contextlib
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import launcher as l
r=Path(sys.argv[2]); healthy=sys.argv[3]=='yes'
l.rt.mobile=lambda:None
l.rt.token=lambda:'test'
l.rt.config=lambda:{}
@contextlib.contextmanager
def state():
 fd=os.open(str(r),os.O_RDONLY|os.O_DIRECTORY)
 try:yield fd
 finally:os.close(fd)
l.rt.state=state
l.rt.load=lambda name:{'current':'a'*64}
l.consume=lambda p:p
l.status=lambda **kw:(r/'healthy').write_text('ok') if kw.get('event')=='healthy' else None
child_code="import socket,time,os,sys; from pathlib import Path; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); Path(sys.argv[1]).write_text(str(os.getpid())+' '+str(s.getsockname()[1])); time.sleep(60)"
def spawn(version):
 return subprocess.Popen([sys.executable,'-c',child_code,str(r/'child')])
l.spawn=spawn
def health(*args):
 if not healthy:raise ValueError('not yet healthy')
 return True
l.health=health
l.run()
'''
            proc=subprocess.Popen([sys.executable,'-c',code,str(HERE/'source-v030'),str(d),'yes' if healthy else 'no'])
            pid=None;port=None
            try:
                deadline=time.monotonic()+8
                while time.monotonic()<deadline:
                    if (d/'child').exists() and (not healthy or (d/'healthy').exists()):
                        parts=(d/'child').read_text().split()
                        if len(parts)==2:pid,port=map(int,parts);break
                    time.sleep(.02)
                self.assertIsNotNone(pid)
                proc.send_signal(signal.SIGTERM)
                # Repeat immediately: signal may interrupt Popen's own wait in finally.
                proc.send_signal(signal.SIGTERM)
                self.assertEqual(proc.wait(timeout=6),0)
                with self.assertRaises(ProcessLookupError):os.kill(pid,0)
                with socket.socket() as s:s.bind(('127.0.0.1',port));s.listen(1)
            finally:
                if proc.poll() is None:proc.kill();proc.wait()
                if pid:
                    try:os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_real_sigterm_during_health_wait(self):self.real_supervisor(False)
    def test_real_sigterm_during_healthy_child_wait(self):self.real_supervisor(True)

if __name__=='__main__':unittest.main(verbosity=2)
