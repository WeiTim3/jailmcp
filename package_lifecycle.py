"""Embedded maintainer-script implementation. No imports from mobile paths."""
import hashlib
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

LABEL = 'app.openminis.jbbridge'
STORE = Path('/usr/local/lib/openminis-jb')
RECEIPT = STORE / '.clean-install-v032'
VERSION = '0.3.2-4+experimental'
RECEIPT_DATA = ('OpenMinis-Jailbreak clean-install ' + VERSION + '\n').encode()
STAGE = 'dispatch'
HELPER_TAGS = ('identity', 'documents-anchor', 'project-conflict', 'socket', 'fresh-complete', 'stopped', 'cleanup')

def stage(name):
    global STAGE
    STAGE = name
DEST = Path('/Library/LaunchDaemons') / (LABEL + '.plist')
BOOT = "import sys,runpy; sys.path.insert(0,'/usr/local/lib/openminis-jb'); runpy.run_path('/usr/local/lib/openminis-jb/launcher.py',run_name='__main__')"
HASHES = {}  # Filled by reproducible builder.
REMOVAL = ''  # Filled by reproducible builder.
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/var/mobile', 'PYTHONUNBUFFERED': '1'}

def run(args, mobile=False, timeout=25):
    kw = {}
    if mobile:
        account = pwd.getpwnam('mobile')
        def drop():
            os.initgroups('mobile', account.pw_gid)
            os.setgid(account.pw_gid); os.setuid(501)
        kw['preexec_fn'] = drop
    return subprocess.run([str(a) for a in args], env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, **kw)

def require(result):
    if result.returncode: raise RuntimeError('Child failed; output withheld')
    return result

def guard(path):
    for p in [path] + list(path.parents):
        if p.is_symlink(): raise RuntimeError('Unexpected symlink in root destination')
        if p.exists():
            s = p.stat()
            library = p == Path('/Library') and s.st_uid == 0 and s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 0o775
            if s.st_uid != 0 or (s.st_mode & 0o022 and not library):
                raise RuntimeError('Unsafe root artifact or ancestor')
            if p == path and p.is_file() and (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1):
                raise RuntimeError('Unsafe root file')

def root():
    value = require(run(['/usr/bin/jbroot'])).stdout.decode().strip()
    p = Path(value)
    if (str(p.parent) not in ('/var/containers/Bundle/Application', '/private/var/containers/Bundle/Application')
        or not re.fullmatch(r'\.jbroot-[0-9a-fA-F]{16}', p.name)
        or not p.is_symlink() or os.readlink(p) != '/' or p.resolve() != Path('/')):
        raise RuntimeError('Unverified Roothide mapping; installation blocked')
    return p

def preflight():
    stage('platform-root')
    if sys.platform != 'darwin' or os.geteuid() != 0: raise RuntimeError('Requires Roothide iOS root dpkg')
    stage('mobile-identity')
    account = pwd.getpwnam('mobile')
    if account.pw_uid != 501 or 0 in os.getgrouplist('mobile', account.pw_gid):
        raise RuntimeError('Unsafe mobile identity/groups')
    stage('architecture')
    if require(run(['/usr/bin/dpkg', '--print-architecture'])).stdout.strip() != b'iphoneos-arm64e':
        raise RuntimeError('Wrong dpkg architecture')
    stage('jbroot-mapping')
    r = root()
    stage('root-store-guard'); guard(STORE)
    stage('root-plist-guard'); guard(DEST)
    return r

def expected(r):
    python = Path('/usr/bin/python3').resolve()
    if not re.fullmatch(r'python3(?:\.[0-9]+)?', python.name): raise RuntimeError('Unexpected Python interpreter')
    return {'Label': LABEL, 'ProgramArguments': [str(r / str(python).lstrip('/')), '-I', '-B', '-c', BOOT],
        'UserName': 'mobile', 'GroupName': 'mobile', 'RunAtLoad': True, 'KeepAlive': True,
        'ThrottleInterval': 15, 'ExitTimeOut': 15, 'EnvironmentVariables': {'PATH': ENV['PATH'], 'PYTHONUNBUFFERED': '1'},
        'StandardOutPath': '/dev/null', 'StandardErrorPath': '/dev/null'}

def equivalent(data, r):
    p = plistlib.loads(data); q = expected(r)
    patched = p.pop('__Patched', None)
    if patched not in (None, True): return False
    for key in ('StandardOutPath', 'StandardErrorPath'):
        if not isinstance(p.get(key), str) or not os.path.samefile(p[key], q[key]): return False
        p[key] = q[key]
    a = p.get('ProgramArguments')
    if not isinstance(a, list) or len(a) != 5 or not os.path.samefile(a[0], q['ProgramArguments'][0]): return False
    a[0] = q['ProgramArguments'][0]
    return p == q

def known(r, required=False):
    for name, sha in HASHES.items():
        p = STORE / name; guard(p)
        if p.exists():
            if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != sha:
                raise RuntimeError('Unknown or incompatible root runtime; blocked before overwrite')
        elif required: raise RuntimeError('Missing packaged runtime')
    if DEST.exists() and (not DEST.is_file() or not equivalent(DEST.read_bytes(), r)):
        raise RuntimeError('Unknown same-label plist; blocked')

def active():
    found = set()
    for domain in ('user/501', 'system'):
        result = run(['/usr/bin/launchctl', 'print', domain + '/' + LABEL])
        if result.returncode:
            # Missing service is normal; transport/permission failures are not proof of absence.
            if b'Could not find service' in result.stderr or b'Could not find specified service' in result.stderr:
                continue
            raise RuntimeError('Cannot establish service registration state')
        text = result.stdout.decode(errors='replace')
        path = re.search(r'^\s*path = (.+?)\s*$', text, re.M)
        header = re.search(r'^\s*(user/501|system)/app\.openminis\.jbbridge\s*=\s*\{', text)
        if not path or not header or not DEST.exists() or not os.path.samefile(path[1], DEST):
            raise RuntimeError('Unknown service registration')
        # A matching on-disk plist alone does not prove the loaded job is ours.
        program = re.search(r'^\s*program = (.+?)\s*$', text, re.M)
        arguments = re.search(r'^\s*arguments = \{\s*\n(.*?)^\s*\}', text, re.M | re.S)
        argv = [line.strip() for line in arguments[1].splitlines() if line.strip()] if arguments else []
        if (not program or not os.path.samefile(program[1], '/usr/bin/python3') or
                len(argv) != 5 or argv[1:] != ['-I', '-B', '-c', BOOT] or
                not os.path.samefile(argv[0], '/usr/bin/python3')):
            raise RuntimeError('Loaded same-label job has unverified program/arguments')
        found.add(header[1])
    if len(found) > 1: raise RuntimeError('Multiple service domains')
    return next(iter(found), None)

def mobile(code, timeout=30):
    return run(['/usr/bin/python3', '-I', '-B', '-c',
        "import sys; sys.path.insert(0,'/usr/local/lib/openminis-jb'); " + code], mobile=True, timeout=timeout)

def validate_mobile():
    # No mobile source executed: code() only hashes and compiles, after setuid.
    code = ("import maintenance_runtime as rt; rt.mobile(); rt.token(); rt.config(); "
        "p=rt.load('active-v030.json'); "
        "[rt.code(p[k]) for k in ('current','previous','trial') if p.get(k)]")
    require(mobile(code))

def healthy():
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        result = mobile("import maintenance_runtime as rt,launcher; rt.mobile(); "
            "s=rt.load('supervisor-v030.json'); assert s['event']=='healthy'; "
            "assert s['current']==rt.load('active-v030.json')['current']; "
            "launcher.health(s['child_pid'],s['current'])", timeout=5)
        if result.returncode == 0: return
        time.sleep(0.5)
    raise RuntimeError('UID501 API3 authenticated health failed')

def stop():
    if active():
        # Roothide translates system interface to user/501; never pkill/killall.
        stage('prerm-bootout')
        require(run(['/usr/bin/launchctl', 'bootout', 'system/' + LABEL]))
        for _ in range(40):
            if not active(): return
            time.sleep(0.25)
        stage('prerm-bootout-timeout')
        raise RuntimeError('Service still registered; removal blocked')

def removal(code):
    account = pwd.getpwnam('mobile')
    if account.pw_uid != 501 or 0 in os.getgrouplist('mobile', account.pw_gid):
        raise RuntimeError('Unsafe mobile identity')
    operations = {'fresh()': 'fresh', 'stopped()': 'stopped', 'cleanup()': 'cleanup'}
    operation = operations[code]
    result = run(['/usr/bin/python3', '-I', '-B', '-c',
        REMOVAL + '\nchecked(' + repr(operation) + ')'], mobile=True)
    if result.returncode:
        tag = result.stderr.decode(errors='replace').strip()
        if tag in ('HELPER_FAIL:' + t for t in HELPER_TAGS):
            # Bound the report: the same failing stage must never be appended
            # repeatedly (a retired loop could print HELP_FAIL ~40 times).
            stage(STAGE.split('/HELPER_FAIL:')[0] + '/' + tag)
    return result

def remove_stop():
    # The supervisor of this release kills and reaps its whole child process
    # group before releasing its lock, so no orphan listener survives bootout.
    # Never enumerate processes and never signal a PID learned from mobile data.
    stop()
    stage('prerm-orphan-guard')
    deadline = time.monotonic() + 12
    while True:
        if removal('stopped()').returncode == 0: return
        if time.monotonic() >= deadline: break
        time.sleep(.5)
    raise RuntimeError('Service port or supervisor lock still held after bounded stop; '
        'removal aborted before any payload removal')

def receipt():
    guard(RECEIPT)
    return RECEIPT.is_file() and RECEIPT.read_bytes() == RECEIPT_DATA

def create_receipt():
    guard(RECEIPT)
    fd = os.open(RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(RECEIPT_DATA); stream.flush(); os.fsync(stream.fileno())

def remove_residue():
    # postrm must survive missing payload/metadata and repeated purge.
    try:
        if not receipt():
            print('NOTICE: no clean-install ownership receipt; mobile data preserved'); return
        guard(DEST)
        if DEST.exists() and not equivalent(DEST.read_bytes(), root()):
            print('WARNING: unknown plist; all residues preserved'); return
        if active():
            print('WARNING: service still registered; residues preserved'); return
        require(removal('stopped()'))
    except Exception:
        print('WARNING: stop could not be verified; residues preserved'); return
    cleaned = False
    try:
        result = removal('cleanup()')
        if result.returncode: print('WARNING: mobile cleanup incomplete; no token disclosed')
        else:
            cleaned = True
            if result.stdout: print('NOTICE: nonempty/conflicting mobile paths preserved if present')
    except Exception: print('WARNING: mobile cleanup unavailable; preserved')
    try:
        guard(DEST)
        if DEST.exists():
            if equivalent(DEST.read_bytes(), root()): DEST.unlink()
            else: print('WARNING: unknown plist preserved')
    except Exception: print('WARNING: root plist cleanup skipped safely')
    # No verified 0.3.0 metadata schema exists for failed migration backups.
    # Never infer ownership from a name alone or import the failed migration code.
    for p in (STORE / 'migration-backup-v030', Path('/usr/local/lib/openminis-jb-transaction')):
        if os.path.lexists(p): print('WARNING: unverified migration diagnostics preserved')
    try:
        guard(STORE)
        if cleaned and receipt(): RECEIPT.unlink()
        if STORE.exists(): STORE.rmdir()
    except Exception: print('NOTICE: nonempty/conflicting runtime directory preserved')

def atomic(data):
    guard(DEST)
    fd, name = tempfile.mkstemp(prefix='.openminis-', dir=str(DEST.parent))
    try:
        os.fchmod(fd, 0o644); os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(name, DEST)
    finally:
        if os.path.exists(name): os.unlink(name)

def prior_state():
    """dpkg's recorded status for this package, or None when it cannot be read."""
    try:
        result = run(['/usr/bin/dpkg-query', '-W', '-f=${Status}', 'app.openminis.jailbreak'])
    except Exception:
        return None
    if result.returncode: return None
    return result.stdout.decode(errors='replace').strip()

def replaces_installed_payload(action, args):
    """True only when this invocation would overwrite an actually-installed package.

    After a normal removal dpkg keeps a 'deinstall ok config-files' record, so a
    reinstall is still a clean install and must NOT require a manual purge; only a
    genuinely installed payload is refused.
    """
    if action == 'upgrade': return True
    if action != 'install' or len(args) < 2 or not args[1]: return False
    state = prior_state()
    if state is None:
        # Status unreadable: fall back to artifacts, which preinst validates anyway.
        return os.path.lexists(STORE) or os.path.lexists(DEST)
    return 'ok installed' in state

def main(phase, args):
    stage(phase + '-dispatch')
    action = args[0] if args else ''
    if phase == 'preinst' and replaces_installed_payload(action, args):
        stage('clean-install-only-installed-payload')
        print('CLEAN-INSTALL ONLY: 检测到已安装的旧版本；请先卸载，并私下备份用户数据，本包不支持原地升级覆盖。', file=sys.stderr)
        raise RuntimeError('CLEAN-INSTALL ONLY: an installed baseline must be removed first; no in-place upgrade')
    if phase == 'preinst' and action != 'install': return
    if phase == 'postinst' and action != 'configure': return
    if phase == 'prerm' and action != 'remove': return
    if phase == 'postrm' and action not in ('remove', 'purge'): return
    if phase == 'postrm':
        remove_residue(); return
    if phase == 'prerm':
        # Missing payload is not itself unsafe; existing root artifacts still validated.
        r = preflight(); known(r, required=False)
        if active() and not receipt():
            raise RuntimeError('Active job lacks this release ownership receipt; removal blocked')
        remove_stop(); return
    r = preflight()
    stage(phase + '-known-artifacts'); known(r, required=phase == 'postinst')
    if phase == 'preinst':
        stage('preinst-root-residue')
        if (os.path.lexists(STORE) or os.path.lexists(DEST) or
                os.path.lexists('/usr/local/lib/openminis-jb-transaction')):
            raise RuntimeError('Root runtime/backup residue exists; preserve and review before clean install')
        stage('preinst-service')
        if active():
            raise RuntimeError('Same-label service exists; uninstall baseline first')
        stage(phase + '-mobile-fresh')
        require(removal('fresh()'))
        return
    stage('postinst-service-receipt')
    before = active()
    owned = receipt()
    if not owned:
        if before or DEST.exists(): raise RuntimeError('Unexpected existing service; clean install only')
        stage(phase + '-mobile-fresh')
        require(removal('fresh()'))
        create_receipt()
    if before:
        validate_mobile(); healthy()
        print('OpenMinis-Jailbreak: existing API3 service adopted without restart; data unchanged')
        return
    old = DEST.read_bytes() if DEST.exists() else None
    stage('postinst-mobile-setup')
    require(mobile('import mobile_setup; mobile_setup.setup()'))
    stage('postinst-plist')
    if old is None: atomic(plistlib.dumps(expected(r)))
    try:
        stage('postinst-bootstrap')
        require(run(['/usr/bin/launchctl', 'bootstrap', 'system', DEST]))
        if not active() or not equivalent(DEST.read_bytes(), r): raise RuntimeError('Registration mismatch')
        stage('postinst-health')
        healthy()
    except BaseException:
        # Preserve previously loaded service by never stopping it in this branch.
        # Failed fresh/offline activation is undone; diagnostics stay non-secret.
        stop()
        if old is None:
            if DEST.exists(): DEST.unlink()
        else: atomic(old)
        raise RuntimeError('Activation failed; prior plist restored, mobile data preserved') from None
    print('OpenMinis-Jailbreak: UID501 API3 service healthy; token not printed')

if __name__ == '__main__':
    try: main(sys.argv[1], sys.argv[2:])
    except BaseException:
        print('OpenMinis-Jailbreak: FAILED phase=' + sys.argv[1] + ' stage=' + STAGE +
            '. No further changes were made by this step; resolve the named stage and retry '
            '(clean-install only; preserve and review conflicts). No exception or child output disclosed.',
            file=sys.stderr)
        sys.exit(1)
