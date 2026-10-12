"""Embedded maintainer-script implementation. No imports from mobile paths."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time

LABEL = 'app.openminis.jbbridge'
STORE = Path('/usr/local/lib/openminis-jb')
TRANSACTION = Path('/usr/local/lib/openminis-jb-transaction')
RECEIPT = STORE / '.clean-install-v032'
VERSION = '0.3.6-1+experimental'
RECEIPT_DATA = ('OpenMinis-Jailbreak clean-install ' + VERSION + '\n').encode()
RECEIPT_PREFIX = b'OpenMinis-Jailbreak clean-install '
SCHEMA = 'openminis-jb-upgrade-1'
STAGE = 'dispatch'
REPORTED = False
HELPER_TAGS = ('identity', 'documents-anchor', 'project-conflict', 'socket', 'fresh-complete', 'stopped', 'cleanup')
RUNTIME = ('launcher.py', 'maintenance_runtime.py', 'bridge.py', 'mobile_setup.py')
POINTER_KEYS = ('current', 'previous', 'trial')
SYSCTL = ('/usr/bin/sysctl', '/usr/sbin/sysctl', '/bin/sysctl', '/sbin/sysctl')
SHA = re.compile('[0-9a-f]{64}')
LISTENER_SECONDS = 20

def stage(name):
    global STAGE
    STAGE = name
DEST = Path('/Library/LaunchDaemons') / (LABEL + '.plist')
BOOT = "import sys,runpy; sys.path.insert(0,'/usr/local/lib/openminis-jb'); runpy.run_path('/usr/local/lib/openminis-jb/launcher.py',run_name='__main__')"
HASHES = {}  # Filled by reproducible builder.
# Explicit allowlist of known-good *installed* root runtimes. All four files must
# match one listed set exactly; the packaged set of this release is appended at
# run time (HASHES) so that a same-version upgrade is also accepted. Known but
# deliberately unlisted releases (uninstall the baseline instead of upgrading):
#   0.3.2-3 / 0.3.2-4  launcher b905c063a8e7235b2e40cd1e3137e77372537d4611ff0af1e410049e9f96b497, bridge 425029fd6c59d9a0df39849357a3ac66773bc2140c1b6f4c62978d917fc766eb
#   0.3.4-2            launcher b905c063a8e7235b2e40cd1e3137e77372537d4611ff0af1e410049e9f96b497, bridge 4bffa899030206840d8f815c38fa25c267f29843e36f96328260aff6108605a0
KNOWN_SETS = {
    '0.3.3-1': {'launcher.py': 'b905c063a8e7235b2e40cd1e3137e77372537d4611ff0af1e410049e9f96b497',
                'maintenance_runtime.py': 'e38fe25d1d61ba759824a3d17af2101af0fbc1a6533c3444e8636211d95af46a',
                'bridge.py': 'ec7d57759c5841090db1ec999b86d769e89d3156e5c3fad8cdf5b1cf8c4b9003',
                'mobile_setup.py': '78ed4a0f75a16ba15298649713db62d3434c86e894ba0a3cace5385907389550'},
    '0.3.5-1': {'launcher.py': 'b905c063a8e7235b2e40cd1e3137e77372537d4611ff0af1e410049e9f96b497',
                'maintenance_runtime.py': 'e38fe25d1d61ba759824a3d17af2101af0fbc1a6533c3444e8636211d95af46a',
                'bridge.py': 'dfa21e1a76329ed5774559e4a67661dcb4fdd5c03fc2d4877d11e2afcf55b73f',
                'mobile_setup.py': '78ed4a0f75a16ba15298649713db62d3434c86e894ba0a3cace5385907389550'},
}
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

def legacy_receipt():
    """True when a receipt written by *some* earlier release of this package exists."""
    try:
        guard(RECEIPT)
        return RECEIPT.is_file() and RECEIPT.read_bytes().startswith(RECEIPT_PREFIX)
    except Exception:
        return False

def create_receipt():
    guard(RECEIPT)
    fd = os.open(RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(RECEIPT_DATA); stream.flush(); os.fsync(stream.fileno())

def refresh_receipt():
    """Package-owned metadata only: prove this release owns the mobile side.

    Never touches token, config, audit, versions or any mobile file.
    """
    guard(RECEIPT)
    if not os.path.lexists(RECEIPT): create_receipt(); return
    info = RECEIPT.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or not legacy_receipt():
        raise RuntimeError('Unexpected ownership receipt; blocked')
    fd, name = tempfile.mkstemp(prefix='.openminis-receipt-', dir=str(STORE))
    try:
        os.fchmod(fd, 0o600); os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(RECEIPT_DATA); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, RECEIPT)
    finally:
        if os.path.exists(name): os.unlink(name)

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
    for p in (STORE / 'migration-backup-v030', TRANSACTION):
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

# --------------------------------------------------------------- upgrade support
#
# In-place upgrade contract (0.3.6):
#   preinst 'upgrade'  -> full preflight, runtime/plist verification, snapshot,
#                         bounded service stop; no user data is ever touched.
#   postinst configure -> plist/runtime reconciliation, UID501 mobile pointer
#                         switch, service start, authenticated health check,
#                         commit (or snapshot rollback and a non-zero exit).
# Nothing in this path writes, resets or inspects token, config, audit or the
# versioned bridge directories except through read-only UID501 fingerprints.

def file_sha(path):
    try:
        if path.is_symlink() or not path.is_file(): return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None

def runtime_hashes():
    """sha256 of all four root runtime files, or None when any is unsafe/missing."""
    try:
        found = {}
        for name in RUNTIME:
            path = STORE / name
            guard(path)
            if path.is_symlink() or not path.is_file(): return None
            found[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        return found
    except Exception:
        return None

def known_set(hashes):
    """Label of the matching known-good installed runtime set, or None."""
    if hashes is None: return None
    for label, values in KNOWN_SETS.items():
        if hashes == values: return label
    if HASHES and hashes == dict(HASHES): return 'packaged ' + VERSION
    return None

def boot_stamp():
    """Identity of the current boot; a snapshot from another boot is never reused."""
    try:
        # libSystem is the only dependency-free way to read kern.boottime; a
        # packaged sysctl binary is used only when ctypes is unavailable.
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        buffer = ctypes.create_string_buffer(16)
        size = ctypes.c_size_t(16)
        if libc.sysctlbyname(b'kern.boottime', buffer, ctypes.byref(size), None, 0) == 0:
            seconds = ctypes.c_int64.from_buffer_copy(buffer.raw[:8]).value
            if seconds > 0: return hashlib.sha256(('boot:%d' % seconds).encode()).hexdigest()
    except Exception:
        pass
    for path in SYSCTL:
        try:
            if not os.path.exists(path): continue
            result = run([path, '-n', 'kern.boottime'], timeout=10)
        except Exception:
            continue
        if result.returncode == 0:
            text = ' '.join(result.stdout.decode('utf-8', 'replace').split())
            if text: return hashlib.sha256(('sysctl:' + text).encode()).hexdigest()
    for command in (['sysctl', '-n', 'kern.boottime'],):
        try:
            result = run(command, timeout=10)
        except Exception:
            continue
        if result.returncode == 0:
            text = ' '.join(result.stdout.decode('utf-8', 'replace').split())
            if text: return hashlib.sha256(('sysctl:' + text).encode()).hexdigest()
    raise RuntimeError('Cannot establish boot identity; upgrade blocked before any change')

# Embedded UID501 helpers. They are only ever executed through mobile(), i.e.
# after setuid(501); no versioned or packaged source is imported as root.
MOBILE_FINGERPRINT = (
"import json\n"
"import maintenance_runtime as rt\n"
"rt.mobile()\n"
"rt.token()\n"
"rt.config()\n"
"pointer = rt.load('active-v030.json')\n"
"assert set(pointer) <= set(('current', 'previous', 'trial')), 'Unexpected active pointer keys'\n"
"assert isinstance(pointer.get('current'), str), 'Missing active version'\n"
"rt.code(rt.valid_sha(pointer['current']))\n"
"for name in ('previous', 'trial'):\n"
"    value = pointer.get(name)\n"
"    if value is not None:\n"
"        try:\n"
"            rt.code(rt.valid_sha(value))\n"
"        except FileNotFoundError:\n"
"            pass\n"
"salt = bytes.fromhex(_ARG['salt'])\n"
"found = {}\n"
"with rt.state() as fd:\n"
"    for name, key, limit, private, lines in (('token', 'token', 4096, False, False),\n"
"                                             ('config-v030.json', 'config', rt.MAX_FILE, True, False),\n"
"                                             ('audit-v030.jsonl', 'audit', 32768, True, True)):\n"
"        try:\n"
"            data = rt.read_at(fd, name, limit, private)\n"
"        except FileNotFoundError:\n"
"            data = None\n"
"        found[key] = {'sha': None, 'size': None, 'lines': None} if data is None else {\n"
"            'sha': rt.sha(salt + data), 'size': len(data),\n"
"            'lines': data.count(b'\\n') if lines else None}\n"
"print(json.dumps({'state': found,\n"
"                  'pointer': dict((n, pointer[n]) for n in ('current', 'previous', 'trial') if n in pointer)}))\n"
)
MOBILE_RECONCILE = (
"import maintenance_runtime as rt\n"
"rt.mobile()\n"
"rt.token()\n"
"rt.config()\n"
"data = (rt.STORE / 'bridge.py').read_bytes()\n"
"packaged = rt.sha(data)\n"
"assert packaged == _ARG['bridge'], 'Packaged bridge changed during the upgrade'\n"
"pointer = rt.load('active-v030.json')\n"
"current = rt.valid_sha(pointer['current'])\n"
"rt.code(current)\n"
"updated = dict((n, pointer.get(n)) for n in ('current', 'previous', 'trial'))\n"
"if packaged == current:\n"
"    print('MOBILE_ACTIVE:unchanged')\n"
"else:\n"
"    rt.stage(data, packaged)\n"
"    updated.pop('trial', None)\n"
"    updated['previous'] = current\n"
"    updated['current'] = packaged\n"
"    rt.save('active-v030.json', updated)\n"
"    rt.code(packaged)\n"
"    print('MOBILE_ACTIVE:switched')\n"
)
MOBILE_RESTORE = (
"import maintenance_runtime as rt\n"
"rt.mobile()\n"
"snapshot = _ARG['pointer']\n"
"assert isinstance(snapshot, dict) and set(snapshot) <= set(('current', 'previous', 'trial'))\n"
"value = {}\n"
"for name in snapshot:\n"
"    item = snapshot[name]\n"
"    value[name] = None if item is None else rt.valid_sha(item)\n"
"assert rt.valid_sha(value.get('current'))\n"
"rt.code(value['current'])\n"
"rt.save('active-v030.json', value)\n"
"rt.token()\n"
"rt.config()\n"
"print('MOBILE_ACTIVE:restored')\n"
)

def mobile_arg(body, payload):
    return '_ARG = ' + repr(payload) + '\n' + body

def mobile_out(body, payload, timeout=30):
    return require(mobile(mobile_arg(body, payload), timeout=timeout)).stdout.decode('utf-8', 'replace')

def mobile_json(body, payload, timeout=30):
    lines = [line for line in mobile_out(body, payload, timeout).strip().splitlines() if line.strip()]
    if not lines: raise RuntimeError('Mobile helper reported no result')
    return json.loads(lines[-1])

def fingerprint(salt=None):
    """Read-only UID501 view of the mobile state; fails closed on any doubt."""
    salt = salt or os.urandom(16).hex()
    data = mobile_json(MOBILE_FINGERPRINT, {'salt': salt})
    state = data.get('state'); pointer = data.get('pointer')
    if not isinstance(state, dict) or sorted(state) != ['audit', 'config', 'token']:
        raise RuntimeError('Unverified mobile state shape')
    for key in state:
        item = state[key]
        if not isinstance(item, dict) or item.get('size') is not None and not isinstance(item.get('size'), int):
            raise RuntimeError('Unverified mobile state fingerprint')
        if item.get('sha') is not None and not SHA.fullmatch(item['sha']):
            raise RuntimeError('Unverified mobile state fingerprint')
    if (not isinstance(pointer, dict) or not pointer or set(pointer) - set(POINTER_KEYS)
            or not isinstance(pointer.get('current'), str) or not SHA.fullmatch(pointer['current'])):
        raise RuntimeError('Unverified mobile active pointer')
    for name in pointer:
        if pointer[name] is not None and not SHA.fullmatch(pointer[name] if isinstance(pointer[name], str) else ''):
            raise RuntimeError('Unverified mobile active pointer')
    return {'salt': salt, 'state': state, 'pointer': pointer}

def fingerprint_shas(live):
    return dict((key, live['state'][key]['sha']) for key in ('token', 'config', 'audit'))

def audit_ok(before, after):
    """Best effort: this package never rewrites the audit; the service may append."""
    if before is None: return True
    if after is None: return False
    if before.get('sha') == after.get('sha'): return True
    return (after.get('lines') or 0) >= (before.get('lines') or 0) or (before.get('lines') or 0) >= 100

def reconcile(live):
    """Stage the packaged bridge as the active UID501 version when it differs."""
    text = mobile_out(MOBILE_RECONCILE, {'bridge': HASHES['bridge.py']})
    for line in text.splitlines():
        if line.strip().startswith('MOBILE_ACTIVE:'):
            marker = line.strip().split(':', 1)[1]
            if marker in ('unchanged', 'switched'): return marker
    raise RuntimeError('Mobile reconcile reported no result')

def restore_pointer(pointer):
    mobile_out(MOBILE_RESTORE, {'pointer': pointer})

def pointer_expectation(live, marker):
    if marker != 'switched': return None
    return {'current': HASHES['bridge.py'], 'previous': live['pointer']['current']}

# ------------------------------------------------------------- transaction store

def write_private(path, data):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())

def sync_dir(path):
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    except OSError: pass

def transaction_files():
    """Every regular file in the transaction directory, verified root-owned."""
    found = []
    def walk(folder, depth):
        if depth > 4: raise RuntimeError('Unexpected upgrade transaction content; review before retrying')
        with os.scandir(str(folder)) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or info.st_uid != 0:
                    raise RuntimeError('Unexpected upgrade transaction content; review before retrying')
                if entry.is_dir(follow_symlinks=False):
                    walk(Path(entry.path), depth + 1)
                elif entry.is_file(follow_symlinks=False):
                    if info.st_nlink != 1:
                        raise RuntimeError('Unexpected upgrade transaction content; review before retrying')
                    found.append(Path(entry.path))
                else:
                    raise RuntimeError('Unexpected upgrade transaction content; review before retrying')
    walk(TRANSACTION, 0)
    return found

def discard_transaction():
    if not os.path.lexists(TRANSACTION): return
    for path in transaction_files(): os.unlink(str(path))
    for folder, dirs, files in os.walk(str(TRANSACTION), topdown=False, followlinks=False):
        if Path(folder) != TRANSACTION: os.rmdir(folder)
    os.rmdir(str(TRANSACTION))

def transaction_meta():
    """Structurally valid transaction metadata, else None (never trusts content)."""
    def digest(value):
        return value is None or (isinstance(value, str) and SHA.fullmatch(value) is not None)
    try:
        info = TRANSACTION.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or
                info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700): return None
        meta = json.loads((TRANSACTION / 'meta.json').read_bytes())
    except Exception:
        return None
    if not isinstance(meta, dict) or meta.get('schema') != SCHEMA: return None
    if not isinstance(meta.get('boot'), str) or not SHA.fullmatch(meta['boot']): return None
    if meta.get('to_version') != VERSION: return None
    if not isinstance(meta.get('committed'), bool): return None
    if not isinstance(meta.get('label'), str): return None
    runtime = meta.get('runtime')
    if not isinstance(runtime, dict) or sorted(runtime) != sorted(RUNTIME): return None
    for name in runtime:
        if not digest(runtime[name]) or runtime[name] is None: return None
    for key in ('plist', 'receipt'):
        if not digest(meta.get(key)): return None
    mobile = meta.get('mobile')
    if not isinstance(mobile, dict): return None
    pointer = mobile.get('pointer')
    if (not isinstance(pointer, dict) or not pointer or set(pointer) - set(POINTER_KEYS)
            or not digest(pointer.get('current')) or pointer.get('current') is None): return None
    for name in pointer:
        if not digest(pointer[name]): return None
    salt = mobile.get('salt')
    if not isinstance(salt, str) or re.fullmatch('[0-9a-f]{32}', salt) is None: return None
    state = mobile.get('state')
    if not isinstance(state, dict) or sorted(state) != ['audit', 'config', 'token']: return None
    for key in state:
        if not digest(state[key]): return None
    return meta

def reusable(meta, boot, current, live):
    """A leftover snapshot may only be replaced when it provably describes the
    current pre-upgrade state and was taken during this same boot."""
    # The ownership receipt is package metadata that is deliberately refreshed
    # forward (so removal keeps working after a failed configure) and is
    # therefore NOT part of the reuse comparison.
    return (meta['boot'] == boot
            and meta['runtime'] == current
            and meta['plist'] == file_sha(DEST)
            and meta['mobile']['pointer'] == live['pointer'])

def snapshot(boot, current, label, live, from_version):
    os.mkdir(str(TRANSACTION), 0o700)
    os.chmod(str(TRANSACTION), 0o700)
    info = TRANSACTION.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or
            info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError('Unsafe upgrade transaction directory')
    folder = TRANSACTION / 'runtime'
    os.mkdir(str(folder), 0o700)
    for name in RUNTIME:
        data = (STORE / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != current[name]:
            raise RuntimeError('Root runtime changed while snapshotting')
        write_private(folder / name, data)
    plist = DEST.read_bytes() if DEST.is_file() and not DEST.is_symlink() else None
    if plist is not None: write_private(TRANSACTION / 'plist', plist)
    if os.path.lexists(RECEIPT):
        if not legacy_receipt(): raise RuntimeError('Unexpected ownership receipt; blocked')
        write_private(TRANSACTION / 'receipt', RECEIPT.read_bytes())
    meta = {'schema': SCHEMA, 'created': int(time.time()), 'boot': boot,
            'from_version': from_version, 'to_version': VERSION, 'label': label,
            'runtime': current, 'plist': file_sha(DEST), 'receipt': file_sha(RECEIPT),
            'mobile': {'pointer': live['pointer'], 'salt': live['salt'],
                       'state': fingerprint_shas(live)},
            'committed': False}
    write_private(TRANSACTION / 'meta.json', json.dumps(meta, sort_keys=True, indent=1).encode())
    sync_dir(folder); sync_dir(TRANSACTION); sync_dir(TRANSACTION.parent)

def replace_root(path, data):
    """Atomically put a root-owned payload file back (never follows a link)."""
    guard(path)
    fd, name = tempfile.mkstemp(prefix='.openminis-restore-', dir=str(path.parent))
    try:
        os.fchmod(fd, 0o644); os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, str(path))
    finally:
        if os.path.exists(name): os.unlink(name)

def restore_snapshot(meta):
    """Put back exactly the root runtime and plist recorded before the unpack."""
    for name in RUNTIME:
        data = (TRANSACTION / 'runtime' / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != meta['runtime'][name]:
            raise RuntimeError('Upgrade snapshot is inconsistent')
        replace_root(STORE / name, data)
    if meta['plist'] is not None:
        data = (TRANSACTION / 'plist').read_bytes()
        if hashlib.sha256(data).hexdigest() != meta['plist']:
            raise RuntimeError('Upgrade snapshot is inconsistent')
        atomic(data)
    return (runtime_hashes() == meta['runtime'] and file_sha(DEST) == meta['plist'])

def commit(meta):
    marked = dict(meta, committed=True, committed_at=int(time.time()), stage=STAGE)
    fd, name = tempfile.mkstemp(prefix='.openminis-commit-', dir=str(TRANSACTION))
    try:
        os.fchmod(fd, 0o600); os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(json.dumps(marked, sort_keys=True, indent=1).encode())
            stream.flush(); os.fsync(stream.fileno())
        os.replace(name, str(TRANSACTION / 'meta.json'))
    finally:
        if os.path.exists(name): os.unlink(name)
    sync_dir(TRANSACTION)
    try:
        discard_transaction()
    except Exception:
        # The transaction is already marked committed, so a later preinst treats
        # it as obsolete and replaces it; never fail a successful upgrade here.
        print('NOTICE: committed upgrade snapshot preserved for the next run')

def confirm_listener_released():
    stage('upgrade-listener-released')
    deadline = time.monotonic() + LISTENER_SECONDS
    while True:
        if removal('stopped()').returncode == 0: return
        if time.monotonic() >= deadline: break
        time.sleep(.5)
    raise RuntimeError('Upgrade could not confirm the listener was released')

def start_service():
    if active(): return
    require(run(['/usr/bin/launchctl', 'bootstrap', 'system', DEST]))
    if not active(): raise RuntimeError('Service registration failed')

def restore_service():
    """Best effort on an abort path: the service is never left stopped by us."""
    try:
        start_service()
    except Exception:
        pass

def ensure_plist(r):
    if not DEST.is_file() or DEST.is_symlink() or not equivalent(DEST.read_bytes(), r):
        atomic(plistlib.dumps(expected(r)))

def packaged_ready():
    if sorted(HASHES) != sorted(RUNTIME):
        raise RuntimeError('Packaged runtime hashes unavailable; blocked')

def upgrade_preinst(args):
    from_version = args[1] if len(args) > 1 and re.fullmatch(r'[0-9][0-9A-Za-z.+~:-]{0,63}', args[1] or '') else None
    stage('upgrade-preflight')
    r = preflight()
    stage('upgrade-runtime-allowlist')
    current = runtime_hashes()
    label = known_set(current)
    if label is None:
        raise RuntimeError('Installed root runtime is not an approved release; '
            'in-place upgrade blocked before any change (uninstall the baseline to reinstall)')
    stage('upgrade-plist-shape')
    if not DEST.is_file() or DEST.is_symlink() or not equivalent(DEST.read_bytes(), r):
        raise RuntimeError('Existing service plist is not the expected shape; upgrade blocked before any change')
    stage('upgrade-boot-identity')
    boot = boot_stamp()
    stage('upgrade-mobile-state')
    live = fingerprint()
    stage('upgrade-leftover-snapshot')
    if os.path.lexists(TRANSACTION):
        meta = transaction_meta()
        if not (meta is not None and (meta['committed'] or reusable(meta, boot, current, live))):
            raise RuntimeError('Leftover upgrade snapshot does not describe this pre-upgrade state; '
                'review and remove ' + str(TRANSACTION) + ' before retrying (nothing was changed)')
        discard_transaction()
    stage('upgrade-snapshot')
    try:
        snapshot(boot, current, label, live, from_version)
    except BaseException:
        try: discard_transaction()
        except Exception: pass
        raise
    stage('upgrade-stop')
    try:
        stop()
        confirm_listener_released()
    except BaseException:
        restore_service()
        try: discard_transaction()
        except Exception: pass
        raise
    print('OpenMinis-Jailbreak: upgrade preflight passed (installed ' + label + ' -> ' + VERSION + '); '
          'root runtime, plist and mobile pointer snapshotted; service stopped; '
          'token, config, audit and versioned bridges untouched')

def recover(meta, live, marker):
    """Best effort restoration after a failed configure; reports what it proved."""
    notes = []
    if marker == 'switched' and live is not None:
        try:
            restore_pointer(live['pointer']); notes.append('mobile active pointer restored')
        except Exception: notes.append('mobile active pointer NOT restored')
    else:
        notes.append('mobile active pointer unchanged')
    try:
        notes.append('snapshot restored' if restore_snapshot(meta) else 'snapshot restore unverified')
    except Exception: notes.append('root runtime/plist NOT restored')
    try:
        if active(): stop()
        start_service(); healthy(); notes.append('old version restarted and healthy')
    except Exception: notes.append('old version restart not verified')
    return notes

def upgrade_activate(r, meta=None):
    """Shared upgrade activation. `meta` enables root/plist rollback from a snapshot."""
    global REPORTED
    live = None; marker = 'unchanged'
    try:
        stage('activate-runtime')
        packaged_ready(); known(r, required=True)
        stage('activate-plist')
        ensure_plist(r)
        stage('activate-mobile-baseline')
        salt = meta['mobile']['salt'] if meta is not None else None
        live = fingerprint(salt)
        if meta is not None:
            baseline = meta['mobile']['state']
            changed = [key for key in ('token', 'config') if fingerprint_shas(live)[key] != baseline.get(key)]
            if changed:
                raise RuntimeError('Mobile token/config changed since the upgrade preflight; blocked before any change')
            if fingerprint_shas(live)['audit'] != baseline.get('audit'):
                print('NOTICE: mobile audit records changed between preflight and configure; not rewritten by this package')
        stage('activate-receipt')
        refresh_receipt()
        stage('activate-mobile-reconcile')
        marker = reconcile(live)
        stage('activate-service')
        if marker == 'switched' and active(): stop()
        start_service()
        if not equivalent(DEST.read_bytes(), r): raise RuntimeError('Registration mismatch')
        stage('activate-health')
        healthy()
        stage('activate-verify')
        after = fingerprint(live['salt'])
        changed = [key for key in ('token', 'config')
                   if fingerprint_shas(after)[key] != fingerprint_shas(live)[key]]
        if changed: raise RuntimeError('Mobile token/config changed during activation')
        if not audit_ok(live['state']['audit'], after['state']['audit']):
            print('NOTICE: mobile audit records were rotated or extended by the service itself')
        expected = pointer_expectation(live, marker)
        if expected is not None and after['pointer'] != expected:
            raise RuntimeError('Mobile active pointer does not match the reconciled state')
        if expected is None and after['pointer'].get('current') != live['pointer']['current']:
            # A self-update queued by the user was promoted concurrently; the
            # packaged bridge stays staged and the health check proved the result.
            print('NOTICE: mobile active version changed by a queued self-update; packaged bridge remains staged')
        if meta is not None:
            stage('activate-commit'); commit(meta)
    except BaseException:
        if meta is not None:
            notes = recover(meta, live, marker)
        else:
            notes = []
            if marker == 'switched' and live is not None:
                try:
                    restore_pointer(live['pointer']); notes.append('mobile active pointer restored')
                except Exception: notes.append('mobile active pointer NOT restored')
            else:
                notes.append('mobile active pointer unchanged')
            notes.append('no snapshot available; the packaged runtime was left in place')
            try:
                start_service(); notes.append('service restarted')
            except Exception: notes.append('service restart not verified')
        REPORTED = True
        sys.stderr.write('OpenMinis-Jailbreak: UPGRADE FAILED stage=' + STAGE + '; ' + '; '.join(notes) +
            '. Token, config and audit were not modified by this package; this step exits non-zero.\n')
        sys.stderr.flush()
        raise RuntimeError('Upgrade failed; recovery attempted')
    print('OpenMinis-Jailbreak: upgraded in place (' + str(meta['label'] if meta else 'no-snapshot') + ' -> ' +
          VERSION + '); token, config and audit preserved; UID501 API3 service healthy')

def postinst_configure():
    r = preflight()
    if os.path.lexists(TRANSACTION):
        meta = transaction_meta()
        if meta is not None: return upgrade_activate(r, meta)
        print('WARNING: unrecognised upgrade transaction preserved; continuing without a snapshot', file=sys.stderr)
    stage('postinst-known-artifacts'); known(r, required=True)
    stage('postinst-service-receipt')
    before = active()
    owned = receipt()
    if not owned and legacy_receipt(): return upgrade_activate(r)
    if not owned:
        if before or DEST.exists(): raise RuntimeError('Unexpected existing service; clean install only')
        stage('postinst-mobile-fresh')
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

def main(phase, args):
    global REPORTED
    REPORTED = False
    stage(phase + '-dispatch')
    action = args[0] if args else ''
    if phase == 'preinst':
        if action == 'upgrade': return upgrade_preinst(args)
        if action != 'install': return
        if replaces_installed_payload(action, args):
            stage('clean-install-only-installed-payload')
            print('CLEAN-INSTALL ONLY: 检测到已安装的旧版本；请先卸载，并私下备份用户数据，本包不支持原地升级覆盖。', file=sys.stderr)
            raise RuntimeError('CLEAN-INSTALL ONLY: an installed baseline must be removed first; no in-place upgrade')
        r = preflight()
        stage(phase + '-known-artifacts'); known(r, required=False)
        stage('preinst-root-residue')
        if (os.path.lexists(STORE) or os.path.lexists(DEST) or
                os.path.lexists(TRANSACTION)):
            raise RuntimeError('Root runtime/backup residue exists; preserve and review before clean install')
        stage('preinst-service')
        if active():
            raise RuntimeError('Same-label service exists; uninstall baseline first')
        stage(phase + '-mobile-fresh')
        require(removal('fresh()'))
        return
    if phase == 'postinst':
        if action != 'configure': return
        return postinst_configure()
    if phase == 'prerm':
        if action != 'remove': return
        # Missing payload is not itself unsafe; existing root artifacts still validated.
        r = preflight(); known(r, required=False)
        if active() and not receipt():
            raise RuntimeError('Active job lacks this release ownership receipt; removal blocked')
        remove_stop(); return
    if phase == 'postrm':
        if action not in ('remove', 'purge'): return
        remove_residue(); return

if __name__ == '__main__':
    try: main(sys.argv[1], sys.argv[2:])
    except BaseException:
        if not REPORTED:
            print('OpenMinis-Jailbreak: FAILED phase=' + sys.argv[1] + ' stage=' + STAGE +
                '. No further changes were made by this step; resolve the named stage and retry '
                '(clean-install only; preserve and review conflicts). No exception or child output disclosed.',
                file=sys.stderr)
        sys.exit(1)
