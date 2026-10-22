"""Fixed mobile runtime; not a root helper. Python 3.9+."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import tempfile
import threading
import time

STATE = Path('/var/mobile/Documents/OpenMinis-Jailbreak/.jailmcp')
STORE = Path('/usr/local/lib/jailmcp')
PORT = 18765
MAX_FILE = 131072
LOCK = threading.RLock()
PROCESS_LOCK = threading.Lock()
PROCESSES = set()
STOPPING = False

def stop_commands():
    global STOPPING
    with PROCESS_LOCK:
        STOPPING = True
        owned = list(PROCESSES)
        for process in owned:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
    # Outside PROCESS_LOCK and never in a signal handler: reap owned commands.
    for process in owned:
        try: process.wait(timeout=0.3)
        except subprocess.TimeoutExpired: pass

def mobile():
    if os.getuid() != 501 or os.geteuid() != 501:
        raise RuntimeError('UID/EUID 501 required; never runs as root')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def valid_sha(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('Invalid SHA256')
    return value

def directory(path):
    # Resolve only the configured trusted anchor (iOS /var aliases supported),
    # then open every physical component without following a link.
    path = Path(path).resolve(strict=True)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new
        return fd
    except BaseException:
        os.close(fd); raise

def state_fd():
    # Do not resolve mobile-controlled project/state symlinks.
    anchor = STATE.parent.parent.resolve(strict=True)
    fd = directory(anchor)
    try:
        for part in (STATE.parent.name, STATE.name):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
    except BaseException:
        os.close(fd); raise
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        os.close(fd); raise ValueError('Unsafe state')
    return fd

def subdir(fd, name, create=False):
    if create:
        try: os.mkdir(name, 0o700, dir_fd=fd)
        except FileExistsError: pass
    out = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    st = os.fstat(out)
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        os.close(out); raise ValueError('Unsafe private directory')
    return out

def read_at(fd, name, limit=MAX_FILE, private=False):
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        st = os.fstat(f)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                st.st_uid != os.geteuid() or st.st_size > limit or
                (private and st.st_mode & 0o077)):
            raise ValueError('Unsafe or oversized file')
        with os.fdopen(f, 'rb', closefd=False) as stream: data = stream.read(limit + 1)
        if len(data) > limit: raise ValueError('Oversized file')
        return data
    finally: os.close(f)

def write_at(fd, name, data, mode=None, preserve=False):
    """Atomic replace; keep the destination's mode when asked.

    State files are always 0600 because callers leave `mode` unset and
    `preserve` False. Project writes pass preserve=True so editing a 0755
    script does not silently turn it into 0600; an explicit `mode` wins.
    """
    existing = None
    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid():
            raise ValueError('Unsafe destination')
        existing = stat.S_IMODE(st.st_mode) & 0o777
    except FileNotFoundError: pass
    if mode is not None:
        if type(mode) is not int or mode < 0 or mode & ~0o777:
            raise ValueError('Invalid mode')
    elif preserve and existing is not None:
        mode = existing
    else:
        mode = 0o600
    temp = '.v030-' + secrets.token_hex(12)
    f = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        # os.open() is filtered by umask, so pin the exact mode on the descriptor.
        os.fchmod(f, mode)
        with os.fdopen(f, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try: os.unlink(temp, dir_fd=fd)
        except FileNotFoundError: pass

@contextlib.contextmanager
def state():
    fd = state_fd()
    try: yield fd
    finally: os.close(fd)

def load(name, default=None):
    with state() as fd:
        try: return json.loads(read_at(fd, name, private=True))
        except FileNotFoundError:
            if default is not None: return default
            raise

def save(name, value):
    with state() as fd: write_at(fd, name, json.dumps(value, sort_keys=True).encode())

def token():
    # Preserve old token byte-for-byte; original mode may be 0640.
    with state() as fd: value = read_at(fd, 'token', 4096).decode().strip()
    if len(value) < 32 or any(c.isspace() for c in value): raise ValueError('Invalid token')
    return value

def config():
    value = load('config-v030.json')
    if not isinstance(value.get('projects'), dict) or not value['projects']:
        raise ValueError('No configured projects')
    return value

def audit(event, success):
    # Event is a fixed tool name, never arguments, output, command or exception.
    with LOCK, state() as fd:
        try: old = read_at(fd, 'audit-v030.jsonl', 32768, True)
        except FileNotFoundError: old = b''
        line = json.dumps({'time': int(time.time()), 'event': event,
                           'success': bool(success), 'uid': os.geteuid()}).encode() + b'\n'
        write_at(fd, 'audit-v030.jsonl', b''.join((old + line).splitlines(True)[-100:]))

def code(version):
    valid_sha(version)
    with state() as fd:
        versions = subdir(fd, 'versions-v030')
        try:
            child = subdir(versions, version)
            try: data = read_at(child, 'bridge.py', private=True)
            finally: os.close(child)
        finally: os.close(versions)
    if sha(data) != version: raise ValueError('Version hash changed')
    compile(data, '<bridge>', 'exec', dont_inherit=True)
    return data

def stage(data, expected):
    valid_sha(expected)
    if not 0 < len(data) <= MAX_FILE or sha(data) != expected: raise ValueError('Hash/size')
    compile(data, '<bridge>', 'exec', dont_inherit=True)
    with state() as fd:
        versions = subdir(fd, 'versions-v030', True)
        try:
            child = subdir(versions, expected, True)
            try: write_at(child, 'bridge.py', data)
            finally: os.close(child)
        finally: os.close(versions)
    return expected

def project_fd(project):
    projects = config()['projects']
    if not isinstance(project, str) or project not in projects: raise ValueError('Project not allowed')
    path = Path(projects[project])
    if not path.is_absolute() or path.is_symlink(): raise ValueError('Project anchor')
    resolved = path.resolve(strict=True)
    # State itself cannot be a file-tool project, even via an alias.
    if resolved == STATE.resolve() or STATE.resolve() in resolved.parents:
        raise ValueError('Private state')
    return directory(resolved)

@contextlib.contextmanager
def target(project, path):
    if (not isinstance(path, str) or not path or path.startswith('/') or
            '\x00' in path or any(x in ('', '.', '..', '.jailmcp') for x in path.split('/'))):
        raise ValueError('Invalid relative path')
    parts = path.split('/')
    fd = project_fd(project)
    try:
        for part in parts[:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new
            if os.path.samestat(os.fstat(fd), STATE.stat()): raise ValueError('Private state')
        yield fd, parts[-1]
    finally: os.close(fd)

def command(command_text, project, timeout=15, output_limit=16384):
    mobile()
    if config().get('allow_mobile_shell') is not True: raise ValueError('Shell disabled')
    if not isinstance(command_text, str) or not 0 < len(command_text) <= 16384 or '\x00' in command_text:
        raise ValueError('Invalid command')
    if type(timeout) is not int or not 1 <= timeout <= 60: raise ValueError('Invalid timeout')
    if type(output_limit) is not int or not 1 <= output_limit <= 32768: raise ValueError('Invalid limit')
    fd = project_fd(project)
    # A small fixed Python trampoline applies limits AFTER exec (safe with threads).
    # No preexec_fn; no inherited token/API-key environment; no elevation helper.
    trampoline = ("import os,resource,sys; os.fchdir(int(sys.argv[1])); "
                  "os.close(int(sys.argv[1])); resource.setrlimit(resource.RLIMIT_FSIZE,(262144,262144)); "
                  "os.execv('/bin/sh',['/bin/sh','-c',sys.argv[2]])")
    import sys
    import selectors
    timed_out = False
    capture_limited = False
    with tempfile.TemporaryFile(dir=str(STATE)) as out, tempfile.TemporaryFile(dir=str(STATE)) as err:
        try:
            with PROCESS_LOCK:
                if STOPPING: raise ValueError('Service is restarting')
                proc = subprocess.Popen([sys.executable, '-I', '-c', trampoline, str(fd), command_text],
                    pass_fds=(fd,), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                    'HOME': '/var/mobile', 'LANG': 'C.UTF-8', 'TMPDIR': '/tmp'})
                PROCESSES.add(proc)
        finally: os.close(fd)
        selector = selectors.DefaultSelector()
        sizes = [0, 0]
        for index, stream in enumerate((proc.stdout, proc.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True; break
                for key, mask in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj); continue
                    index = key.data
                    available = 262144 - sizes[index]
                    (out, err)[index].write(chunk[:available])
                    sizes[index] += min(available, len(chunk))
                    if len(chunk) > available:
                        capture_limited = True; break
                if capture_limited: break
            if not timed_out and not capture_limited:
                try: proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired: timed_out = True
        finally:
            selector.close()
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.stdout.close(); proc.stderr.close()
            try: proc.wait(timeout=3)
            finally:
                with PROCESS_LOCK: PROCESSES.discard(proc)
        out.seek(0); err.seek(0)
        return {'exit_code': proc.returncode, 'timed_out': timed_out,
                'stdout': out.read(output_limit).decode('utf-8', 'replace'),
                'stderr': err.read(output_limit).decode('utf-8', 'replace'),
                'truncated': capture_limited or any(n > output_limit for n in sizes),
                'capture_limited': capture_limited, 'capture_cap_per_stream': 262144}
