#!/usr/bin/env python3
"""Root-owned fixed launcher, executed exclusively as mobile by launchd.

Shutdown contract (0.3.2-3+experimental). Every bound below is far under the
plist ExitTimeOut (15s), so launchd never has to SIGKILL this process first:
  1. the child is spawned with start_new_session=True, so it is its own session
     and process-group leader (pgid == pid); its whole group can be signalled
     without ever reaching an unrelated mobile process;
  2. SIGTERM/SIGINT/SIGHUP handlers only set a flag (async-signal-safe: no
     locks, no wait(), no I/O), so a signal may land anywhere in the loop;
  3. terminate() signals the verified process group of the live Popen child
     only, never a PID read from mobile state/status files, and never uses
     pkill/killall;
  4. a parent-death pipe is passed to the child. The launcher-controlled boot
     snippet starts a daemon thread that exits the child on EOF, so the child
     and its 127.0.0.1 listener are released even when launchd SIGKILLs this
     process and no cleanup code ever runs. The snippet is the same "-c" string
     for every bridge version, so no versioned bridge has to cooperate;
  5. if the child cannot be confirmed dead within the bound, this process exits
     nonzero so that package removal fails before any payload is removed.
"""
import fcntl
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import maintenance_runtime as rt

CHILD = None
STOP = False
INCOMPLETE = False
HEALTH_SECONDS = 20
GRACE_SECONDS = 2
KILL_GRACE_SECONDS = 1
WATCH_WRITE = None

BOOT = ("import sys,os,threading\n"
        "sys.path.insert(0,%r)\n"
        "import maintenance_runtime as rt\n"
        "rt.mobile()\n"
        "def _openminis_parent_watch(fd):\n"
        "    while True:\n"
        "        try: chunk=os.read(fd,1)\n"
        "        except OSError: chunk=b''\n"
        "        if not chunk: os._exit(0)\n"
        "if %d>=0:\n"
        "    threading.Thread(target=_openminis_parent_watch,args=(%d,),daemon=True).start()\n"
        "data=sys.stdin.buffer.read(131073)\n"
        "assert rt.sha(data)==%r\n"
        "sys.argv=['bridge.py','serve']\n"
        "exec(compile(data,'<versioned-bridge>','exec'),{'__name__':'__main__'})\n")

def boot_for(version, watch_fd):
    # One snippet for every bridge version: watchdog first, versioned exec last.
    return BOOT % (str(rt.STORE), watch_fd, watch_fd, version)

def health(pid, version):
    def call(method, params):
        request = urllib.request.Request('http://127.0.0.1:%d/mcp' % rt.PORT,
            json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
            headers={'Authorization': 'Bearer ' + rt.token(), 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=1) as response: return json.load(response)['result']
    init = call('initialize', {'protocolVersion': '2025-03-26'})
    values = []
    for name in ('jb_device_info', 'jb_maintenance_info'):
        result = call('tools/call', {'name': name, 'arguments': {}})
        if result.get('isError'): raise ValueError('Health tool error')
        values.append(json.loads(result['content'][0]['text']))
    device, info = values
    if (device.get('uid') != 501 or device.get('pid') != pid or
            device.get('source_sha256') != version or info.get('source_sha256') != version or
            not device.get('bridge') or device['bridge'] != init['serverInfo']['version'] or
            info.get('version') != device['bridge'] or info.get('supervised') is not True or
            info.get('api') != 3 or info.get('uid') != 501 or info.get('pid') != pid):
        raise ValueError('Health identity/version mismatch')
    return True

def close_watch():
    # The write end is closed only when this supervisor intends the child to die.
    global WATCH_WRITE
    if WATCH_WRITE is not None:
        try: os.close(WATCH_WRITE)
        except OSError: pass
        WATCH_WRITE = None

def spawn(version):
    global WATCH_WRITE
    data = rt.code(version)
    # Execute a captured and verified snapshot via stdin, not a mutable pathname.
    # The read end of a fresh pipe is inherited by the child only (pass_fds);
    # the write end stays open here and reaches EOF exactly when this process
    # dies, including a launchd SIGKILL.
    read_fd, write_fd = os.pipe()
    try:
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/var/mobile',
               'PYTHONUNBUFFERED': '1', 'OPENMINIS_SOURCE_SHA256': version,
               'OPENMINIS_SUPERVISED': '1'}
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', boot_for(version, read_fd)],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, pass_fds=(read_fd,),
                                 start_new_session=True, env=env)
    except BaseException:
        for fd in (read_fd, write_fd):
            try: os.close(fd)
            except OSError: pass
        raise
    os.close(read_fd)
    close_watch()
    WATCH_WRITE = write_fd
    try: child.stdin.write(data); child.stdin.close()
    except (BrokenPipeError, OSError): pass
    return child

def child_group(child):
    """Verified own-group id of the live Popen child, else None.

    Only a child whose pgid equals its pid (guaranteed by start_new_session in
    spawn) may be signalled as a group. Anything else falls back to the
    single-PID reaping path, so an unverified group is never signalled.
    """
    try:
        pid = int(child.pid)
    except (AttributeError, TypeError, ValueError): return None
    try:
        if pid > 1 and os.getpgid(pid) == pid: return pid
    except (OSError, TypeError, ValueError): pass
    return None

def reaped(child, timeout):
    try: child.wait(timeout=timeout); return True
    except subprocess.TimeoutExpired: return False

def terminate(child):
    """Bounded, group-aware child shutdown. Returns True when reaped."""
    global INCOMPLETE
    if child is None: return True
    if child.poll() is not None:
        close_watch(); return True
    group = child_group(child)
    if group is None:
        # Unverified group (never the case for spawn()): bounded single-PID path.
        try: child.terminate()
        except OSError: pass
        dead = reaped(child, GRACE_SECONDS)
        if not dead:
            try: child.kill()
            except OSError: pass
            dead = reaped(child, KILL_GRACE_SECONDS)
    else:
        try: os.killpg(group, signal.SIGTERM)
        except ProcessLookupError: pass
        dead = reaped(child, GRACE_SECONDS)
        if not dead:
            try: os.killpg(group, signal.SIGKILL)
            except ProcessLookupError: pass
            dead = reaped(child, KILL_GRACE_SECONDS)
    close_watch()
    if not dead: INCOMPLETE = True
    return dead

def stop(signum, frame):
    # Async signal context must not acquire Popen/runtime locks, wait or do I/O.
    global STOP
    STOP = True

def arm_signals():
    # Installed as early as practical: before any runtime/state access.
    for name in ('SIGTERM', 'SIGINT', 'SIGHUP'):
        number = getattr(signal, name, None)
        if number is None: continue
        try: signal.signal(number, stop)
        except (OSError, RuntimeError, ValueError): pass

def pause(seconds):
    # Signal-responsive bounded sleep: launchd never waits for a long backoff.
    deadline = time.monotonic() + seconds
    while not STOP and time.monotonic() < deadline: time.sleep(0.05)

def status(**fields):
    rt.save('supervisor-v030.json', dict({'supervisor_pid': os.getpid(), 'time': int(time.time())}, **fields))

def consume(pointer):
    """Move pending intent into the crash-recoverable pointer before deleting it."""
    with rt.state() as fd:
        try: pending = json.loads(rt.read_at(fd, 'pending-v030.json', private=True))
        except FileNotFoundError: return pointer
        if pending.get('base') != pointer['current']:
            os.unlink('pending-v030.json', dir_fd=fd)
            return pointer
        target = rt.valid_sha(pending['target'])
        rt.code(target)
        if target != pointer['current']:
            pointer = dict(pointer, trial=target)
            rt.save('active-v030.json', pointer)
        os.unlink('pending-v030.json', dir_fd=fd); os.fsync(fd)
        return pointer

def listener_released():
    """The service port must be bindable again after the child was reaped."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(('127.0.0.1', rt.PORT)); probe.listen(1)
        except OSError: return False
    return True

def run():
    global CHILD
    arm_signals()
    rt.mobile(); rt.token(); rt.config()
    with rt.state() as fd:
        lock = os.open('supervisor-v030.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    pointer = rt.load('active-v030.json')
    # A prior supervisor died before promotion: current is still last known good.
    if pointer.pop('trial', None):
        rt.save('active-v030.json', pointer)
        with rt.state() as fd:
            try: os.unlink('pending-v030.json', dir_fd=fd)
            except FileNotFoundError: pass
        status(event='interrupted-trial-reverted', current=pointer['current'])
    failures = 0
    try:
        while not STOP:
            pointer = rt.load('active-v030.json')
            try: pointer = consume(pointer)
            except Exception:
                status(event='pending-rejected', current=pointer['current'])
                with rt.state() as fd:
                    try: os.unlink('pending-v030.json', dir_fd=fd)
                    except FileNotFoundError: pass
            candidate = pointer.get('trial', pointer['current'])
            good = False
            try:
                CHILD = spawn(candidate)
                deadline = time.monotonic() + HEALTH_SECONDS
                while not STOP and CHILD.poll() is None and time.monotonic() < deadline:
                    try:
                        health(CHILD.pid, candidate); good = True; break
                    except Exception: time.sleep(0.2)
                if good and not STOP:
                    if 'trial' in pointer:
                        pointer = {'current': candidate, 'previous': pointer['current']}
                        rt.save('active-v030.json', pointer)
                    status(event='healthy', current=candidate, child_pid=CHILD.pid)
                    started = time.monotonic()
                    while not STOP and CHILD.poll() is None:
                        time.sleep(0.1)
                    if time.monotonic() - started >= 10: failures = 0
                    else: failures += 1
            except Exception:
                failures += 1
            finally:
                if CHILD is not None: terminate(CHILD); CHILD = None
            if STOP: break
            if not good:
                if 'trial' in pointer:
                    pointer.pop('trial')
                    rt.save('active-v030.json', pointer)
                    status(event='startup-failed-reverted', current=pointer['current'], rejected=candidate)
                    failures = 0
                else:
                    failures += 1
                    status(event='current-startup-failed', current=candidate)
            pause(min(0.25 * max(failures, 1), 5))
    finally:
        os.close(lock)
    # The child must be gone and the port released before this process exits,
    # otherwise removal must fail before any payload is removed.
    if INCOMPLETE or not listener_released():
        try: status(event='shutdown-incomplete')
        except Exception: pass
        return 1
    return 0

if __name__ == '__main__':
    try: code = run()
    except Exception:
        # Never print token, arbitrary exception contents or child output.
        sys.exit(1)
    sys.exit(code if isinstance(code, int) else 0)
