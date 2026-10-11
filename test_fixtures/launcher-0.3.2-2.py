#!/usr/bin/env python3
"""Root-owned fixed launcher, executed exclusively as mobile by launchd."""
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
import maintenance_runtime as rt

CHILD = None
STOP = False
HEALTH_SECONDS = 20
GRACE_SECONDS = 2

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

def spawn(version):
    data = rt.code(version)
    # Execute a captured and verified snapshot via stdin, not a mutable pathname.
    boot = ("import sys; sys.path.insert(0,%r); "
            "import maintenance_runtime as rt; rt.mobile(); "
            "data=sys.stdin.buffer.read(131073); "
            "assert rt.sha(data)==%r; "
            "sys.argv=['bridge.py','serve']; "
            "exec(compile(data,'<versioned-bridge>','exec'),{'__name__':'__main__'})") % (str(rt.STORE), version)
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/var/mobile',
           'PYTHONUNBUFFERED': '1', 'OPENMINIS_SOURCE_SHA256': version,
           'OPENMINIS_SUPERVISED': '1'}
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c', boot], stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, env=env)
    try: child.stdin.write(data); child.stdin.close()
    except (BrokenPipeError, OSError): pass
    return child

def terminate(child):
    # Only the unreaped Popen child is ours; never consume a mobile PID file.
    if child.poll() is not None: return
    child.terminate()
    try: child.wait(timeout=GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=GRACE_SECONDS)

def stop(signum, frame):
    # Async signal context must not acquire Popen/runtime locks.
    global STOP
    STOP = True

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

def run():
    global CHILD
    rt.mobile(); rt.token(); rt.config()
    with rt.state() as fd:
        lock = os.open('supervisor-v030.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
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
            time.sleep(min(0.25 * max(failures, 1), 5))
    finally:
        os.close(lock)

if __name__ == '__main__':
    try: run()
    except Exception:
        # Never print token, arbitrary exception contents or child output.
        sys.exit(1)
