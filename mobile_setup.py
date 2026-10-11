"""Package-owned UID501 setup; canonical clean install only."""
import os
from pathlib import Path
import secrets
import maintenance_runtime as rt

BASE = Path('/var/mobile/Documents/OpenMinis-Jailbreak')
ALIAS = Path('/var/mobile/Documents/openminis-jailbreak')

def setup(validate=False):
    rt.mobile()
    if os.path.lexists(ALIAS):
        raise ValueError('Lowercase alias is forbidden; uninstall old release first')
    if os.path.lexists(BASE) or os.path.lexists(rt.STATE):
        if validate: raise ValueError('Existing canonical project/state requires verified uninstall first')
        # Configure retry only: preinst independently refused every existing path.
        rt.token(); rt.config()
        pointer = rt.load('active-v030.json')
        for key in ('current', 'previous', 'trial'):
            if pointer.get(key): rt.code(pointer[key])
        return
    if validate:
        return
    parent = rt.directory(BASE.parent)
    try:
        os.mkdir(BASE.name, mode=0o700, dir_fd=parent)
        project = os.open(BASE.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try: os.mkdir('.bridge-state', mode=0o700, dir_fd=project)
        finally: os.close(project)
    finally: os.close(parent)
    with rt.state() as fd:
        f = os.open('token', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(f, 'w') as out:
            out.write(secrets.token_hex(32) + '\n'); out.flush(); os.fsync(out.fileno())
    rt.token()
    data = (rt.STORE / 'bridge.py').read_bytes()
    version = rt.stage(data, rt.sha(data))
    rt.save('config-v030.json', {'projects': {'main': str(BASE)}, 'allow_mobile_shell': True})
    rt.save('active-v030.json', {'current': version, 'previous': None})
    rt.config(); rt.code(version)

if __name__ == '__main__': setup()
