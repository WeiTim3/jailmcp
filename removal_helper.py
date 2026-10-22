"""Embedded UID501 helper: no payload imports, no PID-based signalling."""
import contextlib
import fcntl
import os
import socket
import stat

DOCS = '/var/mobile/Documents'
DOCS_ALIAS = '/private/var/mobile/Documents'
STAGE = 'identity'
BASE = 'OpenMinis-Jailbreak'
ALIAS = 'openminis-jailbreak'
PORT = 18765

def identity():
    if os.getuid() != 501 or os.geteuid() != 501:
        raise RuntimeError('UID501 required')

def directory(name, parent=None):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)

@contextlib.contextmanager
def documents():
    global STAGE
    STAGE = 'documents-anchor'
    identity()
    # Only these two package-fixed system paths may follow mappings. No caller
    # input, project/state component, or root-side deletion uses this exception.
    fd = os.open(DOCS, os.O_RDONLY | os.O_DIRECTORY)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 501:
            raise RuntimeError('Unsafe Documents owner/type')
        alternate = os.open(DOCS_ALIAS, os.O_RDONLY | os.O_DIRECTORY)
        try:
            other = os.fstat(alternate)
            if (info.st_dev, info.st_ino) != (other.st_dev, other.st_ino):
                raise RuntimeError('Documents aliases disagree')
        finally: os.close(alternate)
        yield fd
    finally: os.close(fd)

def exists(fd, name):
    try: return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError: return None

def socket_free():
    identity()
    # Match HTTPServer reuse semantics, yet reject an active TCP listener.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', PORT))
        s.listen(1)

def fresh():
    global STAGE
    with documents() as fd:
        STAGE = 'project-conflict'
        if exists(fd, ALIAS) or exists(fd, BASE):
            raise RuntimeError('Canonical project or lowercase alias already exists')
    STAGE = 'socket'
    socket_free()
    STAGE = 'fresh-complete'

def checked(operation):
    # Never print exception text, paths from exceptions, tokens or child output.
    import sys
    try:
        {'fresh': fresh, 'stopped': stopped, 'cleanup': cleanup}[operation]()
    except Exception:
        tag = STAGE if operation == 'fresh' else operation
        print('HELPER_FAIL:' + tag, file=sys.stderr)
        raise SystemExit(1)

def stopped():
    socket_free()
    # Lock is inspected by descriptor, never imported and never used as a PID.
    try:
        with documents() as fd:
            if not exists(fd, BASE): return
            project = directory(BASE, fd)
            try:
                if not exists(project, '.jailmcp'): return
                state = directory('.jailmcp', project)
                try:
                    try: lock = os.open('supervisor-v030.lock', os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=state)
                    except FileNotFoundError: return
                    try:
                        info = os.fstat(lock)
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != 501 or info.st_nlink != 1:
                            raise RuntimeError('Unsafe supervisor lock')
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally: os.close(lock)
                finally: os.close(state)
            finally: os.close(project)
    except FileNotFoundError: pass

def erase(parent, name):
    info = exists(parent, name)
    if info is None: return
    if stat.S_ISDIR(info.st_mode):
        fd = directory(name, parent)
        try:
            for item in os.listdir(fd): erase(fd, item)
        finally: os.close(fd)
        os.rmdir(name, dir_fd=parent)
    else:
        # Unlink symlink/hardlink names only; never touch the target contents.
        os.unlink(name, dir_fd=parent)

def cleanup():
    identity()
    try:
        with documents() as fd:
            if exists(fd, ALIAS): print('WARNING: historical lowercase path preserved')
            info = exists(fd, BASE)
            if info is None: return
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 501:
                print('WARNING: conflicting canonical path preserved'); return
            project = directory(BASE, fd)
            try: erase(project, '.jailmcp')
            finally: os.close(project)
            try: os.rmdir(BASE, dir_fd=fd)
            except OSError: print('NOTICE: ordinary project files preserved')
    except FileNotFoundError: pass
