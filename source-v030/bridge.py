#!/usr/bin/env python3
"""v0.3 authenticated localhost MCP bridge. Mobile authority, NOT a sandbox."""
import base64
import errno
import fnmatch
import hashlib
import hmac
import json
import os
import socket
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import maintenance_runtime as rt

VERSION = '0.3.10'
# One full 262144-byte chunk is ~349528 base64 characters; the transport limit
# must cover that plus the JSON envelope so jb_write_chunk can accept MAX_CHUNK.
MAX_BODY = 400000
SOURCE = os.environ.get('OPENMINIS_SOURCE_SHA256', '')
SUPERVISED = os.environ.get('OPENMINIS_SUPERVISED') == '1'
EXIT_REQUESTED = threading.Event()
# The service runs with a minimal PATH (/usr/bin:/bin:/usr/sbin:/sbin) that does not
# include the jailbreak tool directory, so a bare 'ps' can fail to resolve. Probe the
# fixed known locations instead: the first executable wins.
PS_CANDIDATES = ('/rootfs/bin/ps', '/bin/ps', '/usr/bin/ps', '/usr/local/bin/ps')
SYSTEM_VERSION_PLIST = '/System/Library/CoreServices/SystemVersion.plist'

def ps_path():
    for candidate in PS_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise ValueError('ps unavailable')

def os_version():
    """Marketing iOS version and build.

    uname's Darwin release only identifies the kernel and cannot distinguish patch
    releases, so read the system's own record instead of inferring a version.
    """
    try:
        import plistlib
        with open(SYSTEM_VERSION_PLIST, 'rb') as stream:
            data = plistlib.load(stream)
        version, build = data.get('ProductVersion'), data.get('ProductBuildVersion')
        if isinstance(version, str) and version and isinstance(build, str) and build:
            return {'version': version, 'build': build}
    except Exception:
        pass
    return None

def schema(properties=None, required=()):
    return {'type': 'object', 'properties': properties or {}, 'required': list(required), 'additionalProperties': False}

STRING = {'type': 'string'}
BOOL = {'type': 'boolean'}
SHA = {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}
FILE = {'project': STRING, 'path': STRING}
TOOLS = []

def tool(name, description, properties=None, required=()):
    TOOLS.append({'name': name, 'description': description, 'inputSchema': schema(properties, required)})

tool('jb_device_info', 'OS, process UID/PID, exact running source SHA256.')
tool('jb_process_list', 'Bounded process names/PIDs/UIDs; no process arguments.')
tool('jb_maintenance_info', 'Authority, configuration and supervisor status; no token.')
tool('jb_read_file', 'Read a mobile-owned regular project file; private state excluded.', FILE, FILE)
tool('jb_write_file', 'Atomic create/overwrite base64 file; optional compare-and-swap SHA256.',
     dict(FILE, data_base64=STRING, expected_sha256=SHA), ('project', 'path', 'data_base64'))
tool('jb_edit_file', 'Replace exactly ONE UTF-8 match atomically; expected SHA256 required.',
     dict(FILE, old=STRING, new=STRING, expected_sha256=SHA), ('project', 'path', 'old', 'new', 'expected_sha256'))
tool('jb_exec', 'Explicitly authorized arbitrary mobile shell. NOT sandboxed. No root helper; no inherited secrets.',
     {'project': STRING, 'command': STRING, 'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 60},
      'output_limit': {'type': 'integer', 'minimum': 1, 'maximum': 32768}}, ('project', 'command'))
tool('jb_stage_update', 'Store bridge.py after SHA256 and Python syntax check. Not a safety approval.',
     {'data_base64': STRING, 'sha256': SHA}, ('data_base64', 'sha256'))
tool('jb_validate_update', 'Recheck staged SHA256 and syntax without executing.', {'sha256': SHA}, ('sha256',))
tool('jb_apply_update', 'Queue staged version then exit; fixed supervisor healthchecks and automatically reverts on startup failure.',
     {'sha256': SHA}, ('sha256',))
tool('jb_restart', 'Exit this mobile process; supervisor respawns the active version.')
tool('jb_rollback', 'Queue previous last-good version; supervisor healthchecks and activates it.')
tool('jb_list_dir', 'Bounded name-sorted directory listing read off an already anchored dirfd; lstat metadata, symlinks never followed.',
     {'project': STRING, 'path': STRING, 'limit': {'type': 'integer', 'minimum': 1, 'maximum': 1000},
      'offset': {'type': 'integer', 'minimum': 0}}, ('project',))
tool('jb_stat', 'lstat metadata (size, octal mode, uid/gid, mtime, nlink) plus sha256 for regular files up to 1048576 bytes; symlink target reported without following it.',
     FILE, FILE)
tool('jb_delete', 'Delete one file, symlink or empty directory. recursive=true also requires confirm=true, deletes depth-first, is bounded to 10000 entries, never follows a symlink and never removes a project root.',
     dict(FILE, recursive=BOOL, confirm=BOOL), FILE)
tool('jb_rename', 'os.rename inside ONE project through dir_fd. No parent directory is created, an existing destination is refused unless overwrite=true, and traversal is refused.',
     {'project': STRING, 'src': STRING, 'dst': STRING, 'overwrite': BOOL}, ('project', 'src', 'dst'))
tool('jb_search', 'Bounded walk from root (private state skipped, symlinked directories never entered): fnmatch name glob and/or literal content match with 1-based line and bounded excerpt; truncation reasons are reported.',
     {'project': STRING, 'root': STRING, 'name_pattern': STRING, 'content': STRING,
      'limit': {'type': 'integer', 'minimum': 1, 'maximum': 1000},
      'max_files': {'type': 'integer', 'minimum': 1, 'maximum': 100000},
      'max_file_bytes': {'type': 'integer', 'minimum': 1, 'maximum': 16777216}}, ('project',))
tool('jb_read_chunk', 'Base64 chunk of a regular file (<=262144 bytes) with the sha256 and size of the WHOLE file and an eof flag.',
     dict(FILE, offset={'type': 'integer', 'minimum': 0},
          length={'type': 'integer', 'minimum': 1, 'maximum': 262144}), FILE)
tool('jb_write_chunk', 'Write base64 at an offset, creating the file if absent. Multi-chunk writes are NOT atomic; expected_sha256 compare-and-swaps the current content before writing and only protects when supplied; truncate requires offset 0; final fsyncs. The whole-file sha256 is computed only on the final chunk or with want_sha256, so a multi-chunk write costs linear time rather than re-reading the file every chunk.',
     dict(FILE, offset={'type': 'integer', 'minimum': 0}, data_base64=STRING,
          expected_sha256=SHA, truncate=BOOL, final=BOOL, want_sha256=BOOL),
     ('project', 'path', 'offset', 'data_base64'))
tool('jb_projects', 'Configured project roots with current existence/directory status. Read-only: no tool can add or widen roots.')
tool('jb_mkdir', 'Create ONE directory inside a project root through the same dirfd + O_NOFOLLOW traversal as the other file tools: no absolute path, no empty/. /.. component, no symlinked component, never the private state directory. parents=false requires the parent to exist; parents=true creates missing components one at a time, each reopened with O_NOFOLLOW. mode is an octal string 0700..0777 (privileged bits refused) applied under a restrictive umask so the result can never exceed it. An existing leaf is refused and reported as a directory, file, symlink or other.',
     dict(FILE, parents=BOOL, mode=STRING), ('project', 'path'))
tool('jb_upload_begin', 'Open a staged multi-chunk upload under the private state directory (never reachable through the file tools, so it does not pollute the project) and return an opaque upload_id. At most 4 concurrent uploads and 256 MiB staged in total in this build; stale staging is only ever removed by a bounded sweep of the upload area. Nothing becomes visible in a project until jb_upload_commit, which is the ATOMIC alternative to multi-call jb_write_chunk (that path is not atomic).',
     {'project': STRING, 'name': STRING})
tool('jb_upload_chunk', 'Write base64 at an offset inside a staged upload with the same offset and compare-and-swap semantics as jb_write_chunk: an offset past the staged end is refused, expected_sha256 compare-and-swaps the whole staged content when supplied, and the reply carries the bytes written and the staged size - the whole-staged sha256 is computed only with want_sha256, never per chunk. jb_upload_commit verifies the assembled digest. Nothing is visible in the project.',
     {'upload_id': STRING, 'offset': {'type': 'integer', 'minimum': 0}, 'data_base64': STRING,
      'expected_sha256': SHA, 'want_sha256': BOOL}, ('upload_id', 'offset', 'data_base64'))
tool('jb_upload_commit', 'Verify the assembled upload (against expected_sha256 when supplied) and install it at project/path with ONE os.replace anchored on the destination dirfd, so the name holds either the old file or the complete new data and never a partial write. Refuses an existing destination unless overwrite=true, never replaces a directory, a symlink or a foreign/hardlinked file, refuses the private state directory, and removes the staging so the id cannot be reused. A refused commit changes nothing.',
     {'upload_id': STRING, 'project': STRING, 'path': STRING, 'expected_sha256': SHA,
      'overwrite': BOOL}, ('upload_id', 'project', 'path'))
tool('jb_upload_abort', 'Discard a staged upload and its idempotent opaque id; the id can never be reused afterwards and only the upload area is touched.',
     {'upload_id': STRING}, ('upload_id',))
tool('jb_find', 'Read-only search over the REAL device tree: a name glob and/or a literal file-content string (with 1-based line and a bounded excerpt), a size range, and per-match metadata (mode, uid, gid, mtime). Give paths the way the device uses them: /var/... is read as /private/var/... under /rootfs, so /var/mobile/Documents means the real SYSTEM data volume (default path /var/mobile). jailbreak=true searches the bridge\'s own view instead (which lands in the jbroot); a path already under /rootfs is used as-is. Bounded by wall clock, entry count, depth, match count and per-file bytes; symlinked directories are never entered; nothing can be written.',
     {'path': STRING, 'name_pattern': STRING, 'content': STRING, 'jailbreak': BOOL,
      'limit': {'type': 'integer', 'minimum': 1, 'maximum': 1000},
      'max_depth': {'type': 'integer', 'minimum': 0, 'maximum': 32},
      'max_seconds': {'type': 'integer', 'minimum': 1, 'maximum': 30},
      'min_bytes': {'type': 'integer', 'minimum': 0},
      'max_bytes': {'type': 'integer', 'minimum': 0},
      'max_file_bytes': {'type': 'integer', 'minimum': 1, 'maximum': 16777216}}, ())

SPEC = {x['name']: x['inputSchema'] for x in TOOLS}

def decode(value):
    if not isinstance(value, str) or len(value) > 174764: raise ValueError('Oversized base64')
    data = base64.b64decode(value, validate=True)
    if len(data) > rt.MAX_FILE: raise ValueError('Oversized file')
    return data

def exit_bridge():
    rt.stop_commands()
    os._exit(0)

def defer_exit():
    EXIT_REQUESTED.set()

def enqueue(target):
    if not SUPERVISED: raise ValueError('Fixed supervisor required')
    pointer = rt.load('active-v030.json')
    if pointer.get('trial') or EXIT_REQUESTED.is_set(): raise ValueError('Update busy')
    with rt.state() as fd:
        try: rt.read_at(fd, 'pending-v030.json', private=True)
        except FileNotFoundError: pass
        else: raise ValueError('Pending update exists')
    rt.code(target)
    if target == pointer['current']: raise ValueError('Already active')
    rt.save('pending-v030.json', {'target': target, 'base': pointer['current']})
    defer_exit()
    return {'queued': True, 'target_sha256': target, 'healthcheck_required': True, 'reconnect_after_seconds': 3}


# ---------------------------------------------------------------------------
# 0.3.5 file interface. Every path goes through rt.target / rt.project_fd, i.e.
# the same dirfd + O_NOFOLLOW per-component traversal the 0.3.x file tools use:
# no absolute paths, no empty/. /.. components, no symlinked component, and the
# private state directory is refused by name everywhere. Nothing below resolves
# a path twice, follows a link, or leaves a project root.
# 0.3.5 adds jb_mkdir and the staged-upload quartet (jb_upload_begin,
# jb_upload_chunk, jb_upload_commit, jb_upload_abort). Staging lives in
# <state>/uploads-v030, which the traversal above can never reach.
PRIVATE = '.bridge-state'        # the component name rt.target already refuses
UPLOAD_DIR = 'uploads-v030'      # staging area, INSIDE the private state dir
UPLOAD_ID_BYTES = 16             # upload ids are 32 hex characters
MAX_UPLOADS = 4                  # concurrent staged uploads
MAX_UPLOAD_TOTAL = 268435456     # 256 MiB staged in total across all uploads
UPLOAD_STALE_SECONDS = 3600      # untouched for this long, staging may be swept
UPLOAD_SWEEP_ENTRIES = 64        # entries examined by one sweep
UPLOAD_SWEEP_REMOVALS = 16       # entries removed by one sweep
UPLOAD_STAGE_FILES = ('data', 'meta.json')
UPLOAD_TEMP_PREFIX = '.v030-upload-'
MKDIR_MIN, MKDIR_MAX = 0o700, 0o777   # allowed jb_mkdir mode range
MAX_PATH = 4096
MAX_LIST = 1000                  # jb_list_dir entries per page
MAX_CHUNK = 262144               # jb_read_chunk / jb_write_chunk payload bytes
MAX_CHUNK_B64 = 349528           # base64 length of MAX_CHUNK
MAX_OFFSET = 1 << 40             # 1 TiB; offsets above this are refused outright
STAT_HASH_LIMIT = 1048576        # jb_stat hashes regular files up to 1 MiB
MAX_WRITE_TOTAL = 268435456      # jb_write_chunk may not grow a file past 256 MiB
MAX_DELETE_ENTRIES = 10000       # jb_delete recursive entry budget
MAX_SEARCH_LIMIT = 1000
MAX_SEARCH_FILES = 100000
MAX_SEARCH_BYTES = 16777216
SEARCH_SECONDS = 10.0            # wall-clock bound, reported in the result
EXCERPT = 200                    # bounded excerpt length
REAL_ROOT = '/rootfs'            # jb_find: the real device tree (a jailbreak redirect owns /var)
# This device carries two trees under the same path prefixes. The SYSTEM tree
# (/rootfs/private/var/mobile) is the real data volume; /var/mobile is a
# roothide redirect that resolves into the jailbreak's jbroot. Search and read
# the SYSTEM tree first, the jailbreak tree second.
SYSTEM_DATA_ROOT = '/rootfs/private/var/mobile'
JAILBREAK_LINK = '/var/mobile'
MAX_FIND_LIMIT = 1000            # jb_find match cap
MAX_FIND_DEPTH = 32
MAX_FIND_SECONDS = 30
MAX_FIND_ENTRIES = 200000

def kind_of(mode):
    if stat.S_ISLNK(mode): return 'symlink'
    if stat.S_ISDIR(mode): return 'dir'
    if stat.S_ISREG(mode): return 'file'
    return 'other'

def state_identity():
    try: value = os.stat(str(rt.STATE))
    except OSError: return None
    return (value.st_dev, value.st_ino)

def list_names(fd):
    """Sorted entry names from an already-anchored directory descriptor.

    os.listdir() with an integer descriptor CONSUMES it on some CPython builds
    (observed on the device's Python 3.9.9: the fd is closed and later reuse fails
    with EBADF), while 3.12 leaves it open. Listing through a duplicate keeps the
    caller's descriptor valid on both, so callers may stat/read/unlink afterwards.
    """
    dup = os.dup(fd)
    try:
        return sorted(os.listdir(dup))
    finally:
        try:
            os.close(dup)
        except OSError:
            pass          # 3.9-style builds already closed the duplicate

def open_dir(project, path):
    """Dirfd for an existing directory inside the project; '' means the root."""
    if path == '':
        return rt.project_fd(project)
    with rt.target(project, path) as (parent, leaf):
        child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    identity = state_identity()
    opened = os.fstat(child)
    if identity is not None and (opened.st_dev, opened.st_ino) == identity:
        os.close(child); raise ValueError('Private state')
    return child

def read_capped(parent, leaf, cap):
    """Text of a leaf, read through the parent dirfd, bounded by cap bytes."""
    handle = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        st = os.fstat(handle)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid():
            raise ValueError('Unsafe file')
        if st.st_size > cap: raise ValueError('Oversized file')
        blocks = []; total = 0
        while total < cap:
            block = os.read(handle, min(65536, cap - total))
            if not block: break
            blocks.append(block); total += len(block)
        return b''.join(blocks).decode('utf-8', 'replace'), total
    finally:
        os.close(handle)

def hash_leaf(parent, leaf):
    """sha256 and size of a whole regular file, streamed; never follows a link."""
    handle = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        st = os.fstat(handle)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid():
            raise ValueError('Unsafe file')
        digest = hashlib.sha256(); total = 0
        while True:
            block = os.read(handle, 1048576)
            if not block: break
            digest.update(block); total += len(block)
        return digest.hexdigest(), st.st_size
    finally:
        os.close(handle)

def decode_chunk(value):
    if not isinstance(value, str) or len(value) > MAX_CHUNK_B64: raise ValueError('Oversized base64')
    data = base64.b64decode(value, validate=True)
    if len(data) > MAX_CHUNK: raise ValueError('Oversized chunk')
    return data

def describe_entry(fd, name):
    try: st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except OSError:
        return {'name': name, 'type': 'other', 'size': None, 'mode': None,
                'mtime': None, 'is_symlink': False, 'unavailable': True}
    return {'name': name, 'type': kind_of(st.st_mode), 'size': st.st_size,
            'mode': oct(stat.S_IMODE(st.st_mode)), 'mtime': int(st.st_mtime),
            'is_symlink': stat.S_ISLNK(st.st_mode)}

def tool_list_dir(args):
    limit = args.get('limit', 100); offset = args.get('offset', 0)
    if not 1 <= limit <= MAX_LIST: raise ValueError('Invalid limit')
    if not 0 <= offset <= MAX_OFFSET: raise ValueError('Invalid offset')
    path = args.get('path', '')
    fd = open_dir(args['project'], path)
    try:
        # Names come from the already-anchored dirfd, so no component of the path
        # is ever re-resolved. Listing goes through list_names() because
        # os.listdir(fd) closes the descriptor on the device's Python 3.9.
        all_names = list_names(fd)
        names = [name for name in all_names if name != PRIVATE]
        total = len(names)
        page = names[offset:offset + limit]
        entries = [describe_entry(fd, name) for name in page]
    finally:
        os.close(fd)
    return {'path': path, 'entries': entries, 'total': total, 'returned': len(entries),
            'offset': offset, 'limit': limit, 'has_more': offset + len(entries) < total,
            'excluded_private': len(all_names) - total}

def tool_stat(args):
    with rt.target(args['project'], args['path']) as (parent, leaf):
        st = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        out = {'path': args['path'], 'name': leaf, 'type': kind_of(st.st_mode),
               'size': st.st_size, 'mode': oct(stat.S_IMODE(st.st_mode)),
               'uid': st.st_uid, 'gid': st.st_gid, 'nlink': st.st_nlink,
               'mtime': int(st.st_mtime), 'is_symlink': stat.S_ISLNK(st.st_mode),
               'hash_limit': STAT_HASH_LIMIT, 'sha256': None, 'sha256_skipped': None,
               'target': None}
        if out['is_symlink']:
            out['sha256_skipped'] = 'symlink-not-followed'
            out['target'] = os.readlink(leaf, dir_fd=parent)
        elif not stat.S_ISREG(st.st_mode):
            out['sha256_skipped'] = 'not-a-regular-file'
        elif st.st_size > STAT_HASH_LIMIT:
            out['sha256_skipped'] = 'larger-than-hash-limit'
        elif st.st_nlink != 1:
            out['sha256_skipped'] = 'multiple-links'
        elif st.st_uid != os.geteuid():
            out['sha256_skipped'] = 'not-mobile-owned'
        else:
            out['sha256'] = hash_leaf(parent, leaf)[0]
        return out

def remove_tree(parent, leaf, counts, budget):
    if spend_entry(budget): raise ValueError('Recursive entry limit exceeded')
    st = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    mode = st.st_mode
    if stat.S_ISDIR(mode):
        child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            for name in list_names(child):
                if name == PRIVATE: raise ValueError('Private state')
                remove_tree(child, name, counts, budget)
        finally:
            os.close(child)
        os.rmdir(leaf, dir_fd=parent)
        counts['directories'] += 1
    else:
        # Symlinks are unlinked, never entered, so nothing outside the project
        # can be reached from a recursive delete.
        os.unlink(leaf, dir_fd=parent)
        if stat.S_ISLNK(mode): counts['symlinks'] += 1
        elif stat.S_ISREG(mode): counts['files'] += 1
        else: counts['others'] += 1

def spend_entry(budget):
    if budget[0] <= 0: return True
    budget[0] -= 1
    return False

def tool_delete(args):
    recursive = args.get('recursive', False); confirm = args.get('confirm', False)
    with rt.target(args['project'], args['path']) as (parent, leaf):
        if leaf == PRIVATE: raise ValueError('Private state')
        st = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        counts = {'files': 0, 'directories': 0, 'symlinks': 0, 'others': 0}
        if stat.S_ISDIR(st.st_mode):
            if recursive:
                if confirm is not True: raise ValueError('Recursive delete requires confirm')
                remove_tree(parent, leaf, counts, [MAX_DELETE_ENTRIES])
            else:
                try: os.rmdir(leaf, dir_fd=parent)
                except OSError as error:
                    raise ValueError('Non-empty directory needs recursive and confirm') from error
                counts['directories'] = 1
        else:
            os.unlink(leaf, dir_fd=parent)
            if stat.S_ISLNK(st.st_mode): counts['symlinks'] = 1
            elif stat.S_ISREG(st.st_mode): counts['files'] = 1
            else: counts['others'] = 1
    counts['entries'] = sum(counts.values())
    return {'deleted': True, 'path': args['path'], 'recursive': recursive is True,
            'confirm': confirm is True, 'counts': counts}

def tool_rename(args):
    overwrite = args.get('overwrite', False)
    with rt.target(args['project'], args['src']) as (src_parent, src_leaf), \
         rt.target(args['project'], args['dst']) as (dst_parent, dst_leaf):
        try:
            existing = os.stat(dst_leaf, dir_fd=dst_parent, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if overwrite is not True: raise ValueError('Destination exists')
            if stat.S_ISDIR(existing.st_mode): raise ValueError('Refusing to replace a directory')
        # Both sides are directory anchors, so the rename cannot leave the project
        # and cannot be redirected by a symlinked component.
        os.rename(src_leaf, dst_leaf, src_dir_fd=src_parent, dst_dir_fd=dst_parent)
        return {'renamed': True, 'src': args['src'], 'dst': args['dst'],
                'overwritten': existing is not None}

def excerpt_line(text, index):
    begin = text.rfind('\n', 0, index) + 1
    end = text.find('\n', index)
    if end < 0: end = len(text)
    line = text[begin:end].rstrip('\r')
    if len(line) <= EXCERPT: return line, False
    start = min(max(0, index - begin - 40), max(0, len(line) - EXCERPT))
    return '...' + line[start:start + EXCERPT - 3], True

def tool_search(args):
    limit = args.get('limit', 50); max_files = args.get('max_files', 5000)
    max_bytes = args.get('max_file_bytes', 1048576)
    if not 1 <= limit <= MAX_SEARCH_LIMIT: raise ValueError('Invalid limit')
    if not 1 <= max_files <= MAX_SEARCH_FILES: raise ValueError('Invalid max_files')
    if not 1 <= max_bytes <= MAX_SEARCH_BYTES: raise ValueError('Invalid max_file_bytes')
    root = args.get('root', ''); pattern = args.get('name_pattern', '')
    content = args.get('content', '')
    if not pattern and not content: raise ValueError('A name glob or a content string is required')
    if len(pattern) > 256 or len(content) > 256: raise ValueError('Filter too long')
    start = time.monotonic()
    matches = []; reasons = []
    counters = {'files': 0, 'entries': 0, 'bytes': 0, 'skipped_large': 0,
                'skipped_unreadable': 0, 'symlinks': 0}
    stopped = False
    # Prefix with root so every reported path stays project-relative and can be
    # fed straight back into jb_stat / jb_read_chunk.
    stack = [(open_dir(args['project'], root), root)]
    try:
        # Depth-first over pre-opened dirfds; a symlinked directory is only ever an
        # entry (never opened), so the walk can never leave the project.
        while stack and not stopped:
            fd, prefix = stack.pop()
            try:
                for name in list_names(fd):
                    if stopped: break
                    if name == PRIVATE: continue
                    if time.monotonic() - start > SEARCH_SECONDS:
                        reasons.append('time'); stopped = True; break
                    rel = prefix + '/' + name if prefix else name
                    try: st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except OSError: continue
                    counters['entries'] += 1
                    named = bool(pattern) and fnmatch.fnmatchcase(name, pattern)
                    if stat.S_ISLNK(st.st_mode): counters['symlinks'] += 1
                    if stat.S_ISDIR(st.st_mode):
                        if named:
                            matches.append({'path': rel, 'type': 'dir', 'size': st.st_size,
                                            'name_match': True, 'line': None, 'excerpt': None})
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        stack.append((child, rel))
                    elif stat.S_ISREG(st.st_mode):
                        if counters['files'] >= max_files:
                            reasons.append('files'); stopped = True; break
                        counters['files'] += 1
                        line = None; excerpt = None; hit = False; trimmed = False
                        if content:
                            if st.st_size > max_bytes:
                                counters['skipped_large'] += 1
                            else:
                                try: text, read_bytes = read_capped(fd, name, max_bytes)
                                except (OSError, ValueError):
                                    counters['skipped_unreadable'] += 1
                                else:
                                    counters['bytes'] += read_bytes
                                    found = text.find(content)
                                    if found >= 0:
                                        hit = True
                                        line = text.count('\n', 0, found) + 1
                                        excerpt, trimmed = excerpt_line(text, found)
                        if named or hit:
                            matches.append({'path': rel, 'type': 'file', 'size': st.st_size,
                                            'name_match': named, 'line': line, 'excerpt': excerpt,
                                            'excerpt_truncated': trimmed})
                    elif named:
                        matches.append({'path': rel, 'type': kind_of(st.st_mode), 'size': st.st_size,
                                        'name_match': True, 'line': None, 'excerpt': None})
                    if len(matches) >= limit:
                        reasons.append('limit'); stopped = True; break
            finally:
                os.close(fd)
    finally:
        for fd, _ in stack:
            try: os.close(fd)
            except OSError: pass
    unique = []
    for reason in reasons:
        if reason not in unique: unique.append(reason)
    return {'root': root, 'matches': matches, 'matches_count': len(matches),
            'truncated': bool(unique), 'reasons': unique,
            'files_scanned': counters['files'], 'entries_scanned': counters['entries'],
            'bytes_read': counters['bytes'], 'skipped_large': counters['skipped_large'],
            'skipped_unreadable': counters['skipped_unreadable'],
            'symlink_entries_not_followed': counters['symlinks'],
            'elapsed_seconds': round(time.monotonic() - start, 3),
            'limits': {'matches': limit, 'files': max_files, 'file_bytes': max_bytes,
                       'seconds': SEARCH_SECONDS}}

def resolve_find_root(path, jailbreak):
    """Map a device path onto the real tree under /rootfs.

    By default the SYSTEM directory wins: /var/... is read as /private/var/... and
    the result is taken under /rootfs, so /var/mobile/Documents means the real data
    volume instead of the jailbreak's redirected tree. jailbreak=true keeps the
    bridge's own view (which lands inside the jbroot), and a path already under
    /rootfs is used as-is. Whatever the route, the result must resolve under
    /rootfs or the request is refused.
    """
    if path == REAL_ROOT or path.startswith(REAL_ROOT + '/'):
        candidate = path
    elif jailbreak is True:
        candidate = path
    else:
        mapped = '/private' + path if (path == '/var' or path.startswith('/var/')) else path
        candidate = REAL_ROOT + ('' if mapped == '/' else mapped)
    resolved = os.path.realpath(candidate)
    if not (resolved == REAL_ROOT or resolved.startswith(REAL_ROOT + '/')):
        raise ValueError('Only the real device tree under ' + REAL_ROOT + ' is searchable')
    return resolved


def tool_find(args):
    path = args.get('path', '/var/mobile')
    pattern = args.get('name_pattern', '')
    content = args.get('content', '')
    limit = args.get('limit', 200)
    depth_max = args.get('max_depth', 12)
    seconds = args.get('max_seconds', 15)
    min_bytes = args.get('min_bytes', 0)
    max_bytes = args.get('max_bytes', 0)
    max_file_bytes = args.get('max_file_bytes', 1048576)
    jailbreak = args.get('jailbreak', False)
    if not isinstance(path, str) or not path.startswith('/') or len(path) > MAX_PATH:
        raise ValueError('Invalid path')
    if (not isinstance(pattern, str) or len(pattern) > 256 or
            not isinstance(content, str) or len(content) > 256):
        raise ValueError('Invalid filter')
    if not pattern and not content:
        raise ValueError('A name glob or a content string is required')
    if not 1 <= limit <= MAX_FIND_LIMIT: raise ValueError('Invalid limit')
    if not 0 <= depth_max <= MAX_FIND_DEPTH: raise ValueError('Invalid max_depth')
    if not 1 <= seconds <= MAX_FIND_SECONDS: raise ValueError('Invalid max_seconds')
    if type(min_bytes) is not int or min_bytes < 0: raise ValueError('Invalid min_bytes')
    if type(max_bytes) is not int or max_bytes < 0: raise ValueError('Invalid max_bytes')
    if max_bytes and max_bytes < min_bytes: raise ValueError('Invalid size range')
    if not 1 <= max_file_bytes <= MAX_SEARCH_BYTES: raise ValueError('Invalid max_file_bytes')
    resolved = resolve_find_root(path, jailbreak)
    start = time.monotonic()
    matches = []
    reasons = []
    counts = {'entries': 0, 'files': 0, 'directories': 0, 'symlinks': 0,
              'bytes': 0, 'skipped_large': 0, 'skipped_unreadable': 0}
    stopped = False
    # One directory fd at a time: the descriptor table here is small (256), so
    # queueing every sibling's fd would exhaust it on a wide tree. Descendants
    # are queued by PATH and opened only when popped.
    stack = [(resolved, 0)]
    while stack and not stopped:
        prefix, depth = stack.pop()
        try:
            fd = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            continue
        try:
            for name in list_names(fd):
                if time.monotonic() - start > seconds:
                    reasons.append('time'); stopped = True; break
                counts['entries'] += 1
                if counts['entries'] > MAX_FIND_ENTRIES:
                    reasons.append('entries'); stopped = True; break
                try: st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError: continue
                mode = st.st_mode
                regular = stat.S_ISREG(mode)
                if stat.S_ISDIR(mode): counts['directories'] += 1
                elif stat.S_ISLNK(mode): counts['symlinks'] += 1
                elif regular: counts['files'] += 1
                # The size range gates regular files only; directories and
                # symlinks are unaffected by it.
                size_ok = True
                if regular:
                    if st.st_size < min_bytes: size_ok = False
                    if max_bytes and st.st_size > max_bytes: size_ok = False
                elif min_bytes or max_bytes:
                    # A size bound is about file sizes, so directories and
                    # symlinks are not reported while one is in force.
                    size_ok = False
                named = bool(pattern) and fnmatch.fnmatchcase(name, pattern)
                hit = False; line = None; excerpt = None; trimmed = False
                if content and regular and size_ok:
                    if st.st_size > max_file_bytes:
                        counts['skipped_large'] += 1
                    else:
                        try: text, read_bytes = read_capped(fd, name, max_file_bytes)
                        except (OSError, ValueError):
                            counts['skipped_unreadable'] += 1
                        else:
                            counts['bytes'] += read_bytes
                            at = text.find(content)
                            if at >= 0:
                                hit = True
                                line = text.count('\n', 0, at) + 1
                                excerpt, trimmed = excerpt_line(text, at)
                if size_ok and (named or hit):
                    matches.append({'path': prefix + '/' + name, 'type': kind_of(mode),
                                    'size': st.st_size if regular else None,
                                    'mode': oct(stat.S_IMODE(mode)), 'uid': st.st_uid,
                                    'gid': st.st_gid, 'mtime': int(st.st_mtime),
                                    'name_match': named, 'line': line,
                                    'excerpt': excerpt, 'excerpt_truncated': trimmed})
                    if len(matches) >= limit:
                        reasons.append('limit'); stopped = True; break
                # Only entries whose lstat says "directory" are queued, each
                # reopened with O_NOFOLLOW, so a symlink is reported but never
                # entered: the walk cannot leave the tree or loop.
                if stat.S_ISDIR(mode) and depth < depth_max:
                    stack.append((prefix + '/' + name, depth + 1))
        finally:
            os.close(fd)
    unique = []
    for reason in reasons:
        if reason not in unique: unique.append(reason)
    return {'root': resolved, 'matches': matches, 'matches_count': len(matches),
            'truncated': bool(unique), 'reasons': unique,
            'entries_scanned': counts['entries'], 'files': counts['files'],
            'directories': counts['directories'], 'symlinks_not_followed': counts['symlinks'],
            'bytes_read': counts['bytes'], 'skipped_large': counts['skipped_large'],
            'skipped_unreadable': counts['skipped_unreadable'],
            'elapsed_seconds': round(time.monotonic() - start, 3),
            'limits': {'matches': limit, 'depth': depth_max, 'seconds': seconds,
                       'entries': MAX_FIND_ENTRIES, 'file_bytes': max_file_bytes},
            'read_only': True}

def tool_read_chunk(args):
    offset = args.get('offset', 0); length = args.get('length', 131072)
    if not 0 <= offset <= MAX_OFFSET: raise ValueError('Invalid offset')
    if not 1 <= length <= MAX_CHUNK: raise ValueError('Invalid length')
    with rt.target(args['project'], args['path']) as (parent, leaf):
        sha, size = hash_leaf(parent, leaf)
        if offset > size: raise ValueError('Offset beyond end of file')
        handle = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            st = os.fstat(handle)
            if not stat.S_ISREG(st.st_mode): raise ValueError('Not a regular file')
            os.lseek(handle, offset, os.SEEK_SET)
            blocks = []; remaining = length
            while remaining > 0:
                block = os.read(handle, remaining)
                if not block: break
                blocks.append(block); remaining -= len(block)
            data = b''.join(blocks)
        finally:
            os.close(handle)
    return {'path': args['path'], 'offset': offset, 'length': length,
            'returned': len(data), 'total_size': size, 'sha256': sha,
            'eof': offset + len(data) >= size,
            'data_base64': base64.b64encode(data).decode()}

def tool_write_chunk(args):
    offset = args['offset']; expected = args.get('expected_sha256', '')
    truncate = args.get('truncate', False); final = args.get('final', False)
    data = decode_chunk(args['data_base64'])
    if not 0 <= offset <= MAX_OFFSET: raise ValueError('Invalid offset')
    if offset + len(data) > MAX_WRITE_TOTAL: raise ValueError('Size limit exceeded')
    if truncate is True and offset != 0: raise ValueError('truncate requires offset 0')
    with rt.target(args['project'], args['path']) as (parent, leaf):
        try: st = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: st = None
        if st is not None and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                               or st.st_uid != os.geteuid()):
            raise ValueError('Unsafe destination')
        if expected:
            # Compare-and-swap against the CURRENT content before any write. Only
            # meaningful when supplied; a write without it is a plain overwrite.
            rt.valid_sha(expected)
            if st is None: raise ValueError('Concurrent modification')
            if hash_leaf(parent, leaf)[0] != expected: raise ValueError('Concurrent modification')
        if truncate is not True and offset > (st.st_size if st is not None else 0):
            raise ValueError('Offset beyond end of file')
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
        if truncate is True: flags |= os.O_TRUNC
        handle = os.open(leaf, flags, 0o600, dir_fd=parent)
        try:
            opened = os.fstat(handle)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or opened.st_uid != os.geteuid()):
                raise ValueError('Unsafe destination')
            os.lseek(handle, offset, os.SEEK_SET)
            written = 0
            while written < len(data):
                written += os.write(handle, data[written:])
            if final is True: os.fsync(handle)
            size = os.fstat(handle).st_size
        finally:
            os.close(handle)
        # Hashing the WHOLE file after every chunk is quadratic - a 256 MiB file
        # written in 256 KiB chunks would read ~137 GB. Only the last chunk, or a
        # caller that asks, pays for it (size is a cheap fstat).
        sha = hash_leaf(parent, leaf)[0] if (final is True or args.get('want_sha256') is True) else None
    return {'written': len(data), 'offset': offset, 'sha256': sha, 'size': size,
            'synced': final is True, 'truncated': truncate is True,
            'atomic': False, 'cas_checked': bool(expected), 'hashed': sha is not None}

def projects_info():
    configured = rt.config()['projects']
    out = {}
    for name, path in configured.items():
        report = {'path': path, 'exists': False, 'is_directory': False, 'is_symlink': False}
        try:
            st = os.stat(path)
            report['exists'] = True
            report['is_directory'] = stat.S_ISDIR(st.st_mode)
            report['is_symlink'] = stat.S_ISLNK(os.lstat(path).st_mode)
        except OSError:
            pass
        out[name] = report
    return {'projects': out, 'count': len(out), 'mutable': False,
            'max_file_bytes': rt.MAX_FILE,
            'note': 'Read-only view; roots are configured on the device, not by tools.'}

def relative_parts(path):
    """Project-relative components under exactly the rules rt.target applies."""
    if (not isinstance(path, str) or not path or len(path) > MAX_PATH or
            path.startswith('/') or '\x00' in path or
            any(part in ('', '.', '..', PRIVATE) for part in path.split('/'))):
        raise ValueError('Invalid relative path')
    return path.split('/')

def same_private(fd):
    """True when an already-opened descriptor IS the private state directory."""
    identity = state_identity()
    if identity is None: return False
    value = os.fstat(fd)
    return (value.st_dev, value.st_ino) == identity

def parse_mode(value):
    """Octal string limited to 0700..0777; privileged bits are refused outright."""
    if not isinstance(value, str) or not 3 <= len(value) <= 4:
        raise ValueError('Invalid mode string')
    if len(value) == 4 and value[0] != '0':
        raise ValueError('Invalid mode string')
    digits = value[1:] if len(value) == 4 else value
    if any(character not in '01234567' for character in digits):
        raise ValueError('Invalid mode string')
    mode = int(digits, 8)
    if mode & 0o7000: raise ValueError('Privileged mode bits refused')
    if not MKDIR_MIN <= mode <= MKDIR_MAX: raise ValueError('Mode outside 0700-0777')
    return mode

def mkdir_at(parent, leaf, mode):
    """Create one component under a restrictive umask, then pin the mode exactly.

    os.mkdir applies the process umask, so the directory is born no wider than
    `mode` (the umask is tightened to 0o077 for the call and always restored).
    The new directory is reopened with O_NOFOLLOW and its mode is pinned to the
    requested value through that descriptor, so nothing can be substituted
    between creation and the mode fix, and the result never exceeds `mode`.
    """
    previous = os.umask(0o077)
    try:
        os.mkdir(leaf, mode, dir_fd=parent)
    finally:
        os.umask(previous)
    child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        st = os.fstat(child)
        actual = stat.S_IMODE(st.st_mode)
        if st.st_uid != os.geteuid() or actual & ~mode:
            raise ValueError('Unsafe directory')
        if actual != mode: os.fchmod(child, mode)
    finally:
        os.close(child)

def tool_mkdir(args):
    parents = args.get('parents', False)
    mode = parse_mode(args.get('mode', '0700'))
    parts = relative_parts(args['path'])
    leaf = parts[-1]
    if leaf == PRIVATE: raise ValueError('Private state')
    made = []
    fd = rt.project_fd(args['project'])
    try:
        for part in parts[:-1]:
            if part == PRIVATE: raise ValueError('Private state')
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if parents is not True: raise ValueError('Parent directory does not exist')
                mkdir_at(fd, part, mode)
                made.append(part)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except NotADirectoryError as error:
                raise ValueError('Parent component is not a directory') from error
            if same_private(child):
                os.close(child); raise ValueError('Private state')
            os.close(fd); fd = child
        try:
            existing = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            # The refusal names the kind so the caller can tell a duplicate
            # directory from a file, symlink or device that blocks the name.
            raise ValueError('Path already exists as a %s' % kind_of(existing.st_mode))
        mkdir_at(fd, leaf, mode)
        made.append(leaf)
        created = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
        actual_mode = oct(stat.S_IMODE(created.st_mode))
    finally:
        os.close(fd)
    return {'created': True, 'project': args['project'], 'path': args['path'],
            'name': leaf, 'type': 'dir', 'mode': actual_mode,
            'requested_mode': oct(mode), 'parents': parents is True,
            'created_components': made, 'created_directories': len(made)}

def is_upload_id(value):
    return (isinstance(value, str) and len(value) == 2 * UPLOAD_ID_BYTES and
            all(character in '0123456789abcdef' for character in value))

def valid_upload_id(value):
    if not is_upload_id(value): raise ValueError('Invalid upload id')
    return value

def uploads_area(fd, create=False):
    try: return rt.subdir(fd, UPLOAD_DIR, create)
    except FileNotFoundError:
        raise ValueError('No staging area')

def open_upload(uploads, upload_id):
    valid_upload_id(upload_id)
    try: return rt.subdir(uploads, upload_id)
    except FileNotFoundError:
        raise ValueError('Unknown or consumed upload id')

def staged_size(up):
    try: st = os.stat('data', dir_fd=up, follow_symlinks=False)
    except OSError: return 0
    return st.st_size if stat.S_ISREG(st.st_mode) else 0

def upload_names(uploads):
    """Names directly inside the upload area that are shaped like OUR ids."""
    return [name for name in list_names(uploads) if is_upload_id(name)]

def open_upload_ro(uploads, name):
    try: return rt.subdir(uploads, name)
    except (OSError, ValueError): return None

def staged_total(uploads, names):
    total = 0
    for name in names:
        up = open_upload_ro(uploads, name)
        if up is None: continue
        try:
            if os.fstat(up).st_uid == os.geteuid(): total += staged_size(up)
        finally:
            os.close(up)
    return total

def newest_mtime(up):
    """Newest of the directory, the staged bytes and the metadata: an upload that
    is still being written therefore never looks stale."""
    values = []
    for name in (None,) + UPLOAD_STAGE_FILES:
        try:
            value = os.fstat(up) if name is None else os.stat(name, dir_fd=up,
                                                             follow_symlinks=False)
            values.append(value.st_mtime)
        except OSError:
            continue
    return max(values) if values else 0.0

def destroy_staging(uploads, upload_id):
    """Delete the staged bytes and unpublish the id. Bounded: it only ever looks
    at entries directly inside one upload directory and only unlinks the fixed
    staging names plus this build's temporary prefix. If anything unexpected
    survives the directory cannot be removed, so the id is renamed out of the id
    namespace instead: either way it can never be reused.
    """
    up = open_upload_ro(uploads, upload_id)
    if up is None: return False
    try:
        for index, name in enumerate(list_names(up)):
            if index >= UPLOAD_SWEEP_ENTRIES: break
            if name in UPLOAD_STAGE_FILES or name.startswith(UPLOAD_TEMP_PREFIX):
                try: os.unlink(name, dir_fd=up)
                except OSError: pass
    finally:
        os.close(up)
    try:
        os.rmdir(upload_id, dir_fd=uploads)
        return True
    except OSError:
        try: os.rename(upload_id, 'dead-' + upload_id, src_dir_fd=uploads, dst_dir_fd=uploads)
        except OSError: pass
        return False

def sweep_uploads(uploads, now=None):
    """Bounded removal of stale staging. Only entries directly inside the upload
    area whose name is one of our ids, are directories we own and look untouched
    for UPLOAD_STALE_SECONDS are considered, so the sweep can never reach outside
    the upload area. Staging left behind by a killed process is harmless: it is
    only ever removed here (or by an explicit abort)."""
    now = time.time() if now is None else now
    removed = 0
    for index, name in enumerate(list_names(uploads)):
        if index >= UPLOAD_SWEEP_ENTRIES or removed >= UPLOAD_SWEEP_REMOVALS: break
        if not is_upload_id(name): continue
        up = open_upload_ro(uploads, name)
        if up is None: continue
        try:
            if os.fstat(up).st_uid != os.geteuid(): continue
            age = now - newest_mtime(up)
        finally:
            os.close(up)
        if age < UPLOAD_STALE_SECONDS: continue
        destroy_staging(uploads, name)
        removed += 1
    return removed

def new_upload_id(uploads, names):
    for _ in range(16):
        candidate = os.urandom(UPLOAD_ID_BYTES).hex()
        if candidate in names: continue
        try: os.stat(candidate, dir_fd=uploads, follow_symlinks=False)
        except FileNotFoundError: return candidate
    raise ValueError('Could not allocate an upload id')

def tool_upload_begin(args):
    project = args.get('project', '')
    name = args.get('name', '')
    if not isinstance(project, str) or (project and project not in rt.config()['projects']):
        raise ValueError('Project not allowed')
    if not isinstance(name, str) or len(name) > 128 or '/' in name or '\x00' in name:
        raise ValueError('Invalid name')
    with rt.state() as fd:
        uploads = uploads_area(fd, True)
        try:
            swept = sweep_uploads(uploads)
            names = upload_names(uploads)
            if len(names) >= MAX_UPLOADS: raise ValueError('Too many concurrent uploads')
            if staged_total(uploads, names) >= MAX_UPLOAD_TOTAL:
                raise ValueError('Staging area full')
            upload_id = new_upload_id(uploads, names)
            os.mkdir(upload_id, 0o700, dir_fd=uploads)
            up = rt.subdir(uploads, upload_id)
            try:
                handle = os.open('data', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=up)
                os.close(handle)
                rt.write_at(up, 'meta.json', json.dumps(
                    {'upload_id': upload_id, 'project': project, 'name': name,
                     'created': int(time.time()), 'staged_bytes': 0}).encode())
            finally:
                os.close(up)
            open_count = len(names) + 1
            used = staged_total(uploads, upload_names(uploads))
        finally:
            os.close(uploads)
    return {'upload_id': upload_id, 'staged': 0, 'sha256': hashlib.sha256(b'').hexdigest(),
            'open_uploads': open_count, 'concurrent_limit': MAX_UPLOADS,
            'staged_total': used, 'total_limit': MAX_UPLOAD_TOTAL,
            'swept_stale': swept, 'visible_in_project': False,
            'note': 'Stage with jb_upload_chunk, then jb_upload_commit installs the '
                    'whole file with one os.replace (atomic).'}

def tool_upload_chunk(args):
    upload_id = valid_upload_id(args['upload_id'])
    offset = args['offset']; expected = args.get('expected_sha256', '')
    data = decode_chunk(args['data_base64'])
    if not 0 <= offset <= MAX_OFFSET: raise ValueError('Invalid offset')
    if offset + len(data) > MAX_UPLOAD_TOTAL: raise ValueError('Size limit exceeded')
    with rt.state() as fd:
        uploads = uploads_area(fd)
        try:
            up = open_upload(uploads, upload_id)
            try:
                current = staged_size(up)
                total = staged_total(uploads, upload_names(uploads))
                if expected:
                    # Same compare-and-swap rule as jb_write_chunk: the whole
                    # staged content is checked before anything is written.
                    rt.valid_sha(expected)
                    if hash_leaf(up, 'data')[0] != expected:
                        raise ValueError('Concurrent modification')
                if offset > current: raise ValueError('Offset beyond end of file')
                if total - current + offset + len(data) > MAX_UPLOAD_TOTAL:
                    raise ValueError('Size limit exceeded')
                handle = os.open('data', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=up)
                try:
                    opened = os.fstat(handle)
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                            or opened.st_uid != os.geteuid()):
                        raise ValueError('Unsafe staging')
                    os.lseek(handle, offset, os.SEEK_SET)
                    written = 0
                    while written < len(data):
                        written += os.write(handle, data[written:])
                    os.fsync(handle)
                    size = os.fstat(handle).st_size
                finally:
                    os.close(handle)
                # See jb_write_chunk: never re-hash the whole staging file per
                # chunk. jb_upload_commit verifies the assembled digest once.
                sha = hash_leaf(up, 'data')[0] if args.get('want_sha256') is True else None
            finally:
                os.close(up)
        finally:
            os.close(uploads)
    return {'upload_id': upload_id, 'written': len(data), 'offset': offset,
            'sha256': sha, 'size': size, 'synced': True, 'cas_checked': bool(expected),
            'hashed': sha is not None,
            'visible_in_project': False, 'atomic': False,
            'note': 'Staged only; jb_upload_commit installs the whole file atomically.'}

def install_staged(up, parent, leaf):
    """Install the staged bytes under the destination dirfd.

    The normal path is ONE os.replace, which makes the destination name hold
    either the old file or the complete new file, never a partial one. When the
    staging area and the project are on different filesystems (EXDEV) the bytes
    are copied into a private temporary file in the DESTINATION directory, which
    is fsynced and then os.replace'd in: the destination is likewise never
    partial, and the temporary file is removed on every failure path.
    """
    try:
        os.replace('data', leaf, src_dir_fd=up, dst_dir_fd=parent)
        return 'moved'
    except OSError as error:
        if error.errno != errno.EXDEV: raise
    temp = UPLOAD_TEMP_PREFIX + os.urandom(12).hex()
    source = os.open('data', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=up)
    try:
        st = os.fstat(source)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid():
            raise ValueError('Unsafe staging')
        handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
        try:
            while True:
                block = os.read(source, 1048576)
                if not block: break
                written = 0
                while written < len(block):
                    written += os.write(handle, block[written:])
            os.fsync(handle)
        finally:
            os.close(handle)
        os.replace(temp, leaf, src_dir_fd=parent, dst_dir_fd=parent)
    finally:
        try: os.unlink(temp, dir_fd=parent)
        except FileNotFoundError: pass
        os.close(source)
    return 'copied'

def tool_upload_commit(args):
    upload_id = valid_upload_id(args['upload_id'])
    expected = args.get('expected_sha256', '')
    overwrite = args.get('overwrite', False)
    parts = relative_parts(args['path'])
    if parts[-1] == PRIVATE: raise ValueError('Private state')
    if expected: rt.valid_sha(expected)
    replaced = False
    with rt.state() as state_fd:
        uploads = uploads_area(state_fd)
        up = open_upload(uploads, upload_id)
        try:
            try: sha, size = hash_leaf(up, 'data')
            except FileNotFoundError:
                raise ValueError('Unknown or consumed upload id')
            if expected and sha != expected:
                # Nothing outside the staging area is touched on a mismatch.
                raise ValueError('Assembled hash mismatch')
            with rt.target(args['project'], args['path']) as (parent, leaf):
                if leaf == PRIVATE or same_private(parent): raise ValueError('Private state')
                try: existing = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: existing = None
                if existing is not None:
                    if stat.S_ISDIR(existing.st_mode):
                        raise ValueError('Refusing to replace a directory')
                    if overwrite is not True:
                        raise ValueError('Destination exists; overwrite required')
                    if (not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
                            or existing.st_uid != os.geteuid()):
                        raise ValueError('Unsafe destination')
                    replaced = True
                install = install_staged(up, parent, leaf)
                os.fsync(parent)
        finally:
            os.close(up)
        removed = destroy_staging(uploads, upload_id)
    return {'committed': True, 'upload_id': upload_id, 'project': args['project'],
            'path': args['path'], 'sha256': sha, 'size': size, 'bytes': size,
            'replaced': replaced, 'install': install, 'atomic': True, 'fsynced': True,
            'staging_removed': removed,
            'atomic_scope': 'The destination NAME is switched by one os.replace inside '
                            'the destination dirfd: a concurrent reader sees either the '
                            'old file or the complete new file. Durability of that name '
                            'is fsynced too.',
            'consumed': True}

def tool_upload_abort(args):
    upload_id = valid_upload_id(args['upload_id'])
    with rt.state() as state_fd:
        try: uploads = uploads_area(state_fd)
        except ValueError:
            return {'aborted': True, 'upload_id': upload_id, 'removed': False,
                    'staging_area': 'absent'}
        try: removed = destroy_staging(uploads, upload_id)
        finally: os.close(uploads)
    return {'aborted': True, 'upload_id': upload_id, 'removed': removed,
            'staging_area': 'present', 'reusable': False}

FILE_OPERATIONS = {
    'jb_list_dir': tool_list_dir, 'jb_stat': tool_stat, 'jb_delete': tool_delete,
    'jb_rename': tool_rename, 'jb_search': tool_search,
    'jb_read_chunk': tool_read_chunk, 'jb_write_chunk': tool_write_chunk,
    'jb_mkdir': tool_mkdir, 'jb_upload_begin': tool_upload_begin,
    'jb_upload_chunk': tool_upload_chunk, 'jb_upload_commit': tool_upload_commit,
    'jb_upload_abort': tool_upload_abort,
}


def invoke(name, args):
    rt.mobile()
    if name not in SPEC or not isinstance(args, dict): raise ValueError('Unknown tool/arguments')
    spec = SPEC[name]
    if set(args) - set(spec['properties']) or set(spec['required']) - set(args): raise ValueError('Arguments')
    for key, value in args.items():
        kind = spec['properties'][key].get('type')
        if kind == 'string' and not isinstance(value, str): raise ValueError('Type')
        if kind == 'integer' and type(value) is not int: raise ValueError('Type')
        if kind == 'boolean' and not isinstance(value, bool): raise ValueError('Type')
    if name == 'jb_device_info':
        u = os.uname()
        return {'system': u.sysname, 'release': u.release, 'machine': u.machine, 'ios': os_version(),
                'uid': os.getuid(), 'pid': os.getpid(), 'bridge': VERSION, 'source_sha256': SOURCE}
    if name == 'jb_maintenance_info':
        conf = rt.config()
        return {'version': VERSION, 'api': 3, 'uid': os.getuid(), 'pid': os.getpid(), 'source_sha256': SOURCE,
                'supervised': SUPERVISED, 'root_helper': False, 'sandbox': False,
                'exec': conf.get('allow_mobile_shell') is True, 'apply': SUPERVISED,
                'projects': conf['projects'], 'max_file_bytes': rt.MAX_FILE,
                'paths': {'system': SYSTEM_DATA_ROOT, 'jailbreak': os.path.realpath(JAILBREAK_LINK),
                          'prefer': 'system',
                          'note': 'system and jailbreak share path prefixes but are different trees; prefer system'},
                'active': rt.load('active-v030.json'), 'supervisor': rt.load('supervisor-v030.json', {}),
                'authority': 'All mobile authority; existing external elevation rights are NOT prevented',
                'audit': '100 records; fixed tool names and status only; mobile-editable'}
    if name == 'jb_projects': return projects_info()
    if name == 'jb_process_list':
        # Fixed command avoids argument exposure, same bounded execution machinery.
        # ps_path() resolves the absolute binary; a bare 'ps' is not on the daemon PATH.
        project = next(iter(rt.config()['projects']))
        executable = ps_path()
        result = rt.command(executable + ' -axo pid,uid,comm', project, 4, 16384)
        if result['exit_code'] != 0: raise ValueError('ps unavailable')
        return {'lines': result['stdout'].splitlines()[:101], 'limit': 100, 'executable': executable}
    if name == 'jb_exec':
        return rt.command(args['command'], args['project'], args.get('timeout', 15), args.get('output_limit', 16384))
    if name == 'jb_find':
        return tool_find(args)
    with rt.LOCK:
        if name in ('jb_read_file', 'jb_write_file', 'jb_edit_file'):
            with rt.target(args['project'], args['path']) as (fd, leaf):
                if name == 'jb_read_file':
                    data = rt.read_at(fd, leaf)
                    return {'data_base64': base64.b64encode(data).decode(), 'sha256': rt.sha(data), 'bytes': len(data)}
                if 'expected_sha256' in args:
                    rt.valid_sha(args['expected_sha256'])
                    old = rt.read_at(fd, leaf)
                    if rt.sha(old) != args['expected_sha256']: raise ValueError('Concurrent modification')
                if name == 'jb_write_file': data = decode(args['data_base64'])
                else:
                    text = old.decode('utf-8')
                    if not args['old'] or text.count(args['old']) != 1: raise ValueError('Exactly one match required')
                    data = text.replace(args['old'], args['new'], 1).encode()
                if len(data) > rt.MAX_FILE: raise ValueError('Oversized file')
                rt.write_at(fd, leaf, data)
                return {'written': True, 'sha256': rt.sha(data), 'bytes': len(data)}
        if name in FILE_OPERATIONS: return FILE_OPERATIONS[name](args)
        if name == 'jb_stage_update':
            version = rt.stage(decode(args['data_base64']), args['sha256'])
            return {'staged': True, 'sha256': version, 'syntax_valid': True, 'safety_approved': False}
        if name == 'jb_validate_update':
            rt.code(args['sha256']); return {'syntax_valid': True, 'sha256': args['sha256'], 'safety_approved': False}
        if name == 'jb_apply_update': return enqueue(args['sha256'])
        if name == 'jb_rollback':
            pointer = rt.load('active-v030.json')
            return enqueue(pointer['previous'])
        if name == 'jb_restart':
            if not SUPERVISED: raise ValueError('Supervisor required')
            defer_exit(); return {'restart_queued': True}
    raise ValueError('Unknown tool')

def rpc(req):
    if not isinstance(req, dict) or req.get('jsonrpc') != '2.0':
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid Request'}}
    if 'id' not in req: return None
    rid = req['id']; params = req.get('params', {})
    if not isinstance(params, dict):
        return {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32602, 'message': 'Invalid params'}}
    method = req.get('method')
    if method == 'initialize':
        proposed = params.get('protocolVersion')
        result = {'protocolVersion': proposed if proposed in ('2024-11-05', '2025-03-26', '2025-06-18') else '2025-03-26',
                  'capabilities': {'tools': {}}, 'serverInfo': {'name': 'openminis-jb', 'version': VERSION}}
    elif method == 'ping': result = {}
    elif method == 'tools/list': result = {'tools': TOOLS}
    elif method == 'tools/call':
        name = params.get('name'); success = False
        try:
            value = invoke(name, params.get('arguments', {}))
            result = {'content': [{'type': 'text', 'text': json.dumps(value)}], 'isError': False}; success = True
        except Exception:
            result = {'content': [{'type': 'text', 'text': 'Operation failed: invalid arguments, unsafe state or unavailable operation; details withheld'}], 'isError': True}
        try: rt.audit(name if isinstance(name, str) and name in SPEC else 'unknown-tool', success)
        except Exception: pass
    else:
        return {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32601, 'message': 'Method not found'}}
    return {'jsonrpc': '2.0', 'id': rid, 'result': result}

class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 8
    allow_reuse_address = True
    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(address, handler)
    def process_request(self, request, address):
        if not self.slots.acquire(False):
            request.close(); return
        try: super().process_request(request, address)
        except BaseException:
            self.slots.release(); raise
    def process_request_thread(self, request, address):
        try: super().process_request_thread(request, address)
        finally: self.slots.release()
    def handle_error(self, request, address): pass

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def setup(self):
        super().setup(); self.connection.settimeout(5)
    def reply(self, status, data=None):
        body = b'' if data is None else json.dumps(data).encode()
        self.send_response(status); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body))); self.send_header('Connection', 'close')
        self.end_headers()
        if body: self.wfile.write(body)
        self.wfile.flush(); self.close_connection = True
    def authorized(self):
        if len(self.headers.get_all('Authorization', [])) != 1:
            self.reply(401); return False
        if (len(self.headers.get_all('Host', [])) != 1 or self.headers.get('Origin') is not None or
                self.headers.get('Host') not in ('127.0.0.1:%d' % rt.PORT, 'localhost:%d' % rt.PORT)):
            self.reply(403); return False
        if not hmac.compare_digest(self.headers['Authorization'].encode(), ('Bearer ' + self.server.token).encode()):
            self.reply(401); return False
        return True
    def do_GET(self):
        if self.authorized(): self.reply(405 if self.path == '/mcp' else 404)
    def do_POST(self):
        if not self.authorized(): return
        if self.path != '/mcp': self.reply(404); return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if (self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1 or
                    not 0 < size <= MAX_BODY):
                self.reply(413); return
            body = self.rfile.read(size)
            if len(body) != size: self.reply(400); return
            req = json.loads(body)
        except (ValueError, OSError, RecursionError): self.reply(400); return
        out = rpc(req)
        try: self.reply(202 if out is None else 200, out)
        finally:
            if EXIT_REQUESTED.is_set():
                # A response is flushed first. OS suspension/network loss can still
                # prevent client receipt; query status after reconnecting.
                timer = threading.Timer(2, exit_bridge)
                timer.daemon = True; timer.start()

def serve():
    import signal
    rt.mobile()
    stopping = False
    def request_stop(signum, frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    server = Server(('127.0.0.1', rt.PORT), Handler)
    server.timeout = 0.2
    server.token = rt.token(); rt.config()
    try:
        while not stopping:
            server.handle_request()
    finally:
        server.server_close()
        rt.stop_commands()

if __name__ == '__main__':
    serve()
