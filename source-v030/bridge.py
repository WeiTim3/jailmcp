#!/usr/bin/env python3
"""v0.3 authenticated localhost MCP bridge. Mobile authority, NOT a sandbox."""
import base64
import hmac
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import maintenance_runtime as rt

VERSION = '0.3.3'
MAX_BODY = 200000
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

def invoke(name, args):
    rt.mobile()
    if name not in SPEC or not isinstance(args, dict): raise ValueError('Unknown tool/arguments')
    spec = SPEC[name]
    if set(args) - set(spec['properties']) or set(spec['required']) - set(args): raise ValueError('Arguments')
    for key, value in args.items():
        kind = spec['properties'][key].get('type')
        if kind == 'string' and not isinstance(value, str): raise ValueError('Type')
        if kind == 'integer' and type(value) is not int: raise ValueError('Type')
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
                'active': rt.load('active-v030.json'), 'supervisor': rt.load('supervisor-v030.json', {}),
                'authority': 'All mobile authority; existing external elevation rights are NOT prevented',
                'audit': '100 records; fixed tool names and status only; mobile-editable'}
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
