#!/usr/bin/env python3
"""Deterministic source archive for the current release.

Produces OpenMinis-Jailbreak_<version>-source.tar.gz and rewrites SHA256SUMS so
that it lists the release .deb and the source archive (never the test-only
ABORT-TEST artifact). Byte-identical for identical sources: members are sorted,
all metadata is fixed and gzip carries no timestamp.
"""
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile

import package_lifecycle as lifecycle

HERE = Path(__file__).resolve().parent
VERSION = lifecycle.VERSION
ROOT = 'openminis-jb'
EPOCH = 1760000000
MEMBERS = [
    'build.py',
    'package_lifecycle.py',
    'removal_helper.py',
    'mobile_setup.py',
    'source_archive.py',
    'run_baseline_api_tests.py',
    'test_package.py',
    'test_safety.py',
    'test_filetools.py',
    'test_supervisor.py',
    'test_api.py',
    'test_upgrade.py',
    'README.md',
    'README.zh-CN.md',
    '.github/workflows/prefs.yml',
    '.github/workflows/build.yml',
]
DOCS = []
DIRS = ['source-v030', 'test_fixtures', 'prefs']

def members():
    found = []
    for name in MEMBERS + DOCS:
        path = HERE / name
        if path.is_file(): found.append((name, path))
    for folder in DIRS:
        for path in sorted((HERE / folder).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts:
                found.append((str(path.relative_to(HERE)), path))
    return sorted(found)

def build():
    out_bytes = io.BytesIO()
    with tarfile.open(fileobj=out_bytes, mode='w', format=tarfile.GNU_FORMAT) as archive:
        for name, path in members():
            data = path.read_bytes()
            info = tarfile.TarInfo(ROOT + '/' + name)
            info.size = len(data); info.mode = 0o644; info.mtime = EPOCH
            info.uid = info.gid = 0; info.uname = info.gname = ''
            archive.addfile(info, io.BytesIO(data))
    raw = gzip.compress(out_bytes.getvalue(), compresslevel=9, mtime=0)
    # mtime=0 in gzip makes the header deterministic; suppress the trailing name.
    archive_path = HERE / ('OpenMinis-Jailbreak_' + VERSION + '-source.tar.gz')
    archive_path.write_bytes(raw)
    lines = []
    for path in sorted([HERE / ('OpenMinis-Jailbreak_' + VERSION + '_iphoneos-arm64e.deb'),
                        archive_path]):
        lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name)
    (HERE / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
    # The device-test artifact must never appear in the release checksums.
    if (HERE / 'OpenMinis-Jailbreak_0.3.8-ABORT-TEST.deb').exists():
        assert 'ABORT-TEST' not in (HERE / 'SHA256SUMS').read_text()
    return archive_path

if __name__ == '__main__':
    path = build()
    print(path.name, path.stat().st_size)
    print((HERE / 'SHA256SUMS').read_text().rstrip())
