#!/usr/bin/env python3
"""Build the deliberately broken device-test package for OpenMinis-Jailbreak 0.3.7.

TEST ONLY. Never publish this .deb: it is not part of SHA256SUMS and must never
be uploaded to a release. It carries THIS release's control scripts (preinst,
postinst, prerm, postrm) together with a data.tar.gz that is corrupted in the
middle, so dpkg:

  1. runs the new `preinst upgrade <old-version>`   (preflight, snapshot, stop),
  2. fails while unpacking the payload              (partial/unusable runtime),
  3. calls the new `postrm abort-upgrade <old-version>`.

Step 3 is exactly the RISK 1 path this release fixes: the same-boot snapshot is
restored (root runtime, plist, mobile active pointer), the service is restarted
and the previous version is left healthy while dpkg stays usable.

The archive size is unchanged by the corruption (bytes are XORed in place inside
the gzip member), so the outer ar container stays well formed.
"""
import hashlib
import os
from pathlib import Path

import build as builder

HERE = Path(__file__).resolve().parent
RELEASE = builder.VERSION.split('-')[0]                      # 0.3.7
NAME = 'OpenMinis-Jailbreak_' + RELEASE + '-ABORT-TEST.deb'
OUT = HERE / NAME
EPOCH = '1760000000'
CORRUPT_XOR = 0x5A
CORRUPT_LEN = 64
AR_MAGIC = b'!<arch>\n'

def ar_members(raw):
    """[(name, bytes)] of an ar archive; dpkg-deb archives are plain ar."""
    if raw[:8] != AR_MAGIC: raise ValueError('not an ar archive')
    offset = 8
    members = []
    while offset + 60 <= len(raw):
        header = raw[offset:offset + 60]
        name = header[0:16].decode().strip().rstrip('/')
        size = int(header[48:58].decode().strip())
        start = offset + 60
        members.append((name, raw[start:start + size]))
        offset = start + size + (size % 2)
    return members

def ar_header(name, size):
    return (name.ljust(16) + EPOCH.ljust(12) + '0'.ljust(6) + '0'.ljust(6) +
            '100644'.ljust(8) + str(size).ljust(10) + '`\n').encode()

def ar_build(members):
    out = bytearray(AR_MAGIC)
    for name, data in members:
        out += ar_header(name, len(data)) + data
        if len(data) % 2: out += b'\n'
    return bytes(out)

def make():
    builder.build()                       # reproducible release .deb + staging tree
    raw = builder.OUT.read_bytes()
    members = ar_members(raw)
    names = [name for name, _ in members]
    assert names == ['debian-binary', 'control.tar.gz', 'data.tar.gz'], names
    control = members[1][1]
    data = members[2][1]
    middle = len(data) // 2
    damaged = bytearray(data)
    for index in range(middle, middle + CORRUPT_LEN):
        damaged[index] ^= CORRUPT_XOR
    damaged = bytes(damaged)
    assert len(damaged) == len(data), 'corruption must not change the member size'
    OUT.write_bytes(ar_build([('debian-binary', members[0][1]),
                              ('control.tar.gz', control),
                              ('data.tar.gz', damaged)]))
    os.chmod(OUT, 0o644)
    return OUT

if __name__ == '__main__':
    path = make()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print('TEST-ONLY %s  %d bytes' % (path.name, path.stat().st_size))
    print(digest + '  ' + path.name)
    print('corrupted byte range: middle of data.tar.gz (%d bytes XOR 0x%02x)' % (CORRUPT_LEN, CORRUPT_XOR))
    print('control.tar.gz and this release\'s control scripts are intact and signed by digest only')
