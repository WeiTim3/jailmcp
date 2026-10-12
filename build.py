#!/usr/bin/env python3
"""Offline reproducible builder for the clean-install-only experimental package."""
import ast, hashlib, json, os, shutil, subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE=HERE/'source-v030'
STAGE=Path('/tmp/openminis-jb-package-build-root')
import package_lifecycle as lifecycle
VERSION=lifecycle.VERSION
OUT=HERE/('OpenMinis-Jailbreak_'+VERSION+'_iphoneos-arm64e.deb')
EPOCH='1760000000'

def build():
    if STAGE.exists(): shutil.rmtree(STAGE)
    runtime=STAGE/'usr/local/lib/openminis-jb'; runtime.mkdir(parents=True)
    hashes={}
    for name in ('launcher.py','maintenance_runtime.py','bridge.py','mobile_setup.py'):
        src=HERE/name if name=='mobile_setup.py' else SOURCE/name
        data=src.read_bytes(); ast.parse(data,feature_version=(3,9)); hashes[name]=hashlib.sha256(data).hexdigest(); (runtime/name).write_bytes(data)
    control=STAGE/'DEBIAN'; control.mkdir()
    (control/'control').write_text(f'''Package: app.openminis.jailbreak
Name: OpenMinis-Jailbreak
Version: {VERSION}
Architecture: iphoneos-arm64e
Maintainer: OpenMinis Local Build <local@localhost>
Section: System
Priority: optional
Pre-Depends: python3 (>= 3.9.9-2), python3.9 (>= 3.9.9-2), roothide (>= 0.1.0), launchctl (>= 1:1.2.0)
Depends: libpython3.9 (>= 3.9.9-2)
Description: OpenMinis-Jailbreak local API3 mobile service (experimental)
 Canonical OpenMinis-Jailbreak service with in-place upgrades: Sileo can update
 this package without uninstalling, and the token, config and audit survive.
 No project alias; no data migration.
''')
    life=(HERE/'package_lifecycle.py').read_text().replace('HASHES = {}  # Filled by reproducible builder.','HASHES = '+repr(hashes)).replace("REMOVAL = ''  # Filled by reproducible builder.","REMOVAL = "+repr((HERE/'removal_helper.py').read_text()))
    ast.parse(life,feature_version=(3,9))
    # Root-executable recovery helper (0.3.7): the same module with its control
    # entry point replaced by the restore CLI. Build.py asserts the split marker
    # is unique, so the generated file can never be truncated by accident.
    MARKER='\n# === package_lifecycle control-script entry point ===\n'
    assert life.count(MARKER)==1,'control-script entry marker must appear exactly once'
    helper=('#!/usr/bin/python3\n'+life.split(MARKER)[0]+
        "if __name__ == '__main__':\n    sys.exit(restore_main(sys.argv[1:]))\n")
    ast.parse(helper,feature_version=(3,9))
    binary=STAGE/'usr/local/bin/openminis-jb-restore-runtime'
    binary.parent.mkdir(parents=True); binary.write_text(helper)
    for phase in ('preinst','postinst','prerm','postrm'):
        text="#!/bin/sh\nexec /usr/bin/python3 -I -B - "+phase+" \"$@\" <<'OPENMINIS_PACKAGE_PY'\n"+life+"\nOPENMINIS_PACKAGE_PY\n"
        if phase == 'postrm':
            text = text.replace('exec /usr/bin/python3', '/usr/bin/python3', 1)
            text = text.replace('#!/bin/sh\n', '#!/bin/sh\nif [ ! -x /usr/bin/python3 ]; then\n echo "WARNING: Python unavailable; residues preserved for manual cleanup" >&2\n exit 0\nfi\n', 1)
            text += 'rc=$?\nif [ "$rc" -ne 0 ]; then echo "WARNING: optional cleanup incomplete; residues preserved" >&2; fi\nexit 0\n'
        (control/phase).write_text(text); (control/phase).chmod(0o755)
    docs=STAGE/'usr/share/doc/app.openminis.jailbreak'; docs.mkdir(parents=True); (docs/'README.zh-CN.md').write_text((HERE/'README.zh-CN.md').read_text()); (docs/'source-hashes.json').write_text(json.dumps(hashes,sort_keys=True,indent=2)+'\n')
    md5=[]
    for p in sorted(STAGE.rglob('*')):
        if p.is_dir(): p.chmod(0o755)
        elif p.parent==control: pass
        elif p==binary: p.chmod(0o755); md5.append(hashlib.md5(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(STAGE)))
        else: p.chmod(0o644); md5.append(hashlib.md5(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(STAGE)))
    (control/'md5sums').write_text('\n'.join(md5)+'\n')
    for p in STAGE.rglob('*'): os.utime(p,(int(EPOCH),int(EPOCH)))
    os.utime(STAGE,(int(EPOCH),int(EPOCH)))
    subprocess.run(['dpkg-deb','--root-owner-group','-Zgzip','-z9','--build',str(STAGE),str(OUT)],check=True,env=dict(os.environ,SOURCE_DATE_EPOCH=EPOCH))
    sha=hashlib.sha256(OUT.read_bytes()).hexdigest(); (HERE/'SHA256SUMS').write_text(sha+'  '+OUT.name+'\n'); print(sha+'  '+OUT.name)
if __name__=='__main__': build()
