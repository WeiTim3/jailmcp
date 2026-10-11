#!/usr/bin/env python3
"""Generate the standalone read-only preflight with the exact packaged helper.

Emits the historical -v032r2.py name (still asserted by test_safety) and the
current -v032r3.py build. Both embed the same packaged helper text and the
current package version, and remain read-only by construction: they perform no
installation, no deletion and never read a token.
"""
import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
if not (PACKAGE / 'package_lifecycle.py').is_file():
    PACKAGE = Path('/var/minis/workspace/OpenMinis-Jailbreak-clean')
WORKSPACE = PACKAGE
VERSION = re.search(r"^VERSION = '([^']+)'", (PACKAGE / 'package_lifecycle.py').read_text(), re.M).group(1)
source = (PACKAGE / 'package_lifecycle.py').read_text().split("if __name__ == '__main__':")[0]
source += '\nREMOVAL = ' + repr((PACKAGE / 'removal_helper.py').read_text()) + '\n'
source += '''
def diagnostic():
    print('READ-ONLY preflight __VERSION__; no file/package changes or token access')
    failed = False
    def check(label, fn):
        nonlocal failed
        stage(label)
        try:
            fn()
            print('PASS phase=preinst stage=' + label)
        except Exception:
            failed = True
            print('FAIL phase=preinst stage=' + STAGE)
    def package_status():
        result = run(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Abbrev}', 'app.openminis.jailbreak'])
        if result.returncode == 1 and not result.stdout:
            return
        if result.returncode:
            stage('package-status-query'); raise RuntimeError()
        value = result.stdout.strip()
        if value not in (b'un', b'pn'):
            # Includes rc/config-files: preinst install <old-version> is rejected.
            stage('package-status-not-purged'); raise RuntimeError()
    def residue():
        for label, path in [('root-store-residue', STORE), ('root-plist-residue', DEST),
                ('root-transaction-residue', Path('/usr/local/lib/openminis-jb-transaction'))]:
            stage(label)
            if os.path.lexists(path): raise RuntimeError()
    def registration():
        if active(): raise RuntimeError()
    check('platform-root-architecture-mapping-guards', preflight)
    check('package-status-purged', package_status)
    check('root-residue-absent', residue)
    check('service-absent', registration)
    # fresh() binds 127.0.0.1:18765, so an orphaned child listener of an older
    # release is reported here as stage=mobile-fresh/HELPER_FAIL:stopped.
    check('mobile-fresh', lambda: require(removal('fresh()')))
    print('RESULT=' + ('FAIL: review named stage; nothing changed' if failed else
        'PASS: read-only preflight only; installation/launchd/health NOT validated'))
    return 1 if failed else 0

if __name__ == '__main__':
    sys.exit(diagnostic())
'''
source = source.replace('__VERSION__', VERSION)
ast_ok = compile(source, '<preflight>', 'exec')
for name in ('openminis-preflight-readonly-v032r4.py', 'openminis-preflight-readonly-v032r3.py'):
    target = WORKSPACE / name
    target.write_text(source)
    compile(source, str(target), 'exec')
    print('%s  %s' % (name, VERSION))
print('helper bytes embedded:', len(source.split('REMOVAL = ')[1].split('\n')[0]))
