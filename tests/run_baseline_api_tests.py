"""Run baseline API tests against this release, never import old runtime."""
from pathlib import Path
import sys
import types
import unittest
HERE=Path(__file__).resolve().parent
BASELINE=HERE.parent/'openminis-jb-v030'
sys.path[:0]=[str(HERE/'source-v030'),str(BASELINE)]
source=(BASELINE/'test_v030.py').read_text()
source=source.replace("HERE = Path(__file__).parent", "HERE = Path(%r)" % str(HERE/'source-v030'))
source=source.replace("/var/mobile/Documents/openminis-jailbreak/.bridge-state", "/var/mobile/Documents/OpenMinis-Jailbreak/.bridge-state")
source=source.replace('b"VERSION = \'0.3.0\'"','b"VERSION = \'0.3.2\'"')
module=types.ModuleType('baseline_api_tests');module.__file__=str(BASELINE/'test_v030.py')
exec(compile(source,module.__file__,'exec'),module.__dict__)
suite=unittest.TestSuite()
for name in ('Files','Commands','Updates','HTTP','RealSupervisor'):
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(getattr(module,name)))
result=unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful():sys.exit(1)
