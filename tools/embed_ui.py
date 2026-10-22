#!/usr/bin/env python3
"""Embed source-v030/ui.html into bridge.py's UI_HTML constant.

Edit the HTML as a normal file, run this, and `python3 test_filetools.py`
checks that the embedded copy is byte-identical.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / 'source-v030' / 'ui.html'
BRIDGE = ROOT / 'source-v030' / 'bridge.py'
OPEN = 'UI_HTML = r"""'
CLOSE = '"""\n'

html = UI.read_text()
if '"""' in html:
    raise SystemExit('ui.html must not contain a triple quote')
source = BRIDGE.read_text()
start = source.index(OPEN)
end = source.index(CLOSE, start + len(OPEN)) + len(CLOSE)
BRIDGE.write_text(source[:start] + OPEN + html + CLOSE + source[end:])
print('embedded %d bytes into %s' % (len(html), BRIDGE))
