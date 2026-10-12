# Device test: failed-unpack abort recovery (0.3.7)

**TEST ONLY — do not publish, do not add to SHA256SUMS, do not upload to a release.**

Artifact: `OpenMinis-Jailbreak_0.3.7-ABORT-TEST.deb`
SHA256: `609ba2aa0f213e59a6cdc23f49ac41c16ae51749d081fc3c5fcc8712d40c67fb`
Built by: `make_abort_test_deb.py` (rebuilt with `python3 make_abort_test_deb.py`)

## What it is

The real 0.3.7 package with **this release's control scripts intact** (`preinst`,
`postinst`, `prerm`, `postrm` are byte-identical to the release build) and a
`data.tar.gz` that is corrupted in the middle (64 bytes XOR 0x5A at 50 % of the
member). The control archive still verifies, so dpkg will start the upgrade
normally:

1. `new-preinst upgrade <old-version>` runs: preflight, runtime allow-list,
   plist check, mobile fingerprint, snapshot into
   `/usr/local/lib/openminis-jb-transaction`, bounded stop of the service.
2. The payload unpack **fails**: the extracted tar stops after
   `usr/local/lib/openminis-jb/bridge.py` (that file is written at full size but
   with garbage content) and `launcher.py`, `maintenance_runtime.py` and
   `mobile_setup.py` are left missing. The service is therefore unusable.
3. dpkg calls `new-postrm abort-upgrade <old-version>` — the path this release
   fixes.

## What to expect

With 0.3.7 installed as the *new* package (i.e. the device already offers 0.3.7,
or you install the real 0.3.7 first so this test .deb is a genuine upgrade), the
abort path must:

- print exactly **one** line, either
  `OpenMinis-Jailbreak: dpkg aborted the upgrade after preinst; the pre-upgrade
  root runtime, service plist and mobile active pointer were restored from the
  same-boot snapshot, ...` (success), or a single `NOTICE: OpenMinis-Jailbreak
  abort recovery: ...` line explaining why nothing was changed;
- restore all four root runtime files and the plist byte-for-byte;
- restore the mobile active pointer;
- restart the service and pass the authenticated health check;
- leave `token`, `config-v030.json` and `audit-v030.jsonl` byte-identical;
- keep the uncommitted snapshot at `/usr/local/lib/openminis-jb-transaction`
  for review;
- exit 0, so dpkg finishes instead of leaving a wedged package state.

`dpkg -i` still returns a non-zero status overall — the upgrade did fail. That is
expected; what matters is that the service is healthy and dpkg is usable again.

## How to use it

On the device, as root (Filza terminal, NewTerm, or SSH):

```
# 0. optional: make sure the real 0.3.7 is what the device is offering
dpkg -l app.openminis.jailbreak

# 1. install the broken test package (expected to fail; that is the point)
dpkg -i /var/mobile/OpenMinis-Jailbreak_0.3.7-ABORT-TEST.deb ; echo "dpkg exit=$?"

# 2. the package version must still be the OLD one (the upgrade did not happen)
dpkg-query -W -f='${Package} ${Version} ${Status}\n' app.openminis.jailbreak

# 3. the root runtime must be complete and correct again
shasum -a 256 /usr/local/lib/openminis-jb/*.py

# 4. the service must be running and healthy (port 18765 must be bound)
launchctl print system/app.openminis.jbbridge | head -20
grep -c . /var/mobile/Documents/OpenMinis-Jailbreak/.bridge-state/audit-v030.jsonl

# 5. the snapshot is kept for review (committed=false) and PREVIOUS stays absent
python3 -c "import json;print(json.load(open('/usr/local/lib/openminis-jb-transaction/meta.json')))"
ls -la /usr/local/lib/openminis-jb-previous 2>/dev/null || echo "no rollback copy (expected: this run never activated)"

# 6. OpenMinis must still connect with the SAME token (no reconfiguration)
```

Then finish by installing the real package again:

```
# the leftover snapshot describes the current state, so it is replaced safely
dpkg -i /var/mobile/OpenMinis-Jailbreak_0.3.7-1+experimental_iphoneos-arm64e.deb
# after this succeeds, /usr/local/lib/openminis-jb-previous exists (0700) with the
# previous runtime, and /usr/local/lib/openminis-jb-transaction is gone
/usr/local/bin/openminis-jb-restore-runtime --dry-run
```

## Verifying the "no change" branch as well

Running the same broken .deb on a device that has **no** uncommitted snapshot for
this version (for example right after a completed 0.3.7 install, or after a
reboot so the snapshot is cross-boot) must print one `NOTICE` line such as

```
NOTICE: OpenMinis-Jailbreak abort recovery: no uncommitted upgrade snapshot
exists for 0.3.7-1+experimental; nothing else was changed and dpkg may finish
```

and change nothing at all — no file is written, the service is left as found, and
dpkg still finishes.

## Cleanup

The test .deb only installs the same payload files as the release; nothing extra
is left behind except the snapshot described above, which the next successful
upgrade replaces. Nothing in this artifact is part of the release checksums.
