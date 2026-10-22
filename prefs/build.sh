#!/bin/sh
# Build the native Settings pane with the standard Theos aarch64 toolchain.
#
# This is the same setup the Theos installer uses on aarch64 Linux:
#   https://github.com/L1ghtmann/llvm-project/releases  (iOSToolchain-aarch64)
# It contains Apple ld64 (with TAPI) and ldid, and is required: lld cannot
# produce loadable arm64e ObjC metadata.
#
# Usage:
#   IOS_SDK=/path/iPhoneOS16.5.sdk THEOS_TOOLCHAIN=/path/toolchain/iphone \
#     sh prefs/build.sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SDK=${IOS_SDK:-/opt/sdk/iPhoneOS16.5.sdk}
TC=${THEOS_TOOLCHAIN:-/opt/theos/toolchain/linux/iphone}
CLANG="$TC/bin/clang"
LD="$TC/bin/ld"
LIDID="$TC/bin/ldid"
BUNDLE="$ROOT/layout/Library/PreferenceBundles/OpenMinisJBPrefs.bundle"
ENTRY="$ROOT/layout/Library/PreferenceLoader/Preferences/OpenMinisJBPrefs.plist"

test -x "$CLANG" || { echo "missing Theos clang: $CLANG" >&2; exit 1; }
test -x "$LD" || { echo "missing Theos ld64: $LD" >&2; exit 1; }
test -d "$SDK" || { echo "missing SDK: $SDK" >&2; exit 1; }
mkdir -p "$BUNDLE" "$(dirname "$ENTRY")"

"$CLANG" -target arm64e-apple-ios16.0 -isysroot "$SDK" \
  -I"$ROOT/prefs/include" -fobjc-arc -Wall \
  -c "$ROOT/prefs/OMJBPrefs.m" -o "$BUNDLE/OpenMinisJBPrefs.o"
"$LD" -arch arm64e -platform_version ios 16.0 16.0 -syslibroot "$SDK" \
  -F "$SDK/System/Library/Frameworks" -bundle -fixup_chains \
  -undefined dynamic_lookup -framework Foundation -framework UIKit \
  -o "$BUNDLE/OpenMinisJBPrefs" "$BUNDLE/OpenMinisJBPrefs.o"
rm -f "$BUNDLE/OpenMinisJBPrefs.o"
if [ -x "$LIDID" ]; then "$LIDID" -S "$BUNDLE/OpenMinisJBPrefs"; fi

cp "$ROOT/prefs/Resources/Info.plist" "$BUNDLE/Info.plist"
cp "$ROOT/prefs/Resources/Root.plist" "$BUNDLE/Root.plist"
cp "$ROOT/prefs/Resources/icon.png" "$BUNDLE/icon.png"
cp "$ROOT/prefs/Resources/OpenMinisJBPrefs.plist" "$ENTRY"
chmod 0755 "$BUNDLE/OpenMinisJBPrefs"
chmod 0644 "$BUNDLE/Info.plist" "$BUNDLE/Root.plist" "$BUNDLE/icon.png" "$ENTRY"
echo "built $BUNDLE"
