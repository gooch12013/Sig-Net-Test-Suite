#!/bin/sh
# Builds build/Sig-Net Test Suite.dmg to hand to other Mac users (USB stick, file share):
# the app for Apple Silicon and Intel, beside an Applications shortcut to drag it onto.
set -eu
cd "$(dirname "$0")/.."

NAME="Sig-Net Test Suite"
UNIVERSAL=1 scripts/make-app.sh

STAGE="build/dmg"
rm -rf "$STAGE" && mkdir -p "$STAGE"
cp -R "build/$NAME.app" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -quiet -volname "$NAME" -srcfolder "$STAGE" -format UDZO -ov "build/$NAME.dmg"
rm -rf "$STAGE"
echo "Built build/$NAME.dmg"
