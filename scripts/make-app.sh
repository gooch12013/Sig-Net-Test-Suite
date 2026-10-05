#!/bin/sh
# Builds a double-clickable "Sig-Net Test Suite.app" in build/.
#   scripts/make-app.sh            build only
#   scripts/make-app.sh --install  build and copy to /Applications
set -eu
cd "$(dirname "$0")/.."

NAME="Sig-Net Test Suite"
APP="build/$NAME.app"

swift build -c release
BIN="$(swift build -c release --show-bin-path)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/SignetTestSuite" "$APP/Contents/MacOS/"
cp Sources/SignetTestSuite/Resources/SigNetLogo.png "$APP/Contents/Resources/"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>$NAME</string>
  <key>CFBundleDisplayName</key><string>$NAME</string>
  <key>CFBundleExecutable</key><string>SignetTestSuite</string>
  <key>CFBundleIdentifier</key><string>com.signet.testsuite</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$(git describe --tags --always 2>/dev/null || echo 0.1)</string>
  <key>CFBundleVersion</key><string>$(git rev-list --count HEAD 2>/dev/null || echo 1)</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSLocalNetworkUsageDescription</key><string>Sends and receives Sig-Net traffic on the local network.</string>
</dict></plist>
EOF

# Ad-hoc signature: runs on this Mac. Another Mac needs a Developer ID signature and notarization.
codesign --force --sign - "$APP"
echo "Built $APP"

if [ "${1:-}" = "--install" ]; then
    rm -rf "/Applications/$NAME.app"
    cp -R "$APP" /Applications/
    echo "Installed /Applications/$NAME.app"
fi
