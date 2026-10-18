# Packaging as a Mac app

`scripts/make-app.sh` turns the SwiftPM build into a double-clickable
`Sig-Net Test Suite.app`, so the suite runs without `swift run`.

```sh
scripts/make-app.sh             # builds build/Sig-Net Test Suite.app
scripts/make-app.sh --install   # same, then copies it to /Applications
```

`npm run install:mac` runs the second line: it rebuilds from this folder and
replaces /Applications/Sig-Net Test Suite.app. Quit and reopen the app to run
the new build.

## What the script does

1. Runs `swift build -c release`.
2. Creates the bundle: the binary in `Contents/MacOS` and `SigNetLogo.png` in
   `Contents/Resources`. There is nothing else to bundle: the app is pure Swift.
3. Writes `Info.plist` with the bundle ID `com.signet.testsuite`, a version
   taken from git, macOS 13 as the minimum, and `NSLocalNetworkUsageDescription`.
4. Signs the bundle ad hoc (`codesign --sign -`).

`AppView.swift` looks for the logo in `Bundle.main` before `Bundle.module`.
SwiftPM's `Bundle.module` expects its resource bundle at the root of the
`.app`, and codesign rejects files there.

`build/` is in `.gitignore`.

## First launch

macOS asks for local network access the first time the app runs. Click Allow.
If you don't, the app can't send or receive any Sig-Net traffic. To change the
answer later, open System Settings → Privacy & Security → Local Network.

## Sharing with other Macs

```sh
npm run package:mac      # or scripts/make-dmg.sh
```

Builds `build/Sig-Net Test Suite.dmg`: the app as one binary for Apple Silicon
and Intel (macOS 13 or later), beside an Applications shortcut. Copy the DMG to
a USB stick; on the other Mac, open it and drag the app onto Applications. The
universal build needs Xcode; the command line tools alone build only this Mac's
architecture. `package.json` exists only so IDEs such as WebStorm list the
script: there is nothing to `npm install`.

## Limits

- **Ad-hoc signed.** macOS only checks the signature of quarantined files,
  and a file copied from a USB stick isn't quarantined, so the DMG above
  opens on any Mac that way. A downloaded, emailed or AirDropped copy is
  quarantined: the first open is refused, then System Settings → Privacy &
  Security → Open Anyway allows it. Removing that step needs a Developer ID
  signature plus notarization (`notarytool`), which the scripts don't do.
- **Generic icon.** The logo is a wide banner (880×224) and would look
  squashed as a square icon. A square mark would need converting to `.icns`
  (`sips` + `iconutil`) and setting as `CFBundleIconFile`.
- **No auto-update.** After changing the code, run `--install` again.
