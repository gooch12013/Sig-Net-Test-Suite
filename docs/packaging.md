# Packaging as a Mac app

`scripts/make-app.sh` turns the SwiftPM build into a double-clickable
`Sig-Net Test Suite.app`, so the suite runs without `swift run`.

```sh
scripts/make-app.sh             # builds build/Sig-Net Test Suite.app
scripts/make-app.sh --install   # same, then copies it to /Applications
```

## What the script does

1. Runs `swift build -c release`.
2. Creates the bundle: the binary in `Contents/MacOS`, `SigNetLogo.png` in
   `Contents/Resources`, and `libsignet.dylib` in `Contents/Frameworks`.
   The library comes from `vendor/signet`, or `SIGNET_PREFIX` if set.
3. Adds an `@executable_path/../Frameworks` rpath so the binary finds the
   bundled library instead of the one in the project folder.
4. Writes `Info.plist` with the bundle ID `com.signet.testsuite`, a version
   taken from git, macOS 13 as the minimum, and `NSLocalNetworkUsageDescription`.
5. Signs the bundle ad hoc (`codesign --sign -`).

`AppView.swift` looks for the logo in `Bundle.main` before `Bundle.module`.
SwiftPM's `Bundle.module` expects its resource bundle at the root of the
`.app`, and codesign rejects files there.

`build/` is in `.gitignore`.

## First launch

macOS asks for local network access the first time the app runs. Click Allow.
If you don't, the app can't send or receive any Sig-Net traffic. To change the
answer later, open System Settings → Privacy & Security → Local Network.

## Limits

- **This Mac only.** The ad-hoc signature only works on the Mac that built
  the app. Giving it to someone else needs a Developer ID signature plus
  notarization (`notarytool`, using the App Store Connect key at
  `$ASC_KEY_PATH`). The script doesn't do this yet.
- **Generic icon.** The logo is a wide banner (880×224) and would look
  squashed as a square icon. A square mark would need converting to `.icns`
  (`sips` + `iconutil`) and setting as `CFBundleIconFile`.
- **No auto-update.** After changing the code, run `--install` again.
- The linker warning that the dylib targets a newer macOS than the package
  still appears. It's harmless on this Mac, but rebuild the library with a
  matching deployment target before shipping to older systems.
