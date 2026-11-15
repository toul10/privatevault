# Releasing PrivateVault

Maintainer checklist for a build that other people may install.

`Scripts/build-app.sh` makes **ad-hoc signed** builds. They run on the Mac that built them, but Gatekeeper blocks
them on every other Mac and macOS cannot prove they were not tampered with (`THREAT_MODEL.md` §4). **Never publish
an ad-hoc build.** Releases are signed with a Developer ID certificate and notarized by Apple.

## One-time setup

1. Join the **Apple Developer Program** (paid yearly membership) with the account that will publish the app.
2. Install **Xcode** (it provides `notarytool`, `stapler` and the SwiftUI macro plugin).
3. Xcode → Settings → Accounts → Manage Certificates → **+** → *Developer ID Application*. Check it:

   ```
   security find-identity -v -p codesigning     # → "Developer ID Application: <Name> (<TEAMID>)"
   ```

4. Store the notarization credentials once, in the Keychain (create an app-specific password at
   appleid.apple.com; it is asked interactively — never put it in a file, a script or CI):

   ```
   xcrun notarytool store-credentials pv-notary --apple-id <apple-id> --team-id <TEAMID>
   ```

## Decide before the first public release

- **Bundle identifier.** `com.kostastoulis.privatevault` names the sandbox container and the Keychain items of
  every installation. Changing it later strands existing vaults (users would need a backup + restore). Keep it, or
  change it once — before anyone else installs the app.
- **Your own installation.** Moving from an ad-hoc build to a Developer ID build changes the app's code identity.
  The vault file itself is never touched, but on first launch macOS asks again for Keychain access (click
  **Always Allow**); if the Secret Key cannot be read, the app asks for the Recovery Kit once. Before switching:
  make an encrypted backup and have the printed Recovery Kit of the current vault at hand.

## Every release

1. Update `CHANGELOG.md`, and in `Packaging/Info.plist` raise `CFBundleShortVersionString` (marketing version)
   and `CFBundleVersion` (build number, always increasing).
2. All gates must pass:

   ```
   Scripts/run-tests.sh
   Scripts/run-tests.sh -c release --filter 'Argon2|AEAD|HKDF|HPKE'
   Scripts/secret-scan.sh --all && Scripts/secret-scan.sh --commits HEAD
   Scripts/audit-network.sh --strict
   ```

   and the checks in `DEPENDENCY_SECURITY.md` §9. CI must be green on the release commit.
3. Build the production identity: `Scripts/build-app.sh --production` → `dist/PrivateVault.app`.
4. Replace the ad-hoc signature with your Developer ID (hardened runtime, secure timestamp, same entitlements):

   ```
   codesign --force --options runtime --timestamp \
     --entitlements Packaging/PrivateVault.entitlements \
     --sign "Developer ID Application: <Name> (<TEAMID>)" dist/PrivateVault.app
   Scripts/verify-bundle.sh dist/PrivateVault.app
   ```

   If the bundle contains `Contents/Frameworks/libswiftCompatibilitySpan.dylib`, sign that file the same way first.
5. Notarize and staple:

   ```
   ditto -c -k --keepParent dist/PrivateVault.app dist/PrivateVault-notarize.zip
   xcrun notarytool submit dist/PrivateVault-notarize.zip --keychain-profile pv-notary --wait
   xcrun stapler staple dist/PrivateVault.app
   spctl --assess --type execute --verbose dist/PrivateVault.app   # → accepted, source=Notarized Developer ID
   ```

6. Package the **stapled** app (`ditto -c -k --keepParent dist/PrivateVault.app dist/PrivateVault-<version>.zip`,
   or a DMG), record `shasum -a 256` of the file, tag the commit `v<version>`, and publish a GitHub Release with the
   file and its SHA-256 in the notes.
7. Users have no automatic updates (the app never connects to the network): announce security fixes clearly in
   the release notes so people know to update.

## Mac App Store (alternative)

The app is already sandboxed with minimal entitlements. App Store distribution additionally needs an App Store
provisioning profile, App Store Connect metadata, the export-compliance answer for encryption, a privacy label
("Data Not Collected", see `PRIVACY.md`) and Apple's review.
