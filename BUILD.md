# Building ComputerCheck

## Prerequisites

- Rust (cargo) and Node (npm). Verified with cargo 1.96, node 25.
- `python3` on PATH for dev, with `fpdf2` (`pip3 install --user fpdf2`) for the
  German/English PDF report. For release also `pyinstaller`
  (`pip3 install --user pyinstaller fpdf2`) so the bundled engine includes the
  PDF dependency.
- For signing: Apple Developer ID `Developer ID Application: Luis Assardo
  (LWSXUT3Y4S)` in the login Keychain, plus an app-specific password for
  notarization.

## Dev loop

```sh
npm install
npm run tauri dev
```

The Rust `run_scan` command, in a debug build, runs `python3 -m engine.selfcheck`
from the project root and captures its JSON. No packaging needed to iterate.

## How the engine ships in release

The notarized app must not depend on a system Python. So release builds bundle a
single self-contained engine binary:

1. `scripts/build-engine.sh` runs PyInstaller on `scripts/engine_entry.py`
   (which calls `engine.selfcheck.main`) and writes
   `src-tauri/engine-dist/computer-check-engine`.
2. `src-tauri/tauri.release.conf.json` is a config **patch** that adds that
   binary to `bundle.resources`. It is kept separate from `tauri.conf.json` on
   purpose: Tauri validates resource paths at config load, so referencing the
   not-yet-built binary in the base config would break `cargo check` and
   `tauri dev`. The release uses `--config src-tauri/tauri.release.conf.json` to
   merge it in only when packaging.
3. In a release build, `run_scan` resolves the engine from the app's resource
   dir (`engine-dist/computer-check-engine`) instead of `python3`.

## One-command signed release

```sh
APPLE_ID="luisassardo@me.com" \
APPLE_PASSWORD="xxxx-xxxx-xxxx-xxxx" \
APPLE_TEAM_ID="LWSXUT3Y4S" \
bash scripts/release-macos.sh
```

This builds the engine, then `tauri build --target universal-apple-darwin
--config src-tauri/tauri.release.conf.json`, then notarizes and staples the dmg.
Mirrors `../api-pass/scripts/release-macos.sh`.

## The C-LAB age recipient key

The encrypted export is sealed to `CLAB_AGE_RECIPIENT` in `src-tauri/src/lib.rs`.
As of 2026-06-05 this is C-LAB's **production** public key; the matching private
key is held offline by Luis only and never lives in this repo.

Decrypt a received export: `age -d -i <your-identity-file> ComputerCheck-export.age`
(or via the ingest tool, which wraps this).

To rotate: `age-keygen -o new-identity.txt`, replace `CLAB_AGE_RECIPIENT` with the
new `age1...` public key, keep the new private key safe + backed up, bump the
version, and re-release. The old key's submissions stay readable with the old
identity file, so keep retired identity files until their exports are ingested.

## Windows build (via GitHub Actions)

Tauri cannot cross-compile a Windows app from macOS, so Windows is built on a
Windows runner by `.github/workflows/release-windows.yml`:

1. Builds the engine to a `.exe` with `scripts/build-engine.ps1` (PyInstaller +
   fpdf2).
2. `npm run tauri build --config src-tauri/tauri.release.conf.json` → NSIS + MSI.
3. Authenticode-signs the installers IF these repo secrets exist (else unsigned,
   SmartScreen "Run anyway"):
   - `WINDOWS_CERTIFICATE` — base64 of your code-signing `.pfx`
   - `WINDOWS_CERTIFICATE_PASSWORD`
4. Uploads installers + `SHA256SUMS-windows.txt` as a workflow artifact.

Trigger by pushing a `v*` tag or running the workflow manually from the Actions
tab. The engine logic only truly executes on Windows, so smoke-test the produced
installer on a real Windows machine (macOS CI only verifies the checks import,
run, and carry full EN/ES/DE text).

To build locally on a Windows machine instead:
`powershell -File scripts/build-engine.ps1; npm run tauri build -- --config src-tauri/tauri.release.conf.json`

## Notes

- Icons under `src-tauri/icons/` are currently the ApiPass placeholders. Replace
  with ComputerCheck art before public release, and refresh the favicon in
  `frontend/index.html`.
- `minimumSystemVersion` is 11.0. The `keyring` crate uses the macOS Keychain for
  the history data key and the device pseudonym.
