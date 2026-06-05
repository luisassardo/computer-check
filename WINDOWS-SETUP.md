# Running ComputerCheck on Windows (dev + local build)

This is a runbook for a Windows machine (e.g. via Claude Code on Windows). Goal:
get the app running so the Windows checks execute for real, then optionally build
an (unsigned) installer.

The Windows checks have NEVER run on real hardware yet — they were written and
translated on a Mac, which can't run PowerShell. So `npm run tauri dev` here is
the real validation step. Expect to find and fix a few Windows-specific issues.

## 1. Get the code onto Windows

Pick one:

- **GitHub (recommended)** — also required for the CI build workflow to run.
  On the Mac side the repo can be pushed to `github.com/luisassardo/computer-check`
  (private is fine). Then on Windows:
  ```powershell
  git clone https://github.com/luisassardo/computer-check.git
  cd computer-check
  ```
- **Copy the folder** (Proton Drive / USB). Copy the `computer-check` folder but
  SKIP `node_modules/`, `src-tauri/target/`, and `dev-age-identity.txt`. You will
  reinstall deps fresh on Windows.

## 2. Install the toolchain

On Windows 11 (winget):
```powershell
winget install OpenJS.NodeJS.LTS
winget install Python.Python.3.12
winget install Rustlang.Rustup
# MSVC C++ build tools + Windows SDK (Tauri needs these to compile):
winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
# WebView2 runtime (preinstalled on Win11; install on Win10 if missing):
winget install Microsoft.EdgeWebView2Runtime
```
Then finish Rust setup and the Python libs:
```powershell
rustup default stable
python -m pip install --upgrade pip
pip install fpdf2 pyinstaller
```
Restart the terminal so PATH updates take effect. Sanity check:
```powershell
node -v; npm -v; python --version; rustc --version; cargo --version
```

## 3. Run in dev (the important step)

```powershell
cd computer-check
npm install
npm run tauri dev
```
First launch compiles the Rust dependency tree (several minutes). A ComputerCheck
window opens. Click **Scan my device**. In dev the app runs
`python -m engine.selfcheck`, which on Windows runs the 24 Windows checks via
PowerShell.

What to verify:
- The scan completes and the report shows ~24 findings (not all ERROR).
- History persists across scans (key stored in Windows Credential Manager).
- The 3 PDF buttons (EN/ES/DE) save files; open the German + Spanish PDFs.
- The encrypted export saves a `.age` file.

If the scan errors, copy the terminal output (the Rust side logs there) and the
specific failing check, and hand it back for a fix. The most likely issues are
PowerShell quoting/flags in individual checks (there is a known unresolved
`NoneType ... strip` crash on at least one ThinkPad model in the sister tool).

## 4. Build an UNSIGNED installer (optional, local)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-engine.ps1
npm run tauri build -- --config src-tauri\tauri.release.conf.json
```
Output (NSIS `.exe` + MSI) lands in `src-tauri\target\release\bundle\`.
Because it's unsigned, Windows SmartScreen shows "Windows protected your PC" →
**More info → Run anyway**. That's expected until a signing cert is added (see
BUILD.md). Publish the SHA-256 separately so users can verify the download.

## 5. Build via CI instead (no local toolchain needed)

Once the repo is on GitHub, push a `v*` tag or run the **Release (Windows)**
workflow manually. It builds the same unsigned installers and uploads them as an
artifact. Add `WINDOWS_CERTIFICATE` + `WINDOWS_CERTIFICATE_PASSWORD` secrets later
to get signed builds automatically.
