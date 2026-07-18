# ComputerCheck — Handoff to a new agent

Read this before doing anything else in this folder. Pair with:
- `../CONVENTIONS.md` (portfolio-wide rules — READ FIRST)
- `../securityscan-usb/HANDOFF.md` (sister tool, mature reference implementation)
- Memory at `~/.claude/projects/-Users-luisassardo-Desktop-PROJECTS/memory/`

**Status snapshot**: v0.1.4 shipped 2026-07-17 with a Lockdown Mode detection fix (users who enabled LM were still seeing FAIL because the check read preference domains that don't exist). macOS DMG is freshly notarized. Windows .exe is CI-built but still **unsigned** (SmartScreen warning until the SSL.com eSigner cert is procured — see below). Apple Developer legal agreements refreshed on 2026-07-17 — notarytool works again. **2026-07-18**: cleared the in-flight working tree — a batch of docs/CI/ingest commits landed and were pushed (no version bump, no new release); see "Recent state" for the list.

---

## Who this is for

**Luis Assardo** — journalist + developer, **resident in Germany (EU)**. Work still centered on Guatemala (vectorcritico.com, investigations). Audience: high-risk users — journalists, sources, DACH-area HRD organizations. Threat model assumes capable adversaries (Pegasus-class mercenary spyware, targeted attacks).

**Operational rules (never violate — full text in CONVENTIONS.md)**:
1. Read-only by default.
2. Nothing sent anywhere unless the user explicitly exports.
3. Honest about limits — no speculative IoCs.
4. Aging hardware → hard "replace" recommendation ALWAYS paired with budget-conscious interim mitigations.
5. Reservado por default. Don't propose GitHub publish, telemetry, or phone-home. Open-source decisions are Luis's.

**EU-residency implications (DECIDED — SSL.com eSigner)**: Windows signing uses **SSL.com Individual Validated (IV) + eSigner** — cloud/headless signing, no USB token, automatable from GitHub Actions via the official `sslcom/esigner-codesign` action (only the file hash leaves the runner). Luis signs as an individual (persona física) and needs CI automation; IV+eSigner is the only option that combines both. ~$130–250/year; SmartScreen reputation builds over time. Since the March 2026 CA/Browser ballot (CSC-13) there is no downloadable `.pfx` at all — every key must live in a FIPS 140-2 L2 HSM, which is exactly what eSigner provides. **Certum on SimplySign was rejected** (requires a desktop app + OTP per sign → bad for CI); Azure Trusted Signing rejected (individuals US/CA-only, Luis is EU). The `release-windows.yml` workflow is migrated to eSigner with auto-skip until the secrets exist. Not yet purchased as of this handover; that's why the .exe is still unsigned. See memory `reference-code-signing-2026`.

---

## What ComputerCheck is (Mode B)

Sister to SecurityScan-USB. Where the USB tool is **operator-driven forensic** (Mode A — Luis audits someone else's device), ComputerCheck is **self-check** (Mode B — the person audits their OWN laptop).

The end user opens the app, clicks "Scan my device", sees a plain-language report, and keeps an encrypted local history. Nothing is sent unless the user explicitly exports (age-encrypted to C-LAB, IoC excluded).

- **UI**: bilingual EN-ES. PDF reports in EN + ES + DE from the report view.
- **Engine**: same Finding schema as SecurityScan-USB (`securityscan.findings/2`, backward-compatible superset of v1). Vendored per CONVENTIONS.md — no shared library yet.
- **Storage**: AES-256-GCM encrypted local history, key in the OS keystore (macOS Keychain, Windows Credential Manager).
- **Pseudonym**: random per-install ID persisted in the keystore. Never a real hostname sent anywhere.

Landing page: [computercheck.c-lab.tools](https://computercheck.c-lab.tools/) → Cloudflare Pages → static, no trackers, CSP-locked.

---

## Where things live

```
tools-cybersecurity/computer-check/
├── HANDOFF.md                          ← this file
├── README.md                           ← end-user + dev docs
├── BUILD.md                            ← build instructions (Mac + Windows)
├── WINDOWS-SETUP.md                    ← runbook for developing on a Windows machine
├── PLAN.md                             ← phased roadmap + current status
├── SECURITY.md                         ← (new, uncommitted — Luis's ongoing work)
├── LICENSE                             ← MIT
│
├── engine/                             ← Python source, JSON-on-stdout to Tauri host
│   ├── __init__.py                     ← version (should track package.json / Cargo.toml)
│   ├── selfcheck.py                    ← entrypoint. main() calls _force_utf8_stdio() FIRST
│   ├── core.py                         ← Finding, ScanContext, run_cmd, safe_check, summarize
│   ├── i18n.py                         ← EN/ES/DE UI strings
│   ├── report_pdf.py                   ← PDF renderer (fpdf2), takes payload on stdin
│   ├── checks_macos/                   ← 23 checks, vendored from securityscan-usb
│   ├── checks_windows/                 ← 24 checks, vendored from securityscan-usb
│   └── reporters/                      ← same schema as sister tool
│
├── src-tauri/                          ← Rust shell (Tauri v2)
│   ├── Cargo.toml                      ← version 0.1.4
│   ├── tauri.conf.json                 ← productName, version, identifier
│   ├── tauri.release.conf.json         ← release overrides
│   ├── engine-dist/                    ← PyInstaller output goes here; Tauri bundles it as a resource
│   └── src/                            ← Rust: run_scan, history_load, history_append, etc.
│
├── frontend/                           ← ARGUS (C-LAB cyan) design, three views: Scan, Report, History
│                                          CSP-locked, no external CDNs, fonts vendored
│
├── ingest/                             ← C-LAB inbox: receives exported .age files from users
│   └── cc_ingest.py                    ← (uncommitted — Luis's ongoing work)
│
├── landing/                            ← Static landing at computercheck.c-lab.tools
│   ├── index.html                      ← two "Download" CTAs linking to /releases/latest/download/…
│   ├── site.js                         ← bilingual EN-ES i18n
│   └── README.md                       ← Cloudflare Pages deploy instructions
│
├── scripts/
│   ├── build-engine.sh                 ← macOS PyInstaller build (universal2)
│   ├── build-engine.ps1                ← Windows PyInstaller build
│   ├── release-macos.sh               ← macOS release: build + sign + notarize + gh release
│   ├── engine.entitlements            ← macOS runtime entitlements
│   ├── engine_entry.py                 ← PyInstaller entry point
│   └── make-icon.py                    ← icon generator
│
├── .github/workflows/
│   └── release-windows.yml             ← Windows CI: builds engine + Tauri, uploads to release
│
└── build/                              ← PyInstaller build artifacts (regenerated)
```

---

## Recent state — what just happened

### 2026-07-18 — cleared the in-flight working tree (docs / CI / ingest)

No code behavior change in the app, no version bump, no new release. Committed and pushed the batch of work that had been sitting uncommitted since v0.1.4, split into focused commits (all on `main`, `cce8635..706e4eb`):

- `f534f9a` **Ingest** — added a `tool` column (`"computer-check"` | `"mobile-check"`) to the `scans` table in `ingest/cc_ingest.py`, with an idempotent `ALTER TABLE` migration for pre-existing DBs, so the shared C-LAB inbox can tell desktop from mobile payloads. The CC engine already emits `tool` (`engine/selfcheck.py:88,141`).
- `a601226` **Docs** — corrected the README age-key note (the committed `CLAB_AGE_RECIPIENT` is the PRODUCTION key, NOT a dev throwaway; rotation is a two-repo fleet operation) + added `SECURITY.md` (private disclosure to security@c-lab.tools, 72h ack, safe harbor, EN/ES/DE).
- `1825e5d` **CI (Windows)** — replaced the old `.pfx`/signtool path with **SSL.com eSigner** (cloud/headless, `sslcom/esigner-codesign`), self-skipping until the `ES_*` secrets exist; also generates a CycloneDX SBOM and attaches it to the release.
- `d2771c0` **Chore** — synced `Cargo.lock` app version to 0.1.4.
- `706e4eb` **HANDOFF.md** — began tracking this file in git and reconciled its Windows-signing guidance to eSigner (previously it still recommended Certum, contradicting the CI).

**Signing docs reconciled**: HANDOFF.md (EU-residency section + open-item #1) and memory `reference-code-signing-2026` + `MEMORY.md` index all now agree — **SSL.com eSigner IV is the decided path**, Certum/Azure rejected. See open-item #1.

**Dependabot alert #1 dismissed** (`not_used`): `glib` GHSA-wrw7-89jp-8q8g (medium) is a Linux-only transitive dep via Tauri's GTK/webkit2gtk backend. CC ships macOS (WKWebView) + Windows (WebView2) only — `cargo tree` for all three shipped targets shows glib in none of them, and it's pinned by `gtk 0.18`/`tauri 2.11` so it isn't bumpable locally. Will auto-resolve on a future Tauri GTK upgrade. Do not re-flag.

### v0.1.4 shipped 2026-07-17 — Lockdown Mode detection fix

**Trigger**: Multiple macOS testers reported that after enabling Lockdown Mode in System Settings and re-scanning, the tool still reported "Lockdown Mode is NOT enabled". Their toggle had NOT reverted — it was the tool reading the wrong keys.

**Root cause**: `_check_lockdown_mode` read two preference domains that don't exist on any macOS version:
- `com.apple.security.lockdownmode` (never existed as a defaults domain)
- `com.apple.LaunchServices LSEnableLockdownMode` (never existed as a key)

Both were speculation from the original write. The check therefore could not return PASS since day one.

**Fix** (commit `943c09d`): read the real key. Lockdown Mode toggles `LDMGlobalEnabled` in NSGlobalDomain (`~/Library/Preferences/.GlobalPreferences.plist`).
- value = `1` → LM is ON
- key does not exist → LM is OFF (or never enabled)
- value = `0` → LM was explicitly turned off after being on

The new check reads both `defaults read -g LDMGlobalEnabled` and the `-currentHost` variant defensively via a tri-state helper. Evidence text shows exactly what each defaults call returned so future misdetection is diagnosable.

**Same fix applied to sister tool SecurityScan-USB** locally at `../securityscan-usb/engine/checks_macos/cat02_malware.py` — but SSU is USB-distributed (not a git repo), so no commit / no release. Luis needs to rsync it to the physical USB manually.

**Release** (commit `cce8635`, tag `v0.1.4`):
- Version bumped to 0.1.4 in `package.json`, `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`
- macOS: `release-macos.sh` ran successfully — signed, notarized, stapled, uploaded
- Windows CI ran to completion in ~9 min
- Landing URLs both resolve to v0.1.4 assets
- Assets:
  - `ComputerCheck-macOS.dmg` (27.8 MB, notarized) — SHA-256: `f021aae056787763785c56ff472a433c1b315baa5b407fee00302dad8f770f8d`
  - `ComputerCheck-Windows-Setup.exe` (21.3 MB, **unsigned**) — SHA-256: `5AFC8375F372CD6E307F14274F35E18C4888792CFFEE71D908CCEAE8A1101150`
  - `ComputerCheck_0.1.4_universal.dmg` (versioned macOS copy)
  - `SHA256SUMS-macos.txt`, `SHA256SUMS-windows.txt`

**Apple agreement blocker (resolved)**: Before the v0.1.4 release, `notarytool` was rejecting requests with `HTTP 403 — A required agreement is missing or has expired`. That's the Apple Developer Program License Agreement getting periodically updated. Luis logged into developer.apple.com/account and accepted the pending agreements; notarytool works again. If it fails again in the future with 403, first check for pending agreements before assuming the certificate is broken.

### v0.1.3 shipped 2026-06-11 — Windows UTF-8 encoding fix

**Trigger**: A journalist-course participant ran v0.1.2 on a ThinkPad. Scan crashed with `UnicodeDecodeError` / `UnicodeEncodeError` at three I/O boundaries.

**Fix** (commit `2b2c150`):
- `engine/core.py::run_cmd()` — `subprocess.run` now passes `encoding="utf-8", errors="replace"`
- `engine/core.py::_detect_os_version()` — same on the `sw_vers` call
- `engine/selfcheck.py::_force_utf8_stdio()` — reconfigures `sys.stdout`/`sys.stderr` to UTF-8 at the top of `main()`, guarded with `hasattr(stream, "reconfigure")` so PyInstaller-wrapped streams don't break

**Rule promoted to CONVENTIONS.md**: `Python on Windows — force UTF-8 at every I/O boundary (mandatory)` with copy-paste patterns. Every new tool in the portfolio must apply the three sites from day one.

---

## Uncommitted working-tree changes

Working tree is **clean** as of 2026-07-18. The batch that used to live here (release-windows.yml, README.md, ingest/cc_ingest.py, SECURITY.md) has been committed and pushed — see the 2026-07-18 entry above. `HANDOFF.md` is now tracked in git.

**Still uncommitted OUTSIDE this repo**: the v0.1.4 Lockdown Mode fix was also applied to `../securityscan-usb/engine/checks_macos/cat02_malware.py`. That folder is not a git repo — Luis distributes SSU by rsync to a physical USB. He still needs to run the manual sync to propagate the fix (open-item #3).

---

## Known issues + open items

### Open

| # | Item | Notes |
|---|---|---|
| 1 | Windows .exe is UNSIGNED | SmartScreen "Windows protected your PC" — More info → Run anyway. Decided path: **SSL.com Individual Validated (IV) + eSigner** (cloud/headless, ~$130–250/year). Buy the IV cert + enable eSigner (validation takes a few days), then add four repo secrets: `ES_USERNAME`, `ES_PASSWORD`, `ES_CREDENTIAL_ID`, `ES_TOTP_SECRET`. The workflow (commit `1825e5d`) already signs NSIS + MSI via `sslcom/esigner-codesign` and self-skips until those secrets exist. Claude never handles those values. See "EU-residency implications" above and memory `reference-code-signing-2026`. |
| 2 | Windows checks have never fully validated on hardware yet | The scan runs now (post-UTF-8 fix), but individual checks may still surface Windows-specific quirks (localized PowerShell errors, weird registry states). Any FAIL/ERROR with a stack trace is diagnostic gold — feed it back for a defensive fix. |
| 3 | Push v0.1.4 SecurityScan-USB fix to the physical USB | Same LM detection fix was applied to `../securityscan-usb/engine/checks_macos/cat02_malware.py` locally. Luis needs to sync to the USB (his manual rsync workflow) so the SSU tool also detects LM correctly. |
| 4 | ingest/ pipeline in-progress (Luis's work) | Don't rearchitect. If asked to help, read `PLAN.md` first for the intended C-LAB inbox flow. The `tool` column (desktop vs mobile) landed 2026-07-18 (`f534f9a`); further ingest iteration is still Luis's. `ingest/cc.db` is gitignored — never commit it. |

### Recently fixed (do NOT re-introduce)

| Fix | Where | Why |
|---|---|---|
| **Lockdown Mode detection** — read the real `LDMGlobalEnabled` key in NSGlobalDomain, not the speculative `com.apple.security.lockdownmode` / `com.apple.LaunchServices LSEnableLockdownMode` domains | `engine/checks_macos/cat02_malware.py::_check_lockdown_mode` | Users were correctly enabling LM but the tool always returned FAIL — bug went unnoticed since the check was written because in every author's test, LM was OFF anyway |
| UTF-8 on subprocess.run | `engine/core.py::run_cmd` and `_detect_os_version` | Windows _readerthread crashes on non-latin-1 stdout |
| UTF-8 on sys.stdout/stderr | `engine/selfcheck.py::_force_utf8_stdio` called first line of `main()` | json.dump(ensure_ascii=False) crashes on `→` in cp1252 stdout |
| `safe_check` fault isolation | `engine/core.py::safe_check` — already used in checks_macos + checks_windows | A crash in one check no longer kills the whole category module |

### Operational lesson from the LM bug

The Lockdown Mode check was PASS-in-theory-only for its entire history — no author had LM enabled during development. **Whenever a check has a "positive" branch that requires a specific machine state to test, ensure at least one author or tester actually reaches that state before shipping.** For LM specifically, the fastest way to validate: on any Mac, `defaults write -g LDMGlobalEnabled -bool YES && defaults read -g LDMGlobalEnabled` (should print `1`), run the check, expect PASS, then `defaults delete -g LDMGlobalEnabled`. No reboot needed to test the check; only real activation requires reboot.

---

## Architecture (short)

```
User launches ComputerCheck.app / .exe
   │
   ▼
Tauri (Rust) shell shows Scan / Report / History views
   │  invokes command "run_scan"
   ▼
Spawns engine binary (PyInstaller-bundled, no system Python needed)
   │  the engine reads no args, prints JSON to stdout
   ▼
engine/selfcheck.py::main()
   1. _force_utf8_stdio()          ← MUST BE FIRST
   2. ScanContext.detect()
   3. Register OS-appropriate checks (checks_macos or checks_windows)
   4. Scanner.run() — every check wrapped in safe_check
   5. build_payload() → json.dump(payload, sys.stdout, ensure_ascii=False)
   │
   ▼
Tauri captures stdout, parses JSON, renders report + appends to encrypted history
   │
   ▼
User can: view report, export PDF (EN/ES/DE), or export age-encrypted to C-LAB
```

**Non-negotiable**: JSON on stdout is the only contract between engine and Tauri. Never `print()` debug lines to stdout — the JSON parse breaks. Use `sys.stderr` for anything else.

---

## How to cut a new release

For future encoding fixes, check-additions, translation updates, etc.:

1. Edit source. If any commands are added/removed to run_cmd or run_ps, verify they use the UTF-8 pattern (CONVENTIONS.md).
2. Bump version consistently: `package.json`, `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`. Three files, same version.
3. Commit + push to main.
4. Tag: `git tag -a vX.Y.Z -m "…" && git push origin vX.Y.Z`.
5. Windows CI (`.github/workflows/release-windows.yml`) runs automatically on the tag push. Creates the release if it doesn't exist. Uploads `ComputerCheck-Windows-Setup.exe` + SHA256SUMS.
6. macOS: run `APPLE_KEYCHAIN_PROFILE="computercheck-notary" APPLE_TEAM_ID="LWSXUT3Y4S" bash scripts/release-macos.sh`. Signs, notarizes, uploads DMG + SHA256SUMS. If you just want to carry the previous DMG (no macOS code changes), download from the previous release and re-upload with `gh release upload vX.Y.Z --clobber`.
7. Verify landing URLs resolve:
   - `curl -sIL https://github.com/luisassardo/computer-check/releases/latest/download/ComputerCheck-Windows-Setup.exe`
   - Same for `ComputerCheck-macOS.dmg`

**If `release-macos.sh` fails with `HTTP 403 — required agreement is missing`**: it's an Apple legal agreement update. Log into developer.apple.com/account, accept the pending agreements (typically labeled "Review Updated Agreements" or in the "Agreements, Tax, and Banking" tab). Don't debug the certificate — that's not the problem. Then re-run.

---

## Portfolio context

`tools-cybersecurity/` contains many tools now (some full apps, some static utilities). Read `../CONVENTIONS.md` for the full tool index. High level:

- **SecurityScan-USB** (Mode A, operator-driven) — the mature reference. Read its `HANDOFF.md` for the shared bug catalog and architectural patterns.
- **ComputerCheck** (Mode B, self-check) — this tool. Vendored engine from SecurityScan-USB.
- **MobileCheck** — self-check for phones (adb Android + pymobiledevice3 iOS), same schema.
- **api-pass, hash-check** — static client-side utilities. Different shape.
- **wifi-scan, wifi-check, website-check, privacy-scan, android-triage** — various states of readiness.

**Do NOT extract a shared engine library yet.** CONVENTIONS.md explicitly forbids it until both leading tools hit v1.0.

**Bundled release consideration**: `apipass`, `hashcheck`, `computer-check` will likely be released together as a C-LAB suite. When that happens, their GitHub repo descriptions/topics/READMEs will be standardized together. Until then, each stays as-is.

---

## First-message boilerplate for a new agent

Send this in the first message of a new session:

> Read `/Users/luisassardo/Desktop/PROJECTS/tools-cybersecurity/CONVENTIONS.md` and `/Users/luisassardo/Desktop/PROJECTS/tools-cybersecurity/computer-check/HANDOFF.md` before starting. Then read the relevant memory files at `~/.claude/projects/-Users-luisassardo-Desktop-PROJECTS/memory/`. We're working on ComputerCheck. Reservado por default — don't propose GitHub publication, telemetry, or open-sourcing decisions.

Additional pointers:
- If touching the engine: also read `../securityscan-usb/HANDOFF.md` for the shared bug catalog.
- If touching the release flow: read `BUILD.md` and `WINDOWS-SETUP.md`.
- If touching ingest/: read `PLAN.md` first — Luis is iterating there.

---

## Last updated

Updated 2026-07-18: committed/pushed the in-flight docs+CI+ingest batch (`cce8635..706e4eb`, no version bump), reconciled Windows signing to SSL.com eSigner across docs+memory, dismissed the glib Dependabot alert (Linux-only, not shipped), and started tracking this file in git. Previous: rewritten 2026-07-17 after shipping v0.1.4 (Lockdown Mode detection fix; Apple agreements refreshed); 2026-06-11 after v0.1.3 (UTF-8 encoding fix). Update this file when the state drifts materially — especially: version number, open issues, recently fixed bugs, and any change to the release flow.
