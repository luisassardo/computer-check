# ComputerCheck — phase tracker

Full spec: `../securityscan-usb/SELFCHECK-SPEC.md`.

## Phase 1 — local self-assessment app  ✅ scaffolded + verified
- [x] Vendor macOS engine subset (`engine/`, schema bump to v2)
- [x] `selfcheck.py` entrypoint: read-only scan, JSON on stdout (verified on real Mac: 23 findings)
- [x] Tauri shell mirroring ApiPass (`cargo check` green): run_scan, encrypted history, pseudonym
- [x] AES-256-GCM history with Keychain key; one-click wipe
- [x] ARGUS cyan frontend: Scan / Report / History (report + trend verified in preview)
- [x] PyInstaller engine packaging + signed release script
- [x] ComputerCheck app icon set (monitor + check, C-LAB cyan) via scripts/make-icon.py + tauri icon; matching favicon
- [x] EN/ES toggle on static chrome (self-contained in app.js; node.js leaves i18n per-tool). Verified in preview.
- [x] **Trilingual PDF reports (EN/ES/DE)** on demand: 3 buttons in report view -> save dialog -> `export_pdf`. All three PDFs verified generating + rendering.
- [x] **ES added across the engine**: `*_es` on Finding + `localized('es')`, ES UI strings in i18n, all 23 macOS checks translated to Spanish. PDF rebranded ComputerCheck.
- [x] Headline broadened "Check your Mac" -> "Check your computer" (Mac+Windows product); Mac-specific copy generalized.
- [x] History richer visualizations: KPI cards + score-over-time line/area chart + status-per-scan stacked bars (inline SVG, CSP-safe). Alignment bug fixed.
- [ ] End-to-end run of the real app (`npm run tauri dev`) confirmed by Luis
- [ ] Pilot with a small group as a pure self-assessment tool (no export yet)

## Phase 2 — encrypted export + urgent channel  ✅ built + verified
- [x] `age` encrypt-to-C-LAB-key export (`age` crate; `export_encrypted` cmd). Round-trip + baked-key decrypt verified via `cargo test`.
- [x] Routine export EXCLUDES IoC-class findings (standards ∋ Citizen Lab / Amnesty MVT). Verified: routine=2 findings no-IoC, urgent=3 with-IoC.
- [x] Org code surfaced + pseudonym shown in the export panel (transparency: shows what will be sent).
- [x] Spyware/IoC urgent channel: distinct block + Access Now link + consent checkbox gating a separate `ComputerCheck-URGENT.age` (full payload).
- [x] Real export panel replaces "Export · soon".
- [ ] **Luis: replace the DEV age key** (`CLAB_AGE_RECIPIENT` in src-tauri/src/lib.rs) with your real public key; keep private offline. Dev key + instructions in `dev-age-identity.txt` (gitignored).
- decision: `evidence` IS included in the routine export (full diagnostics, encrypted to C-LAB). Resolves spec open Q#3. Add a sanitize toggle later if desired.

## Phase 3 — operator ingest + cohort dashboard
- [ ] Local `age` decrypt CLI for Luis
- [ ] Extend `dashboard.py`: per-org cohorts + per-device pseudonym trend
- [ ] Decide DB home (extend dashboard / SQLite / D1 / Airtable)

## Phase 4 — landing page
- [ ] `c-lab.tools` tool page (ARGUS), verified download (SHA-256 + notarization)
- [ ] Link from the C-LAB desk + network map

## Phase 5 — Windows  (code prep ✅ done; build needs a Windows runner)
- [x] Vendored `checks_windows/` (24 checks) into the engine; `selfcheck.py` now OS-aware (macOS vs Windows dispatch).
- [x] All 24 Windows checks translated to Spanish (EN+ES+DE), verified: ES==DE counts, runs with 0 missing / 0 crashes.
- [x] Rust cross-platform: keyring uses Windows Credential Manager (`windows-native`); `python` vs `python3` in dev; `.exe` engine sidecar; release bundles `engine-dist/*`; `bundle.targets = "all"` (mac=dmg/app, win=nsis/msi).
- [x] `scripts/build-engine.ps1` (Windows engine .exe) + `.github/workflows/release-windows.yml` (build + Authenticode sign + checksums + upload).
- [ ] **Run the Windows build**: push a `v*` tag (or run the workflow manually). Add repo secrets `WINDOWS_CERTIFICATE` (base64 .pfx) + `WINDOWS_CERTIFICATE_PASSWORD` for signing; without them it builds UNSIGNED (SmartScreen).
- [ ] Smoke-test the produced installer on a real Windows machine (the engine logic only truly runs on Windows; mac verified imports + ES coverage only).

## Open questions (need Luis) — see spec §13
1. Public name / does this own the C-LAB "Forensics" tile or its own tile?
2. ~~App UI language set~~ RESOLVED: EN-ES UI + on-demand German PDF only.
3. ~~`evidence` in routine export~~ RESOLVED: included (full, encrypted to C-LAB). Sanitize toggle is a future option.
4. Org-code issuance: per-org from Luis, or self-declared?
5. Database home (Phase 3).
