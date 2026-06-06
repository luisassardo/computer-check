# CLAUDE.md — ComputerCheck working memory

Durable notes for working in this repo. For live status read `PLAN.md`; for the
end-to-end build read `BUILD.md`; for the product framing read `README.md`. This
file captures the things that are easy to get wrong and the conventions to keep.

## What this is

ComputerCheck is **Mode B** of the SecurityScan / C-LAB family: a person runs a
read-only security self-assessment on **their own** computer (macOS shipping,
Windows code-complete), gets a plain-language report, and keeps an encrypted
local history. Nothing leaves the machine unless the user explicitly exports.

Mode A (the operator-driven forensic USB tool) lives in the sibling repo
`../securityscan-usb/`. The full design spec is
`../securityscan-usb/SELFCHECK-SPEC.md`. Shared conventions:
`../CONVENTIONS.md`. **These siblings are not checked out in this repo** — they
are referenced, not vendored.

## Architecture (one screen)

```
Tauri app (Rust, src-tauri/) ──spawn──> engine (Python, engine/)
  frontend/  ARGUS cyan UI: Scan / Report / History   │ JSON on stdout
  history    AES-256-GCM, key in OS keystore          │ schema securityscan.findings/2
  pseudonym  random, in OS keystore                    ▼
                                  report in-app + appended to encrypted history
```

- `engine/` — vendored macOS + Windows subsets of the SecurityScan engine
  (Finding model, `checks_macos/`, `checks_windows/`, reporters) plus
  `selfcheck.py`, the OS-aware JSON-on-stdout entrypoint.
- `src-tauri/` — Rust shell. Commands: `run_scan`, `history_load`,
  `history_append`, `history_wipe`, `get_pseudonym`, `open_url`,
  `export_encrypted`, `export_pdf`.
- `frontend/` — ARGUS design system, cyan accent, CSP-locked (no inline JS,
  fonts vendored). i18n is self-contained in `app.js` (EN/ES toggle).
- `ingest/cc_ingest.py` — operator-side: decrypt a folder of `.age` exports with
  Luis's private key, aggregate v2 payloads into a self-contained ARGUS HTML
  cross-org analytics dashboard.
- `landing/` — static bilingual download page (Cloudflare Pages target).
- `scripts/` — `build-engine.sh` / `.ps1` (PyInstaller), `release-macos.sh`
  (sign + notarize), `make-icon.py`.

## Conventions / gotchas (don't relearn these the hard way)

- **Vendoring, not sharing.** Per `../CONVENTIONS.md`, engine code is vendored
  into each tool — no shared library until both tools reach v1.0. Don't try to
  import across sibling repos.
- **Trilingual findings.** Every Finding carries EN + ES + DE text (`*_es`,
  `*_de`). When adding/editing a check, fill all three or the PDF/UI coverage
  checks will flag it. UI is EN-ES only; German is PDF-on-demand only.
- **Release engine config is a separate patch file.**
  `src-tauri/tauri.release.conf.json` adds the PyInstaller binary to
  `bundle.resources`. It is kept OUT of `tauri.conf.json` on purpose: Tauri
  validates resource paths at config load, so the base config must not reference
  the not-yet-built binary or `cargo check` / `tauri dev` break. Release builds
  merge it via `--config src-tauri/tauri.release.conf.json`.
- **Dev vs release engine path.** Debug build runs `python3 -m engine.selfcheck`
  from the project root (needs `python3` + `fpdf2` on PATH). Release build runs
  the bundled `engine-dist/computer-check-engine[.exe]` — no system Python.
- **The age recipient key is PRODUCTION.** `CLAB_AGE_RECIPIENT` in
  `src-tauri/src/lib.rs` is C-LAB's real public key (since 2026-06-05). The
  private half is held offline by Luis only and is never in the repo. The old
  dev throwaway key and its identity file were removed. To rotate: see BUILD.md
  ("The C-LAB age recipient key") — keep retired identity files until their
  exports are ingested.
- **Export privacy model.** Routine export (`ComputerCheck-export.age`) excludes
  IoC/spyware-class findings and includes evidence (full diagnostics, encrypted
  to C-LAB). Urgent channel (`ComputerCheck-URGENT.age`) is consent-gated and
  includes the IoC detail. Exports carry org code + random pseudonym, never a
  real identity. Filenames are collision-safe:
  `ComputerCheck-<ORG>-<YYYYMMDD>-<pseudonym8>.age` (PDFs stay date-only —
  they're personal).
- **Windows can't be cross-compiled from macOS.** It builds on a Windows runner
  via `.github/workflows/release-windows.yml`. Signing needs repo secrets
  `WINDOWS_CERTIFICATE` (base64 .pfx) + `WINDOWS_CERTIFICATE_PASSWORD`; without
  them it builds UNSIGNED (SmartScreen).

## Build / dev quickref

```sh
npm install
npm run tauri dev          # dev loop; needs python3 + fpdf2 on PATH

# signed + notarized macOS release:
APPLE_ID="…" APPLE_PASSWORD="…" APPLE_TEAM_ID="LWSXUT3Y4S" bash scripts/release-macos.sh

# Windows: push a v* tag or run the release-windows workflow manually
```

Current version: **0.1.1** (`package.json` + `src-tauri/tauri.conf.json`).
0.1.0 shipped with the dev key and is superseded.

## Status snapshot

Phases 1–4 built + verified; Phase 5 (Windows) code-complete, needs a runner +
cert. The remaining open items and Luis-only decisions live at the bottom of
`PLAN.md` and in the current `HANDOFF.md`.
