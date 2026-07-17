# HANDOFF — ComputerCheck

_Last updated: 2026-06-06. Snapshot for resuming work in a fresh session._
_Read alongside `CLAUDE.md` (durable memory), `PLAN.md` (phase tracker),
`BUILD.md` (build), `README.md` (product)._

## Where things stand

- **Version 0.1.1.** macOS app built + verified through Phase 4. Windows (Phase
  5) is code-complete but has never been compiled/signed — it needs a Windows
  runner and a code-signing cert.
- **Branch**: `claude/session-memory-handoff-LakSU`, currently even with
  `origin/main` plus this memory/handoff commit.
- **Last substantive work**: the ingest dashboard was rebuilt from a device list
  into a cross-org analytics view (`ingest/cc_ingest.py`, commit `6432a44`).
  Before that: production age key baked in + dev key removed (`1a31ea0`).
- **Production age key is live** in `src-tauri/src/lib.rs` (`CLAB_AGE_RECIPIENT`);
  private half offline with Luis only.

## What's done (verified)

- Phase 1: notarizable Tauri macOS app, one-click read-only scan, friendly
  report, AES-256-GCM encrypted history, EN/ES UI, trilingual (EN/ES/DE) PDF
  reports, app icon set, richer history visualizations. 23 macOS checks, all
  translated.
- Phase 2: age-encrypted export to C-LAB (routine excludes IoC; urgent channel
  consent-gated), org code + pseudonym surfaced in the export panel. Round-trip
  verified via `cargo test`.
- Phase 3: `ingest/cc_ingest.py` decrypts a folder of `.age` exports and renders
  a self-contained ARGUS cross-org analytics HTML dashboard. Verified end-to-end
  with synthetic exports. Collection model = **manual** (Proton/Signal/email →
  drop into a folder).
- Phase 4: `landing/` bilingual download page built + verified in preview;
  release publishing wired for stable download filenames.
- Phase 5 prep: 24 Windows checks vendored + translated (EN/ES/DE), OS-aware
  engine, cross-platform Rust (Windows Credential Manager keyring), Windows
  build/sign GitHub Actions workflow.

## Open / next actions

**Needs Luis to do (not code):**
1. End-to-end run of the real macOS app (`npm run tauri dev`) confirmed by Luis.
2. Pilot with a small group as a pure self-assessment tool.
3. **Run the Windows build**: push a `v*` tag (or run the workflow manually).
   Add repo secrets `WINDOWS_CERTIFICATE` (base64 .pfx) +
   `WINDOWS_CERTIFICATE_PASSWORD` for signing, else it builds UNSIGNED.
4. Smoke-test the produced Windows installer on a real Windows machine (engine
   logic only truly runs on Windows; on mac only imports + ES coverage verified).
5. Deploy `landing/` to Cloudflare Pages → `computercheck.c-lab.tools`; link from
   the C-LAB desk + network map.
6. Publish a `v*` release (mac script + push the tag for Windows CI) so the
   landing download buttons resolve.

**Open decisions (need Luis) — spec §13 / PLAN.md:**
- #1 Public name / does this own the C-LAB "Forensics" tile or its own tile?
- #4 Org-code issuance: per-org from Luis, or self-declared?
- #5 Database home for ingested data (current HTML dashboard / SQLite / D1 /
  Airtable) — the HTML is the simplest first form; a Cloudflare upload endpoint
  is a later option if volume grows.
- Resolved: #2 (EN-ES UI + on-demand German PDF), #3 (evidence included in
  routine export, sanitize toggle is a future option).

## Resuming checklist for a fresh session

1. `git status` / `git log --oneline -5` to confirm branch + latest commit.
2. Re-read `PLAN.md` bottom (open `[ ]` items) and this file.
3. For any engine check change: fill EN + ES + DE text on the Finding.
4. Don't touch `tauri.conf.json` to add the engine binary — that's
   `tauri.release.conf.json` only (see CLAUDE.md gotchas).
5. Verify before claiming done: `cargo test` (Rust/export), `npm run tauri dev`
   (app), or run `ingest/cc_ingest.py` on a sample folder.
