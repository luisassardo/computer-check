# ComputerCheck

Read-only security self-assessment for your own computer. Part of C-LAB, in the
ARGUS network. This is **Mode B** of the SecurityScan family: a person checks
their **own** computer (macOS now, Windows planned), sees a plain-language
report, and keeps an encrypted local history to watch their security improve over
time. Nothing is sent anywhere unless the user explicitly exports and shares it.

UI is bilingual EN-ES. The PDF report can be downloaded in three languages
(English, Spanish, German) from the report view; every finding carries EN + ES +
DE text in the engine.

The operator-driven forensic USB tool (Mode A) lives in `../securityscan-usb/`
and is unchanged. Full design: `../securityscan-usb/SELFCHECK-SPEC.md`.

## Status

macOS app is built and verified (Phases 1–2). Windows is code-complete and
builds via CI (Phase 5); it needs a Windows runner to compile and a cert to sign.

- **Phase 1**: notarizable Tauri macOS app, one-click read-only scan, friendly
  report, AES-256-GCM encrypted local history (key in the system keystore).
- **Phase 2**: trilingual PDF reports (EN/ES/DE), age-encrypted export to C-LAB
  (IoC excluded), spyware urgent channel.
- **Phase 5 (prep done)**: Windows checks vendored + translated, OS-aware engine,
  cross-platform Rust, and a GitHub Actions Windows build/sign workflow.

See `PLAN.md` for the full status and `BUILD.md` to build.

## How it fits together

```
Tauri app (Rust)  ──spawn──>  engine (Python, read-only macOS checks)
   frontend: ARGUS cyan UI            │ JSON on stdout (schema securityscan.findings/2)
   history: AES-256-GCM, Keychain key │
   pseudonym: random, Keychain        ▼
                              report rendered in-app + appended to encrypted history
```

- `engine/` — vendored macOS subset of the SecurityScan engine (Finding model,
  `checks_macos/`, reporters) plus `selfcheck.py`, the JSON-on-stdout entrypoint.
  Vendored per `../CONVENTIONS.md` (no shared library until both tools hit v1.0).
- `src-tauri/` — Rust shell. Commands: `run_scan`, `history_load`,
  `history_append`, `history_wipe`, `get_pseudonym`, `open_url`.
- `frontend/` — ARGUS design system (cyan accent), three views: Scan, Report,
  History. CSP-locked, no inline, fonts vendored.
- `scripts/` — `build-engine.sh` (PyInstaller), `release-macos.sh` (sign +
  notarize, mirrors ApiPass).

## Develop

```sh
npm install
npm run tauri dev        # runs the Python engine from source (needs python3 on PATH)
```

In `tauri dev` the shell calls `python3 -m engine.selfcheck`. In a release build
it calls the bundled engine binary instead (no system Python needed).

## Release (signed + notarized)

```sh
APPLE_ID="…" APPLE_PASSWORD="…" APPLE_TEAM_ID="LWSXUT3Y4S" \
  bash scripts/release-macos.sh
```

See `BUILD.md` for the details and prerequisites.

## Sharing with C-LAB (optional)

From the report you can create an **`age`-encrypted file** to send to the C-LAB
research network. It is encrypted to C-LAB's public key, so only C-LAB can open
it and the send channel does not have to be trusted. Two paths:

- **Routine export** (`ComputerCheck-export.age`): all findings EXCEPT spyware /
  IoC indicators, plus the org code and a random device pseudonym (no real name).
- **Urgent channel** (`ComputerCheck-URGENT.age`): shown only if a spyware
  indicator is found, behind an explicit consent checkbox, and includes the
  indicator detail so the team can help fast.

Sending is always user-initiated. The recipient key lives in
`src-tauri/src/lib.rs` (`CLAB_AGE_RECIPIENT`). The committed value is a DEV
throwaway — replace it with the real C-LAB public key before any real use (see
`BUILD.md`).

## Privacy posture

- Read-only on the audited Mac. The only writes are this app's own encrypted
  history and (later) a user-chosen export file.
- History is encrypted at rest; "Wipe history" removes the file and the key.
- No analytics, no telemetry, no auto-update beacon.
