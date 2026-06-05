#!/usr/bin/env bash
# Build the read-only scan engine into a single self-contained binary so the
# notarized app needs NO system Python. Output lands where tauri.conf.json's
# bundle resources expects it.
#
# Run this BEFORE `npm run tauri build` (the release script does it for you).
#
# Requires: python3 with pyinstaller (pip3 install --user pyinstaller).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT_DIR="src-tauri/engine-dist"
NAME="computer-check-engine"

echo "==> Building engine binary with PyInstaller…"
rm -rf build "${OUT_DIR}" *.spec
python3 -m PyInstaller \
  --onefile \
  --name "${NAME}" \
  --distpath "${OUT_DIR}" \
  --workpath build/pyinstaller \
  --specpath build \
  --paths . \
  scripts/engine_entry.py

# macOS: the bundled engine is its own executable inside the .app, so Apple
# notarization requires IT to be Developer-ID signed with hardened runtime + a
# secure timestamp (PyInstaller only ad-hoc signs it). Sign here, before Tauri
# bundles it. Set MAC_SIGN_IDENTITY in the release script; skipped otherwise (CI/Windows).
if [ -n "${MAC_SIGN_IDENTITY:-}" ]; then
  echo "==> Signing engine binary (Developer ID + hardened runtime + timestamp)…"
  codesign --force --options runtime --timestamp \
    --entitlements scripts/engine.entitlements \
    --sign "$MAC_SIGN_IDENTITY" "${OUT_DIR}/${NAME}"
  codesign --verify --strict --verbose=2 "${OUT_DIR}/${NAME}" 2>&1 | tail -2 || true
fi

echo "==> Smoke test (expect JSON on stdout)…"
"${OUT_DIR}/${NAME}" --device-pseudonym smoketest | head -c 120; echo " …"
echo "✅ Engine binary at ${OUT_DIR}/${NAME}"
