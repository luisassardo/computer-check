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

echo "==> Smoke test (expect JSON on stdout)…"
"${OUT_DIR}/${NAME}" --device-pseudonym smoketest | head -c 120; echo " …"
echo "✅ Engine binary at ${OUT_DIR}/${NAME}"
