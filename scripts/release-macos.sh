#!/usr/bin/env bash
# Build the engine, then build, sign, and notarize the universal macOS app.
# Mirrors the ApiPass release flow (same Developer ID + notarytool pattern).
#
# Usage (secrets stay in your env, never committed):
#   APPLE_ID="luisassardo@me.com" \
#   APPLE_PASSWORD="xxxx-xxxx-xxxx-xxxx" \
#   APPLE_TEAM_ID="LWSXUT3Y4S" \
#   bash scripts/release-macos.sh
set -euo pipefail

: "${APPLE_ID:?set APPLE_ID (your Apple Developer email)}"
: "${APPLE_PASSWORD:?set APPLE_PASSWORD (app-specific password, not your real one)}"
: "${APPLE_TEAM_ID:?set APPLE_TEAM_ID (e.g. LWSXUT3Y4S)}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

VERSION="$(node -p "require('./package.json').version")"
DMG="src-tauri/target/universal-apple-darwin/release/bundle/dmg/ComputerCheck_${VERSION}_universal.dmg"

echo "==> ComputerCheck v${VERSION} — universal release"
rustup target add x86_64-apple-darwin aarch64-apple-darwin >/dev/null 2>&1 || true

# 1. Build the self-contained engine binary (no system Python in the shipped app).
bash scripts/build-engine.sh

# 2. Build + sign + notarize the app. The release config patch adds the engine
#    as a bundled resource; APPLE_* env makes tauri notarize the .app.
echo "==> Building + signing + notarizing the universal app…"
npx tauri build --target universal-apple-darwin --config src-tauri/tauri.release.conf.json

# 3. Notarize + staple the .dmg (retry loop: notarytool uploads can be flaky).
echo "==> Notarizing + stapling the .dmg…"
ok=0
for a in 1 2 3 4 5; do
  xcrun notarytool submit "$DMG" \
    --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" \
    --wait > /tmp/cc-notary.log 2>&1 || true
  if grep -q "status: Accepted" /tmp/cc-notary.log; then ok=1; break; fi
  echo "   notary retry ${a}…"; sleep 4
done
[ "$ok" = 1 ] || { echo "Notarization failed — see /tmp/cc-notary.log"; exit 1; }
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
spctl -a -t open --context context:primary-signature -vv "$DMG"

echo "==> Checksums…"
( cd "$(dirname "$DMG")" && shasum -a 256 "$(basename "$DMG")" > SHA256SUMS.txt && cat SHA256SUMS.txt )
echo "✅ Built, signed, notarized: $DMG"
