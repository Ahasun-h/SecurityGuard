#!/usr/bin/env bash
# Security Guard - macOS Gatekeeper & Quarantine Fix Script

set -e

APP_NAME="Security Guard.app"
CANDIDATE_PATHS=(
  "/Applications/${APP_NAME}"
  "${HOME}/Applications/${APP_NAME}"
  "${HOME}/Downloads/${APP_NAME}"
  "${HOME}/Desktop/${APP_NAME}"
  "$(pwd)/dist/mac-arm64/${APP_NAME}"
  "$(pwd)/dist/mac/${APP_NAME}"
)

FOUND_PATH=""

for path in "${CANDIDATE_PATHS[@]}"; do
  if [ -d "$path" ]; then
    FOUND_PATH="$path"
    break
  fi
done

if [ -n "$1" ] && [ -d "$1" ]; then
  FOUND_PATH="$1"
fi

if [ -z "$FOUND_PATH" ]; then
  echo "⚠️  Could not find '${APP_NAME}' automatically."
  echo "👉 Please drag '${APP_NAME}' into your /Applications folder, then re-run:"
  echo "    ./fix-mac.sh"
  echo "Or specify the app path directly:"
  echo "    ./fix-mac.sh \"/path/to/${APP_NAME}\""
  exit 1
fi

echo "🔍 Found application at: ${FOUND_PATH}"
echo "🔓 Removing macOS quarantine flags (com.apple.quarantine)..."
xattr -cr "${FOUND_PATH}"

echo "✍️  Applying valid ad-hoc signature..."
codesign --force --deep --sign - "${FOUND_PATH}" 2>/dev/null || true

echo "✅ Success! macOS Gatekeeper lock removed."
echo "🚀 You can now open '${APP_NAME}' freely without 'damaged' warnings."
