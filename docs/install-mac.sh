#!/usr/bin/env bash
# Security Guard Desktop - Automated macOS Installer
# Downloads, installs to /Applications, removes quarantine, and launches with ZERO warnings.

set -e

echo ""
echo "  🛡️  Installing Security Guard Desktop for macOS..."
echo "  -------------------------------------------------"

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
  ZIP_URL="https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0-arm64-mac.zip"
  echo "  🍏 Detected Architecture: Apple Silicon (M1/M2/M3/M4)"
else
  ZIP_URL="https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0-mac.zip"
  echo "  🍏 Detected Architecture: Intel x64"
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "  ⬇️  Downloading latest release from GitHub..."
curl -fsSL "$ZIP_URL" -o "$TMP_DIR/SecurityGuard.zip"

echo "  📦 Extracting application..."
unzip -q "$TMP_DIR/SecurityGuard.zip" -d "$TMP_DIR"

APP_PATH="$TMP_DIR/Security Guard.app"
DEST_PATH="/Applications/Security Guard.app"

if [ -d "$DEST_PATH" ]; then
  echo "  🔄 Replacing existing version in /Applications..."
  rm -rf "$DEST_PATH"
fi

echo "  📂 Moving to /Applications..."
mv "$APP_PATH" "$DEST_PATH"

echo "  🔓 Bypassing macOS Gatekeeper quarantine..."
xattr -cr "$DEST_PATH" 2>/dev/null || true
codesign --force --deep --sign - "$DEST_PATH" 2>/dev/null || true

echo "  ✅ Installation successful!"
echo "  🚀 Launching Security Guard..."
open "$DEST_PATH"
echo ""
echo "  Security Guard is now running and protecting your system! 🛡️"
echo ""
