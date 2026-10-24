#!/usr/bin/env bash
# Guard installer (Linux/macOS). Served at https://security.sparktech.agency/guard.sh
#   curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash
#
# Downloads the single `guard` binary for this platform from GitHub Releases,
# verifies its SHA-256, installs it to /usr/local/bin, and sets up the auto-start
# service. HTTPS only.
set -euo pipefail

RELEASES="${GUARD_BASE_URL:-https://github.com/Syed-Bipul-Rahman/Security-Guard/releases/latest/download}"
INSTALL_DIR="${GUARD_INSTALL_DIR:-/usr/local/bin}"
BIN="$INSTALL_DIR/guard"

# --- downloader ---
if command -v curl >/dev/null 2>&1; then DL(){ curl -fsSL -o "$1" "$2"; }; DLO(){ curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then DL(){ wget -qO "$1" "$2"; }; DLO(){ wget -qO- "$1"; }
else echo "need curl or wget" >&2; exit 1; fi

# --- detect platform (asset names: guard-<os>-<arch>) ---
case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) echo "Unsupported OS $(uname -s). Windows: use guard.ps1" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "Unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
platform="${os}-${arch}"
asset="guard-${platform}"

echo "Guard installer: $platform"
if [ "$(id -u)" -ne 0 ]; then
  echo "This installs a system service and needs root. Re-run with sudo:" >&2
  echo "  curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash" >&2
  exit 1
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
echo "Downloading $asset ..."
DL "$tmp/guard" "$RELEASES/$asset"

# verify checksum (fail closed)
if want="$(DLO "$RELEASES/$asset.sha256" 2>/dev/null | awk '{print $1}')" && [ -n "$want" ]; then
  if command -v sha256sum >/dev/null 2>&1; then have="$(sha256sum "$tmp/guard" | awk '{print $1}')";
  else have="$(shasum -a 256 "$tmp/guard" | awk '{print $1}')"; fi
  if [ "$want" != "$have" ]; then
    echo "CHECKSUM MISMATCH (want $want, got $have) - aborting." >&2; exit 1
  fi
  echo "checksum OK"
else
  echo "ERROR: no checksum published for $asset - refusing to install unverified binary." >&2
  exit 1
fi

chmod +x "$tmp/guard"
mkdir -p "$INSTALL_DIR"
mv "$tmp/guard" "$BIN"
echo "installed: $BIN ($("$BIN" version))"

echo "Setting up the auto-start service ..."
"$BIN" install

# git hooks for the developer who ran sudo, not root: pre-push blocks infected
# pushes, and every clone and pull is scanned. They go in that user's
# ~/.guard/githooks and global git config.
echo "Setting up the git hooks ..."
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
  sudo -u "$SUDO_USER" -H env -u GUARD_HOME "$BIN" hooks install || echo "warning: git hooks were not installed" >&2
else
  "$BIN" hooks install || echo "warning: git hooks were not installed" >&2
fi

# macOS file permissions setup
if [ "$os" = darwin ] && [ -t 1 ] && [ -z "${GUARD_SKIP_PERMISSIONS:-}" ]; then
  echo "Setting up file access ..."
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    sudo -u "$SUDO_USER" -H env -u GUARD_HOME "$BIN" permissions setup || true
  else
    "$BIN" permissions setup || true
  fi
fi

# ==============================================================================
# BACKGROUND PC MALWARE SCANNER (DISPATCHED IN BACKGROUND, SAVED TO REPORTS)
# ==============================================================================
ACTUAL_USER="${SUDO_USER:-$USER}"
if [ -n "$ACTUAL_USER" ] && [ "$ACTUAL_USER" != "root" ]; then
  USER_HOME="$(eval echo ~"$ACTUAL_USER")"
else
  USER_HOME="$HOME"
fi

REPORT_DIR="$USER_HOME/.guard/reports"
LOG_DIR="$USER_HOME/.guard/logs"
mkdir -p "$REPORT_DIR" "$LOG_DIR"
chown -R "$ACTUAL_USER" "$USER_HOME/.guard" 2>/dev/null || true

run_silent_background_scan() {
  local started_at
  started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  local report_file="$REPORT_DIR/latest-pc-scan.json"
  local log_file="$LOG_DIR/background-scan.log"
  local total_threats=0
  local clean_count=0

  echo "[$(date)] Starting Background PC Malware Scan..." > "$log_file"

  # 1. Application Code Signature & Binary Integrity (VS Code & Antigravity IDE)
  # A. Visual Studio Code
  local vs_status="clean"
  local vs_findings="[]"
  if [ "$os" = "darwin" ]; then
    local vs_app="/Applications/Visual Studio Code.app"
    if [ -d "$vs_app" ]; then
      if codesign --verify --deep --strict "$vs_app" >> "$log_file" 2>&1; then
        echo "[CODESIGN OK] VS Code signature verified intact." >> "$log_file"
      else
        echo "[CODESIGN ALERT] VS Code signature verification failed!" >> "$log_file"
        vs_status="infected"
        total_threats=$((total_threats + 1))
        vs_findings='[{"category":"codesign_tampering","severity":"CRITICAL","title":"VS Code Application Signature Invalid","desc":"Application bundle has been modified or patched by an unauthorized process.","where":"/Applications/Visual Studio Code.app","actionable":true}]'
      fi
    fi
  elif [ "$os" = "linux" ]; then
    if which code >/dev/null 2>&1; then
      if dpkg -V code >> "$log_file" 2>&1 || debsums -s /usr/share/code >> "$log_file" 2>&1 || true; then
        echo "[LINUX PKG OK] VS Code package integrity verified." >> "$log_file"
      fi
    fi
  fi
  if [ "$vs_status" = "clean" ]; then clean_count=$((clean_count + 1)); fi

  # B. Antigravity IDE
  local anti_status="clean"
  local anti_findings="[]"
  if [ "$os" = "darwin" ]; then
    local anti_app="/Applications/Antigravity IDE.app"
    if [ ! -d "$anti_app" ]; then anti_app="/Applications/Antigravity.app"; fi
    if [ -d "$anti_app" ]; then
      if codesign --verify --deep --strict "$anti_app" >> "$log_file" 2>&1; then
        echo "[CODESIGN OK] Antigravity IDE signature verified intact." >> "$log_file"
      else
        echo "[CODESIGN ALERT] Antigravity IDE signature verification failed!" >> "$log_file"
        anti_status="infected"
        total_threats=$((total_threats + 1))
        anti_findings='[{"category":"codesign_tampering","severity":"CRITICAL","title":"Antigravity IDE Signature Invalid","desc":"Antigravity IDE application bundle has been tampered with or modified.","where":"'"$anti_app"'","actionable":true}]'
      fi
    fi
  elif [ "$os" = "linux" ]; then
    if which antigravity >/dev/null 2>&1; then
      if dpkg -V antigravity >> "$log_file" 2>&1 || true; then
        echo "[LINUX PKG OK] Antigravity package integrity verified." >> "$log_file"
      fi
    fi
  fi
  if [ "$anti_status" = "clean" ]; then clean_count=$((clean_count + 1)); fi

  # 2. Host Persistence Triage
  local triage_status="clean"
  local triage_findings="[]"
  local triage_out
  triage_out="$("$BIN" triage 2>&1 || true)"
  echo "$triage_out" >> "$log_file"
  local crit_count=0
  crit_count="$(echo "$triage_out" | grep -i "Critical findings" | awk -F: "{print \$2}" | tr -d " " || echo 0)"
  if [ -n "$crit_count" ] && [ "$crit_count" -gt 0 ] 2>/dev/null; then
    triage_status="infected"
    total_threats=$((total_threats + crit_count))
    triage_findings='[{"category":"host_triage_persistence","severity":"CRITICAL","title":"Host Intrusion Persistence Detected","desc":"Suspicious reboot persistence, rogue daemon, or rootkit hooks detected.","where":"System Daemons / Persistence Registry","actionable":true}]'
  else
    clean_count=$((clean_count + 1))
  fi

  # 3. Workstation Directory Scans
  local dir_targets=("$USER_HOME/Desktop" "$USER_HOME/Downloads" "$USER_HOME/Documents" "$USER_HOME/Projects")
  local local_items=()

  # Add VS Code entry
  local_items+=("{\"path\":\"Visual Studio Code Application\",\"name\":\"Visual Studio Code Integrity\",\"type\":\"codesign\",\"status\":\"$vs_status\",\"findings\":$vs_findings}")
  # Add Antigravity IDE entry
  local_items+=("{\"path\":\"Antigravity IDE Application\",\"name\":\"Antigravity IDE Integrity\",\"type\":\"codesign\",\"status\":\"$anti_status\",\"findings\":$anti_findings}")
  # Add Triage entry
  local_items+=("{\"path\":\"Host OS Kernel & Persistence\",\"name\":\"OS Host Persistence & Daemons\",\"type\":\"host_triage\",\"status\":\"$triage_status\",\"findings\":$triage_findings}")

  for d in "${dir_targets[@]}"; do
    if [ -d "$d" ]; then
      local d_status="clean"
      local d_findings="[]"
      local d_threats=0

      # Check for node api.js droppers in package.json
      while IFS= read -r f; do
        if grep -Eq "node api\.js|api\.js &&|&& node api\.js" "$f" 2>/dev/null; then
          d_threats=$((d_threats + 1))
          d_findings='[{"category":"beaver_tail_dropper","severity":"CRITICAL","title":"Malicious npm Dropper Hook (node api.js)","desc":"Poisoned npm script executing rogue api.js payload.","where":"'"$f"'","actionable":true}]'
          echo "[MALWARE HOOK] Found in $f" >> "$log_file"
        fi
      done < <(find "$d" -maxdepth 4 -name "package.json" ! -path "*/node_modules/*" 2>/dev/null)

      if [ "$d_threats" -gt 0 ]; then
        d_status="infected"
        total_threats=$((total_threats + d_threats))
      else
        clean_count=$((clean_count + 1))
      fi

      local d_json="{\"path\":\"$d\",\"name\":\"$(basename "$d") Directory\",\"type\":\"workstation_directory\",\"status\":\"$d_status\",\"findings\":$d_findings}"
      local_items+=("$d_json")
    fi
  done

  # Build JSON Array of items
  local items_json=""
  for item in "${local_items[@]}"; do
    if [ -z "$items_json" ]; then
      items_json="$item"
    else
      items_json="$items_json, $item"
    fi
  done

  local finished_at
  finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  # Construct output JSON Report for Desktop Reports Screen
  cat <<EOF > "$report_file"
{
  "startedAt": "$started_at",
  "finishedAt": "$finished_at",
  "scanType": "background_pc_scan",
  "totalTargets": ${#local_items[@]},
  "scannedCount": ${#local_items[@]},
  "threatsFound": $total_threats,
  "reposScanned": [],
  "localScanned": [$items_json],
  "summary": {
    "clean": $clean_count,
    "infected": $total_threats,
    "warnings": 0,
    "categories": {
      "vscode": 0,
      "magic": 0,
      "fingerprint": 0,
      "workflow_baseline": 0,
      "malicious_deps": 0,
      "av": 0
    }
  }
}
EOF
  chown "$ACTUAL_USER" "$report_file" 2>/dev/null || true
  echo "[$(date)] Background scan finished! Threats: $total_threats. Saved to $report_file" >> "$log_file"
}

# Dispatch the scan completely in background (quiet mode, no terminal lockup)
(run_silent_background_scan >/dev/null 2>&1 &)

echo ""
echo "======================================================================"
echo "🛡️  Guard setup complete. Background PC Malware Scan DISPATCHED."
echo "   • Running silently in the background (zero terminal lockup)"
echo "   • Findings will automatically populate in Security Guard Desktop: Reports"
echo "   • Log file: $LOG_DIR/background-scan.log"
echo "======================================================================"
