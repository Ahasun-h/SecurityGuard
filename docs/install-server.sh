#!/usr/bin/env bash
# ==============================================================================
# Security Guard Server Edition - Automated Linux Server Installer
# Installs background malware watcher, instant email alerts, and web dashboard.
#
# Usage:
#   curl -fsSL https://ahasun-h.github.io/SecurityGuard/install-server.sh | sudo bash
# ==============================================================================

set -euo pipefail

echo ""
echo "  ================================================================"
echo "    🛡️  SECURITY GUARD SERVER EDITION INSTALLER"
echo "  ================================================================"
echo "    Continuous Server Malware Shield & Web Forensic Dashboard"
echo "  ================================================================"
echo ""

# Ensure running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "  ❌ Error: This installer sets up a systemd service and requires root." >&2
  echo "  👉 Please re-run with sudo:" >&2
  echo "     curl -fsSL https://ahasun-h.github.io/SecurityGuard/install-server.sh | sudo bash" >&2
  exit 1
fi

INSTALL_DIR="/opt/securityguard"
SERVICE_NAME="securityguard-server"
PORT="${PORT:-8888}"

# 1. Detect Architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) GUARD_ARCH="linux-x64" ;;
  aarch64|arm64) GUARD_ARCH="linux-arm64" ;;
  *) echo "  ❌ Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

echo "  🔍 Detected Architecture: $ARCH ($GUARD_ARCH)"

# 2. Ensure Node.js is installed
if ! command -v node >/dev/null 2>&1; then
  echo "  📦 Node.js not found. Installing Node.js..."
  if command -v apt-get >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
  elif command -v yum >/dev/null 2>&1; then
    curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
    yum install -y nodejs
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nodejs
  else
    echo "  ❌ Please install Node.js 18+ manually and re-run." >&2
    exit 1
  fi
fi

echo "  ✅ Node.js $(node -v) verified."

# 3. Install Native Guard Engine
echo "  ⬇️  Installing native Guard cybersecurity engine..."
mkdir -p /usr/local/bin
GUARD_BIN_URL="https://github.com/Syed-Bipul-Rahman/Security-Guard/releases/latest/download/guard-${GUARD_ARCH}"
if curl -fsSL -o /usr/local/bin/guard "$GUARD_BIN_URL" 2>/dev/null; then
  chmod +x /usr/local/bin/guard
  echo "  ✅ Native guard engine installed at /usr/local/bin/guard ($(/usr/local/bin/guard version 2>/dev/null || echo '2.2.0'))"
else
  echo "  ⚠️  Could not download native guard binary. Server will run in high-performance Node.js watcher mode."
fi

# 4. Deploy Security Guard Server Package
echo "  📂 Deploying server dashboard to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Download latest server files from GitHub repo
REPO_URL="https://raw.githubusercontent.com/Ahasun-h/SecurityGuard/main"
mkdir -p "$INSTALL_DIR/server/public"

curl -fsSL "$REPO_URL/server/server.js" -o "$INSTALL_DIR/server/server.js"
curl -fsSL "$REPO_URL/server/mailer.js" -o "$INSTALL_DIR/server/mailer.js"
curl -fsSL "$REPO_URL/server/public/index.html" -o "$INSTALL_DIR/server/public/index.html"
curl -fsSL "$REPO_URL/server/public/styles.css" -o "$INSTALL_DIR/server/public/styles.css"
curl -fsSL "$REPO_URL/server/public/app.js" -o "$INSTALL_DIR/server/public/app.js"

# 5. Create Systemd Service
echo "  ⚙️  Configuring systemd background service ($SERVICE_NAME)..."
cat <<EOF > /etc/systemd/system/${SERVICE_NAME}.service
[Unit]
Description=Security Guard Server Edition - Malware Shield & Web Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/server
ExecStart=$(command -v node) ${INSTALL_DIR}/server/server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production
Environment=PORT=${PORT}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

# Get Primary Server IP
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "YOUR-SERVER-IP")

echo ""
echo "  ================================================================"
echo "  🎉 SECURITY GUARD SERVER INSTALLED & RUNNING!"
echo "  ================================================================"
echo ""
echo "  🌐 Web View Dashboard : http://${SERVER_IP}:${PORT}"
echo "  🛡️ Background Shield  : Active (Watching /var/www, /home, /etc)"
echo "  📧 Email Alerts       : Ready (Configure in Web View Settings)"
echo "  ⚙️ Service Command    : systemctl status ${SERVICE_NAME}"
echo ""
echo "  Open http://${SERVER_IP}:${PORT} in your browser to view your live server dashboard!"
echo "  ================================================================"
echo ""
