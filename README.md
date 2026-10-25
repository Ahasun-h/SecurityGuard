<p align="center">
  <img src="assets/icon.png" alt="Security Guard Desktop" width="140" height="140" style="border-radius: 28px; box-shadow: 0 12px 36px rgba(0, 240, 255, 0.25);"><br>
  <h1 align="center">Security Guard Desktop 🛡️</h1>
  <p align="center">
    <strong>Open-Source Cyber Defense, Host Integrity & Supply-Chain Security Operations Platform</strong><br>
    Built with Electron, Node.js & the native <code>guard</code> cybersecurity engine.
  </p>
  <p align="center">
    <a href="https://ahasun-h.github.io/SecurityGuard/"><strong>🌐 Official Distribution Website</strong></a> •
    <a href="#-downloads--installers"><strong>Downloads</strong></a> •
    <a href="#-quick-start"><strong>Quick Start</strong></a> •
    <a href="#-core-features"><strong>Features</strong></a> •
    <a href="#-how-to-build-from-source"><strong>Build</strong></a> •
    <a href="#-cli-guard-engine"><strong>Guard Engine</strong></a>
  </p>
  <p align="center">
    <a href="https://ahasun-h.github.io/SecurityGuard/"><img src="https://img.shields.io/badge/website-live%20distribution-00f0ff?style=flat-square&logo=googlechrome" alt="Distribution Webpage"></a>
    <img src="https://img.shields.io/badge/version-1.0.0-06b6d4?style=flat-square" alt="Version">
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-10b981?style=flat-square" alt="Platform">
    <img src="https://img.shields.io/badge/architecture-Apple%20Silicon%20%7C%20Intel%20%7C%20x64-6366f1?style=flat-square" alt="Arch">
    <img src="https://img.shields.io/badge/license-MIT-3b82f6?style=flat-square" alt="License">
    <img src="https://img.shields.io/badge/signatures-codesign%20%2B%20authenticode-f59e0b?style=flat-square" alt="Signatures">
  </p>
</p>

---

> [!TIP]
> **Works out of the box with zero complex configuration.**  
> Continuous background PC filesystem protection, host persistence triage, and deep repository threat hunting with full data sovereignty. Your code, credentials, and telemetry never leave your local machine.

---

## 📥 Downloads & Installers

Pre-built binaries and official packages for macOS, Windows, and Linux. Choose the installer for your operating system:

| Platform | Package Format | Architecture | Direct Download Link |
| :--- | :--- | :--- | :--- |
| 🍏 **macOS** | **`.dmg` Installer** *(Recommended)* | Apple Silicon (M1/M2/M3/M4) | [**Download `.dmg` (arm64)**](https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0-arm64.dmg) |
| 🍏 **macOS** | **`.dmg` Installer** | Intel (x64) | [**Download `.dmg` (x64)**](https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0.dmg) |
| 🍏 **macOS** | **`.zip` Standalone** | Universal | [**Download `.zip` (arm64)**](https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0-arm64-mac.zip) • [**`.zip` (x64)**](https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0-mac.zip) |
| 🪟 **Windows** | **`.exe` Setup (NSIS)** | 64-bit (x64) | [**Download Setup `.exe`**](https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard.Setup.1.0.0.exe) |
| 🪟 **Windows** | **Portable `.exe`** | 64-bit (x64) | [**Download Portable `.exe`**](https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard.1.0.0.exe) |
| 🐧 **Linux** | **`.AppImage`** *(All Distros)* | 64-bit (x64) | [**Download `.AppImage`**](https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/Security.Guard-1.0.0.AppImage) |
| 🐧 **Linux** | **`.deb` Package** *(Ubuntu/Debian)* | 64-bit (amd64) | [**Download `.deb`**](https://github.com/Ahasun-h/SecurityGuard/releases/download/v1.0.0/security-guard_1.0.0_amd64.deb) |

> [!TIP]
> ### ⚡ macOS Fast 1-Line Installer (Zero Warnings • Recommended)
> Run this single command in your Mac Terminal. It automatically downloads the latest release, installs it to your `/Applications` folder, removes any Gatekeeper quarantine flags, and launches the app with **zero warnings**:
> ```bash
> curl -fsSL https://ahasun-h.github.io/SecurityGuard/install-mac.sh | bash
> ```

> [!IMPORTANT]
> ### 🍏 macOS (Sequoia / Sonoma): Manual Installation via .DMG
> When downloading a `.dmg` using Google Chrome or Safari, macOS attaches a quarantine flag (`com.apple.quarantine`) and may display a misleading popup: *"Security Guard is damaged and can't be opened. You should move it to the Bin / Trash."* **The app is completely clean and NOT damaged.**
>
> If you installed via the `.dmg`, choose either of these fast solutions:
>
> #### ⚡ Method 1: Instant 1-Line Terminal Fix
> 1. In the popup dialog, click **Cancel** *(do NOT click "Move to Bin")*.
> 2. Open **Terminal** and run:
>    ```bash
>    xattr -cr "/Applications/Security Guard.app"
>    ```
>    *(Or run the included project script: `./fix-mac.sh` or `npm run fix:mac`)*.
> 3. Double-click **Security Guard** in your Applications folder—it will open immediately without any warning!
>
> #### 🖱️ Method 2: Finder Right-Click (Control-Click)
> 1. Open **Finder** and navigate to your **Applications** folder.
> 2. Hold down the **Control (Ctrl)** key and click (or **Right-Click**) on **`Security Guard.app`**.
> 3. Click **Open** from the context menu.
> 4. In the dialog box that appears, click **Open**. macOS will permanently save your permission.

> [!TIP]
> **Windows Users — Microsoft Defender SmartScreen ("Windows protected your PC")**:  
> Because Security Guard is a free open-source community tool without an expensive commercial EV certificate, Windows SmartScreen displays a warning upon first download.  
> **How to Install on Windows:**
> 1. In the blue/red SmartScreen dialog, click **More info** (if not already clicked).
> 2. Click **Run anyway** to launch the installer.  
> 
> *(Or Right-click `Security.Guard.Setup.1.0.0.exe` → **Properties** → check **Unblock** at the bottom → click **OK**).*

### ✨ Zero Configuration Required (Fully Automated)

> **No terminal commands required.**  
> When you install and open the **Security Guard Desktop** application:
> 1. 🛡️ **Automated Background Shield**: The continuous background filesystem watcher automatically activates.
> 2. ⚡ **Silent PC Malware Scan**: It immediately scans your workstation, host persistence hooks, and developer application signatures in the background.
> 3. 🔔 **Instant Desktop Notification**: Once the background scan finishes, you receive a native desktop notification and the full telemetry report appears directly in the **Reports** tab.

---

## 🖥️ Security Guard Server Edition (Web View & Instant Email Alerts)

A dedicated, lightweight daemon for cloud servers, VPS, and Linux hosts (Ubuntu, Debian, CentOS, RHEL, AWS EC2).

### 🌟 Key Server Capabilities:
- 🛡️ **Continuous Server Malware Shield**: Monitors `/var/www`, web applications, `/etc/cron.*`, and `/home` directories in real time for injected webshells, backdoors, reverse-shell scripts, and crypto-miners.
- 📧 **Instant Email Alerts to Server Owner**: The moment an infected file or trojan is intercepted, an alert email is dispatched immediately to the server owner with infected file paths, malware names, and direct links.
- 🌐 **Executive Web View Dashboard (`http://<SERVER_IP>:8888`)**: View live server telemetry, resource loads (CPU/RAM), threat incident logs, and trigger on-demand forensic scans directly from any web browser.
- ⚡ **1-Click Remote Neutralization**: Isolate and neutralize infected files directly from the web interface.

### ⚡ 1-Line Server Install (Auto-Starts via Systemd)
Run this single command on your Linux server:
```bash
curl -fsSL https://ahasun-h.github.io/SecurityGuard/install-server.sh | sudo bash
```
*(Or run manually in this repository: `npm run server`)*

Once installed, open `http://<YOUR_SERVER_IP>:8888` in your browser to access the Web View!

## 🚀 Quick Start

Run directly from source in development mode:

```bash
# 1. Clone repository
git clone https://github.com/Ahasun-h/SecurityGuard.git
cd SecurityGuard

# 2. Install dependencies
npm install

# 3. Launch application
npm start
```

---

## 🛡️ Core Features

### 1. ⚡ Continuous Background PC Malware Shield (Win, Mac, Linux)
- Always-on background kernel and filesystem watcher (`guard watch`) active as an auto-start system service:
  - **macOS**: Native LaunchDaemon (`me.syedbipul.guard`)
  - **Linux**: `systemd` background service (`guard.service`)
  - **Windows**: Windows Background Service & Process Monitor
- Intercepts poisoned npm/PyPI dependencies, malicious dropper scripts (`api.js`, `node api.js`), and rogue tasks in real-time.
- Automatically pushes native OS desktop notifications and feeds incidents live into the **Reports** tab.

### 2. 💽 Dedicated Local Disk & Drive Scanning
- Distinct from Git repository scans: targeted purely at physical storage drives, root volumes, user downloads, and installed applications.
- Audits local directories for injected shellcodes, reverse-shell droppers, and backdoors without cloning or counting remote Git repositories.

### 3. 🗑️ 1-Click Trojan & Malware Deletion (Move to Trash / Recycle Bin)
- When a trojan, infected `.app` bundle, or tampered developer tool is detected (e.g. `/Applications/Visual Studio Code.app`), you can excise it instantly:
  - Click **`🗑️ Delete Trojan (Move to Trash)`** directly on the threat card.
  - Safely sends the malicious payload to macOS Trash or Windows Recycle Bin using native OS APIs.
  - Automatically updates session telemetry counters and marks the threat neutralized.

### 4. 🔍 Cross-Platform Application Signature & Integrity Check
Strict cryptographic code signature and binary tamper detection for core developer tools:
- **Visual Studio Code**:
  - macOS: `codesign --verify --deep --strict "/Applications/Visual Studio Code.app"`
  - Windows: `Get-AuthenticodeSignature "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe"`
  - Linux: `dpkg -V code` or `debsums -s /usr/share/code`
- **Antigravity IDE**:
  - macOS: `codesign --verify --deep --strict "/Applications/Antigravity IDE.app"`
  - Windows: `Get-AuthenticodeSignature "$env:LOCALAPPDATA\Programs\Antigravity\Antigravity.exe"`
  - Linux: Package integrity verification & SHA-256 hash checks

### 5. 🚨 Host Persistence & Rootkit Triage (`guard triage`)
- Audits system persistence vectors across reboot hooks:
  - macOS: `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents`, and cron jobs
  - Linux: `/etc/systemd/system`, `/etc/cron.*`, and `/etc/ld.so.preload` rootkit hooks
  - Windows: Scheduled tasks, Registry Run/RunOnce keys, and WMI event persistence

### 6. 🔑 Browser-Based GitHub OAuth & Smart Session Memory
- Browser-based OAuth authorization flow or direct Personal Access Token.
- **Incremental Sync**: Caches repositories in session memory and syncs live delta changes from servers.
- **Fail-Safe Disconnect**: Logging out purges all cached tokens, repositories, and credentials.

### 7. 📦 10-Repository Batch Scanning Engine
- Scans complete portfolios in controlled **10-repo segments** with shallow temporary sandboxes.
- Prevents API rate-limiting and memory spikes, automatically compiling reports and advancing to subsequent batches.

### 8. 🤖 Multi-Model AI Threat Intelligence Copilot
- Integrates with leading AI providers:
  - **Google Gemini** (`gemini-1.5-flash`, `gemini-1.5-pro`)
  - **OpenAI** (`gpt-4o`, `gpt-4o-mini`)
  - **Anthropic Claude** (`claude-3-5-sonnet`)
  - **Ollama** (Local private models: `llama3`, `deepseek-r1`, `mistral`)
- Generates executive risk summaries, vector analyses, and copy-paste terminal excision playbooks.

---

## 🔨 How to Build From Source

You can build production distributables for all operating systems using the preconfigured `electron-builder` toolchain:

```bash
# 🍏 Build macOS .dmg & .zip (Apple Silicon & Intel)
npm run build:mac

# 🪟 Build Windows .exe (Interactive NSIS Installer & Portable)
npm run build:win

# 🐧 Build Linux .AppImage & .deb (Debian/Ubuntu)
npm run build:linux

# 🚀 Build for All Targets (Mac, Windows & Linux)
npm run build
```

All compiled releases will be stored in the `dist/` directory with native icons (`.icns`, `.ico`, `.png`).

---

## 🔬 CLI Guard Engine

The native `guard` command-line engine powers the underlying static analysis:

| Command | Action |
| :--- | :--- |
| `guard watch` | Start always-on filesystem watcher daemon |
| `guard triage` | Host incident-response triage (reboot persistence, daemons, cron) |
| `guard scan <path>` | Full tree scan for poisoned configs, droppers, and malicious dependencies |
| `guard scan-git <path>` | Audits git commit history diffs across all branches |
| `guard av scan <path>` | Antivirus heuristics with YARA rule databases |
| `guard clean <path>` | Surgically excise malware code while preserving clean project files |
| `guard hooks install` | Installs pre-push and clone interception git hooks |

---

## 🔒 Security & Privacy Statement

- **100% Local Processing**: All scan analysis, tokens, and telemetry remain strictly on your local machine.
- **Fail-Closed Verification**: Binary downloads in `guard.sh` verify cryptographically against published SHA-256 checksums before installation.
- **Ephemeral Sandbox Clones**: GitHub repositories are shallow-cloned to temporary sandboxes and wiped immediately upon inspection.

---

## 📄 License & Copyright

Copyright © 2026 **Ahasun Habib**. Licensed under the [MIT License](LICENSE).
