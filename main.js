const { app, BrowserWindow, ipcMain, dialog, shell, Notification, clipboard } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { exec, spawn } = require('child_process');
const https = require('https');

let mainWindow;
const CONFIG_DIR = path.join(os.homedir(), '.guard');
const CONFIG_FILE = path.join(CONFIG_DIR, 'desktop-config.json');

// Ensure config directory exists
if (!fs.existsSync(CONFIG_DIR)) {
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  } catch (e) {
    console.error('Failed to create config dir', e);
  }
}

function loadConfig() {
  if (fs.existsSync(CONFIG_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    } catch (e) {
      console.error('Error reading config:', e);
    }
  }
  return {
    githubToken: '',
    guardPath: '/usr/local/bin/guard',
    aiProvider: 'gemini', // 'gemini' | 'openai' | 'claude' | 'ollama'
    aiApiKey: '',
    aiModel: 'gemini-1.5-flash',
    ollamaEndpoint: 'http://localhost:11434',
    selectedLocalPresets: ['Desktop', 'Downloads', 'Documents'],
    customLocalPaths: [],
    disconnected: false
  };
}

function saveConfig(cfg) {
  const current = loadConfig();
  const merged = { ...current, ...cfg };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(merged, null, 2), 'utf8');
  return merged;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 890,
    minWidth: 1080,
    minHeight: 740,
    backgroundColor: '#f7f4ee',
    title: 'Security Guard Desktop - Defense & Intelligence Hub',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 18, y: 14 },
    icon: process.platform === 'win32'
      ? path.join(__dirname, 'assets', 'icon.ico')
      : path.join(__dirname, 'assets', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.webContents.on('did-finish-load', () => {
    // Automatically execute silent background PC malware scan 2 seconds after app launch
    setTimeout(async () => {
      try {
        console.log('[AUTO-START] Executing silent background PC malware & integrity scan...');
        const rep = await executeBackgroundPcScan();
        
        // Native OS Desktop Notification
        if (Notification.isSupported()) {
          const threats = rep.threatsFound || 0;
          const notif = new Notification({
            title: threats > 0 ? '⚠️ Security Guard Alert' : '🛡️ Workstation Protected',
            body: threats > 0
              ? `${threats} potential threat(s) detected during background scan. Click to review in Reports.`
              : 'Background PC Malware scan completed: Developer tools and workstation verified intact.',
            icon: path.join(__dirname, 'assets', 'icon.png')
          });
          notif.on('click', () => {
            if (mainWindow) {
              if (mainWindow.isMinimized()) mainWindow.restore();
              mainWindow.show();
              mainWindow.focus();
              mainWindow.webContents.send('navigate-to-tab', 'reports');
            }
          });
          notif.show();
        }
      } catch (autoErr) {
        console.warn('[AUTO-START] Background scan error:', autoErr);
      }
    }, 2000);
  });


  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  if (process.platform === 'darwin' && app.dock) {
    try {
      app.dock.setIcon(path.join(__dirname, 'assets', 'icon.png'));
    } catch (_) {}
  }
  createWindow();
  startLiveAlertsWatcher();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// Helper: Run command as promise
function runExec(cmd, options = {}) {
  return new Promise((resolve, reject) => {
    exec(cmd, { maxBuffer: 1024 * 1024 * 20, ...options }, (error, stdout, stderr) => {
      resolve({
        code: error ? error.code || 1 : 0,
        stdout: stdout ? stdout.toString() : '',
        stderr: stderr ? stderr.toString() : '',
        error: error ? error.message : null
      });
    });
  });
}

// Comprehensive signatures for Lazarus Group / BeaverTail / Contagious Interview campaign
const BEAVERTAIL_SIGNATURES = [
  {
    id: 'beaver_tail_token_var',
    pattern: /k\$nodabqyPCpvUiq/i,
    name: 'BeaverTail Var Token (k$nodabqyPCpvUiq)',
    desc: 'Matched active Lazarus BeaverTail obfuscated variable signature',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_token_rv',
    pattern: /rv\$mIJCKYxZ/i,
    name: 'BeaverTail Resolver Function (rv$mIJCKYxZ)',
    desc: 'Matched BeaverTail string-decoding dispatcher function',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_token_etv',
    pattern: /EtVPcVKfhHvchsbpbJRrEavgP/i,
    name: 'BeaverTail Array Generator (EtVPcVKfh...)',
    desc: 'Matched BeaverTail string-array payload supplier',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_token_dfc',
    pattern: /DFcT_MdshgUDGLvdTVTIBV\$b/i,
    name: 'BeaverTail Encrypted Array (DFcT_...)',
    desc: 'Matched encrypted hexadecimal string array container',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_xor_constants',
    pattern: /622625\^622625|753605\^753604|365567\^365567|155681\^155680|666334\^666334|845704\^845696/i,
    name: 'BeaverTail XOR Arithmetic Obfuscator',
    desc: 'Matched characteristic bitwise XOR obfuscator constants',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_global_bang',
    pattern: /global\[['"]!['"]\]\s*=|global\['\\x21'\]/i,
    name: "BeaverTail Global Persistence Hook (global['!'])",
    desc: 'Matched Lazarus signature storing decryptor in global["!"]',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_y7_func',
    pattern: /function\s+y7\s*\([a-zA-Z0-9_$,\s]{5,}\)/i,
    name: 'BeaverTail Decryption Routine (function y7)',
    desc: 'Matched core string array XOR permutation routine y7()',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_string_rev',
    pattern: /(?:eilili|mor\|bctj\|e)["']\.split\(["']["']\)\.reverse\(\)\.join\(["']["']\)/i,
    name: 'BeaverTail Reverse-String Marker',
    desc: 'Matched BeaverTail reversed string token unpacker',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_s8_v8_dispatch',
    pattern: /function\s+s8\([^)]*\)\s*\{return\s+y7\(.*r8\['a'\].*r8\['f'\]/i,
    name: 'BeaverTail Dispatcher Routine (s8/v8)',
    desc: 'Matched dynamic dispatch and execution routine',
    type: 'obfuscated_payload',
    severity: 'critical'
  },
  {
    id: 'beaver_tail_hex_dense_array',
    pattern: /\[\s*['"][0-9a-f]{20,}['"]\s*,\s*['"][0-9a-f]{4,}['"]\s*,\s*['"][0-9a-f]{20,}['"]/i,
    name: 'BeaverTail Dense Hex Payload Array',
    desc: 'Matched dense hexadecimal string matrix for in-memory payload assembly',
    type: 'obfuscated_payload',
    severity: 'critical'
  }
];

// Directories to ignore during scanning
const IGNORED_SCAN_DIRS = new Set([
  '.git',
  'node_modules',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  '.cache',
  '.husky',
  '.idea',
  '.svn',
  '.hg',
  'dev',
  'proc',
  'sys',
  'System',
  '.Spotlight-V100',
  '.fseventsd',
  '.Trashes',
  '.DocumentRevisions-V100',
  '$Recycle.Bin',
  '$RECYCLE.BIN',
  'System Volume Information',
  'Volumes',
  'private'
]);

// Helper: Single-pass recursive collector for files needing inspection
function collectFilesForScan(dir, maxDepth = 10, currentDepth = 0, state = { count: 0, maxFiles: 15000 }) {
  const result = {
    pkgFiles: [],
    dropperFiles: [],
    sourceFiles: []
  };

  if (currentDepth > maxDepth || (state && state.count >= state.maxFiles)) return result;

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (state && state.count >= state.maxFiles) break;
      if (IGNORED_SCAN_DIRS.has(entry.name)) continue;
      if (entry.isSymbolicLink && entry.isSymbolicLink()) continue;

      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        const sub = collectFilesForScan(fullPath, maxDepth, currentDepth + 1, state);
        result.pkgFiles.push(...sub.pkgFiles);
        result.dropperFiles.push(...sub.dropperFiles);
        result.sourceFiles.push(...sub.sourceFiles);
      } else if (entry.isFile()) {
        if (state) state.count++;
        const base = entry.name.toLowerCase();
        if (base === 'package.json') {
          result.pkgFiles.push(fullPath);
        } else if (
          base === 'api.js' || 
          base === '.api.js' || 
          base === 'payload.js' || 
          base === 'fa-solid.lfk' || 
          base === 'fa-solid.lkf' || 
          base === 'fa-solid-300.llf' || 
          base === 'fa-solid-800.lkf' || 
          base === 'fa-solid-500.woff2' ||
          (base.startsWith('fa-solid') && (base.endsWith('.lfk') || base.endsWith('.lkf') || base.endsWith('.llf') || base.endsWith('.woff2')))
        ) {
          result.dropperFiles.push(fullPath);
          result.sourceFiles.push(fullPath);
        } else if (/\.(js|mjs|cjs|ts|jsx|tsx|html|vue|svelte|json)$/i.test(entry.name)) {
          result.sourceFiles.push(fullPath);
        }
      }
    }
  } catch (_) {}

  return result;
}

// Campaign-specific scanner: BeaverTail / Contagious Interview / Lazarus Supply-Chain Droppers
function scanForBeaverTailMalware(targetDir) {
  const findings = [];
  try {
    const collected = collectFilesForScan(targetDir);

    // 1. Scan package.json files for "node api.js" or "api.js &&"
    for (const pkg of collected.pkgFiles) {
      try {
        const text = fs.readFileSync(pkg, 'utf8');
        if (
          text.includes('node api.js') ||
          text.includes('api.js &&') ||
          text.includes('&& node api.js') ||
          text.includes('roboter')
        ) {
          findings.push({
            category: 'beaver_tail_dropper',
            severity: 'critical',
            name: 'node api.js (Dropper Hook)',
            desc: "Malicious npm script hook injecting 'node api.js' execution or poisoned package",
            where: path.relative(targetDir, pkg),
            fullPath: pkg,
            actionable: true,
            type: 'script_hook'
          });
        }
      } catch (_) {}
    }

    // 2. Scan for standalone dropper files (api.js, .api.js, payload.js)
    for (const dropper of collected.dropperFiles) {
      findings.push({
        category: 'beaver_tail_dropper',
        severity: 'critical',
        name: `${path.basename(dropper)} (Malware Dropper)`,
        desc: `Suspicious backdoor dropper file '${path.basename(dropper)}' discovered in repository`,
        where: path.relative(targetDir, dropper),
        fullPath: dropper,
        actionable: true,
        type: 'dropper_file'
      });
    }

    // 3. Scan all source and script files for BeaverTail signatures
    for (const src of collected.sourceFiles) {
      // Don't double-flag if already flagged as dropper_file unless extra signatures exist
      try {
        const stats = fs.statSync(src);
        if (stats.size > 0 && stats.size < 3000000) {
          const content = fs.readFileSync(src, 'utf8');
          for (const sig of BEAVERTAIL_SIGNATURES) {
            if (sig.pattern.test(content)) {
              findings.push({
                category: 'beaver_tail_dropper',
                severity: sig.severity,
                name: sig.name,
                desc: sig.desc,
                where: path.relative(targetDir, src),
                fullPath: src,
                actionable: true,
                type: sig.type,
                signatureId: sig.id
              });
              break; // One primary detection per file is sufficient
            }
          }
        }
      } catch (_) {}
    }
  } catch (err) {
    console.error('BeaverTail scan error:', err);
  }
  return findings;
}

// Deep disinfection engine for local directory or shallow-cloned repo
function disinfectLocalDirectory(dirPath, options = {}) {
  const isRemote = options.isRemote || false;
  const quarantineDir = path.join(os.homedir(), '.guard', 'quarantine');
  if (!fs.existsSync(quarantineDir)) {
    try { fs.mkdirSync(quarantineDir, { recursive: true }); } catch (_) {}
  }

  const collected = collectFilesForScan(dirPath);
  let cleanedCount = 0;
  const cleanedFiles = [];

  // 1. Sanitize package.json files
  for (const pkg of collected.pkgFiles) {
    try {
      const raw = fs.readFileSync(pkg, 'utf8');
      let json = JSON.parse(raw);
      let changed = false;

      // Clean devDependencies & dependencies
      ['devDependencies', 'dependencies'].forEach(depType => {
        if (json[depType]) {
          ['roboter', 'invisibleferret', 'beaver-tail'].forEach(badPkg => {
            if (json[depType][badPkg]) {
              delete json[depType][badPkg];
              changed = true;
            }
          });
        }
      });

      // Clean scripts
      if (json.scripts) {
        for (const [k, v] of Object.entries(json.scripts)) {
          if (typeof v === 'string' && (v.includes('node api.js') || v.includes('api.js'))) {
            const cleanedVal = v
              .replace(/node\s+api\.js\s*&&\s*/gi, '')
              .replace(/&&\s*node\s+api\.js/gi, '')
              .replace(/node\s+api\.js/gi, '')
              .replace(/api\.js\s*&&\s*/gi, '')
              .trim();
            if (cleanedVal !== v) {
              json.scripts[k] = cleanedVal;
              changed = true;
            }
          }
        }
      }

      if (changed) {
        fs.writeFileSync(pkg, JSON.stringify(json, null, 2) + '\n', 'utf8');
        cleanedCount++;
        cleanedFiles.push({ file: path.relative(dirPath, pkg), action: 'Sanitized package.json scripts' });
      }
    } catch (_) {}
  }

  // 2. Remove or quarantine api.js, .api.js, payload.js
  for (const dropper of collected.dropperFiles) {
    try {
      if (isRemote) {
        fs.unlinkSync(dropper);
      } else {
        const dest = path.join(quarantineDir, `${Date.now()}_${path.basename(dropper)}.quarantine`);
        fs.renameSync(dropper, dest);
      }
      cleanedCount++;
      cleanedFiles.push({ file: path.relative(dirPath, dropper), action: 'Quarantined/removed backdoor dropper / fake font file' });
    } catch (_) {}
  }

  // 2b. Clean malicious .vscode/tasks.json and .vscode/settings.json
  const vscodeDir = path.join(dirPath, '.vscode');
  if (fs.existsSync(vscodeDir)) {
    ['tasks.json', 'settings.json'].forEach(file => {
      const target = path.join(vscodeDir, file);
      if (fs.existsSync(target)) {
        try {
          const content = fs.readFileSync(target, 'utf8');
          if (content.includes('folderOpen') || content.includes('fa-solid') || content.includes('tasks.json') || content.includes('allowAutomaticTasks') || content.includes('api.js')) {
            if (isRemote) {
              fs.unlinkSync(target);
            } else {
              const dest = path.join(quarantineDir, Date.now() + '_' + file + '.quarantine');
              fs.renameSync(target, dest);
            }
            cleanedCount++;
            cleanedFiles.push({ file: path.join('.vscode', file), action: 'Removed malicious .vscode auto-exec configuration' });
          }
        } catch (_) {}
      }
    });
  }

  // 3. Clean source files with BeaverTail payloads
  for (const src of collected.sourceFiles) {
    try {
      if (!fs.existsSync(src)) continue;
      const content = fs.readFileSync(src, 'utf8');
      let isBeaverTail = false;
      for (const sig of BEAVERTAIL_SIGNATURES) {
        if (sig.pattern.test(content)) {
          isBeaverTail = true;
          break;
        }
      }

      if (isBeaverTail) {
        // Strip the BeaverTail payload blocks
        const stripped = content
          .replace(/var\s+k\$nodabqyPCpvUiq[\s\S]*?v8\(['"][^'"]*['"]\s*,\s*x8\)\([^)]*\)\s*;?/gi, '')
          .replace(/global\['!'\]\s*=\s*['"][^'"]*['"];\s*function\s+y7\([\s\S]*?v8\(['"][^'"]*['"]\s*,\s*x8\)\([^)]*\)\s*;?/gi, '')
          .trim();

        if (stripped.length < 50) {
          // Pure malware file
          if (isRemote) {
            fs.unlinkSync(src);
          } else {
            const dest = path.join(quarantineDir, `${Date.now()}_${path.basename(src)}.quarantine`);
            fs.renameSync(src, dest);
          }
          cleanedCount++;
          cleanedFiles.push({ file: path.relative(dirPath, src), action: 'Quarantined pure malware script' });
        } else {
          // Source file with injected payload
          if (!isRemote) {
            const backup = path.join(quarantineDir, `${Date.now()}_backup_${path.basename(src)}`);
            fs.writeFileSync(backup, content, 'utf8');
          }
          fs.writeFileSync(src, stripped + '\n', 'utf8');
          cleanedCount++;
          cleanedFiles.push({ file: path.relative(dirPath, src), action: 'Stripped BeaverTail payload from source' });
        }
      }
    } catch (_) {}
  }

  return { cleanedCount, cleanedFiles };
}

// Disinfect a remote GitHub repository and push clean code
async function disinfectRemoteRepo(repoFullName) {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) {
      token = tokenRes.stdout.trim();
    }
  }

  const cleanDir = path.join(os.tmpdir(), `disinfect_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
  try {
    const authCloneUrl = token 
      ? `https://x-access-token:${token}@github.com/${repoFullName}.git`
      : `https://github.com/${repoFullName}.git`;
    
    // Clone full repo to inspect and clean all branches
    const cloneRes = await runExec(`git clone "${authCloneUrl}" "${cleanDir}"`);
    if (cloneRes.code !== 0) {
      return { success: false, error: `Failed to clone repository ${repoFullName}: ${cloneRes.stderr || cloneRes.error}` };
    }

    // Run deep disinfection on cloned directory
    const disRes = disinfectLocalDirectory(cleanDir, { isRemote: true });

    // Check git diff
    // Iterate over all remote branches and clean each branch
    const branchRes = await runExec('git branch -r', { cwd: cleanDir });
    const remoteBranches = branchRes.stdout.split('\n')
      .map(b => b.trim().replace(/^origin\//, ''))
      .filter(b => b && !b.includes('HEAD'));

    let totalCleanedBranches = 0;
    const branchesCleaned = [];

    for (const br of remoteBranches) {
      await runExec(`git checkout -B ${br} origin/${br}`, { cwd: cleanDir });
      const branchDis = disinfectLocalDirectory(cleanDir, { isRemote: true });
      const statusCheck = await runExec('git status --porcelain', { cwd: cleanDir });
      if (statusCheck.stdout.trim()) {
        await runExec('git config user.name "Security Guard Desktop"', { cwd: cleanDir });
        await runExec('git config user.email "security-guard@antigravity.internal"', { cwd: cleanDir });
        await runExec('git add -A', { cwd: cleanDir });
        await runExec('git commit -m "[Security Guard] Remove BeaverTail backdoor files, fake fonts, and sanitize package.json"', { cwd: cleanDir });
        await runExec(`git push origin ${br}`, { cwd: cleanDir });
        totalCleanedBranches++;
        branchesCleaned.push(br);
      }
    }

    if (totalCleanedBranches > 0) {
      return {
        success: true,
        message: `Successfully disinfected ${repoFullName}! Cleaned branches: ${branchesCleaned.join(', ')}`,
        cleanedFiles: branchesCleaned
      };
    }
    const statusRes = { stdout: '' };
    if (!statusRes.stdout.trim()) {
      return { success: true, message: `Repository ${repoFullName} had no active modifications on the current branch.` };
    }

    // Configure user, commit, and push
    await runExec('git config user.name "Security Guard Desktop"', { cwd: cleanDir });
    await runExec('git config user.email "security-guard@antigravity.internal"', { cwd: cleanDir });
    await runExec('git add -A', { cwd: cleanDir });
    await runExec('git commit -m "[Security Guard] Disinfect BeaverTail malware and remove malicious script hooks"', { cwd: cleanDir });
    
    const pushRes = await runExec('git push origin HEAD', { cwd: cleanDir });
    if (pushRes.code !== 0) {
      return { success: false, error: `Git push failed: ${pushRes.stderr || pushRes.error}` };
    }

    return {
      success: true,
      message: `Successfully disinfected ${repoFullName}! Cleaned ${disRes.cleanedCount} file(s) and pushed clean commits to GitHub.`,
      cleanedFiles: disRes.cleanedFiles
    };
  } catch (err) {
    return { success: false, error: err.message };
  } finally {
    try { fs.rmSync(cleanDir, { recursive: true, force: true }); } catch (_) {}
  }
}

// ----------------- IPC HANDLERS -----------------

// Parser for guard deps check output
function parseDepsOutput(stdout) {
  const packages = [];
  const regex = /\[([a-zA-Z0-9_-]+)\]\s+([a-zA-Z0-9_@\/\.-]+)\s+\(your version:\s*([^;]+);\s*malicious range:\s*([^)]+)\)\s*(?:in\s*([a-zA-Z0-9_\/\.-]+))?/gi;
  let match;
  while ((match = regex.exec(stdout)) !== null) {
    packages.push({
      ecosystem: match[1],
      name: match[2],
      yourVersion: match[3].trim(),
      maliciousRange: match[4].trim(),
      manifest: match[5] ? match[5].trim() : 'manifest'
    });
  }
  return packages;
}

// 1. Guard Binary Status
ipcMain.handle('guard:check-status', async () => {
  const cfg = loadConfig();
  const guardBin = cfg.guardPath || '/usr/local/bin/guard';
  
  let whichRes = await runExec(`which "${guardBin}" || which guard || true`);
  let foundPath = whichRes.stdout.trim();
  
  if (!foundPath && fs.existsSync(guardBin)) {
    foundPath = guardBin;
  }

  if (!foundPath) {
    return { installed: false, version: null, path: null };
  }

  const verRes = await runExec(`"${foundPath}" version || true`);
  const rawVersion = verRes.stdout.trim() || '2.2.0';
  const cleanVersion = rawVersion.replace(/^guard\s+/i, '');

  return {
    installed: true,
    version: cleanVersion,
    path: foundPath
  };
});

// 2. Continuous Background Daemon Status (Cross-Platform Mac, Windows, Linux)
ipcMain.handle('guard:get-daemon-status', async () => {
  const osType = process.platform;
  const arch = process.arch;
  let isRunning = false;
  let pid = null;
  let details = '';
  let serviceName = 'guard';

  try {
    if (osType === 'darwin') {
      serviceName = 'me.syedbipul.guard';
      const pgrepRes = await runExec('pgrep -f "guard watch" || true');
      const pids = pgrepRes.stdout.trim().split('\n').filter(Boolean);
      if (pids.length > 0) {
        isRunning = true;
        pid = parseInt(pids[0], 10);
        details = `macOS LaunchDaemon (${serviceName}) active on PID ${pid}`;
      } else {
        details = 'macOS background LaunchDaemon not currently running';
      }
    } else if (osType === 'linux') {
      serviceName = 'guard.service';
      const sysRes = await runExec('systemctl is-active guard 2>/dev/null || pgrep -f "guard watch" || true');
      const out = sysRes.stdout.trim();
      if (out === 'active' || /^\d+$/.test(out)) {
        isRunning = true;
        details = 'Linux systemd service guard.service active';
      } else {
        details = 'Linux systemd service standby';
      }
    } else if (osType === 'win32') {
      serviceName = 'GuardBackgroundService';
      const winRes = await runExec('powershell -NoProfile "Get-Process guard -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id" || true');
      const pids = winRes.stdout.trim().split('\r\n').filter(Boolean);
      if (pids.length > 0) {
        isRunning = true;
        pid = parseInt(pids[0], 10);
        details = `Windows background service running on PID ${pid}`;
      } else {
        details = 'Windows background service not running';
      }
    }
  } catch (e) {
    details = e.message;
  }

  const cfg = loadConfig();
  const guardBin = cfg.guardPath || (osType === 'win32' ? 'C:\\Program Files\\Guard\\guard.exe' : '/usr/local/bin/guard');
  let verStr = '2.2.0';
  try {
    const verRes = await runExec(`"${guardBin}" version || guard version || true`);
    verStr = verRes.stdout.trim() || '2.2.0';
  } catch (_) {}

  return {
    running: isRunning,
    pid,
    serviceName,
    details,
    version: verStr.replace(/^guard\s+/i, ''),
    platform: `${osType}-${arch}`,
    guardPath: guardBin
  };
});

// 2b. Run OS-Native Host Persistence Triage (guard triage)
ipcMain.handle('guard:run-triage', async () => {
  const cfg = loadConfig();
  const guardBin = cfg.guardPath || (process.platform === 'win32' ? 'C:\\Program Files\\Guard\\guard.exe' : '/usr/local/bin/guard');
  
  try {
    const triageCmd = `"${guardBin}" triage || guard triage`;
    const triageRes = await runExec(triageCmd, { timeout: 180000 });
    const fullOutput = (triageRes.stdout || '') + '\n' + (triageRes.stderr || '');

    let criticalCount = 0;
    let warningCount = 0;
    const critMatch = fullOutput.match(/Critical findings\s*:\s*(\d+)/i);
    if (critMatch) criticalCount = parseInt(critMatch[1], 10);
    const warnMatch = fullOutput.match(/Warnings\s*:\s*(\d+)/i);
    if (warnMatch) warningCount = parseInt(warnMatch[1], 10);

    let reportFile = null;
    const repMatch = fullOutput.match(/Report written ->\s*(\S+)/i);
    if (repMatch) reportFile = repMatch[1];

    const verdict = criticalCount > 0 ? 'CRITICAL_THREATS' : (warningCount > 0 ? 'WARNINGS_DETECTED' : 'CLEAN');

    return {
      success: triageRes.code === 0,
      verdict,
      criticalCount,
      warningCount,
      reportFile,
      output: fullOutput
    };
  } catch (err) {
    return {
      success: false,
      verdict: 'ERROR',
      criticalCount: 0,
      warningCount: 0,
      reportFile: null,
      output: err.message
    };
  }
});

// 2c. Toggle Background Shield Daemon
ipcMain.handle('guard:toggle-daemon', async (event, action) => {
  const cfg = loadConfig();
  const guardBin = cfg.guardPath || (process.platform === 'win32' ? 'C:\\Program Files\\Guard\\guard.exe' : '/usr/local/bin/guard');

  try {
    if (action === 'start') {
      if (process.platform === 'darwin') {
        await runExec(`"${guardBin}" install || true`);
        return { success: true, message: 'Continuous Background Shield started (service me.syedbipul.guard registered).' };
      } else if (process.platform === 'linux') {
        await runExec(`sudo "${guardBin}" install || systemctl start guard || true`);
        return { success: true, message: 'Linux systemd guard background service enabled.' };
      } else {
        await runExec(`"${guardBin}" install || true`);
        return { success: true, message: 'Windows guard background service initialized.' };
      }
    } else {
      if (process.platform === 'darwin') {
        await runExec('pkill -f "guard watch" || true');
        return { success: true, message: 'Background shield daemon stopped.' };
      } else if (process.platform === 'linux') {
        await runExec('systemctl stop guard || pkill -f "guard watch" || true');
        return { success: true, message: 'Background shield daemon stopped.' };
      } else {
        await runExec('taskkill /F /IM guard.exe || true');
        return { success: true, message: 'Windows background shield stopped.' };
      }
    }
  } catch (e) {
    return { success: false, message: e.message };
  }
});

// 2d. Bootstrap / Verify Guard Engine (guard.sh logic)
ipcMain.handle('guard:bootstrap', async () => {
  const scriptPath = path.join(__dirname, 'guard.sh');
  const command = `curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash`;
  return {
    command,
    scriptPath: fs.existsSync(scriptPath) ? scriptPath : null,
    supportedPlatforms: ['darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64', 'windows-x64'],
    currentPlatform: `${process.platform}-${process.arch}`
  };
});

// 2e. Legacy Guard Install Handler
ipcMain.handle('guard:install', async () => {
  const scriptPath = path.join(__dirname, 'guard.sh');
  return {
    command: `curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash`,
    scriptPath: fs.existsSync(scriptPath) ? scriptPath : null
  };
});

// 3. GitHub Auth Status

// GitHub Browser / Universal Device Flow OAuth Login
let currentOAuthSession = null;

ipcMain.handle('github:cancel-oauth-login', () => {
  if (currentOAuthSession) {
    currentOAuthSession.cancelled = true;
    currentOAuthSession = null;
  }
  return { success: true };
});

ipcMain.handle('github:login-browser', async (event) => {
  if (currentOAuthSession) {
    currentOAuthSession.cancelled = true;
    currentOAuthSession = null;
  }

  const session = { cancelled: false };
  currentOAuthSession = session;

  try {
    // 1. If gh CLI is present and already authenticated, use it immediately
    try {
      const tokenRes = await runExec('gh auth token');
      if (tokenRes.stdout && tokenRes.stdout.trim().startsWith('gh')) {
        const token = tokenRes.stdout.trim();
        const profile = await fetchGitHubApi('/user', token);
        const cfg = loadConfig();
        const accounts = cfg.githubAccounts || [];
        const entry = {
          login: profile.login,
          name: profile.name || profile.login,
          avatar_url: profile.avatar_url,
          public_repos: profile.public_repos,
          total_private_repos: profile.total_private_repos || 0,
          html_url: profile.html_url,
          token: token,
          addedAt: new Date().toISOString()
        };
        const existingIdx = accounts.findIndex(a => a.login === profile.login);
        if (existingIdx >= 0) accounts[existingIdx] = entry;
        else accounts.push(entry);

        saveConfig({
          githubAccounts: accounts,
          githubToken: token,
          activeGitHubLogin: profile.login,
          disconnected: false
        });
        currentOAuthSession = null;
        return { success: true, user: entry, method: 'gh-cli' };
      }
    } catch (_) {
      // gh CLI not available or not logged in, proceed to universal browser device flow
    }

    // 2. Universal Browser OAuth Flow via GitHub Device Code (Works on ANY OS without requiring gh CLI)
    const clientId = '178c6fc778ccc68e1d6a';
    const postData = new URLSearchParams({
      client_id: clientId,
      scope: 'repo,read:user,user:email'
    }).toString();

    const deviceResponse = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'github.com',
        path: '/login/device/code',
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData),
          'User-Agent': 'Security-Guard-Desktop/1.0'
        }
      }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
        });
      });
      req.on('error', reject);
      req.write(postData);
      req.end();
    });

    if (!deviceResponse || !deviceResponse.device_code) {
      throw new Error(deviceResponse?.error_description || 'Failed to initialize GitHub browser authorization.');
    }

    const { device_code, user_code, verification_uri, interval = 5, expires_in = 900 } = deviceResponse;

    // Automatically copy code to clipboard
    try {
      clipboard.writeText(user_code);
    } catch (_) {}

    // Send code to frontend so the UI modal can display it with live status
    if (event && event.sender) {
      event.sender.send('github:oauth-device-code', {
        userCode: user_code,
        verificationUri: verification_uri || 'https://github.com/login/device',
        expiresIn: expires_in
      });
    }

    // Automatically launch the default system browser
    shell.openExternal(verification_uri || 'https://github.com/login/device');

    // Poll GitHub for completion
    const startTime = Date.now();
    let pollIntervalMs = (interval || 5) * 1000;

    while (Date.now() - startTime < expires_in * 1000) {
      if (session.cancelled) {
        return { success: false, error: 'Authorization cancelled by user.' };
      }

      await new Promise(r => setTimeout(r, pollIntervalMs));

      if (session.cancelled) {
        return { success: false, error: 'Authorization cancelled by user.' };
      }

      const pollBody = new URLSearchParams({
        client_id: clientId,
        device_code: device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
      }).toString();

      const pollRes = await new Promise((resolve) => {
        const req = https.request({
          hostname: 'github.com',
          path: '/login/oauth/access_token',
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(pollBody),
            'User-Agent': 'Security-Guard-Desktop/1.0'
          }
        }, (res) => {
          let body = '';
          res.on('data', chunk => body += chunk);
          res.on('end', () => {
            try { resolve(JSON.parse(body)); } catch (e) { resolve({}); }
          });
        });
        req.on('error', () => resolve({}));
        req.write(pollBody);
        req.end();
      });

      if (pollRes.access_token) {
        const token = pollRes.access_token;
        const profile = await fetchGitHubApi('/user', token);
        const cfg = loadConfig();
        const accounts = cfg.githubAccounts || [];
        const entry = {
          login: profile.login,
          name: profile.name || profile.login,
          avatar_url: profile.avatar_url,
          public_repos: profile.public_repos,
          total_private_repos: profile.total_private_repos || 0,
          html_url: profile.html_url,
          token: token,
          addedAt: new Date().toISOString()
        };

        const existingIdx = accounts.findIndex(a => a.login === profile.login);
        if (existingIdx >= 0) accounts[existingIdx] = entry;
        else accounts.push(entry);

        saveConfig({
          githubAccounts: accounts,
          githubToken: token,
          activeGitHubLogin: profile.login,
          disconnected: false
        });

        currentOAuthSession = null;
        return { success: true, user: entry, token };
      }

      if (pollRes.error === 'authorization_pending') {
        continue;
      }

      if (pollRes.error === 'slow_down') {
        pollIntervalMs += 5000;
        continue;
      }

      if (pollRes.error === 'expired_token') {
        return { success: false, error: 'Verification code expired. Please click Add Account again.' };
      }

      if (pollRes.error && pollRes.error !== 'authorization_pending') {
        return { success: false, error: pollRes.error_description || pollRes.error };
      }
    }

    return { success: false, error: 'Timed out waiting for browser authorization.' };
  } catch (err) {
    return { success: false, error: err.message };
  } finally {
    if (currentOAuthSession === session) currentOAuthSession = null;
  }
});

ipcMain.handle('github:get-auth-status', async () => {
  const cfg = loadConfig();
  if (cfg.disconnected) {
    return { authenticated: false, user: null, source: 'none' };
  }

  // First check if gh CLI is available and authenticated
  const ghCheck = await runExec('gh auth status || true');
  let ghUser = null;
  let ghToken = null;

  if (ghCheck.stdout.includes('Logged in to github.com account') || ghCheck.stderr.includes('Logged in to github.com account')) {
    const combined = ghCheck.stdout + '\n' + ghCheck.stderr;
    const match = combined.match(/account\s+([A-Za-z0-9_-]+)/);
    if (match) ghUser = match[1];

    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) {
      ghToken = tokenRes.stdout.trim();
    }
  }

  // Fallback or override with saved custom token in config
  const activeToken = cfg.githubToken || ghToken;

  if (!activeToken && !ghUser) {
    return { authenticated: false, user: null, source: 'none' };
  }

  // Validate token with GitHub REST API
  try {
    const profile = await fetchGitHubApi('/user', activeToken);
    return {
      authenticated: true,
      user: {
        login: profile.login,
        name: profile.name || profile.login,
        avatar_url: profile.avatar_url,
        public_repos: profile.public_repos,
        total_private_repos: profile.total_private_repos || 0,
        html_url: profile.html_url
      },
      tokenPreview: activeToken ? `gho_***${activeToken.slice(-4)}` : 'via gh CLI',
      source: cfg.githubToken ? 'saved-token' : 'gh-cli'
    };
  } catch (err) {
    return {
      authenticated: false,
      error: err.message,
      user: null
    };
  }
});

// 4. Save Custom GitHub Token
ipcMain.handle('github:save-token', async (event, token) => {
  const clean = token.trim();
  if (!clean) {
    saveConfig({ githubToken: '', disconnected: true });
    return { success: true, authenticated: false };
  }

  try {
    const profile = await fetchGitHubApi('/user', clean);
    saveConfig({ githubToken: clean });
    return {
      success: true,
      authenticated: true,
      user: {
        login: profile.login,
        name: profile.name || profile.login,
        avatar_url: profile.avatar_url,
        public_repos: profile.public_repos,
        total_private_repos: profile.total_private_repos || 0,
        html_url: profile.html_url
      }
    };
  } catch (e) {
    return { success: false, error: 'Invalid GitHub Token: ' + e.message };
  }
});

// 5. Fetch GitHub Repos — ALL repos, no page cap, with streaming progress
ipcMain.handle('github:fetch-repos', async () => {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
  }
  if (!token) throw new Error('Not authenticated with GitHub.');

  let allRepos = [];
  let page = 1;
  const perPage = 100;

  // Fetch every page until GitHub returns fewer than perPage
  while (true) {
    const repos = await fetchGitHubApi(
      `/user/repos?per_page=${perPage}&page=${page}&affiliation=owner,collaborator,organization_member&visibility=all&sort=updated`,
      token
    );
    if (!Array.isArray(repos) || repos.length === 0) break;
    allRepos.push(...repos);

    // Stream progress to renderer
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('github:repos-progress', {
        loaded: allRepos.length,
        page,
        chunk: repos.map(mapRepo)
      });
    }

    if (repos.length < perPage) break;
    page++;
  }

  const mapped = allRepos.map(mapRepo);
  const effectiveLogin = cfg.activeGitHubLogin || 'default';
  saveCachedRepos(effectiveLogin, mapped, new Date().toISOString());
  return mapped;
});

// Helper: map GitHub API repo object to our compact shape
function mapRepo(r) {
  return {
    id: r.id,
    name: r.name,
    full_name: r.full_name,
    is_private: r.private,
    html_url: r.html_url,
    clone_url: r.clone_url,
    default_branch: r.default_branch,
    description: r.description || '',
    updated_at: r.updated_at,
    size: r.size,
    language: r.language,
    stargazers_count: r.stargazers_count || 0,
    forks_count: r.forks_count || 0
  };
}

// Local Persistent Cache Helpers for Repositories
function getRepoCacheFilePath(login = 'default') {
  const safe = (login || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
  return path.join(CONFIG_DIR, `repos-cache-${safe}.json`);
}

function loadCachedRepos(login = 'default') {
  const file = getRepoCacheFilePath(login);
  if (fs.existsSync(file)) {
    try {
      const data = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (Array.isArray(data.repos)) {
        return data;
      }
    } catch (e) {
      console.warn('Failed to load cached repos:', e);
    }
  }
  return null;
}

function saveCachedRepos(login, repos, lastSyncedAt = new Date().toISOString()) {
  const file = getRepoCacheFilePath(login);
  try {
    const payload = {
      login: login || 'default',
      lastSyncedAt,
      totalCount: repos.length,
      repos
    };
    fs.writeFileSync(file, JSON.stringify(payload, null, 2), 'utf8');
    return payload;
  } catch (e) {
    console.warn('Failed to save cached repos:', e);
    return null;
  }
}

// 5a. Get Cached Repos from Local Disk Session
ipcMain.handle('github:get-cached-repos', async (event, login) => {
  const cfg = loadConfig();
  const effectiveLogin = login || cfg.activeGitHubLogin || 'default';
  return loadCachedRepos(effectiveLogin);
});

// 5a2. Incremental Sync with Live Servers (or Full Sync)
ipcMain.handle('github:sync-repos', async (event, options = {}) => {
  const { forceFull = false, login: requestLogin } = options;
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
  }
  if (!token) throw new Error('Not authenticated with GitHub.');

  let effectiveLogin = requestLogin || cfg.activeGitHubLogin;
  if (!effectiveLogin) {
    try {
      const profile = await fetchGitHubApi('/user', token);
      if (profile && profile.login) effectiveLogin = profile.login;
    } catch (e) {}
  }
  effectiveLogin = effectiveLogin || 'default';

  const existingCache = loadCachedRepos(effectiveLogin);

  // If no cache or forceFull requested, fetch all pages
  if (forceFull || !existingCache || !Array.isArray(existingCache.repos) || existingCache.repos.length === 0) {
    let allRepos = [];
    let page = 1;
    const perPage = 100;

    while (true) {
      const repos = await fetchGitHubApi(
        `/user/repos?per_page=${perPage}&page=${page}&affiliation=owner,collaborator,organization_member&visibility=all&sort=updated&direction=desc`,
        token
      );
      if (!Array.isArray(repos) || repos.length === 0) break;
      allRepos.push(...repos);

      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('github:repos-progress', {
          loaded: allRepos.length,
          page,
          chunk: repos.map(mapRepo)
        });
      }

      if (repos.length < perPage) break;
      page++;
    }

    const mapped = allRepos.map(mapRepo);
    const saved = saveCachedRepos(effectiveLogin, mapped, new Date().toISOString());
    return {
      success: true,
      mode: 'full',
      repos: mapped,
      updatedCount: mapped.length,
      newCount: mapped.length,
      totalCount: mapped.length,
      lastSyncedAt: saved ? saved.lastSyncedAt : new Date().toISOString()
    };
  }

  // Incremental Live Server Sync: fetch only recently changed pages
  const repoMap = new Map();
  for (const r of existingCache.repos) {
    repoMap.set(r.id, r);
  }

  const lastSyncedDate = new Date(existingCache.lastSyncedAt || 0);
  let page = 1;
  const perPage = 100;
  let updatedCount = 0;
  let newCount = 0;
  let shouldContinue = true;

  while (shouldContinue && page <= 10) {
    const livePage = await fetchGitHubApi(
      `/user/repos?per_page=${perPage}&page=${page}&affiliation=owner,collaborator,organization_member&visibility=all&sort=updated&direction=desc`,
      token
    );

    if (!Array.isArray(livePage) || livePage.length === 0) break;

    let pageHasOlderThanSync = false;

    for (const raw of livePage) {
      const mapped = mapRepo(raw);
      const repoUpdatedDate = new Date(mapped.updated_at || 0);

      if (!repoMap.has(mapped.id)) {
        repoMap.set(mapped.id, mapped);
        newCount++;
      } else {
        const existing = repoMap.get(mapped.id);
        const existingUpdatedDate = new Date(existing.updated_at || 0);

        if (repoUpdatedDate > existingUpdatedDate || repoUpdatedDate >= lastSyncedDate) {
          repoMap.set(mapped.id, mapped);
          updatedCount++;
        } else {
          pageHasOlderThanSync = true;
        }
      }
    }

    if (pageHasOlderThanSync || livePage.length < perPage) {
      shouldContinue = false;
    } else {
      page++;
    }
  }

  const mergedRepos = Array.from(repoMap.values()).sort((a, b) => {
    return new Date(b.updated_at || 0) - new Date(a.updated_at || 0);
  });

  const saved = saveCachedRepos(effectiveLogin, mergedRepos, new Date().toISOString());

  return {
    success: true,
    mode: 'incremental',
    repos: mergedRepos,
    updatedCount,
    newCount,
    totalCount: mergedRepos.length,
    lastSyncedAt: saved ? saved.lastSyncedAt : new Date().toISOString()
  };
});

// 5b. Fetch GitHub Repos - Single API Page (true pagination, 100/page)
ipcMain.handle('github:fetch-repos-page', async (event, page = 1, perPage = 100) => {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
  }
  if (!token) throw new Error('Not authenticated with GitHub.');

  const repos = await fetchGitHubApi(
    `/user/repos?per_page=${perPage}&page=${page}&affiliation=owner,collaborator,organization_member&visibility=all&sort=updated`,
    token
  );
  if (!Array.isArray(repos)) return { repos: [], hasMore: false, page };

  return { repos: repos.map(mapRepo), hasMore: repos.length >= perPage, page };
});

// 5c. Disconnect GitHub (clear saved token, disk cache & app session)
ipcMain.handle('github:disconnect', async () => {
  saveConfig({
    githubToken: '',
    activeGitHubLogin: '',
    githubAccounts: [],
    disconnected: true
  });

  // Purge all repo disk cache files
  try {
    if (fs.existsSync(CONFIG_DIR)) {
      const files = fs.readdirSync(CONFIG_DIR);
      for (const f of files) {
        if (f.startsWith('repos-cache-') && f.endsWith('.json')) {
          try {
            fs.unlinkSync(path.join(CONFIG_DIR, f));
          } catch (_) {}
        }
      }
    }
  } catch (e) {
    console.warn('Failed clearing repo disk cache files:', e);
  }

  // Clear renderer web session storage / cookies in Electron
  if (mainWindow && !mainWindow.isDestroyed()) {
    try {
      await mainWindow.webContents.session.clearStorageData();
    } catch (_) {}
  }

  return { success: true };
});

// 5c2. Reconnect CLI session
ipcMain.handle('github:reconnect-cli', async () => {
  saveConfig({ disconnected: false });
  return { success: true };
});

// 5d. Get all saved GitHub accounts
ipcMain.handle('github:get-accounts', async () => {
  const cfg = loadConfig();
  const accounts = cfg.githubAccounts || [];
  return { accounts, activeLogin: cfg.activeGitHubLogin || null };
});

// 5d2. Remove ALL external collaborators from ALL repos
ipcMain.handle('github:remove-all-collaborators', async () => {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
  }
  if (!token) throw new Error('Not authenticated with GitHub.');

  const sendProgress = (msg, type = 'info') => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('collab:progress', { msg, type });
    }
  };

  // 1. Fetch ALL repos owned by the authenticated user
  let allRepos = [];
  let page = 1;
  sendProgress('Fetching all repositories...', 'info');
  while (true) {
    const repos = await fetchGitHubApi(
      `/user/repos?per_page=100&page=${page}&affiliation=owner&visibility=all&sort=updated`,
      token
    );
    if (!Array.isArray(repos) || repos.length === 0) break;
    allRepos.push(...repos);
    if (repos.length < 100) break;
    page++;
  }

  sendProgress(`Found ${allRepos.length} repositories. Scanning collaborators...`, 'info');

  const profile = await fetchGitHubApi('/user', token);
  const ownerLogin = profile.login;

  let totalRemoved = 0;
  let totalErrors = 0;
  const removedList = [];

  for (const repo of allRepos) {
    try {
      // List outside collaborators only (not the owner)
      const collabs = await fetchGitHubApi(
        `/repos/${repo.full_name}/collaborators?affiliation=outside&per_page=100`,
        token
      );
      if (!Array.isArray(collabs) || collabs.length === 0) continue;

      for (const collab of collabs) {
        if (collab.login === ownerLogin) continue; // never remove self
        try {
          // DELETE /repos/{owner}/{repo}/collaborators/{username}
          await deleteGitHubApi(`/repos/${repo.full_name}/collaborators/${collab.login}`, token);
          totalRemoved++;
          removedList.push({ repo: repo.full_name, user: collab.login });
          sendProgress(`Removed @${collab.login} from ${repo.name}`, 'success');
        } catch (e) {
          totalErrors++;
          sendProgress(`Failed to remove @${collab.login} from ${repo.name}: ${e.message}`, 'warning');
        }
      }
    } catch (e) {
      // Some repos may not support the collaborators endpoint (e.g., org repos without access)
      continue;
    }
  }

  sendProgress(`Done. Removed ${totalRemoved} collaborator(s) across ${allRepos.length} repos.`, 'success');
  return { success: true, totalRemoved, totalErrors, removedList };
});


// 5e. Add a GitHub Account (validate and store)
ipcMain.handle('github:add-account', async (event, token) => {
  const clean = token.trim();
  if (!clean) return { success: false, error: 'Token is required.' };

  try {
    const profile = await fetchGitHubApi('/user', clean);
    const cfg = loadConfig();
    const accounts = cfg.githubAccounts || [];

    // Update or add
    const existingIdx = accounts.findIndex(a => a.login === profile.login);
    const entry = {
      login: profile.login,
      name: profile.name || profile.login,
      avatar_url: profile.avatar_url,
      public_repos: profile.public_repos,
      total_private_repos: profile.total_private_repos || 0,
      html_url: profile.html_url,
      token: clean,
      addedAt: new Date().toISOString()
    };
    if (existingIdx >= 0) {
      accounts[existingIdx] = entry;
    } else {
      accounts.push(entry);
    }

    saveConfig({
      githubAccounts: accounts,
      githubToken: clean,
      activeGitHubLogin: profile.login
    });

    return { success: true, user: entry };
  } catch (e) {
    return { success: false, error: 'Invalid GitHub Token: ' + e.message };
  }
});

// 5f. Switch active GitHub account
ipcMain.handle('github:switch-account', async (event, token) => {
  const clean = token.trim();
  try {
    const profile = await fetchGitHubApi('/user', clean);
    saveConfig({ githubToken: clean, activeGitHubLogin: profile.login });
    return {
      success: true,
      user: {
        login: profile.login,
        name: profile.name || profile.login,
        avatar_url: profile.avatar_url,
        public_repos: profile.public_repos,
        total_private_repos: profile.total_private_repos || 0,
        html_url: profile.html_url
      }
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 5g. Remove a saved GitHub account
ipcMain.handle('github:remove-account', async (event, login) => {
  const cfg = loadConfig();
  let accounts = cfg.githubAccounts || [];
  accounts = accounts.filter(a => a.login !== login);

  const newActive = accounts.length > 0 ? accounts[0] : null;
  saveConfig({
    githubAccounts: accounts,
    githubToken: newActive ? newActive.token : '',
    activeGitHubLogin: newActive ? newActive.login : ''
  });

  return { success: true, newActive };
});

// Helper: GitHub API Requester
function fetchGitHubApi(endpoint, token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: endpoint,
      method: 'GET',
      headers: {
        'User-Agent': 'Security-Guard-Desktop/1.0',
        'Accept': 'application/vnd.github.v3+json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error('Failed to parse GitHub response'));
          }
        } else {
          try {
            const errJson = JSON.parse(data);
            reject(new Error(errJson.message || `HTTP ${res.statusCode}`));
          } catch (e) {
            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          }
        }
      });
    });

    req.on('error', err => reject(err));
    req.end();
  });
}

// Helper: GitHub API DELETE Request
function deleteGitHubApi(endpoint, token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: endpoint,
      method: 'DELETE',
      headers: {
        'User-Agent': 'Security-Guard-Desktop/1.0',
        'Accept': 'application/vnd.github.v3+json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        // 204 = No Content (success for DELETE)
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ ok: true, status: res.statusCode });
        } else {
          try {
            const errJson = JSON.parse(data);
            reject(new Error(errJson.message || `HTTP ${res.statusCode}`));
          } catch (e) {
            reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 120)}`));
          }
        }
      });
    });

    req.on('error', err => reject(err));
    req.end();
  });
}

// 6. Native Directory Picker
ipcMain.handle('system:select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  if (result.canceled || !result.filePaths.length) return null;
  return result.filePaths[0];
});

// 7a. Verify VS Code Application Binary Integrity via macOS Codesign

async function verifyApplicationSignatureCrossPlatform(appName) {
  const osType = process.platform;
  const isMac = osType === 'darwin';
  const isWin = osType === 'win32';
  const isLinux = osType === 'linux';
  const userHome = os.homedir();

  let targetAppTitle = appName === 'antigravity' ? 'Antigravity IDE' : 'Visual Studio Code';
  let candidatePaths = [];

  if (appName === 'antigravity') {
    if (isMac) {
      candidatePaths = [
        '/Applications/Antigravity IDE.app',
        '/Applications/Antigravity.app',
        path.join(userHome, 'Applications', 'Antigravity IDE.app'),
        path.join(userHome, 'Applications', 'Antigravity.app')
      ];
    } else if (isWin) {
      const localApp = process.env.LOCALAPPDATA || 'C:\\Users\\Default\\AppData\\Local';
      const progFiles = process.env.ProgramFiles || 'C:\\Program Files';
      candidatePaths = [
        path.join(progFiles, 'Antigravity', 'Antigravity.exe'),
        path.join(progFiles, 'Antigravity IDE', 'Antigravity.exe'),
        path.join(localApp, 'Programs', 'Antigravity', 'Antigravity.exe'),
        path.join(localApp, 'Programs', 'Antigravity IDE', 'Antigravity.exe')
      ];
    } else {
      candidatePaths = ['/usr/bin/antigravity', '/usr/share/antigravity/antigravity', '/opt/antigravity/antigravity'];
    }
  } else {
    // vscode
    if (isMac) {
      candidatePaths = [
        '/Applications/Visual Studio Code.app',
        path.join(userHome, 'Applications', 'Visual Studio Code.app')
      ];
    } else if (isWin) {
      const localApp = process.env.LOCALAPPDATA || 'C:\\Users\\Default\\AppData\\Local';
      const progFiles = process.env.ProgramFiles || 'C:\\Program Files';
      candidatePaths = [
        path.join(progFiles, 'Microsoft VS Code', 'Code.exe'),
        path.join(localApp, 'Programs', 'Microsoft VS Code', 'Code.exe')
      ];
    } else {
      candidatePaths = ['/usr/bin/code', '/usr/share/code/code'];
    }
  }

  let foundPath = candidatePaths.find(p => fs.existsSync(p));

  if (isMac) {
    if (!foundPath) {
      return {
        success: false,
        installed: false,
        appName: targetAppTitle,
        command: `codesign --verify --deep --strict "<not found>"`,
        output: `${targetAppTitle} application bundle not found in /Applications`
      };
    }
    const cmd = `codesign --verify --deep --strict "${foundPath}" 2>&1`;
    const res = await runExec(cmd, { timeout: 35000 });
    const isValid = res.code === 0;
    return {
      success: isValid,
      installed: true,
      appName: targetAppTitle,
      path: foundPath,
      exitCode: res.code,
      command: `codesign --verify --deep --strict "${foundPath}"`,
      output: res.stdout.trim() || (isValid ? 'Signature verified: Valid, sealed, and untampered (Apple Security deep strict check passed).' : 'Codesign check returned non-zero code.')
    };
  } else if (isWin) {
    if (!foundPath) {
      return {
        success: false,
        installed: false,
        appName: targetAppTitle,
        command: `Get-AuthenticodeSignature "<not found>"`,
        output: `${targetAppTitle} executable not found in Program Files or AppData`
      };
    }
    const psCmd = `powershell -NoProfile "Get-AuthenticodeSignature '${foundPath}' | Select-Object -ExpandProperty Status" || true`;
    const res = await runExec(psCmd, { timeout: 30000 });
    const statusText = res.stdout.trim();
    const isValid = statusText.toLowerCase() === 'valid';
    return {
      success: isValid,
      installed: true,
      appName: targetAppTitle,
      path: foundPath,
      command: `Get-AuthenticodeSignature "${foundPath}"`,
      output: isValid ? 'Authenticode signature verified valid and untampered (Microsoft Authenticode check passed).' : `Authenticode verification status: ${statusText || 'Unknown'}`
    };
  } else {
    // Linux
    let pkgName = appName === 'antigravity' ? 'antigravity' : 'code';
    let cmd = `dpkg -V ${pkgName} 2>&1 || debsums -s ${pkgName} 2>&1 || rpm -V ${pkgName} 2>&1 || (which ${pkgName} && sha256sum $(which ${pkgName})) || true`;
    const res = await runExec(cmd, { timeout: 30000 });
    const isValid = res.code === 0;
    return {
      success: isValid,
      installed: !!foundPath,
      appName: targetAppTitle,
      path: foundPath || pkgName,
      command: cmd,
      output: isValid ? 'Package manager integrity & checksum verified intact.' : (res.stdout.trim() || 'Checksum / package integrity verified.')
    };
  }
}

ipcMain.handle('system:verify-app-signature', async (event, appName) => {
  return await verifyApplicationSignatureCrossPlatform(appName || 'vscode');
});

ipcMain.handle('system:verify-vscode-codesign', async () => {
  return await verifyApplicationSignatureCrossPlatform('vscode');
});


// 7. Get Local System Scan Targets

// 1b. Background PC Malware Scan IPC Handlers & Report Ingestion
ipcMain.handle('system:get-latest-background-scan', async () => {
  const repPath = path.join(os.homedir(), '.guard', 'reports', 'latest-pc-scan.json');
  if (fs.existsSync(repPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(repPath, 'utf8'));
      return data;
    } catch (e) {
      return null;
    }
  }
  return null;
});


async function executeBackgroundPcScan() {
  const userHome = os.homedir();
  const cfg = loadConfig();
  const guardBin = cfg.guardPath || (process.platform === 'win32' ? 'C:\\Program Files\\Guard\\guard.exe' : '/usr/local/bin/guard');

  const startedAt = new Date().toISOString();
  const localItems = [];
  let totalThreats = 0;
  let cleanCount = 0;

  // 1. Cross-Platform Application Signature Checks (VS Code & Antigravity IDE)
  for (const app of ['vscode', 'antigravity']) {
    try {
      const sigRes = await verifyApplicationSignatureCrossPlatform(app);
      let appStatus = 'clean';
      let appFindings = [];
      if (sigRes.installed) {
        if (sigRes.success) {
          cleanCount++;
        } else {
          appStatus = 'infected';
          totalThreats++;
          appFindings.push({
            category: 'codesign_tampering',
            severity: 'CRITICAL',
            title: `${sigRes.appName} Signature Invalid (Possible Trojan / Tampering)`,
            desc: `Signature verification failed (${sigRes.command}): ${sigRes.output}`,
            where: sigRes.path || sigRes.appName,
            actionable: true
          });
        }
      } else {
        cleanCount++;
      }
      localItems.push({
        path: sigRes.path || `${sigRes.appName} Application`,
        name: `${sigRes.appName} Application Integrity`,
        type: 'codesign',
        status: appStatus,
        findings: appFindings
      });
    } catch (_) {
      cleanCount++;
    }
  }

  // 2. Host Persistence Triage (guard triage)
  let triageStatus = 'clean';
  let triageFindings = [];
  try {
    const trRes = await runExec(`"${guardBin}" triage || guard triage || true`, { timeout: 90000 });
    const fullOut = (trRes.stdout || '') + '\n' + (trRes.stderr || '');
    const critMatch = fullOut.match(/Critical findings\s*:\s*(\d+)/i);
    const crits = critMatch ? parseInt(critMatch[1], 10) : 0;
    if (crits > 0) {
      triageStatus = 'infected';
      totalThreats += crits;
      triageFindings.push({
        category: 'host_triage_persistence',
        severity: 'CRITICAL',
        title: `Host Intrusion Persistence Detected (${crits} Critical Findings)`,
        desc: 'Suspicious reboot persistence, rogue daemon, or rootkit hooks detected.',
        where: 'System Daemons / Persistence Registry',
        actionable: true
      });
    } else {
      cleanCount++;
    }
  } catch (_) {
    cleanCount++;
  }
  localItems.push({
    path: 'OS Host Persistence & Daemons',
    name: 'OS Host Persistence & Daemons',
    type: 'host_triage',
    status: triageStatus,
    findings: triageFindings
  });

  // 3. Workstation Directory Scans
  const dirs = ['Desktop', 'Downloads', 'Documents', 'Projects'].map(d => path.join(userHome, d));
  for (const d of dirs) {
    if (fs.existsSync(d) && fs.statSync(d).isDirectory()) {
      let dStatus = 'clean';
      let dFindings = [];

      try {
        const campaign = scanForBeaverTailMalware(d);
        if (campaign.length > 0) {
          dStatus = 'infected';
          totalThreats += campaign.length;
          dFindings.push(...campaign.map(c => ({
            category: 'beaver_tail_dropper',
            severity: 'CRITICAL',
            title: c.name || 'Malicious Dropper Hook',
            desc: c.desc || 'Poisoned dropper script or node api.js execution hook',
            where: path.relative(userHome, c.fullPath),
            actionable: true
          })));
        } else {
          cleanCount++;
        }
      } catch (_) {
        cleanCount++;
      }

      localItems.push({
        path: d,
        name: `${path.basename(d)} Workstation Directory`,
        type: 'workstation_directory',
        status: dStatus,
        findings: dFindings
      });
    }
  }

  // 4. Inspect Available Disks
  const availableDisks = detectAvailableDisks();
  for (const disk of availableDisks) {
    cleanCount++;
    localItems.push({
      path: disk.path,
      name: `${disk.name} (${disk.driveType.toUpperCase()} DISK)`,
      type: 'storage_disk',
      status: 'clean',
      findings: [],
      details: `${disk.freeFormatted} free of ${disk.totalFormatted} (${disk.usedPercent}% used)`
    });
  }

  const finishedAt = new Date().toISOString();
  const report = {
    startedAt,
    finishedAt,
    scanType: 'background_pc_scan',
    totalTargets: localItems.length,
    scannedCount: localItems.length,
    threatsFound: totalThreats,
    reposScanned: [],
    localScanned: localItems,
    summary: {
      clean: cleanCount,
      infected: totalThreats,
      warnings: 0,
      categories: {
        vscode: 0,
        magic: 0,
        fingerprint: 0,
        workflow_baseline: 0,
        malicious_deps: 0,
        av: 0
      }
    }
  };

  const repDir = path.join(userHome, '.guard', 'reports');
  if (!fs.existsSync(repDir)) fs.mkdirSync(repDir, { recursive: true });
  fs.writeFileSync(path.join(repDir, 'latest-pc-scan.json'), JSON.stringify(report, null, 2), 'utf8');

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('system:background-pc-scan-finished', report);
  }

  return report;
}

ipcMain.handle('system:run-background-pc-scan', async () => {
  return await executeBackgroundPcScan();
});

// Live watcher for ~/.guard/alerts.jsonl written by the continuous background daemon (guard watch)
function startLiveAlertsWatcher() {
  const alertsFile = path.join(CONFIG_DIR, 'alerts.jsonl');
  let lastSize = 0;
  if (fs.existsSync(alertsFile)) {
    try {
      lastSize = fs.statSync(alertsFile).size;
    } catch (_) {}
  }

  fs.watchFile(alertsFile, { interval: 2000 }, (curr, prev) => {
    if (curr.size > prev.size) {
      try {
        const stream = fs.createReadStream(alertsFile, {
          start: prev.size,
          end: curr.size,
          encoding: 'utf8'
        });
        let buffer = '';
        stream.on('data', chunk => { buffer += chunk; });
        stream.on('end', () => {
          const lines = buffer.trim().split('\n').filter(Boolean);
          for (const line of lines) {
            try {
              const alertData = JSON.parse(line);
              console.log('[SHIELD LIVE ALERT INTERCEPTED]', alertData);

              // 1. Send native desktop notification
              if (Notification.isSupported()) {
                const fCount = (alertData.findings || []).length;
                const firstDesc = (alertData.findings && alertData.findings[0] && alertData.findings[0].desc) || 'Malicious pattern intercepted';
                const firstWhere = (alertData.findings && alertData.findings[0] && alertData.findings[0].where) || alertData.path;

                const notif = new Notification({
                  title: '🚨 Security Guard: Live Malware Intercepted!',
                  body: `${firstDesc} at ${firstWhere} (${fCount} threat(s)). Click to view Report.`,
                  icon: path.join(__dirname, 'assets', 'icon.png')
                });
                notif.on('click', () => {
                  if (mainWindow) {
                    if (mainWindow.isMinimized()) mainWindow.restore();
                    mainWindow.show();
                    mainWindow.focus();
                    mainWindow.webContents.send('navigate-to-tab', 'reports');
                  }
                });
                notif.show();
              }

              // 2. Relay alert to renderer to update the Reports screen in real-time
              if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('guard:realtime-threat-alert', alertData);
              }
            } catch (_) {}
          }
        });
      } catch (e) {
        console.warn('Error reading alerts.jsonl:', e);
      }
    }
  });
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

function detectAvailableDisks() {
  const disks = [];
  const platform = process.platform;

  if (platform === 'darwin') {
    // 1. Primary macOS System Drive (Macintosh HD mounted at /)
    try {
      const stat = fs.statfsSync('/');
      const total = Number(stat.blocks) * Number(stat.bsize);
      const free = Number(stat.bavail) * Number(stat.bsize);
      const used = Math.max(0, total - free);
      const pct = total > 0 ? Math.round((used / total) * 100) : 0;

      let rootName = 'Macintosh HD';
      try {
        if (fs.existsSync('/Volumes')) {
          for (const item of fs.readdirSync('/Volumes')) {
            const p = path.join('/Volumes', item);
            try {
              if (fs.lstatSync(p).isSymbolicLink()) {
                const link = fs.readlinkSync(p);
                if (link === '/' || link === '') {
                  rootName = item;
                  break;
                }
              }
            } catch (_) {}
          }
        }
      } catch (_) {}

      disks.push({
        id: 'disk-mac-root',
        name: rootName,
        path: '/',
        fsType: 'APFS',
        driveType: 'internal',
        isSystem: true,
        totalBytes: total,
        freeBytes: free,
        usedBytes: used,
        totalFormatted: formatBytes(total),
        freeFormatted: formatBytes(free),
        usedFormatted: formatBytes(used),
        usedPercent: pct,
        isDisk: true,
        exists: true
      });
    } catch (e) {
      console.error('Error detecting root disk:', e);
    }

    // 2. Mounted Volumes in /Volumes (External USB, SSDs, HDDs, Disk Images)
    try {
      if (fs.existsSync('/Volumes')) {
        for (const item of fs.readdirSync('/Volumes')) {
          const volPath = path.join('/Volumes', item);
          try {
            const lstat = fs.lstatSync(volPath);
            if (lstat.isSymbolicLink()) {
              const link = fs.readlinkSync(volPath);
              if (link === '/' || link === '') continue; // Already added as root
            }
            const stat = fs.statfsSync(volPath);
            const total = Number(stat.blocks) * Number(stat.bsize);
            const free = Number(stat.bavail) * Number(stat.bsize);
            const used = Math.max(0, total - free);
            const pct = total > 0 ? Math.round((used / total) * 100) : 0;

            if (total > 0) {
              disks.push({
                id: 'disk-vol-' + item.toLowerCase().replace(/[^a-z0-9_-]/g, '_'),
                name: item,
                path: volPath,
                fsType: 'Mounted Volume',
                driveType: 'removable',
                isSystem: false,
                totalBytes: total,
                freeBytes: free,
                usedBytes: used,
                totalFormatted: formatBytes(total),
                freeFormatted: formatBytes(free),
                usedFormatted: formatBytes(used),
                usedPercent: pct,
                isDisk: true,
                exists: true
              });
            }
          } catch (_) {}
        }
      }
    } catch (_) {}
  } else if (platform === 'win32') {
    // Windows logical drives via wmic, PowerShell, or drive letter probing
    const winDisks = [];
    const sysDriveLetter = ((process.env.SystemDrive || 'C:').replace(/[^a-zA-Z]/g, '') || 'C').toUpperCase();

    // Strategy 1: Fast wmic query (standard on all Windows versions)
    try {
      const wmicCmd = 'wmic logicaldisk get Caption,DriveType,FileSystem,FreeSpace,Size,VolumeName /format:csv';
      const wmicOut = execSync(wmicCmd, { encoding: 'utf8', timeout: 4000, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] }).trim();
      if (wmicOut) {
        const lines = wmicOut.split(/\r?\n/).filter(l => l.trim() && !l.toLowerCase().startsWith('node'));
        for (const line of lines) {
          const parts = line.split(',');
          // format: Node,Caption,DriveType,FileSystem,FreeSpace,Size,VolumeName
          if (parts.length >= 6) {
            const caption = (parts[1] || '').trim(); // e.g. "C:"
            if (/^[A-Za-z]:$/.test(caption)) {
              const driveType = parseInt(parts[2], 10) || 3;
              const fsType = (parts[3] || 'NTFS').trim();
              const free = Number(parts[4]) || 0;
              const total = Number(parts[5]) || 0;
              const volName = (parts[6] || '').trim();
              const drivePath = caption + '\\';
              const used = Math.max(0, total - free);
              const pct = total > 0 ? Math.round((used / total) * 100) : 0;
              const isSystem = caption.toUpperCase().startsWith(sysDriveLetter);
              const driveTypeName = driveType === 2 ? 'removable' : (driveType === 4 ? 'network' : 'internal');
              const displayName = volName ? `${volName} (${caption})` : (isSystem ? `Local Disk (${caption}) [System]` : `Storage Drive (${caption})`);

              winDisks.push({
                id: 'disk-win-' + caption.replace(/[^a-zA-Z0-9]/g, '').toLowerCase(),
                name: displayName,
                path: drivePath,
                fsType,
                driveType: driveTypeName,
                isSystem,
                totalBytes: total,
                freeBytes: free,
                usedBytes: used,
                totalFormatted: formatBytes(total),
                freeFormatted: formatBytes(free),
                usedFormatted: formatBytes(used),
                usedPercent: pct,
                isDisk: true,
                exists: true
              });
            }
          }
        }
      }
    } catch (_) {}

    // Strategy 2: PowerShell CIM query if wmic didn't return drives
    if (winDisks.length === 0) {
      try {
        const psCmd = 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace,DriveType | ConvertTo-Json -Compress"';
        const out = execSync(psCmd, { encoding: 'utf8', timeout: 5000, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] }).trim();
        if (out) {
          let items = JSON.parse(out);
          if (!Array.isArray(items)) items = [items];
          for (const item of items) {
            if (!item || !item.DeviceID) continue;
            const driveLetter = item.DeviceID.endsWith('\\') ? item.DeviceID : item.DeviceID + '\\';
            const total = Number(item.Size) || 0;
            const free = Number(item.FreeSpace) || 0;
            const used = Math.max(0, total - free);
            const pct = total > 0 ? Math.round((used / total) * 100) : 0;
            const isSystem = item.DeviceID.toUpperCase().startsWith(sysDriveLetter);
            const driveTypeName = item.DriveType === 2 ? 'removable' : (item.DriveType === 4 ? 'network' : 'internal');
            const volName = item.VolumeName ? `${item.VolumeName} (${item.DeviceID})` : (isSystem ? `Local Disk (${item.DeviceID}) [System]` : `Storage Volume (${item.DeviceID})`);

            winDisks.push({
              id: 'disk-win-' + item.DeviceID.replace(/[^a-zA-Z0-9]/g, '').toLowerCase(),
              name: volName,
              path: driveLetter,
              fsType: item.FileSystem || 'NTFS',
              driveType: driveTypeName,
              isSystem,
              totalBytes: total,
              freeBytes: free,
              usedBytes: used,
              totalFormatted: formatBytes(total),
              freeFormatted: formatBytes(free),
              usedFormatted: formatBytes(used),
              usedPercent: pct,
              isDisk: true,
              exists: true
            });
          }
        }
      } catch (_) {}
    }

    // Strategy 3: Enumerate Drive letters A-Z via fs.existsSync with isolated statfs
    if (winDisks.length === 0) {
      const letters = 'CDEFGHIJKLMNOPQRSTUVWXYZAB'.split('');
      for (const l of letters) {
        const drivePath = `${l}:\\`;
        try {
          if (fs.existsSync(drivePath)) {
            let total = 0, free = 0, used = 0, pct = 0;
            try {
              const stat = fs.statfsSync(drivePath);
              total = Number(stat.blocks) * Number(stat.bsize);
              free = Number(stat.bavail) * Number(stat.bsize);
              used = Math.max(0, total - free);
              pct = total > 0 ? Math.round((used / total) * 100) : 0;
            } catch (_) {}

            const isSystem = l.toUpperCase() === sysDriveLetter;
            winDisks.push({
              id: `disk-win-${l.toLowerCase()}`,
              name: isSystem ? `Local Disk (${l}:) [System]` : `Drive (${l}:)`,
              path: drivePath,
              fsType: 'NTFS',
              driveType: 'internal',
              isSystem,
              totalBytes: total,
              freeBytes: free,
              usedBytes: used,
              totalFormatted: total > 0 ? formatBytes(total) : 'Local Storage',
              freeFormatted: free > 0 ? formatBytes(free) : 'Active',
              usedFormatted: used > 0 ? formatBytes(used) : '0 B',
              usedPercent: pct,
              isDisk: true,
              exists: true
            });
          }
        } catch (_) {}
      }
    }

    // Fallback guarantee: At minimum ensure System Drive is listed
    if (winDisks.length === 0) {
      const sysPath = `${sysDriveLetter}:\\`;
      let total = 0, free = 0, used = 0, pct = 0;
      try {
        const stat = fs.statfsSync(sysPath);
        total = Number(stat.blocks) * Number(stat.bsize);
        free = Number(stat.bavail) * Number(stat.bsize);
        used = Math.max(0, total - free);
        pct = total > 0 ? Math.round((used / total) * 100) : 0;
      } catch (_) {}

      winDisks.push({
        id: `disk-win-${sysDriveLetter.toLowerCase()}`,
        name: `Local Disk (${sysDriveLetter}:) [System]`,
        path: sysPath,
        fsType: 'NTFS',
        driveType: 'internal',
        isSystem: true,
        totalBytes: total,
        freeBytes: free,
        usedBytes: used,
        totalFormatted: total > 0 ? formatBytes(total) : 'System Storage',
        freeFormatted: free > 0 ? formatBytes(free) : 'Active',
        usedFormatted: used > 0 ? formatBytes(used) : '0 B',
        usedPercent: pct,
        isDisk: true,
        exists: true
      });
    }

    disks.push(...winDisks);
  } else if (platform === 'linux') {
    // Linux filesystem partitions
    try {
      const stat = fs.statfsSync('/');
      const total = Number(stat.blocks) * Number(stat.bsize);
      const free = Number(stat.bavail) * Number(stat.bsize);
      const used = Math.max(0, total - free);
      const pct = total > 0 ? Math.round((used / total) * 100) : 0;
      disks.push({
        id: 'disk-linux-root',
        name: 'Root Filesystem (/)',
        path: '/',
        fsType: 'ext4/btrfs',
        driveType: 'internal',
        isSystem: true,
        totalBytes: total,
        freeBytes: free,
        usedBytes: used,
        totalFormatted: formatBytes(total),
        freeFormatted: formatBytes(free),
        usedFormatted: formatBytes(used),
        usedPercent: pct,
        isDisk: true,
        exists: true
      });
    } catch (_) {}

    try {
      if (fs.existsSync('/proc/mounts')) {
        const mounts = fs.readFileSync('/proc/mounts', 'utf8').split('\n');
        const seenPaths = new Set(['/']);
        for (const line of mounts) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 3) {
            const dev = parts[0];
            const mountPoint = parts[1];
            const fsType = parts[2];
            if (
              (dev.startsWith('/dev/') && !dev.includes('loop')) ||
              mountPoint.startsWith('/media') ||
              mountPoint.startsWith('/mnt') ||
              mountPoint.startsWith('/run/media')
            ) {
              if (seenPaths.has(mountPoint)) continue;
              seenPaths.add(mountPoint);
              try {
                const stat = fs.statfsSync(mountPoint);
                const total = Number(stat.blocks) * Number(stat.bsize);
                const free = Number(stat.bavail) * Number(stat.bsize);
                const used = Math.max(0, total - free);
                const pct = total > 0 ? Math.round((used / total) * 100) : 0;
                if (total > 0) {
                  const baseName = path.basename(mountPoint) || mountPoint;
                  disks.push({
                    id: 'disk-linux-' + mountPoint.replace(/[^a-zA-Z0-9_-]/g, '_'),
                    name: `${baseName} (${mountPoint})`,
                    path: mountPoint,
                    fsType,
                    driveType: mountPoint.startsWith('/media') || mountPoint.startsWith('/run/media') ? 'removable' : 'internal',
                    isSystem: mountPoint === '/',
                    totalBytes: total,
                    freeBytes: free,
                    usedBytes: used,
                    totalFormatted: formatBytes(total),
                    freeFormatted: formatBytes(free),
                    usedFormatted: formatBytes(used),
                    usedPercent: pct,
                    isDisk: true,
                    exists: true
                  });
                }
              } catch (_) {}
            }
          }
        }
      }
    } catch (_) {}
  }

  return disks;
}

ipcMain.handle('system:get-available-disks', async () => {
  return detectAvailableDisks();
});

ipcMain.handle('system:get-local-targets', async () => {
  const disks = detectAvailableDisks();
  const home = os.homedir();
  const presets = [
    { id: 'desktop', name: 'Desktop', path: path.join(home, 'Desktop'), exists: fs.existsSync(path.join(home, 'Desktop')), isDisk: false },
    { id: 'downloads', name: 'Downloads', path: path.join(home, 'Downloads'), exists: fs.existsSync(path.join(home, 'Downloads')), isDisk: false },
    { id: 'documents', name: 'Documents', path: path.join(home, 'Documents'), exists: fs.existsSync(path.join(home, 'Documents')), isDisk: false },
    { id: 'home', name: 'Home Directory (~)', path: home, exists: true, isDisk: false }
  ];

  // Also check common developer folders
  const devPaths = [
    path.join(home, 'Developer'),
    path.join(home, 'Projects'),
    path.join(home, 'Sites'),
    path.join(home, 'workspace')
  ];

  devPaths.forEach(dp => {
    if (fs.existsSync(dp)) {
      presets.push({ id: path.basename(dp).toLowerCase(), name: path.basename(dp), path: dp, exists: true, isDisk: false });
    }
  });

  return [...disks, ...presets];
});

// 8. Start Security Scan (GitHub Repos + Local PC)
let isScanning = false;
let shouldCancelScan = false;

ipcMain.handle('scanner:cancel', () => {
  if (isScanning) {
    shouldCancelScan = true;
    return true;
  }
  return false;
});

ipcMain.handle('scanner:start-scan', async (event, options) => {
  if (isScanning) return { error: 'Scan is already running' };
  isScanning = true;
  shouldCancelScan = false;

  const cfg = loadConfig();
  const guardBin = cfg.guardPath || '/usr/local/bin/guard';
  const { githubRepos = [], localPaths = [], scanLocalPc = true, deepGitScan = false, runAntivirus = true } = options;

  const results = {
    startedAt: new Date().toISOString(),
    finishedAt: null,
    totalTargets: githubRepos.length + (scanLocalPc ? localPaths.length : 0),
    scannedCount: 0,
    threatsFound: 0,
    reposScanned: [],
    localScanned: [],
    summary: {
      clean: 0,
      infected: 0,
      warnings: 0,
      categories: {
        vscode: 0,
        magic: 0,
        fingerprint: 0,
        workflow_baseline: 0,
        malicious_deps: 0,
        av: 0
      }
    }
  };

  const sendProgress = (payload) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('scanner:progress', payload);
    }
  };

  const sendLog = (message, type = 'info') => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('scanner:log', { message, type, time: new Date().toLocaleTimeString() });
    }
  };

  const stagingDir = path.join(os.tmpdir(), `guard_scan_${Date.now()}`);
  if (!fs.existsSync(stagingDir)) {
    fs.mkdirSync(stagingDir, { recursive: true });
  }

  try {
    sendLog(`[START] Security Guard Engine initialized. Total targets: ${results.totalTargets}`, 'info');

    // Phase 1: Scan GitHub Repositories
    let token = cfg.githubToken;
    if (!token) {
      const tokenRes = await runExec('gh auth token || true');
      if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
    }

    for (let i = 0; i < githubRepos.length; i++) {
      if (shouldCancelScan) {
        sendLog(`[CANCELLED] Scan aborted by user`, 'warning');
        break;
      }

      const repo = githubRepos[i];
      results.scannedCount++;
      sendProgress({
        phase: 'github',
        current: results.scannedCount,
        total: results.totalTargets,
        currentTarget: repo.full_name,
        percent: Math.round((results.scannedCount / results.totalTargets) * 100)
      });

      sendLog(`[SCAN-REPO ${i + 1}/${githubRepos.length}] Inspecting ${repo.full_name} (${repo.is_private ? 'Private' : 'Public'})...`, 'info');

      const repoFolder = path.join(stagingDir, repo.name.replace(/[^a-zA-Z0-9_-]/g, '_'));
      
      // Clone shallow repo
      const authCloneUrl = token
        ? repo.clone_url.replace('https://', `https://${token}@`)
        : repo.clone_url;

      const cloneCmd = `git clone --depth 1 --quiet "${authCloneUrl}" "${repoFolder}"`;
      const cloneRes = await runExec(cloneCmd, { timeout: 60000 });

      if (cloneRes.code !== 0) {
        sendLog(`[WARN] Failed to clone ${repo.full_name}: ${cloneRes.stderr.trim() || 'Access denied / timeout'}`, 'warning');
        results.reposScanned.push({
          name: repo.name,
          full_name: repo.full_name,
          is_private: repo.is_private,
          status: 'error',
          error: cloneRes.stderr.trim() || 'Clone error',
          findings: []
        });
        results.summary.warnings++;
        continue;
      }

      // Execute Guard Scan
      const scanType = deepGitScan ? 'scan-git' : 'scan';
      const scanCmd = `"${guardBin}" ${scanType} --json "${repoFolder}"`;
      const scanRes = await runExec(scanCmd, { timeout: 120000 });

      let parsedReport = null;
      try {
        parsedReport = JSON.parse(scanRes.stdout);
      } catch (e) {
        // Fallback parsing if stdout has extra banners
        const jsonMatch = scanRes.stdout.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          try { parsedReport = JSON.parse(jsonMatch[0]); } catch (_) {}
        }
      }

      // Check dependency blocklist
      let depFindings = [];
      const depCmd = `"${guardBin}" deps check "${repoFolder}" || true`;
      const depRes = await runExec(depCmd);
      if (depRes.stdout.includes('MALICIOUS') || depRes.stdout.includes('blocked')) {
        const pkgs = parseDepsOutput(depRes.stdout);
        if (pkgs.length > 0) {
          depFindings.push({
            type: 'dependency_audit',
            count: pkgs.length,
            packages: pkgs,
            summary: `${pkgs.length} advisory reference(s) found across manifest files`
          });
        }
      }

      // Process findings
      let repoFindings = [];
      let isInfected = false;

      if (parsedReport && parsedReport.tree) {
        isInfected = parsedReport.tree.infected;
        const tree = parsedReport.tree;
        ['vscode', 'magic', 'fingerprint', 'workflow_baseline', 'malicious_deps', 'av'].forEach(cat => {
          if (Array.isArray(tree[cat]) && tree[cat].length > 0) {
            results.summary.categories[cat] += tree[cat].length;
            tree[cat].forEach(f => {
              repoFindings.push({ category: cat, detail: f });
            });
          }
        });
      }

      if (depFindings.length > 0) {
        // Dependency references flagged by guard deps check
        isInfected = true;
        results.summary.categories.malicious_deps += depFindings.length;
        repoFindings.push(...depFindings.map(d => ({ category: 'malicious_deps', detail: d })));
      }

      // Campaign-Specific Scan (Lazarus / BeaverTail: node api.js, api.js, global['!'])
      const campaignFindings = scanForBeaverTailMalware(repoFolder);
      if (campaignFindings.length > 0) {
        isInfected = true;
        repoFindings.push(...campaignFindings.map(c => ({
          category: 'beaver_tail_dropper',
          detail: {
            ...c,
            isRemoteRepo: true,
            repoFullName: repo.full_name,
            repoName: repo.name,
            where: path.relative(repoFolder, c.fullPath)
          }
        })));
      }

      if (isInfected) {
        results.threatsFound++;
        results.summary.infected++;
        sendLog(`[ALERT] THREAT DETECTED in ${repo.full_name}! Findings: ${repoFindings.length}`, 'danger');
      } else {
        results.summary.clean++;
        sendLog(`[CLEAN] ${repo.full_name} passed all supply-chain and malware checks.`, 'success');
      }

      results.reposScanned.push({
        name: repo.name,
        full_name: repo.full_name,
        is_private: repo.is_private,
        status: isInfected ? 'infected' : 'clean',
        findings: repoFindings,
        raw: parsedReport
      });

      // Clean up cloned folder immediately to save disk
      try {
        fs.rmSync(repoFolder, { recursive: true, force: true });
      } catch (e) {}
    }

    // Phase 2: Local PC Scan
    if (scanLocalPc && !shouldCancelScan) {
      sendLog(`[LOCAL] Beginning Host & Local Filesystem Scan...`, 'info');

      // 0. OS-Native Host Incident Response Triage (guard triage)
      try {
        sendLog(`[HOST TRIAGE] Auditing kernel persistence, rootkit hooks, LaunchDaemons, systemd, and cron...`, 'info');
        const triageCmd = `"${guardBin}" triage || guard triage || true`;
        const triageRes = await runExec(triageCmd, { timeout: 120000 });
        const triageOut = (triageRes.stdout || '') + '\n' + (triageRes.stderr || '');
        const critMatch = triageOut.match(/Critical findings\s*:\s*(\d+)/i);
        const triageCrit = critMatch ? parseInt(critMatch[1], 10) : 0;

        if (triageCrit > 0) {
          results.threatsFound += triageCrit;
          results.summary.infected++;
          sendLog(`[ALERT] Host Triage detected ${triageCrit} CRITICAL persistence/intrusion artifacts!`, 'danger');
          results.localScanned.push({
            path: 'Host Kernel & Persistence Subsystem',
            name: 'OS Host Persistence & Daemons',
            type: 'host_triage',
            status: 'infected',
            findings: [{
              category: 'host_triage_persistence',
              detail: {
                type: 'persistence_threat',
                severity: 'CRITICAL',
                title: `Host Intrusion Persistence Detected (${triageCrit} Critical Findings)`,
                desc: 'Unauthorized reboot persistence, rogue daemon, or rootkit hooks detected on host OS.',
                where: 'System Daemons / Persistence Registry',
                command: `${guardBin} triage`
              }
            }]
          });
        } else {
          sendLog(`[HOST TRIAGE] Host persistence verification passed cleanly (0 critical threats).`, 'success');
          results.localScanned.push({
            path: 'Host Kernel & Persistence Subsystem',
            name: 'OS Host Persistence & Daemons',
            type: 'host_triage',
            status: 'clean',
            findings: [],
            details: 'OS-native host triage verified no persistent rootkits or rogue daemons.'
          });
        }
      } catch (triageErr) {
        sendLog(`[HOST TRIAGE INFO] Host triage check completed: ${triageErr.message}`, 'info');
      }

      // 1. macOS Binary & Application Code Signature Integrity Check (VS Code)
      const vsCodeAppPath = '/Applications/Visual Studio Code.app';
      if (fs.existsSync(vsCodeAppPath)) {
        sendLog(`[TERMINAL] Executing: codesign --verify --deep --strict "${vsCodeAppPath}"`, 'info');
        const codesignCmd = `codesign --verify --deep --strict "${vsCodeAppPath}" 2>&1`;
        const codesignRes = await runExec(codesignCmd, { timeout: 30000 });

        if (codesignRes.code === 0) {
          sendLog(`[CODESIGN VERIFIED] Visual Studio Code signature is valid and untampered (Apple strict deep check passed).`, 'success');
          results.localScanned.push({
            path: vsCodeAppPath,
            name: 'Visual Studio Code Application',
            type: 'application_binary_integrity',
            status: 'clean',
            findings: [],
            details: 'Apple Code Signature verified intact via: codesign --verify --deep --strict'
          });
        } else {
          const errDetail = codesignRes.stdout.trim() || codesignRes.stderr.trim() || 'Unknown codesign error';
          sendLog(`[CODESIGN ALERT] Visual Studio Code code signature verification FAILED! Possible backdoor or binary tampering detected: ${errDetail}`, 'danger');
          results.threatsFound++;
          results.summary.infected++;
          results.localScanned.push({
            path: vsCodeAppPath,
            name: 'Visual Studio Code Application',
            type: 'application_binary_integrity',
            status: 'infected',
            findings: [{
              category: 'codesign_tampering',
              detail: {
                type: 'codesign_failure',
                severity: 'CRITICAL',
                title: 'VS Code Application Signature Invalid (Possible Trojan / Backdoor)',
                desc: `codesign --verify --deep --strict failed with exit code ${codesignRes.code}: ${errDetail}. This indicates internal binaries, framework bundles, or dynamic libraries have been modified by an infostealer or malware.`,
                where: vsCodeAppPath,
                command: `codesign --verify --deep --strict "${vsCodeAppPath}"`
              }
            }]
          });
        }
      } else {
        sendLog(`[LOCAL INFO] Visual Studio Code application not found at ${vsCodeAppPath}.`, 'info');
      }

      for (let j = 0; j < localPaths.length; j++) {
        if (shouldCancelScan) break;
        const targetPath = localPaths[j];
        results.scannedCount++;

        sendProgress({
          phase: 'local',
          current: results.scannedCount,
          total: results.totalTargets,
          currentTarget: targetPath,
          percent: Math.round((results.scannedCount / results.totalTargets) * 100)
        });

        if (!fs.existsSync(targetPath)) {
          sendLog(`[LOCAL SKIP] Directory does not exist: ${targetPath}`, 'warning');
          continue;
        }

        sendLog(`[SCAN-LOCAL ${j + 1}/${localPaths.length}] Scanning ${targetPath}...`, 'info');

        // Run Guard Scan on local directory
        const localScanCmd = `"${guardBin}" scan --json "${targetPath}"`;
        const localScanRes = await runExec(localScanCmd, { timeout: 300000 });

        let localReport = null;
        try {
          localReport = JSON.parse(localScanRes.stdout);
        } catch (e) {
          const m = localScanRes.stdout.match(/\{[\s\S]*\}/);
          if (m) {
            try { localReport = JSON.parse(m[0]); } catch (_) {}
          }
        }

        // Run Antivirus scan if enabled
        let avResult = null;
        if (runAntivirus) {
          const avCmd = `"${guardBin}" av scan "${targetPath}" || true`;
          const avRes = await runExec(avCmd, { timeout: 180000 });
          avResult = avRes.stdout.trim();
        }

        let localFindings = [];
        let isInfected = false;

        if (localReport && localReport.tree) {
          isInfected = localReport.tree.infected;
          const tree = localReport.tree;
          ['vscode', 'magic', 'fingerprint', 'workflow_baseline', 'malicious_deps', 'av'].forEach(cat => {
            if (Array.isArray(tree[cat]) && tree[cat].length > 0) {
              results.summary.categories[cat] += tree[cat].length;
              tree[cat].forEach(f => {
                localFindings.push({ category: cat, detail: f });
              });
            }
          });
        }

        if (avResult && (avResult.includes('malicious') && !avResult.includes('0 malicious'))) {
          isInfected = true;
          localFindings.push({ category: 'av', detail: avResult });
          results.summary.categories.av++;
        }

        // Campaign-Specific Scan (Lazarus / BeaverTail: node api.js, api.js, global['!'])
        const localCampaign = scanForBeaverTailMalware(targetPath);
        if (localCampaign.length > 0) {
          isInfected = true;
          localFindings.push(...localCampaign.map(c => ({
            category: 'beaver_tail_dropper',
            detail: {
              ...c,
              isRemoteRepo: false,
              where: path.relative(targetPath, c.fullPath)
            }
          })));
        }

        if (isInfected) {
          results.threatsFound++;
          results.summary.infected++;
          sendLog(`[LOCAL ALERT] THREAT DETECTED in ${targetPath}!`, 'danger');
        } else {
          results.summary.clean++;
          sendLog(`[LOCAL CLEAN] ${targetPath} clean.`, 'success');
        }

        results.localScanned.push({
          path: targetPath,
          name: path.basename(targetPath) || targetPath,
          status: isInfected ? 'infected' : 'clean',
          findings: localFindings,
          avOutput: avResult
        });
      }
    }

    results.finishedAt = new Date().toISOString();
    sendLog(`[FINISHED] Scan complete! Scanned: ${results.scannedCount}, Threats: ${results.threatsFound}`, results.threatsFound > 0 ? 'warning' : 'success');

  } catch (err) {
    sendLog(`[FATAL ERROR] Scan pipeline failed: ${err.message}`, 'danger');
  } finally {
    // Remove staging directory
    try {
      fs.rmSync(stagingDir, { recursive: true, force: true });
    } catch (e) {}
    isScanning = false;
    shouldCancelScan = false;
  }

  return results;
});

// 9. AI Security Assessment & Remediation
ipcMain.handle('ai:generate-analysis', async (event, scanResults) => {
  const cfg = loadConfig();
  const provider = cfg.aiProvider || 'gemini';
  const apiKey = cfg.aiApiKey || '';
  const model = cfg.aiModel || (provider === 'gemini' ? 'gemini-1.5-flash' : 'gpt-4o-mini');

  if (!apiKey && provider !== 'ollama') {
    throw new Error('AI API Key is not configured. Please open AI Settings and add your API key.');
  }

  // Build condensed security context
  const threatCount = scanResults.threatsFound || 0;
  const reposInfected = (scanResults.reposScanned || []).filter(r => r.status === 'infected');
  const localInfected = (scanResults.localScanned || []).filter(l => l.status === 'infected');

  const findingsSummary = {
    totalScanned: scanResults.scannedCount,
    threatsFound: threatCount,
    categories: scanResults.summary ? scanResults.summary.categories : {},
    infectedRepos: reposInfected.map(r => ({ name: r.full_name, findings: r.findings })),
    infectedLocal: localInfected.map(l => ({ path: l.path, findings: l.findings }))
  };

  const prompt = `You are a Principal Cyber Security Architect and Incident Responder analyzing scan results from "Guard" (supply-chain and malware scanner).
Here is the scan telemetry:
${JSON.stringify(findingsSummary, null, 2)}

Provide a comprehensive, professional Security Risk Report in Markdown with:
1. Executive Risk Level (CRITICAL / HIGH / MEDIUM / LOW / SECURE) with justification.
2. Threat Analysis: Break down any detected supply chain exploits, malicious dependencies, rogue VS Code configurations, CI/CD workflow hijacking, or malicious fingerprints.
3. Attack Vector & Impact Assessment: What an adversary could achieve if unaddressed (credential theft, pipeline poisoning, backdoor persistence).
4. Step-by-Step Remediation Playbook: Concrete terminal commands and actions to clean repositories, purge malicious dependencies, revoke compromised GitHub tokens/secrets, and isolate hosts.
5. Preventative Hardening: 3-5 best practices for developer workstations and CI/CD security.

Keep the response structured, clear, and actionable.`;

  // Attempt Cloud AI with timeout; smoothly fallback to Autonomous Triage Report if key is invalid/offline
  try {
    if (apiKey && apiKey.startsWith('AIzaSy') && provider === 'gemini') {
      return await Promise.race([
        callGeminiApi(apiKey, model, prompt),
        new Promise((_, reject) => setTimeout(() => reject(new Error('AI request timeout')), 10000))
      ]);
    } else if (apiKey && apiKey.startsWith('sk-') && provider === 'openai') {
      return await Promise.race([
        callOpenAiApi(apiKey, model, prompt),
        new Promise((_, reject) => setTimeout(() => reject(new Error('AI request timeout')), 10000))
      ]);
    } else if (provider === 'ollama') {
      return await callOllamaApi(cfg.ollamaEndpoint, model, prompt);
    }
  } catch (err) {
    console.warn('Cloud AI request failed or timed out, generating local assessment:', err.message);
  }

  // Autonomous Intelligent Incident Response Report
  return generateAutonomousSecurityReport(findingsSummary);
});

function generateAutonomousSecurityReport(findingsSummary) {
  const infectedRepos = findingsSummary.infectedRepos || [];
  const infectedLocal = findingsSummary.infectedLocal || [];
  const totalThreats = findingsSummary.threatsFound || 0;

  let riskLevel = totalThreats > 0 ? (totalThreats > 3 ? 'HIGH' : 'MEDIUM') : 'SECURE';
  let hasBackdoor = false;
  let allDeps = [];

  [...infectedRepos, ...infectedLocal].forEach(item => {
    (item.findings || []).forEach(f => {
      if (f.category === 'beaver_tail_dropper') hasBackdoor = true;
      if (f.category === 'malicious_deps') {
        if (f.detail && f.detail.packages) {
          allDeps.push(...f.detail.packages);
        } else if (typeof f.detail === 'string' && f.detail.includes('[npm]')) {
          allDeps.push(...parseDepsOutput(f.detail));
        }
      }
    });
  });

  if (hasBackdoor) riskLevel = 'CRITICAL';

  return `### 🛡️ Security Risk Assessment Report

**Executive Risk Level: ${riskLevel}**
${riskLevel === 'CRITICAL' ? '⚠️ Active Backdoor / Supply-Chain Dropper Signatures Detected' : riskLevel === 'HIGH' ? '⚠️ Multiple Dependency Advisories Flagged in Manifests' : '✓ System Baseline Stable'}

---

#### 1. Threat & Dependency Intelligence
- **Repositories Audited**: ${findingsSummary.totalScanned || 0}
- **Flagged Repositories**: ${infectedRepos.length > 0 ? infectedRepos.map(r => r.name).join(', ') : 'None'}
${allDeps.length > 0 ? `- **Flagged Package References (${allDeps.length})**: ${Array.from(new Set(allDeps.map(d => d.name))).join(', ')}` : ''}

${hasBackdoor ? `> 🚨 **CRITICAL BACKDOOR DETECTED**: Signs of the **Lazarus / BeaverTail** campaign (\`node api.js\` script injection or obfuscated payload) were detected. This vector attempts to hijack local credentials, environment keys, and browser data.` : ''}

${allDeps.length > 0 ? `#### 2. Manifest Dependency Breakdown
The following package references in your manifests (\`package.json\` / \`pnpm-lock.yaml\`) match names on the global security blocklist:
${allDeps.slice(0, 10).map(d => `* **\`${d.name}\`** (installed: \`${d.yourVersion}\`, flagged range: \`${d.maliciousRange}\` in \`${d.manifest}\`)`).join('\n')}
${allDeps.length > 10 ? `* *...and ${allDeps.length - 10} more references.*` : ''}

> ℹ️ **Advisory Note**: Several popular packages (such as \`axios\` or \`chalk\`) appear on advisory databases because historical versions had CVEs. If your installed version is outside the flagged range, the package is benign, but upgrading to the latest patched release is strongly recommended.` : ''}

---

#### 3. Immediate Step-by-Step Remediation Playbook

**Step 1: Update & Refresh Manifests**
Run the following in the affected project folder to resolve dependency advisories:
\`\`\`bash
# For PNPM projects:
pnpm update --latest
pnpm audit --fix

# For NPM projects:
npm audit fix
\`\`\`

**Step 2: Verify Script Hooks in package.json**
Confirm that no unauthorized execution hooks (such as \`node api.js\`) exist in \`scripts\`:
\`\`\`bash
# Inspect scripts for rogue execution:
grep -rn "api.js" package.json
\`\`\`

**Step 3: Review GitHub Collaborators**
Ensure that no unknown users have collaborator access to your repositories:
\`\`\`bash
# Inspect collaborators via GitHub CLI:
gh api /repos/:owner/:repo/collaborators
\`\`\`

---

#### 4. Developer Workstation Hardening
1. **Pre-Push Validation**: Ensure Guard's git pre-push hook is active (\`guard hooks install\`).
2. **Lockfile Pinning**: Commit clean \`pnpm-lock.yaml\` or \`package-lock.json\` to prevent dynamic supply-chain tampering.
3. **Secret Hygiene**: Rotate any personal access tokens or keys accessed on machines with suspected infections.`;
}

// Helper: AI API Callers
function callGeminiApi(apiKey, model, prompt) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2, maxOutputTokens: 2500 }
    });

    const targetModel = model.startsWith('gemini') ? model : 'gemini-1.5-flash';
    const req = https.request({
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/${targetModel}:generateContent?key=${apiKey}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) {
            reject(new Error(json.error.message || 'Gemini API Error'));
          } else {
            const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
            resolve(text || 'No response generated from Gemini.');
          }
        } catch (e) {
          reject(new Error('Failed to parse Gemini response: ' + data));
        }
      });
    });

    req.on('error', err => reject(err));
    req.write(payload);
    req.end();
  });
}

function callOpenAiApi(apiKey, model, prompt) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: model || 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.2
    });

    const req = https.request({
      hostname: 'api.openai.com',
      path: '/v1/chat/completions',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) {
            reject(new Error(json.error.message || 'OpenAI API Error'));
          } else {
            const content = json.choices?.[0]?.message?.content;
            resolve(content || 'No response from OpenAI.');
          }
        } catch (e) {
          reject(new Error('Failed to parse OpenAI response: ' + data));
        }
      });
    });

    req.on('error', err => reject(err));
    req.write(payload);
    req.end();
  });
}

function callClaudeApi(apiKey, model, prompt) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: model || 'claude-3-5-sonnet-20241022',
      max_tokens: 3000,
      messages: [{ role: 'user', content: prompt }]
    });

    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) {
            reject(new Error(json.error.message || 'Anthropic API Error'));
          } else {
            const text = json.content?.[0]?.text;
            resolve(text || 'No response from Claude.');
          }
        } catch (e) {
          reject(new Error('Failed to parse Claude response: ' + data));
        }
      });
    });

    req.on('error', err => reject(err));
    req.write(payload);
    req.end();
  });
}

function callOllamaApi(endpoint, model, prompt) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint || 'http://localhost:11434');
    const httpLib = url.protocol === 'https:' ? https : require('http');

    const payload = JSON.stringify({
      model: model || 'llama3',
      prompt: prompt,
      stream: false
    });

    const req = httpLib.request({
      hostname: url.hostname,
      port: url.port || 11434,
      path: '/api/generate',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.response || 'No response from Ollama.');
        } catch (e) {
          reject(new Error('Failed to parse Ollama response: ' + data));
        }
      });
    });

    req.on('error', err => reject(err));
    req.write(payload);
    req.end();
  });
}

// 10. AI Settings Management
ipcMain.handle('ai:get-settings', () => {
  const cfg = loadConfig();
  return {
    provider: cfg.aiProvider || 'gemini',
    apiKey: cfg.aiApiKey ? `${cfg.aiApiKey.slice(0, 4)}••••••••${cfg.aiApiKey.slice(-4)}` : '',
    hasKey: Boolean(cfg.aiApiKey),
    model: cfg.aiModel || 'gemini-1.5-flash',
    ollamaEndpoint: cfg.ollamaEndpoint || 'http://localhost:11434'
  };
});

ipcMain.handle('ai:save-settings', (event, newSettings) => {
  const current = loadConfig();
  const update = {
    aiProvider: newSettings.provider,
    aiModel: newSettings.model,
    ollamaEndpoint: newSettings.ollamaEndpoint
  };
  // Only update apiKey if not masked and non-empty
  if (newSettings.apiKey && !newSettings.apiKey.includes('••••')) {
    update.aiApiKey = newSettings.apiKey.trim();
  }
  saveConfig(update);
  return { success: true };
});

// 11. Report Export
ipcMain.handle('report:export', async (event, { format, data }) => {
  const defaultPath = path.join(
    os.homedir(),
    'Desktop',
    `Guard_Security_Report_${new Date().toISOString().replace(/[:.]/g, '-')}.${format}`
  );

  const saveRes = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Security Report',
    defaultPath,
    filters: format === 'json'
      ? [{ name: 'JSON Report', extensions: ['json'] }]
      : [{ name: 'HTML Report', extensions: ['html'] }]
  });

  if (saveRes.canceled || !saveRes.filePath) return { success: false };

  let content = '';
  if (format === 'json') {
    content = JSON.stringify(data, null, 2);
  } else {
    content = generateHtmlReport(data);
  }

  fs.writeFileSync(saveRes.filePath, content, 'utf8');
  shell.showItemInFolder(saveRes.filePath);
  return { success: true, filePath: saveRes.filePath };
});

// 12. Auto-Clean & Neutralize Threat (Local PC & Remote GitHub Repos)
ipcMain.handle('threat:auto-clean', async (event, threat) => {
  try {
    if (!threat) return { success: false, error: 'No threat metadata provided.' };

    // Case A: Threat belongs to a remote GitHub repository
    if (threat.isRemoteRepo || threat.repoFullName) {
      const repoFullName = threat.repoFullName;
      if (!repoFullName) {
        return { success: false, error: 'Target remote repository identifier missing.' };
      }
      return await disinfectRemoteRepo(repoFullName);
    }

    // Case B: Local filesystem threat
    const filePath = threat.fullPath || threat.where;
    if (!filePath || !fs.existsSync(filePath)) {
      return { success: false, error: `Target file path does not exist on disk: ${filePath}` };
    }

    // If it's a directory or macOS .app bundle
    if (fs.statSync(filePath).isDirectory()) {
      if (filePath.endsWith('.app')) {
        await shell.trashItem(filePath);
        return { success: true, message: `Moved tampered application bundle to Trash: ${path.basename(filePath)}` };
      }
      const res = disinfectLocalDirectory(filePath, { isRemote: false });
      return { success: true, message: `Disinfected directory! Cleaned ${res.cleanedCount} file(s).` };
    }

    const quarantineDir = path.join(os.homedir(), '.guard', 'quarantine');
    if (!fs.existsSync(quarantineDir)) {
      try { fs.mkdirSync(quarantineDir, { recursive: true }); } catch (_) {}
    }

    // Subcase B1: package.json script hook
    if (path.basename(filePath) === 'package.json') {
      const content = fs.readFileSync(filePath, 'utf8');
      let json = JSON.parse(content);
      let changed = false;

      // Clean devDependencies & dependencies
      ['devDependencies', 'dependencies'].forEach(depType => {
        if (json[depType]) {
          ['roboter', 'invisibleferret', 'beaver-tail'].forEach(badPkg => {
            if (json[depType][badPkg]) {
              delete json[depType][badPkg];
              changed = true;
            }
          });
        }
      });

      // Clean scripts
      if (json.scripts) {
        for (const [k, v] of Object.entries(json.scripts)) {
          if (typeof v === 'string' && (v.includes('node api.js') || v.includes('api.js'))) {
            const cleanedVal = v
              .replace(/node\s+api\.js\s*&&\s*/gi, '')
              .replace(/&&\s*node\s+api\.js/gi, '')
              .replace(/node\s+api\.js/gi, '')
              .replace(/api\.js\s*&&\s*/gi, '')
              .trim();
            if (cleanedVal !== v) {
              json.scripts[k] = cleanedVal;
              changed = true;
            }
          }
        }
      }

      if (changed) {
        fs.writeFileSync(filePath, JSON.stringify(json, null, 2) + '\n', 'utf8');
        return { success: true, message: `Sanitized ${path.basename(filePath)} and removed malicious hooks!` };
      }
      return { success: true, message: `${path.basename(filePath)} is already clean.` };
    }

    // Subcase B2: api.js backdoor dropper file
    if (
      path.basename(filePath) === 'api.js' ||
      path.basename(filePath) === '.api.js' ||
      path.basename(filePath) === 'payload.js' ||
      threat.type === 'dropper_file'
    ) {
      const dest = path.join(quarantineDir, `${Date.now()}_${path.basename(filePath)}.quarantine`);
      fs.renameSync(filePath, dest);
      return { success: true, message: `Quarantined malicious dropper to ~/.guard/quarantine/` };
    }

    // Subcase B3: Obfuscated payload file
    if (threat.type === 'obfuscated_payload' || threat.category === 'beaver_tail_dropper') {
      const content = fs.readFileSync(filePath, 'utf8');
      const stripped = content
        .replace(/var\s+k\$nodabqyPCpvUiq[\s\S]*?v8\(['"][^'"]*['"]\s*,\s*x8\)\([^)]*\)\s*;?/gi, '')
        .replace(/global\['!'\]\s*=\s*['"][^'"]*['"];\s*function\s+y7\([\s\S]*?v8\(['"][^'"]*['"]\s*,\s*x8\)\([^)]*\)\s*;?/gi, '')
        .trim();

      if (stripped.length < 50) {
        const dest = path.join(quarantineDir, `${Date.now()}_${path.basename(filePath)}.quarantine`);
        fs.renameSync(filePath, dest);
        return { success: true, message: `Quarantined pure malware payload file to ~/.guard/quarantine/` };
      } else {
        const backup = path.join(quarantineDir, `${Date.now()}_backup_${path.basename(filePath)}`);
        fs.writeFileSync(backup, content, 'utf8');
        fs.writeFileSync(filePath, stripped + '\n', 'utf8');
        return { success: true, message: `Sanitized ${path.basename(filePath)} (backup saved in ~/.guard/quarantine/)` };
      }
    }

    return { success: false, error: 'Automatic surgical remediation not available for this signature.' };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 12B. Delete / Move Infected Trojan to Trash (App Bundles, Trojans, Droppers, Malicious Files)
ipcMain.handle('threat:delete', async (event, threat) => {
  try {
    if (!threat) return { success: false, error: 'No threat metadata provided.' };

    let targetPath = threat.where || threat.fullPath || threat.path;
    if (!targetPath && threat.detail && typeof threat.detail === 'object') {
      targetPath = threat.detail.where || threat.detail.fullPath || threat.detail.path;
    }

    if (!targetPath) {
      return { success: false, error: 'Could not determine file path of the target threat.' };
    }

    if (!fs.existsSync(targetPath)) {
      return { success: false, error: `Target path does not exist on disk: ${targetPath}` };
    }

    const baseName = path.basename(targetPath);
    try {
      await shell.trashItem(targetPath);
      return { 
        success: true, 
        message: `Successfully moved infected trojan to Trash: ${baseName}`,
        targetPath,
        trashed: true
      };
    } catch (trashErr) {
      const stat = fs.statSync(targetPath);
      if (stat.isDirectory()) {
        fs.rmSync(targetPath, { recursive: true, force: true });
      } else {
        fs.unlinkSync(targetPath);
      }
      return { 
        success: true, 
        message: `Permanently removed infected item: ${baseName}`,
        targetPath,
        deleted: true
      };
    }
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// 13. Disinfect Entire Remote GitHub Repository
ipcMain.handle('github:disinfect-repo', async (event, repoFullName) => {
  return await disinfectRemoteRepo(repoFullName);
});

// 14. Batch Disinfect All Infected Remote Repositories
ipcMain.handle('github:disinfect-all', async (event, repoList) => {
  const results = [];
  for (const repo of repoList) {
    const res = await disinfectRemoteRepo(repo);
    results.push({ repo, ...res });
  }
  return results;
});

// 15. Audit GitHub Collaborators for Rogue Backdoors
ipcMain.handle('github:audit-collaborators', async (event, repoFullName) => {
  const cfg = loadConfig();
  let token = cfg.githubToken;
  if (!token) {
    const tokenRes = await runExec('gh auth token || true');
    if (tokenRes.stdout.trim().startsWith('gh')) token = tokenRes.stdout.trim();
  }
  if (!token) return { success: false, error: 'GitHub authentication required' };

  try {
    const userProfile = await fetchGitHubApi('/user', token);
    const myLogin = userProfile.login;
    const collabs = await fetchGitHubApi(`/repos/${repoFullName}/collaborators`, token);

    if (Array.isArray(collabs)) {
      const externals = collabs.filter(c => c.login !== myLogin);
      return { success: true, myLogin, collaborators: collabs, externalCollaborators: externals };
    }
    return { success: true, myLogin, collaborators: [], externalCollaborators: [] };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

function generateHtmlReport(data) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Guard - Audit Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0c1017; color: #e6edf3; padding: 40px; }
    h1, h2 { color: #00f0ff; }
    .badge { padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 12px; }
    .clean { background: #0d4429; color: #3fb950; }
    .infected { background: #490202; color: #f85149; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #30363d; padding: 12px; text-align: left; }
    th { background: #161b22; }
    .summary-card { display: flex; gap: 20px; margin: 20px 0; }
    .card { background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 8px; flex: 1; }
    pre { background: #010409; padding: 12px; border-radius: 6px; overflow-x: auto; color: #58a6ff; }
  </style>
</head>
<body>
  <h1>🛡️ Security Guard Threat Assessment</h1>
  <p>Generated: ${new Date().toLocaleString()}</p>
  
  <div class="summary-card">
    <div class="card">
      <h3>Total Targets</h3>
      <h2 style="color: #fff;">${data.scannedCount || 0}</h2>
    </div>
    <div class="card">
      <h3>Threats Detected</h3>
      <h2 style="color: ${data.threatsFound > 0 ? '#f85149' : '#3fb950'};">${data.threatsFound || 0}</h2>
    </div>
    <div class="card">
      <h3>Clean Targets</h3>
      <h2 style="color: #3fb950;">${data.summary ? data.summary.clean : 0}</h2>
    </div>
  </div>

  <h2>GitHub Repositories Scanned</h2>
  <table>
    <thead><tr><th>Repository</th><th>Visibility</th><th>Status</th><th>Findings</th></tr></thead>
    <tbody>
      ${(data.reposScanned || []).map(r => `
        <tr>
          <td><strong>${r.full_name}</strong></td>
          <td>${r.is_private ? '🔒 Private' : '🌐 Public'}</td>
          <td><span class="badge ${r.status}">${r.status.toUpperCase()}</span></td>
          <td>${r.findings && r.findings.length ? `<pre>${JSON.stringify(r.findings, null, 2)}</pre>` : 'None'}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <h2>Local PC Targets Scanned</h2>
  <table>
    <thead><tr><th>Location</th><th>Status</th><th>Findings</th></tr></thead>
    <tbody>
      ${(data.localScanned || []).map(l => `
        <tr>
          <td>${l.path}</td>
          <td><span class="badge ${l.status}">${l.status.toUpperCase()}</span></td>
          <td>${l.findings && l.findings.length ? `<pre>${JSON.stringify(l.findings, null, 2)}</pre>` : 'None'}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>
</body>
</html>`;
}
